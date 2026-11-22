// SPDX-License-Identifier: GPL-3.0-or-later

//! Single-screen dashboard.
//!
//! Left: protection status and service controls. Right: connection
//! test and the search for working settings. Bottom: activity log.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};

use crate::bundle;
use crate::probe::{self, Outcome};
use crate::process::{self, TestInstance};
use crate::service::{self, ServiceInfo, SvcState};
use crate::settings::{self, Settings};
use crate::theme::{self, FAINT, GREEN, MUTED, RED, YELLOW};

const EXE_NAME: &str = "dpibreak.exe";

// ---------------------------------------------------------------- state

#[derive(Clone, Default)]
struct Status {
    service: Option<ServiceInfo>,
    service_err: Option<String>,
    driver: Option<ServiceInfo>,
    pids: Vec<u32>,
    updated: bool,
}

impl Status {
    fn service_running(&self) -> bool {
        matches!(&self.service, Some(s) if s.state == SvcState::Running)
    }

    fn service_pid(&self) -> Option<u32> {
        self.service.as_ref().filter(|s| s.pid != 0).map(|s| s.pid)
    }

    /// dpibreak.exe processes that are not the service.
    fn standalone_pids(&self) -> Vec<u32> {
        let svc = self.service_pid();
        self.pids
            .iter()
            .copied()
            .filter(|p| Some(*p) != svc)
            .collect()
    }
}

/// Results of probing a list of sites under one setup.
#[derive(Clone)]
struct Column {
    title: String,
    args: Option<String>,
    note: Option<String>,
    urls: Vec<String>,
    results: Vec<Option<Outcome>>,
}

impl Column {
    fn new(title: impl Into<String>, args: Option<String>, urls: &[String]) -> Self {
        Self {
            title: title.into(),
            args,
            note: None,
            urls: urls.to_vec(),
            results: vec![None; urls.len()],
        }
    }

    fn works(&self) -> usize {
        self.results.iter().flatten().filter(|o| o.works()).count()
    }

    fn done(&self) -> bool {
        self.note.is_some() || self.results.iter().all(Option::is_some)
    }

    fn started(&self) -> bool {
        self.note.is_some() || self.results.iter().any(Option::is_some)
    }
}

#[derive(Clone, Copy)]
enum Target {
    Current,
    Search(usize),
}

#[derive(Default)]
struct Shared {
    status: Status,
    busy: Option<String>,
    current: Option<Column>,
    search: Vec<Column>,
    log: Vec<String>,
    /// dpibreak.exe started by the settings search, if any.
    test_pid: Option<u32>,
    /// The search stopped the service and must start it again.
    restore_service: bool,
}

impl Shared {
    fn column_mut(&mut self, t: Target) -> Option<&mut Column> {
        match t {
            Target::Current => self.current.as_mut(),
            Target::Search(i) => self.search.get_mut(i),
        }
    }
}

#[derive(Clone)]
struct Ctx {
    shared: Arc<Mutex<Shared>>,
    cancel: Arc<AtomicBool>,
    egui: egui::Context,
}

impl Ctx {
    fn lock(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, msg: impl Into<String>) {
        let line = format!("{}  {}", clock(), msg.into());
        let mut s = self.lock();
        s.log.push(line);
        let len = s.log.len();
        if len > 500 {
            s.log.drain(..len - 500);
        }
        drop(s);
        self.egui.request_repaint();
    }

    fn busy(&self, msg: Option<String>) {
        self.lock().busy = msg;
        self.egui.request_repaint();
    }

    /// Claim the busy slot if it is free (check and set under one lock).
    fn try_busy(&self, label: &str) -> bool {
        let mut s = self.lock();
        if s.busy.is_some() {
            return false;
        }
        s.busy = Some(label.to_string());
        drop(s);
        self.egui.request_repaint();
        true
    }

    /// Stop and start the service. If the panel is closed in between,
    /// `on_exit` starts it again.
    fn restart_service(&self) -> Result<(), String> {
        service::stop()?;
        self.lock().restore_service = true;
        let r = service::start();
        self.lock().restore_service = false;
        r
    }

    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    fn refresh_status(&self) {
        let status = read_status();
        self.lock().status = status;
        self.egui.request_repaint();
    }
}

fn clock() -> String {
    // SAFETY: GetLocalTime only writes the returned struct.
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

fn read_status() -> Status {
    let (service, service_err) = match service::query(service::SERVICE_NAME) {
        Ok(s) => (s, None),
        Err(e) => (None, Some(e)),
    };
    Status {
        service,
        service_err,
        driver: service::query(service::DRIVER_SERVICE_NAME).ok().flatten(),
        pids: process::find_pids(EXE_NAME),
        updated: true,
    }
}

fn host(url: &str) -> &str {
    let h = url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    h.strip_prefix("www.").unwrap_or(h)
}

fn outcome_color(o: Option<&Outcome>) -> Color32 {
    match o {
        Some(o) if o.works() => GREEN,
        Some(Outcome::Dns | Outcome::BadCert) => YELLOW,
        Some(_) => RED,
        None => FAINT,
    }
}

/// Very short result text for compact lists.
fn outcome_tag(o: &Outcome) -> String {
    match o {
        Outcome::Ok { secs, .. } => format!("{:.0} ms", secs * 1000.0),
        Outcome::Dns => "DNS".into(),
        Outcome::BadCert => "DNS redirect".into(),
        Outcome::Connect => "IP block".into(),
        Outcome::Timeout => "timeout".into(),
        Outcome::TlsFailed => "TLS cut".into(),
        Outcome::Reset => "reset".into(),
        Outcome::Other(c) => format!("err {c}"),
    }
}

// ------------------------------------------------------------------ app

pub struct App {
    ctx: Ctx,
    settings: Settings,
    saved_json: String,
    last_save_check: Instant,
    confirm_uninstall: bool,
    edit_sites: bool,
    edit_configs: bool,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        theme::apply(&cc.egui_ctx);

        let ctx = Ctx {
            shared: Arc::new(Mutex::new(Shared::default())),
            cancel: Arc::new(AtomicBool::new(false)),
            egui: cc.egui_ctx.clone(),
        };

        // Background status poller.
        {
            let ctx = ctx.clone();
            std::thread::spawn(move || {
                loop {
                    ctx.refresh_status();
                    std::thread::sleep(Duration::from_secs(2));
                }
            });
        }

        if bundle::is_bundled() {
            let ctx = ctx.clone();
            std::thread::spawn(move || prepare_bundle(&ctx));
        }

        let settings = Settings::load();
        let saved_json = serde_json::to_string(&settings).unwrap_or_default();
        ctx.log("DPIBreak Control Panel started");
        if settings.exe_path.is_empty() {
            ctx.log("dpibreak.exe not found: set its path under Service");
        }

        Self {
            ctx,
            settings,
            saved_json,
            last_save_check: Instant::now(),
            confirm_uninstall: false,
            edit_sites: false,
            edit_configs: false,
        }
    }

    fn is_busy(&self) -> bool {
        self.ctx.lock().busy.is_some()
    }

    fn exe_ok(&self) -> bool {
        std::path::Path::new(self.settings.exe_path.trim()).is_file()
    }

    /// Run `job` on a worker thread with a busy label.
    fn spawn<F>(&self, label: &str, job: F)
    where
        F: FnOnce(&Ctx) + Send + 'static,
    {
        let ctx = self.ctx.clone();
        if !ctx.try_busy(label) {
            return;
        }
        ctx.cancel.store(false, Ordering::Relaxed);
        std::thread::spawn(move || {
            job(&ctx);
            ctx.busy(None);
            ctx.refresh_status();
        });
    }

    fn autosave(&mut self) {
        if self.last_save_check.elapsed() < Duration::from_millis(800) {
            return;
        }
        self.last_save_check = Instant::now();
        let json = serde_json::to_string(&self.settings).unwrap_or_default();
        if json != self.saved_json {
            if let Err(e) = self.settings.save() {
                self.ctx.log(format!("could not save settings: {e}"));
            }
            self.saved_json = json;
        }
    }
}

impl eframe::App for App {
    /// Never leave a test dpibreak.exe running or the service stopped
    /// because the window was closed in the middle of a search.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.ctx.cancel.store(true, Ordering::Relaxed);
        let (pid, restore) = {
            let s = self.ctx.lock();
            (s.test_pid, s.restore_service)
        };
        if let Some(pid) = pid {
            _ = process::terminate(pid);
        }
        if restore {
            _ = service::start();
        }
        _ = self.settings.save();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let (status, busy, current, search, log, test_pid) = {
            let s = self.ctx.lock();
            (
                s.status.clone(),
                s.busy.clone(),
                s.current.clone(),
                s.search.clone(),
                s.log.clone(),
                s.test_pid,
            )
        };

        egui::Panel::bottom("activity")
            .resizable(true)
            .default_size(64.0)
            .min_size(48.0)
            .max_size(220.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::CARD)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ui, |ui| self.activity(ui, busy.as_deref(), &log));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(16, 12)),
            )
            .show(ui, |ui| {
                self.header(ui, &status);
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.columns(2, |cols| {
                            self.status_card(&mut cols[0], &status, test_pid);
                            cols[0].add_space(10.0);
                            self.service_card(&mut cols[0], &status);

                            self.test_card(&mut cols[1], current.as_ref());
                            cols[1].add_space(10.0);
                            self.search_card(&mut cols[1], &status, &search, test_pid);
                        });
                    });
            });

        self.autosave();
        ctx.request_repaint_after(Duration::from_millis(if busy.is_some() {
            100
        } else {
            1000
        }));
    }
}

// ------------------------------------------------------- header, footer

impl App {
    fn header(&mut self, ui: &mut egui::Ui, status: &Status) {
        ui.horizontal(|ui| {
            theme::logo(ui, 26.0);
            ui.add_space(2.0);
            ui.label(RichText::new("DPIBreak").size(19.0).strong());
            ui.label(RichText::new("Control Panel").size(19.0).color(MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(s) = &status.service {
                    let (_, args) = service::parse_bin_path(&s.bin_path);
                    if !args.is_empty() {
                        ui.label(RichText::new(args).monospace().color(MUTED));
                        ui.label(RichText::new("Service settings").color(FAINT).size(12.0));
                    }
                }
            });
        });
    }

    fn activity(&mut self, ui: &mut egui::Ui, busy: Option<&str>, log: &[String]) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("ACTIVITY").size(11.0).strong().color(MUTED));
            ui.add_space(6.0);
            if let Some(b) = busy {
                ui.spinner();
                ui.label(RichText::new(b).color(theme::ACCENT_2));
                if theme::link(ui, true, "Cancel", RED).clicked() {
                    self.ctx.cancel.store(true, Ordering::Relaxed);
                    self.ctx.log("cancel requested");
                }
            } else {
                ui.label(RichText::new("Idle").color(FAINT));
            }
        });
        // Do not let the log grow the panel; it scrolls instead.
        egui::ScrollArea::vertical()
            .id_salt("activity_log")
            .stick_to_bottom(true)
            .max_height(ui.available_height())
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 2.0;
                for line in log {
                    ui.label(RichText::new(line).monospace().size(11.5).color(MUTED));
                }
            });
    }
}

// ---------------------------------------------------------- status card

fn state_color(state: SvcState) -> Color32 {
    match state {
        SvcState::Running => GREEN,
        SvcState::Stopped => RED,
        _ => YELLOW,
    }
}

impl App {
    fn status_card(&mut self, ui: &mut egui::Ui, status: &Status, test_pid: Option<u32>) {
        // The search's own dpibreak.exe is not a "manual" instance.
        let standalone: Vec<u32> = status
            .standalone_pids()
            .into_iter()
            .filter(|p| Some(*p) != test_pid)
            .collect();
        let (color, headline, detail) = if !status.updated {
            (MUTED, "Checking…".to_string(), String::new())
        } else if test_pid.is_some() {
            (
                theme::ACCENT_2,
                "Testing settings".to_string(),
                "The service is paused while settings are tried.".to_string(),
            )
        } else if status.service_running() {
            (
                GREEN,
                "Protected".to_string(),
                "DPIBreak is running as a service.".to_string(),
            )
        } else if !standalone.is_empty() {
            (
                YELLOW,
                "Running manually".to_string(),
                format!("dpibreak.exe (PID {}) outside the service.", standalone[0]),
            )
        } else if status.service.is_some() {
            (
                RED,
                "Not protected".to_string(),
                "The service is stopped.".to_string(),
            )
        } else {
            (
                RED,
                "Not protected".to_string(),
                "No DPIBreak service installed.".to_string(),
            )
        };

        let busy = self.is_busy();
        let exe_ok = self.exe_ok();

        theme::card(
            ui,
            "Protection",
            None,
            |ui| {
                match &status.service {
                Some(s) if s.state == SvcState::Running => {
                    if theme::danger(ui, !busy, "Stop")
                        .on_hover_text(
                            "Stop protection. The service stays installed; with auto-start                              on it starts again with Windows.",
                        )
                        .clicked()
                    {
                        self.spawn("Stopping the service", |ctx| match service::stop() {
                            Ok(()) => ctx.log("service stopped"),
                            Err(e) => ctx.log(format!("stop failed: {e}")),
                        });
                    }
                }
                Some(_) => {
                    if theme::success(ui, !busy, "Start").clicked() {
                        self.spawn("Starting the service", |ctx| match service::start() {
                            Ok(()) => ctx.log("service started"),
                            Err(e) => ctx.log(format!("start failed: {e}")),
                        });
                    }
                }
                None => {
                    if theme::primary(ui, !busy && exe_ok, "Install")
                        .on_hover_text("Install DPIBreak as a service and start it")
                        .clicked()
                    {
                        self.install();
                    }
                }
            }
            },
            |ui| {
                egui::Frame::new()
                    .fill(color.gamma_multiply(0.08))
                    .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.35)))
                    .corner_radius(egui::CornerRadius::same(12))
                    .inner_margin(egui::Margin::symmetric(12, 10))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            theme::glow_dot(ui, color, 7.0);
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 1.0;
                                ui.label(RichText::new(&headline).size(19.0).strong().color(color));
                                if !detail.is_empty() {
                                    ui.label(RichText::new(&detail).color(MUTED).size(12.5));
                                }
                            });
                        });
                    });

                ui.add_space(2.0);
                ui.horizontal_wrapped(|ui| {
                    match (&status.service, &status.service_err) {
                        (Some(s), _) => {
                            theme::chip(
                                ui,
                                &format!("Service {}", s.state.label()),
                                state_color(s.state),
                            );
                            theme::chip(
                                ui,
                                if s.auto_start {
                                    "Auto-start"
                                } else {
                                    "Manual start"
                                },
                                if s.auto_start { theme::ACCENT_2 } else { MUTED },
                            );
                        }
                        (None, Some(e)) => {
                            theme::chip(ui, "Service unknown", RED).on_hover_text(e);
                        }
                        (None, None) => {
                            theme::chip(ui, "No service", MUTED);
                        }
                    }
                    match &status.driver {
                        Some(d) => theme::chip(
                            ui,
                            &format!("WinDivert {}", d.state.label()),
                            state_color(d.state),
                        ),
                        None => theme::chip(ui, "WinDivert idle", MUTED),
                    }
                    .on_hover_text("The packet driver DPIBreak uses");
                });

                for pid in &standalone {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("Manual instance · PID {pid}")).color(YELLOW),
                        );
                        if theme::link(ui, true, "Terminate", RED).clicked() {
                            match process::terminate(*pid) {
                                Ok(()) => self.ctx.log(format!("terminated PID {pid}")),
                                Err(e) => self.ctx.log(format!("terminate {pid}: {e}")),
                            }
                        }
                    });
                }
            },
        );
    }

    fn install(&self) {
        let exe = self.settings.exe_path.clone();
        let args = self.settings.args.clone();
        let auto = self.settings.auto_start;
        self.spawn(
            "Installing the service",
            move |ctx| match service::install(&exe, &args, auto).and_then(|()| service::start()) {
                Ok(()) => ctx.log("service installed and started"),
                Err(e) => ctx.log(format!("install failed: {e}")),
            },
        );
    }
}

// --------------------------------------------------------- service card

impl App {
    fn service_card(&mut self, ui: &mut egui::Ui, status: &Status) {
        let busy = self.is_busy();
        let exe_ok = self.exe_ok();
        let changed = status.service.as_ref().is_some_and(|s| {
            !service::same_command(&s.bin_path, &self.settings.exe_path, &self.settings.args)
                || s.auto_start != self.settings.auto_start
        });

        theme::card(
            ui,
            "Service",
            Some("Runs in the background and survives restarts."),
            |ui| {
                if changed {
                    theme::chip(ui, "Not applied", YELLOW)
                        .on_hover_text("The service still runs with its previous settings");
                }
            },
            |ui| {
                theme::field(ui, "Program", |ui| {
                    let w = ui.available_width() - 70.0;
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings.exe_path)
                            .desired_width(w)
                            .hint_text(r"C:\path\to\dpibreak.exe"),
                    )
                    .on_hover_text("Location of dpibreak.exe");
                    if ui.button("Detect").clicked() {
                        match settings::detect_exe() {
                            Some(p) => self.settings.exe_path = p,
                            None => self
                                .ctx
                                .log("dpibreak.exe not found next to the panel or on PATH"),
                        }
                    }
                });
                if bundle::is_bundled() {
                    let builtin = bundle::exe_path().display().to_string();
                    theme::field(ui, "", |ui| {
                        if self.settings.exe_path.eq_ignore_ascii_case(&builtin) {
                            theme::chip(ui, "Built-in DPIBreak", theme::ACCENT_2).on_hover_text(
                                "Shipped inside this panel; nothing else to download",
                            );
                        } else if theme::link(
                            ui,
                            true,
                            "Use the built-in DPIBreak",
                            theme::ACCENT_2,
                        )
                        .on_hover_text(&builtin)
                        .clicked()
                        {
                            self.settings.exe_path = builtin;
                        }
                    });
                }
                if !exe_ok {
                    theme::field(ui, "", |ui| {
                        ui.label(
                            RichText::new("dpibreak.exe not found here")
                                .color(RED)
                                .size(12.5),
                        );
                    });
                }
                theme::field(ui, "Settings", |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings.args)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("-o 0,1"),
                    )
                    .on_hover_text("dpibreak arguments. \"Find working settings\" can pick them.");
                });
                theme::field(ui, "", |ui| {
                    ui.checkbox(&mut self.settings.auto_start, "Start with Windows");
                });

                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    let exe = self.settings.exe_path.clone();
                    let args = self.settings.args.clone();
                    let auto = self.settings.auto_start;
                    match &status.service {
                        None => {
                            if theme::primary(ui, !busy && exe_ok, "Install and start").clicked() {
                                self.install();
                            }
                        }
                        Some(s) => {
                            let running = s.state == SvcState::Running;
                            let apply = if changed {
                                theme::primary(ui, !busy && exe_ok, "Apply settings")
                            } else {
                                theme::secondary(ui, false, "Apply settings")
                            };
                            if apply
                                .on_hover_text("Save to the service; restarts it if running")
                                .clicked()
                            {
                                self.spawn("Applying settings", move |ctx| {
                                    let r =
                                        service::reconfigure(&exe, &args, auto).and_then(|()| {
                                            if running {
                                                ctx.restart_service()
                                            } else {
                                                Ok(())
                                            }
                                        });
                                    match r {
                                        Ok(()) => ctx.log("service settings applied"),
                                        Err(e) => ctx.log(format!("apply failed: {e}")),
                                    }
                                });
                            }
                            if theme::secondary(ui, !busy && running, "Restart").clicked() {
                                self.spawn("Restarting the service", |ctx| {
                                    match ctx.restart_service() {
                                        Ok(()) => ctx.log("service restarted"),
                                        Err(e) => ctx.log(format!("restart failed: {e}")),
                                    }
                                });
                            }

                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if !self.confirm_uninstall {
                                        if theme::link(ui, !busy, "Uninstall", MUTED).clicked() {
                                            self.confirm_uninstall = true;
                                        }
                                    } else {
                                        if theme::link(ui, true, "Keep", MUTED).clicked() {
                                            self.confirm_uninstall = false;
                                        }
                                        if theme::danger(ui, !busy, "Remove").clicked() {
                                            self.confirm_uninstall = false;
                                            self.spawn("Uninstalling the service", |ctx| {
                                                match service::stop()
                                                    .and_then(|()| service::uninstall())
                                                {
                                                    Ok(()) => ctx.log("service uninstalled"),
                                                    Err(e) => {
                                                        ctx.log(format!("uninstall failed: {e}"))
                                                    }
                                                }
                                            });
                                        }
                                    }
                                    if let Some(dir) = std::env::var_os("ProgramData")
                                        .map(|d| std::path::PathBuf::from(d).join("dpibreak"))
                                        .filter(|d| d.is_dir())
                                        && theme::link(ui, true, "Logs", MUTED).clicked()
                                    {
                                        _ = std::process::Command::new("explorer.exe")
                                            .arg(&dir)
                                            .spawn();
                                    }
                                },
                            );
                        }
                    }
                });

                ui.collapsing(
                    RichText::new("Settings help").color(MUTED).size(12.5),
                    |ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        for (flag, help) in [
                            ("-o 0,1", "split the TLS hello after byte 1 (default)"),
                            (
                                "-o 0,5",
                                "split after the record header; try if sites break",
                            ),
                            ("-o 5,0", "send the second part first"),
                            (
                                "--fake-ttl 8",
                                "add a decoy hello that expires after 8 hops",
                            ),
                            ("-a", "like --fake-ttl, with the hop count per server"),
                            ("-b site.com", "leave this site untouched (newer builds)"),
                        ] {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [96.0, 16.0],
                                    egui::Label::new(
                                        RichText::new(flag).monospace().color(theme::ACCENT_2),
                                    ),
                                );
                                ui.label(RichText::new(help).color(MUTED).size(12.5));
                            });
                        }
                    },
                );
            },
        );
    }
}

// ------------------------------------------------------------ test card

impl App {
    fn start_current_test(&self) {
        let urls = self.settings.url_list();
        let timeout = self.settings.timeout_secs;
        self.spawn("Testing sites", move |ctx| {
            ctx.lock().current = Some(Column::new("Current system", None, &urls));
            ctx.log(format!("testing {} sites", urls.len()));
            probe_column(ctx, Target::Current, &urls, timeout);
            let works = ctx.lock().current.as_ref().map(Column::works).unwrap_or(0);
            ctx.log(format!("{works} of {} sites reachable", urls.len()));
        });
    }

    fn test_card(&mut self, ui: &mut egui::Ui, current: Option<&Column>) {
        let busy = self.is_busy();
        let urls = self.settings.url_list();
        let col = current.filter(|c| c.urls == urls);
        let mut run = false;

        theme::card(
            ui,
            "Connection test",
            Some("Can these sites be opened right now?"),
            |ui| {
                run = theme::primary(ui, !busy && !urls.is_empty(), "Run test").clicked();
                if let Some(c) = col.filter(|c| c.done()) {
                    let (works, total) = (c.works(), c.urls.len());
                    let color = if works == total {
                        GREEN
                    } else if works == 0 {
                        RED
                    } else {
                        YELLOW
                    };
                    theme::chip(ui, &format!("{works}/{total} open"), color);
                }
            },
            |ui| {
                theme::inset(ui, |ui| {
                    if urls.is_empty() {
                        ui.label(
                            RichText::new("No sites. Use Edit sites to add some.").color(MUTED),
                        );
                        return;
                    }
                    let half = urls.len().div_ceil(2);
                    ui.columns(2, |cols| {
                        for (i, url) in urls.iter().enumerate() {
                            let ui = &mut cols[i / half];
                            let res = col.and_then(|c| c.results.get(i)).and_then(|r| r.as_ref());
                            ui.horizontal(|ui| {
                                ui.spacing_mut().item_spacing.x = 6.0;
                                theme::dot(ui, outcome_color(res), 4.0);
                                ui.add(egui::Label::new(RichText::new(host(url))).truncate());
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| match res {
                                        Some(o) => {
                                            ui.label(
                                                RichText::new(outcome_tag(o))
                                                    .size(12.0)
                                                    .color(outcome_color(Some(o))),
                                            )
                                            .on_hover_text(o.explain());
                                        }
                                        None if col.is_some() => {
                                            ui.add(egui::Spinner::new().size(11.0));
                                        }
                                        None => {
                                            ui.label(RichText::new("—").color(FAINT));
                                        }
                                    },
                                );
                            });
                        }
                    });
                });

                ui.horizontal(|ui| {
                    if ui.selectable_label(self.edit_sites, "Edit sites").clicked() {
                        self.edit_sites = !self.edit_sites;
                    }
                    ui.add_space(ui.available_width() - 190.0);
                    ui.label(RichText::new("Timeout").color(MUTED).size(12.5));
                    ui.add(egui::Slider::new(&mut self.settings.timeout_secs, 3..=20).suffix(" s"));
                });
                if self.edit_sites {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.settings.urls)
                            .code_editor()
                            .desired_rows(8)
                            .desired_width(f32::INFINITY),
                    );
                    if theme::link(ui, true, "Restore default sites", theme::ACCENT_2).clicked() {
                        self.settings.urls = settings::DEFAULT_URLS.into();
                    }
                }
            },
        );
        if run {
            self.start_current_test();
        }
    }
}

// ---------------------------------------------------------- search card

impl App {
    fn start_find_config(&self) {
        let urls = self.settings.url_list();
        let configs = self.settings.config_list();
        let exe = self.settings.exe_path.trim().to_string();
        let timeout = self.settings.timeout_secs;
        self.spawn("Finding working settings", move |ctx| {
            find_config(ctx, &exe, &urls, &configs, timeout);
        });
    }

    fn search_card(
        &mut self,
        ui: &mut egui::Ui,
        status: &Status,
        search: &[Column],
        test_pid: Option<u32>,
    ) {
        let busy = self.is_busy();
        let manual_running = status
            .standalone_pids()
            .into_iter()
            .any(|p| Some(p) != test_pid);
        let can_run = !busy && self.exe_ok() && !manual_running;
        let mut run = false;

        theme::card(
            ui,
            "Find working settings",
            Some("Tries each setting and ranks them. The service pauses meanwhile."),
            |ui| {
                run = theme::primary(ui, can_run, "Search").clicked();
            },
            |ui| {
                if manual_running {
                    ui.label(
                        RichText::new("Stop the manual dpibreak.exe first.")
                            .color(YELLOW)
                            .size(12.5),
                    );
                }

                let best = search
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| {
                        c.args.is_some() && c.done() && c.note.is_none() && c.works() > 0
                    })
                    .max_by_key(|(i, c)| (c.works(), std::cmp::Reverse(*i)))
                    .map(|(i, _)| i);

                theme::inset(ui, |ui| {
                    if search.is_empty() {
                        ui.label(
                            RichText::new("No results yet. Press Search to compare every setting.")
                                .color(MUTED),
                        );
                    } else {
                        ui.spacing_mut().item_spacing.y = 4.0;
                        for (i, c) in search.iter().enumerate() {
                            self.search_row(ui, c, Some(i) == best);
                        }
                    }
                });

                if ui
                    .selectable_label(self.edit_configs, "Edit settings list")
                    .clicked()
                {
                    self.edit_configs = !self.edit_configs;
                }
                if self.edit_configs {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.settings.configs)
                            .code_editor()
                            .desired_rows(7)
                            .desired_width(f32::INFINITY),
                    );
                    if theme::link(ui, true, "Restore default list", theme::ACCENT_2).clicked() {
                        self.settings.configs = settings::DEFAULT_CONFIGS.into();
                    }
                }
            },
        );
        if run {
            self.start_find_config();
        }
    }

    fn search_row(&mut self, ui: &mut egui::Ui, c: &Column, best: bool) {
        ui.horizontal(|ui| {
            let label = match &c.args {
                Some(a) => {
                    RichText::new(a)
                        .monospace()
                        .color(if best { GREEN } else { theme::TEXT })
                }
                None => RichText::new("No DPIBreak").italics().color(MUTED),
            };
            ui.allocate_ui_with_layout(
                egui::vec2(118.0, 20.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_min_width(118.0);
                    ui.add(egui::Label::new(label).truncate());
                },
            );

            if let Some(note) = &c.note {
                theme::chip(ui, "Failed to start", RED).on_hover_text(note);
                return;
            }
            if !c.started() {
                ui.label(RichText::new("waiting").color(FAINT).size(12.0));
                return;
            }

            ui.spacing_mut().item_spacing.x = 3.0;
            for (url, r) in c.urls.iter().zip(&c.results) {
                let resp = theme::dot(ui, outcome_color(r.as_ref()), 4.5);
                let tip = match r {
                    Some(o) => format!("{}: {}", host(url), o.short()),
                    None => format!("{}: testing…", host(url)),
                };
                resp.on_hover_text(tip);
            }
            ui.spacing_mut().item_spacing.x = 8.0;
            if !c.done() {
                ui.add(egui::Spinner::new().size(12.0));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(args) = &c.args
                    && c.done()
                {
                    let clicked = if best {
                        theme::primary(ui, true, "Use").clicked()
                    } else {
                        theme::link(ui, true, "Use", theme::ACCENT_2).clicked()
                    };
                    if clicked {
                        self.settings.args = args.clone();
                        self.ctx.log(format!(
                            "settings set to \"{args}\"; press Apply settings to save"
                        ));
                    }
                }
                ui.label(
                    RichText::new(format!("{}/{}", c.works(), c.urls.len()))
                        .strong()
                        .color(if c.works() == c.urls.len() {
                            GREEN
                        } else {
                            theme::TEXT
                        }),
                );
                if best {
                    theme::chip(ui, "Best", GREEN);
                }
            });
        });
    }
}

// --------------------------------------------------------------- workers

/// Extract the built-in dpibreak.exe and driver files. If they are in
/// use by a service running an older built-in copy, stop it, update
/// and start it again.
fn prepare_bundle(ctx: &Ctx) {
    if let Err(e) = bundle::harden() {
        ctx.log(format!(
            "could not restrict {}: {e}",
            bundle::install_dir().display()
        ));
    }
    if bundle::up_to_date() {
        return;
    }
    let dir = bundle::install_dir();
    match bundle::extract() {
        Ok(written) => {
            if let Err(e) = bundle::harden() {
                ctx.log(format!("could not restrict {}: {e}", dir.display()));
            }
            ctx.log(format!(
                "built-in DPIBreak installed to {} ({})",
                dir.display(),
                written.join(", ")
            ));
            return;
        }
        Err(e) => ctx.log(format!("built-in files could not be written yet: {e}")),
    }

    let status = read_status();
    let exe = bundle::exe_path().display().to_string();
    let uses_bundle = status.service.as_ref().is_some_and(|s| {
        service::parse_bin_path(&s.bin_path)
            .0
            .eq_ignore_ascii_case(&exe)
    });
    if !(uses_bundle && status.service_running()) {
        ctx.log("close other programs using these files and restart the panel");
        return;
    }

    // Wait for any job the user started to finish first.
    while !ctx.try_busy("Updating built-in DPIBreak") {
        std::thread::sleep(Duration::from_millis(250));
    }
    ctx.log("updating the built-in DPIBreak used by the service");
    ctx.lock().restore_service = true;
    let r = service::stop().and_then(|()| {
        // The driver can take a moment to unload after the service stops.
        let mut last = Err(String::new());
        for _ in 0..10 {
            last = bundle::extract().map(|_| ());
            if last.is_ok() {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        last
    });
    // Start it again even if the update failed.
    let started = service::start();
    ctx.lock().restore_service = false;
    match r.and(started) {
        Ok(()) => ctx.log("built-in DPIBreak updated and service restarted"),
        Err(e) => ctx.log(format!("update failed: {e}")),
    }
    ctx.busy(None);
    ctx.refresh_status();
}

/// Probe all URLs in parallel and store results in the target column.
fn probe_column(ctx: &Ctx, target: Target, urls: &[String], timeout: u32) {
    std::thread::scope(|scope| {
        for (row, url) in urls.iter().enumerate() {
            let ctx = ctx.clone();
            scope.spawn(move || {
                let outcome = probe::probe(url, timeout);
                let mut s = ctx.lock();
                if let Some(cell) = s.column_mut(target).and_then(|c| c.results.get_mut(row)) {
                    *cell = Some(outcome);
                }
                drop(s);
                ctx.egui.request_repaint();
            });
        }
    });
}

fn find_config(ctx: &Ctx, exe: &str, urls: &[String], configs: &[String], timeout: u32) {
    if !std::path::Path::new(exe).is_file() {
        ctx.log(format!("dpibreak.exe not found at {exe}"));
        return;
    }
    if urls.is_empty() || configs.is_empty() {
        ctx.log("add at least one site and one setting");
        return;
    }

    let status = read_status();
    if !status.standalone_pids().is_empty() {
        ctx.log("another dpibreak.exe is running; stop it first");
        return;
    }

    ctx.lock().search = std::iter::once(Column::new("Without DPIBreak", None, urls))
        .chain(
            configs
                .iter()
                .map(|c| Column::new(c.clone(), Some(c.clone()), urls)),
        )
        .collect();

    // Stop it also when it is starting or stopping, so two copies of
    // DPIBreak never divert packets at the same time.
    let service_was_running = status.service_running();
    let service_active = status
        .service
        .as_ref()
        .is_some_and(|s| s.state != SvcState::Stopped);
    if service_active {
        ctx.busy(Some("Pausing the service".into()));
        ctx.log("pausing the service during the search");
        if let Err(e) = service::stop() {
            ctx.log(format!("could not stop the service: {e}"));
            return;
        }
        ctx.lock().restore_service = service_was_running;
    }

    ctx.busy(Some("Testing without DPIBreak".into()));
    ctx.log("testing without DPIBreak");
    probe_column(ctx, Target::Search(0), urls, timeout);

    for (i, args) in configs.iter().enumerate() {
        if ctx.cancelled() {
            ctx.log("search cancelled");
            break;
        }
        let col = i + 1;
        ctx.busy(Some(format!("Trying {}/{}: {args}", i + 1, configs.len())));
        let started = TestInstance::start(exe, args, Duration::from_secs(8), |pid| {
            ctx.lock().test_pid = Some(pid);
        });
        match started {
            Ok(mut instance) => {
                // Give WinDivert a moment after the handle is open.
                std::thread::sleep(Duration::from_millis(300));
                probe_column(ctx, Target::Search(col), urls, timeout);
                instance.stop();
                ctx.lock().test_pid = None;
                let works = ctx.lock().search.get(col).map(Column::works).unwrap_or(0);
                ctx.log(format!("{args}: {works}/{} reachable", urls.len()));
            }
            Err(out) => {
                ctx.lock().test_pid = None;
                ctx.log(format!(
                    "{args}: dpibreak did not start: {}",
                    out.replace('\n', " | ")
                ));
                if let Some(c) = ctx.lock().search.get_mut(col) {
                    c.note = Some(format!("dpibreak did not start:\n{out}"));
                }
            }
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    if service_was_running {
        ctx.busy(Some("Restoring the service".into()));
        match service::start() {
            Ok(()) => ctx.log("service restarted"),
            Err(e) => ctx.log(format!("could not restart the service: {e}")),
        }
        ctx.lock().restore_service = false;
    }

    let s = ctx.lock();
    let baseline = s.search.first().map(Column::works).unwrap_or(0);
    let best = s
        .search
        .iter()
        .filter(|c| c.args.is_some() && c.note.is_none())
        .max_by_key(|c| c.works())
        .cloned();
    drop(s);
    match best {
        Some(c) if c.works() > baseline => ctx.log(format!(
            "best: \"{}\" reaches {}/{} (without DPIBreak: {baseline})",
            c.title,
            c.works(),
            urls.len()
        )),
        Some(_) => ctx.log(format!(
            "no setting did better than without DPIBreak ({baseline}/{}); the sites may be \
             blocked by DNS or IP, or not blocked at all",
            urls.len()
        )),
        None => {}
    }
}
