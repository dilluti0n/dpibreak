// SPDX-License-Identifier: GPL-3.0-or-later

//! Single-screen dashboard.
//!
//! Left: protection status and service controls. Right: connection
//! test and the search for working settings. Bottom: activity log.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};

use crate::platform::process::{self, TestInstance};
use crate::platform::service::{self, ServiceInfo, SvcState};
use crate::platform::{self, Chip, EXE_NAME, Tone, bundle};
use crate::probe::{self, Outcome};
use crate::settings::{self, Settings};
use crate::theme::{self, FAINT, GREEN, MUTED, RED, YELLOW};

// ---------------------------------------------------------------- state

#[derive(Clone, Default)]
struct Status {
    service: Option<ServiceInfo>,
    service_err: Option<String>,
    /// Platform chips (WinDivert driver, firewall backend).
    chips: Vec<Chip>,
    /// Missing system pieces worth telling the user about.
    hints: Vec<String>,
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

    /// dpibreak processes that are not the service.
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
    /// dpibreak started by the settings search, if any.
    test_pid: Option<u32>,
    /// The search stopped the service and must start it again.
    restore_service: bool,
    /// Service log shown inside the panel (Linux: the journal).
    service_log: Option<String>,
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
        service::pause()?;
        self.lock().restore_service = true;
        let r = service::resume();
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
    platform::clock()
}

fn read_status() -> Status {
    let (service, service_err) = match service::query(service::SERVICE_NAME) {
        Ok(s) => (s, None),
        Err(e) => (None, Some(e)),
    };
    let (chips, hints) = platform::status_extras();
    Status {
        service,
        service_err,
        chips,
        hints,
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

fn service_settings_changed(service: Option<(&str, bool)>, settings: &Settings) -> bool {
    service.is_some_and(|(bin_path, auto_start)| {
        !service::same_command(bin_path, &settings.exe_path, &settings.args)
            || auto_start != settings.auto_start
    })
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
            ctx.log(format!("{EXE_NAME} not found: set its path under Service"));
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
        platform::exe_ready(&self.settings.exe_path)
    }

    /// End a dpibreak outside the service. On Linux this needs the
    /// helper (maybe a password prompt), so it runs on a worker.
    fn terminate(&self, pid: u32) {
        #[cfg(windows)]
        match process::terminate(pid) {
            Ok(()) => self.ctx.log(format!("terminated PID {pid}")),
            Err(e) => self.ctx.log(format!("terminate {pid}: {e}")),
        }
        #[cfg(not(windows))]
        self.spawn("Stopping dpibreak", move |ctx| {
            match process::terminate(pid) {
                Ok(()) => ctx.log(format!("terminated PID {pid}")),
                Err(e) => ctx.log(format!("terminate {pid}: {e}")),
            }
        });
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
    /// Never leave a test dpibreak running or the service stopped
    /// because the window was closed in the middle of a search.
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.ctx.cancel.store(true, Ordering::Relaxed);
        let (pid, restore) = {
            let s = self.ctx.lock();
            (s.test_pid, s.restore_service)
        };
        platform::on_exit(pid, restore);
        _ = self.settings.save();
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let (status, busy, current, search, log, test_pid, service_log) = {
            let s = self.ctx.lock();
            (
                s.status.clone(),
                s.busy.clone(),
                s.current.clone(),
                s.search.clone(),
                s.log.clone(),
                s.test_pid,
                s.service_log.clone(),
            )
        };
        if let Some(text) = service_log {
            self.log_window(&ctx, &text);
        }

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
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::link(ui, !log.is_empty(), "Copy", MUTED)
                    .on_hover_text("Copy the activity log to the clipboard")
                    .clicked()
                {
                    ui.ctx().copy_text(log.join("\n"));
                }
            });
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

fn tone_color(tone: Tone) -> Color32 {
    match tone {
        Tone::Good => GREEN,
        Tone::Warn => YELLOW,
        Tone::Bad => RED,
        Tone::Neutral => MUTED,
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
                format!("{EXE_NAME} (PID {}) outside the service.", standalone[0]),
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
        let svc_ok = service::unavailable().is_none();

        theme::card(
            ui,
            "Protection",
            None,
            |ui| match &status.service {
                Some(s) if s.state == SvcState::Running => {
                    if theme::danger(ui, !busy, "Stop")
                        .on_hover_text(platform::STOP_HINT)
                        .clicked()
                    {
                        self.spawn("Stopping the service", |ctx| match service::stop() {
                            Ok(()) => ctx.log("service stopped"),
                            Err(e) => ctx.log(format!("stop failed: {e}")),
                        });
                    }
                }
                Some(_) => {
                    if theme::success(ui, !busy && svc_ok, "Start").clicked() {
                        self.spawn("Starting the service", |ctx| match service::start() {
                            Ok(()) => ctx.log("service started"),
                            Err(e) => ctx.log(format!("start failed: {e}")),
                        });
                    }
                }
                None => {
                    if theme::primary(ui, !busy && exe_ok && svc_ok, "Install")
                        .on_hover_text("Install DPIBreak as a service and start it")
                        .clicked()
                    {
                        self.install();
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
                    for c in &status.chips {
                        theme::chip(ui, &c.text, tone_color(c.tone)).on_hover_text(&c.hover);
                    }
                });

                for hint in &status.hints {
                    ui.label(RichText::new(hint).color(YELLOW).size(12.5));
                }

                for pid in &standalone {
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!("Manual instance · PID {pid}")).color(YELLOW),
                        );
                        if theme::link(ui, !busy, "Terminate", RED).clicked() {
                            self.terminate(*pid);
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
        let svc_ok = service::unavailable().is_none();
        let changed = service_settings_changed(
            status
                .service
                .as_ref()
                .map(|s| (s.bin_path.as_str(), s.auto_start)),
            &self.settings,
        );

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
                    if platform::EXE_EDITABLE {
                        let w = ui.available_width() - 70.0;
                        ui.add(
                            egui::TextEdit::singleline(&mut self.settings.exe_path)
                                .desired_width(w)
                                .hint_text(platform::EXE_HINT),
                        )
                        .on_hover_text(format!("Location of {EXE_NAME}"));
                        if ui.button("Detect").clicked() {
                            match settings::detect_exe() {
                                Some(p) => self.settings.exe_path = p,
                                None => self.ctx.log(format!(
                                    "{EXE_NAME} not found next to the panel or on PATH"
                                )),
                            }
                        }
                    } else {
                        let mut path = self.settings.exe_path.clone();
                        ui.add(
                            egui::TextEdit::singleline(&mut path)
                                .desired_width(f32::INFINITY)
                                .interactive(false),
                        )
                        .on_hover_text(
                            "The service and the tests always run the dpibreak installed here",
                        );
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
                            RichText::new(format!("{EXE_NAME} not found here"))
                                .color(RED)
                                .size(12.5),
                        );
                    });
                }
                if let Some(why) = service::unavailable() {
                    theme::field(ui, "", |ui| {
                        ui.label(RichText::new(why).color(YELLOW).size(12.5));
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
                    ui.checkbox(&mut self.settings.auto_start, platform::AUTO_START_LABEL);
                });

                // Check again after drawing the editable fields so Apply responds
                // to a change in this frame without waiting for the next repaint.
                let changed = service_settings_changed(
                    status
                        .service
                        .as_ref()
                        .map(|s| (s.bin_path.as_str(), s.auto_start)),
                    &self.settings,
                );

                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    let exe = self.settings.exe_path.clone();
                    let args = self.settings.args.clone();
                    let auto = self.settings.auto_start;
                    match &status.service {
                        None => {
                            if theme::primary(ui, !busy && exe_ok && svc_ok, "Install and start")
                                .clicked()
                            {
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
                                match self.settings.save() {
                                    Ok(()) => {
                                        self.saved_json = serde_json::to_string(&self.settings)
                                            .unwrap_or_default();
                                    }
                                    Err(e) => self.ctx.log(format!("could not save settings: {e}")),
                                }
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
                                    self.logs_link(ui, busy);
                                },
                            );
                        }
                    }
                });

                ui.collapsing(
                    RichText::new("Settings help").color(MUTED).size(12.5),
                    |ui| {
                        ui.spacing_mut().item_spacing.y = 3.0;
                        for &(flag, help) in platform::HELP_FLAGS {
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

// ---------------------------------------------------------- service log

impl App {
    /// Windows: open the folder with dpibreak's log file.
    #[cfg(windows)]
    fn logs_link(&mut self, ui: &mut egui::Ui, _busy: bool) {
        if let Some(dir) = std::env::var_os("ProgramData")
            .map(|d| std::path::PathBuf::from(d).join("dpibreak"))
            .filter(|d| d.is_dir())
            && theme::link(ui, true, "Logs", MUTED).clicked()
        {
            _ = std::process::Command::new("explorer.exe").arg(&dir).spawn();
        }
    }

    /// Linux: show the last lines of the service journal in the panel.
    #[cfg(not(windows))]
    fn logs_link(&mut self, ui: &mut egui::Ui, busy: bool) {
        if theme::link(ui, !busy, "Logs", MUTED)
            .on_hover_text("Last lines of the service journal")
            .clicked()
        {
            self.open_logs();
        }
    }

    #[cfg(not(windows))]
    fn open_logs(&self) {
        self.spawn("Reading the service log", |ctx| {
            match service::read_log(300) {
                Ok(text) => {
                    let text = if text.trim().is_empty() {
                        "(no entries)".to_string()
                    } else {
                        text
                    };
                    ctx.lock().service_log = Some(text);
                }
                Err(e) => ctx.log(format!("could not read the service log: {e}")),
            }
        });
    }

    fn log_window(&mut self, ctx: &egui::Context, text: &str) {
        let mut open = true;
        let mut refresh = false;
        egui::Window::new("Service log")
            .open(&mut open)
            .collapsible(false)
            .default_size([760.0, 400.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("journalctl -u {}", service::SERVICE_NAME))
                            .monospace()
                            .color(MUTED),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        refresh = theme::secondary(ui, !self.is_busy(), "Refresh").clicked();
                        if theme::secondary(ui, true, "Copy")
                            .on_hover_text("Copy the whole log to the clipboard")
                            .clicked()
                        {
                            ui.ctx().copy_text(text.to_string());
                        }
                    });
                });
                theme::inset(ui, |ui| {
                    egui::ScrollArea::both()
                        .id_salt("service_log")
                        .stick_to_bottom(true)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            // Read-only but selectable: drag or Ctrl+A, then Ctrl+C.
                            let mut view = text;
                            ui.add(
                                egui::TextEdit::multiline(&mut view)
                                    .font(egui::FontId::monospace(11.5))
                                    .text_color(theme::TEXT)
                                    .frame(egui::Frame::NONE)
                                    .desired_width(f32::INFINITY),
                            );
                        });
                });
            });
        if !open {
            self.ctx.lock().service_log = None;
        }
        #[cfg(not(windows))]
        if refresh {
            self.open_logs();
        }
        #[cfg(windows)]
        let _ = refresh;
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
                        RichText::new(format!("Stop the manual {EXE_NAME} first."))
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
                Some(a) => RichText::new(if best {
                    format!("Best · {a}")
                } else {
                    a.clone()
                })
                .monospace()
                .color(if best { GREEN } else { theme::TEXT }),
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

            // Keep the full result row inside the card at the minimum
            // window width, including the score and Use button.
            ui.spacing_mut().item_spacing.x = 2.0;
            for (url, r) in c.urls.iter().zip(&c.results) {
                let resp = theme::dot(ui, outcome_color(r.as_ref()), 4.0);
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
            });
        });
    }
}

// --------------------------------------------------------------- workers

/// Extract the built-in dpibreak.exe and driver files. If they are in
/// use by a service running an older built-in copy, stop it, update
/// and start it again.
#[cfg(windows)]
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

/// Update the installed copy of the built-in dpibreak if this panel
/// carries a different one. A first install waits for the first action
/// that needs it, so the password is not asked for at every start.
#[cfg(not(windows))]
fn prepare_bundle(ctx: &Ctx) {
    if !bundle::installed() || bundle::up_to_date() {
        return;
    }
    // Wait for any job the user started to finish first.
    while !ctx.try_busy("Updating built-in DPIBreak") {
        std::thread::sleep(Duration::from_millis(250));
    }
    ctx.log("this panel carries a different dpibreak; updating the installed copy");
    match bundle::update() {
        Ok(()) => ctx.log(format!(
            "built-in DPIBreak updated in {}",
            bundle::install_dir().display()
        )),
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
    if !platform::exe_ready(exe) {
        ctx.log(format!("{EXE_NAME} not found at {exe}"));
        return;
    }
    if urls.is_empty() || configs.is_empty() {
        ctx.log("add at least one site and one setting");
        return;
    }

    let status = read_status();
    if !status.standalone_pids().is_empty() {
        ctx.log(format!("another {EXE_NAME} is running; stop it first"));
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
        if let Err(e) = service::pause() {
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
                // Give the packet path a moment after dpibreak is up.
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
        match service::resume() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_is_enabled_for_argument_or_startup_changes() {
        let exe = "/usr/local/lib/dpibreak/dpibreak";
        let installed = format!("{exe} -o 0,1");
        let mut settings = Settings {
            exe_path: exe.into(),
            args: "-o 0,1".into(),
            auto_start: true,
            ..Settings::default()
        };

        assert!(!service_settings_changed(
            Some((&installed, true)),
            &settings
        ));
        settings.args = "-o 0,5".into();
        assert!(service_settings_changed(
            Some((&installed, true)),
            &settings
        ));
        settings.args = "-o 0,1".into();
        settings.auto_start = false;
        assert!(service_settings_changed(
            Some((&installed, true)),
            &settings
        ));
        assert!(!service_settings_changed(None, &settings));
    }
}
