// SPDX-License-Identifier: GPL-3.0-or-later

//! Single-screen dashboard.
//!
//! Left: protection status and service controls. Right: connection
//! test and the search for working settings. Bottom: activity log.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};

use crate::probe::{self, Outcome};
use crate::process::{self, TestInstance};
use crate::service::{self, ServiceInfo, SvcState};
use crate::settings::{self, Settings};
use crate::theme::{self, GREEN, MUTED, RED, YELLOW};

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
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/')
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

    /// Run `job` on a worker thread with a busy label.
    fn spawn<F>(&self, label: &str, job: F)
    where
        F: FnOnce(&Ctx) + Send + 'static,
    {
        if self.is_busy() {
            return;
        }
        let ctx = self.ctx.clone();
        ctx.cancel.store(false, Ordering::Relaxed);
        ctx.busy(Some(label.to_string()));
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
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let (status, busy, current, search, log) = {
            let s = self.ctx.lock();
            (
                s.status.clone(),
                s.busy.clone(),
                s.current.clone(),
                s.search.clone(),
                s.log.clone(),
            )
        };

        egui::Panel::bottom("activity")
            .resizable(true)
            .default_size(96.0)
            .min_size(60.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::CARD)
                    .inner_margin(egui::Margin::symmetric(18, 10)),
            )
            .show(ui, |ui| self.activity(ui, busy.as_deref(), &log));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::same(18)),
            )
            .show(ui, |ui| {
                self.header(ui);
                ui.add_space(12.0);
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.columns(2, |cols| {
                            self.status_card(&mut cols[0], &status);
                            cols[0].add_space(14.0);
                            self.service_card(&mut cols[0], &status);

                            self.test_card(&mut cols[1], current.as_ref());
                            cols[1].add_space(14.0);
                            self.search_card(&mut cols[1], &status, &search);
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

// --------------------------------------------------------------- header

impl App {
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("DPIBreak").size(24.0).strong());
            ui.label(RichText::new("Control Panel").size(24.0).color(MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new("Status, connection tests and the Windows service in one place")
                        .color(MUTED),
                );
            });
        });
    }

    fn activity(&mut self, ui: &mut egui::Ui, busy: Option<&str>, log: &[String]) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Activity").strong());
            ui.add_space(8.0);
            if let Some(b) = busy {
                ui.spinner();
                ui.label(RichText::new(b).color(theme::ACCENT));
                if ui.small_button("Cancel").clicked() {
                    self.ctx.cancel.store(true, Ordering::Relaxed);
                    self.ctx.log("cancel requested");
                }
            } else {
                ui.label(RichText::new("Idle").color(MUTED));
            }
        });
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for line in log {
                    ui.label(RichText::new(line).monospace().size(12.5).color(MUTED));
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
    fn status_card(&mut self, ui: &mut egui::Ui, status: &Status) {
        let standalone = status.standalone_pids();
        let (color, headline, detail) = if !status.updated {
            (MUTED, "Checking…".to_string(), String::new())
        } else if status.service_running() {
            (
                GREEN,
                "Protection is on".to_string(),
                "DPIBreak is running as a Windows service.".to_string(),
            )
        } else if !standalone.is_empty() {
            (
                YELLOW,
                "Running outside the service".to_string(),
                format!(
                    "dpibreak.exe is running (PID {}), but not as the service.",
                    standalone[0]
                ),
            )
        } else if status.service.is_some() {
            (
                RED,
                "Protection is off".to_string(),
                "The service is installed but stopped.".to_string(),
            )
        } else {
            (
                RED,
                "Protection is off".to_string(),
                "DPIBreak is not installed as a service.".to_string(),
            )
        };

        theme::card(
            ui,
            "Status",
            None,
            |_| {},
            |ui| {
                egui::Frame::new()
                    .fill(color.gamma_multiply(0.10))
                    .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.45)))
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::same(14))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            theme::dot(ui, color, 9.0);
                            ui.vertical(|ui| {
                                ui.label(RichText::new(&headline).size(20.0).strong().color(color));
                                if !detail.is_empty() {
                                    ui.label(RichText::new(&detail).color(MUTED));
                                }
                            });
                        });
                    });

                ui.add_space(8.0);

                theme::field(ui, "Service", |ui| {
                    match (&status.service, &status.service_err) {
                        (Some(s), _) => {
                            theme::chip(ui, &s.state.label(), state_color(s.state));
                            ui.label(
                                RichText::new(if s.auto_start {
                                    "starts with Windows"
                                } else {
                                    "manual start"
                                })
                                .color(MUTED),
                            );
                        }
                        (None, Some(e)) => {
                            ui.label(RichText::new(format!("cannot query: {e}")).color(RED));
                        }
                        (None, None) => {
                            theme::chip(ui, "Not installed", MUTED);
                        }
                    }
                });

                if let Some(s) = &status.service {
                    let (_, args) = service::parse_bin_path(&s.bin_path);
                    theme::field(ui, "Settings", |ui| {
                        ui.label(
                            RichText::new(if args.is_empty() {
                                "(defaults)".into()
                            } else {
                                args
                            })
                            .monospace(),
                        );
                    });
                }

                theme::field(ui, "Driver", |ui| match &status.driver {
                    Some(d) => {
                        theme::chip(
                            ui,
                            &format!("WinDivert {}", d.state.label()),
                            state_color(d.state),
                        );
                    }
                    None => {
                        theme::chip(ui, "WinDivert not loaded", MUTED);
                    }
                });

                if !standalone.is_empty() {
                    theme::field(ui, "Other", |ui| {
                        for pid in &standalone {
                            ui.label(format!("PID {pid}"));
                            if ui.small_button("Terminate").clicked() {
                                match process::terminate(*pid) {
                                    Ok(()) => self.ctx.log(format!("terminated PID {pid}")),
                                    Err(e) => self.ctx.log(format!("terminate {pid}: {e}")),
                                }
                            }
                        }
                    });
                }
            },
        );
    }
}

// --------------------------------------------------------- service card

impl App {
    fn service_card(&mut self, ui: &mut egui::Ui, status: &Status) {
        let busy = self.is_busy();
        let exe_ok = std::path::Path::new(&self.settings.exe_path).is_file();
        let changed = status.service.as_ref().is_some_and(|s| {
            !service::same_command(&s.bin_path, &self.settings.exe_path, &self.settings.args)
                || s.auto_start != self.settings.auto_start
        });

        theme::card(
            ui,
            "Service",
            Some("Runs DPIBreak in the background, also after a restart."),
            |_| {},
            |ui| {
                theme::field(ui, "Program", |ui| {
                    let w = ui.available_width() - 84.0;
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
                if !exe_ok {
                    theme::field(ui, "", |ui| {
                        ui.label(
                            RichText::new("dpibreak.exe not found at this path.")
                                .color(RED)
                                .size(13.0),
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
                    .on_hover_text(
                        "dpibreak arguments. \"Find working settings\" can pick them for you.",
                    );
                });
                theme::field(ui, "", |ui| {
                    ui.checkbox(
                        &mut self.settings.auto_start,
                        "Start automatically with Windows",
                    );
                });

                if changed {
                    ui.horizontal(|ui| {
                        theme::chip(ui, "Not applied", YELLOW);
                        ui.label(
                            RichText::new("The service still uses its old settings.")
                                .color(MUTED)
                                .size(13.0),
                        );
                    });
                }

                ui.add_space(6.0);
                let exe = self.settings.exe_path.clone();
                let args = self.settings.args.clone();
                let auto = self.settings.auto_start;

                match &status.service {
                    None => {
                        ui.horizontal(|ui| {
                            if theme::primary(ui, !busy && exe_ok, "Install and start").clicked() {
                                self.spawn("Installing the service", move |ctx| {
                                    match service::install(&exe, &args, auto)
                                        .and_then(|()| service::start())
                                    {
                                        Ok(()) => ctx.log("service installed and started"),
                                        Err(e) => ctx.log(format!("install failed: {e}")),
                                    }
                                });
                            }
                        });
                    }
                    Some(s) => {
                        let running = s.state == SvcState::Running;
                        ui.horizontal(|ui| {
                            if running {
                                if theme::danger(ui, !busy, "Stop").clicked() {
                                    self.spawn("Stopping the service", |ctx| {
                                        match service::stop() {
                                            Ok(()) => ctx.log("service stopped"),
                                            Err(e) => ctx.log(format!("stop failed: {e}")),
                                        }
                                    });
                                }
                            } else if theme::success(ui, !busy, "Start").clicked() {
                                self.spawn("Starting the service", |ctx| match service::start() {
                                    Ok(()) => ctx.log("service started"),
                                    Err(e) => ctx.log(format!("start failed: {e}")),
                                });
                            }

                            let apply = if changed {
                                theme::primary(ui, !busy && exe_ok, "Apply settings")
                            } else {
                                theme::secondary(ui, !busy && exe_ok && changed, "Apply settings")
                            };
                            if apply
                                .on_hover_text(
                                    "Save the settings to the service; restarts it if running",
                                )
                                .clicked()
                            {
                                self.spawn("Applying settings", move |ctx| {
                                    let r =
                                        service::reconfigure(&exe, &args, auto).and_then(|()| {
                                            if running {
                                                service::stop().and_then(|()| service::start())
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
                                    match service::stop().and_then(|()| service::start()) {
                                        Ok(()) => ctx.log("service restarted"),
                                        Err(e) => ctx.log(format!("restart failed: {e}")),
                                    }
                                });
                            }
                        });

                        ui.add_space(4.0);
                        ui.horizontal(|ui| {
                            if !self.confirm_uninstall {
                                if ui
                                    .add_enabled(
                                        !busy,
                                        egui::Button::new(
                                            RichText::new("Uninstall service").color(MUTED),
                                        )
                                        .frame(false),
                                    )
                                    .clicked()
                                {
                                    self.confirm_uninstall = true;
                                }
                            } else {
                                ui.label(RichText::new("Remove the service?").color(RED));
                                if theme::danger(ui, !busy, "Uninstall").clicked() {
                                    self.confirm_uninstall = false;
                                    self.spawn("Uninstalling the service", |ctx| {
                                        match service::stop().and_then(|()| service::uninstall()) {
                                            Ok(()) => ctx.log("service uninstalled"),
                                            Err(e) => ctx.log(format!("uninstall failed: {e}")),
                                        }
                                    });
                                }
                                if ui.button("Cancel").clicked() {
                                    self.confirm_uninstall = false;
                                }
                            }

                            if let Some(dir) = std::env::var_os("ProgramData")
                                .map(|d| std::path::PathBuf::from(d).join("dpibreak"))
                                .filter(|d| d.is_dir())
                            {
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| {
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    RichText::new("Open log folder").color(MUTED),
                                                )
                                                .frame(false),
                                            )
                                            .clicked()
                                        {
                                            _ = std::process::Command::new("explorer.exe")
                                                .arg(&dir)
                                                .spawn();
                                        }
                                    },
                                );
                            }
                        });
                    }
                }

                ui.add_space(6.0);
                ui.collapsing(
                    RichText::new("What do the settings mean?").color(MUTED),
                    |ui| {
                        for (flag, help) in [
                            ("-o 0,1", "Split the TLS hello after byte 1 (default)."),
                            (
                                "-o 0,5",
                                "Split after the TLS record header. Try if sites break.",
                            ),
                            ("-o 5,0", "Send the second part first."),
                            (
                                "--fake-ttl 8",
                                "Also send a decoy hello that expires after 8 hops.",
                            ),
                            ("-a", "Like --fake-ttl, but picks the hop count per server."),
                            (
                                "-b example.com",
                                "Leave this site untouched (newer builds).",
                            ),
                        ] {
                            ui.horizontal(|ui| {
                                ui.add_sized(
                                    [120.0, 18.0],
                                    egui::Label::new(RichText::new(flag).monospace()),
                                );
                                ui.label(RichText::new(help).color(MUTED));
                            });
                        }
                    },
                );
            },
        );
    }
}

// ------------------------------------------------------------ test card

fn outcome_chip(ui: &mut egui::Ui, o: &Outcome) {
    let (text, color) = match o {
        Outcome::Ok { secs, .. } => (format!("Reachable · {secs:.2}s"), GREEN),
        Outcome::Dns => ("DNS blocked".into(), YELLOW),
        Outcome::BadCert => ("DNS redirected".into(), YELLOW),
        Outcome::Connect => ("IP blocked".into(), RED),
        Outcome::Timeout => ("Blocked · timeout".into(), RED),
        Outcome::TlsFailed => ("Blocked · TLS".into(), RED),
        Outcome::Reset => ("Blocked · reset".into(), RED),
        Outcome::Other(c) => (format!("Error {c}"), RED),
    };
    theme::chip(ui, &text, color).on_hover_text(o.explain());
}

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
        let mut run = false;
        theme::card(
            ui,
            "Connection test",
            Some("Checks the sites below with the current setup."),
            |ui| {
                run = theme::primary(ui, !busy, "Run test").clicked();
            },
            |ui| {
                let urls = self.settings.url_list();
                let col = current.filter(|c| c.urls == urls);

                egui::Frame::new()
                    .fill(theme::CARD_ALT)
                    .corner_radius(egui::CornerRadius::same(10))
                    .inner_margin(egui::Margin::symmetric(14, 8))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        if urls.is_empty() {
                            ui.label(
                                RichText::new("No sites. Click Edit sites to add some.")
                                    .color(MUTED),
                            );
                        }
                        for (i, url) in urls.iter().enumerate() {
                            ui.horizontal(|ui| {
                                let res =
                                    col.and_then(|c| c.results.get(i)).and_then(|r| r.as_ref());
                                let color = match res {
                                    Some(o) if o.works() => GREEN,
                                    Some(Outcome::Dns | Outcome::BadCert) => YELLOW,
                                    Some(_) => RED,
                                    None => theme::BORDER,
                                };
                                theme::dot(ui, color, 5.0);
                                ui.label(RichText::new(host(url)).size(15.0));
                                ui.with_layout(
                                    egui::Layout::right_to_left(egui::Align::Center),
                                    |ui| match res {
                                        Some(o) => outcome_chip(ui, o),
                                        None if col.is_some() => {
                                            ui.spinner();
                                        }
                                        None => {
                                            ui.label(
                                                RichText::new("not tested").color(MUTED).size(13.0),
                                            );
                                        }
                                    },
                                );
                            });
                        }
                    });

                if let Some(c) = col.filter(|c| c.done()) {
                    let works = c.works();
                    let total = c.urls.len();
                    let (color, text) = if works == total {
                        (GREEN, format!("All {total} sites are reachable."))
                    } else if works == 0 {
                        (RED, format!("None of the {total} sites are reachable."))
                    } else {
                        (YELLOW, format!("{works} of {total} sites are reachable."))
                    };
                    ui.label(RichText::new(text).color(color).strong());
                }

                ui.horizontal(|ui| {
                    if ui.selectable_label(self.edit_sites, "Edit sites").clicked() {
                        self.edit_sites = !self.edit_sites;
                    }
                    ui.label(RichText::new("Timeout").color(MUTED));
                    ui.add(egui::Slider::new(&mut self.settings.timeout_secs, 3..=20).suffix(" s"));
                });
                if self.edit_sites {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.settings.urls)
                            .code_editor()
                            .desired_rows(6)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.small_button("Restore default sites").clicked() {
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
        let exe = self.settings.exe_path.clone();
        let timeout = self.settings.timeout_secs;
        self.spawn("Finding working settings", move |ctx| {
            find_config(ctx, &exe, &urls, &configs, timeout);
        });
    }

    fn search_card(&mut self, ui: &mut egui::Ui, status: &Status, search: &[Column]) {
        let busy = self.is_busy();
        let can_run = !busy
            && std::path::Path::new(&self.settings.exe_path).is_file()
            && status.standalone_pids().is_empty();
        let mut run = false;

        theme::card(
            ui,
            "Find working settings",
            Some(
                "Tries each setting on the sites and ranks them. The service is paused meanwhile.",
            ),
            |ui| {
                run = theme::primary(ui, can_run, "Start search").clicked();
            },
            |ui| {
                if !status.standalone_pids().is_empty() {
                    ui.label(
                        RichText::new("Stop the other dpibreak.exe (see Status) before searching.")
                            .color(YELLOW),
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

                if search.is_empty() {
                    ui.label(
                        RichText::new(
                            "No results yet. The search first tests without DPIBreak, then each \
                             setting from the list.",
                        )
                        .color(MUTED),
                    );
                } else {
                    egui::Frame::new()
                        .fill(theme::CARD_ALT)
                        .corner_radius(egui::CornerRadius::same(10))
                        .inner_margin(egui::Margin::symmetric(14, 8))
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            for (i, c) in search.iter().enumerate() {
                                self.search_row(ui, c, Some(i) == best);
                            }
                        });
                }

                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(self.edit_configs, "Edit settings list")
                        .clicked()
                    {
                        self.edit_configs = !self.edit_configs;
                    }
                });
                if self.edit_configs {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.settings.configs)
                            .code_editor()
                            .desired_rows(7)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.small_button("Restore default list").clicked() {
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
                Some(a) => RichText::new(a).monospace(),
                None => RichText::new(&c.title).italics().color(MUTED),
            };
            ui.add_sized([150.0, 22.0], egui::Label::new(label).truncate());

            if let Some(note) = &c.note {
                theme::chip(ui, "Failed to start", RED).on_hover_text(note);
                return;
            }
            if !c.started() {
                ui.label(RichText::new("waiting").color(MUTED).size(13.0));
                return;
            }

            for (url, r) in c.urls.iter().zip(&c.results) {
                let color = match r {
                    Some(o) if o.works() => GREEN,
                    Some(_) => RED,
                    None => theme::BORDER,
                };
                let (rect, resp) =
                    ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 5.5, color);
                let tip = match r {
                    Some(o) => format!("{}: {}", host(url), o.short()),
                    None => format!("{}: testing…", host(url)),
                };
                resp.on_hover_text(tip);
            }
            if !c.done() {
                ui.spinner();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(args) = &c.args
                    && c.done()
                {
                    let clicked = if best {
                        theme::primary(ui, true, "Use").clicked()
                    } else {
                        ui.button("Use").clicked()
                    };
                    if clicked {
                        self.settings.args = args.clone();
                        self.ctx.log(format!(
                            "settings set to \"{args}\"; click Apply settings to save"
                        ));
                    }
                    if best {
                        theme::chip(ui, "Best", GREEN);
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

    let service_was_running = status.service_running();
    if service_was_running {
        ctx.busy(Some("Pausing the service".into()));
        ctx.log("pausing the service during the search");
        if let Err(e) = service::stop() {
            ctx.log(format!("could not stop the service: {e}"));
            return;
        }
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
        match TestInstance::start(exe, args, Duration::from_secs(8)) {
            Ok(mut instance) => {
                // Give WinDivert a moment after the handle is open.
                std::thread::sleep(Duration::from_millis(300));
                probe_column(ctx, Target::Search(col), urls, timeout);
                instance.stop();
                let works = ctx.lock().search.get(col).map(Column::works).unwrap_or(0);
                ctx.log(format!("{args}: {works}/{} reachable", urls.len()));
            }
            Err(out) => {
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
