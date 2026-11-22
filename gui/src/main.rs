// SPDX-License-Identifier: GPL-3.0-or-later

//! dpibreak-gui: a small control panel for DPIBreak (Windows and Linux).
//!
//! One screen: protection status, service controls, a connection test
//! and a search for working dpibreak settings.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(any(windows, target_os = "linux"))]
mod app;
#[cfg(any(windows, target_os = "linux"))]
mod platform;
#[cfg(any(windows, target_os = "linux"))]
mod probe;
#[cfg(any(windows, target_os = "linux"))]
mod settings;
#[cfg(any(windows, target_os = "linux"))]
mod theme;

#[cfg(any(windows, target_os = "linux"))]
const WINDOW_TITLE: &str = "DPIBreak Control Panel";

#[cfg(any(windows, target_os = "linux"))]
fn main() -> eframe::Result {
    // Linux: `--helper` (the root side, started through pkexec) and the
    // refusal to run the window as root.
    if let Some(code) = platform::early_main() {
        std::process::exit(code);
    }
    if platform::already_running(WINDOW_TITLE) {
        return Ok(());
    }
    let viewport = eframe::egui::ViewportBuilder::default()
        .with_title(WINDOW_TITLE)
        .with_inner_size([1000.0, 660.0])
        .with_min_inner_size([880.0, 580.0]);
    // Matches the .desktop file, so Wayland compositors show its icon.
    #[cfg(target_os = "linux")]
    let viewport = viewport.with_app_id("dpibreak-panel").with_icon(
        eframe::icon_data::from_png_bytes(include_bytes!("../../res/icon_256.png"))
            .unwrap_or_default(),
    );
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

#[cfg(not(any(windows, target_os = "linux")))]
fn main() {
    eprintln!("dpibreak-gui is only available on Windows and Linux.");
    std::process::exit(1);
}
