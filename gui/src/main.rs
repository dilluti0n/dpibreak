// SPDX-License-Identifier: GPL-3.0-or-later

//! dpibreak-gui: a small Windows control panel for DPIBreak.
//!
//! One screen: protection status, service controls, a connection test
//! and a search for working dpibreak settings.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod probe;
#[cfg(windows)]
mod process;
#[cfg(windows)]
mod service;
#[cfg(windows)]
mod settings;
#[cfg(windows)]
mod theme;

#[cfg(windows)]
fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("DPIBreak Control Panel")
            .with_inner_size([1180.0, 820.0])
            .with_min_inner_size([960.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "DPIBreak Control Panel",
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dpibreak-gui is only available on Windows.");
    std::process::exit(1);
}
