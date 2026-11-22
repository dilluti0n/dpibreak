// SPDX-License-Identifier: GPL-3.0-or-later

//! dpibreak-gui: a small Windows control panel for DPIBreak.
//!
//! One screen: protection status, service controls, a connection test
//! and a search for working dpibreak settings.

#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod app;
#[cfg(windows)]
mod bundle;
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
const WINDOW_TITLE: &str = "DPIBreak Control Panel";

/// Allow one panel at a time: two would fight over the service and
/// the settings file. A second launch brings the first one to front.
#[cfg(windows)]
fn already_running() -> bool {
    use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, SW_RESTORE, SetForegroundWindow, ShowWindow,
    };
    use windows::core::{HSTRING, w};

    // SAFETY: plain Win32 calls; the mutex handle is intentionally kept
    // open for the life of the process.
    unsafe {
        if CreateMutexW(None, false, w!("Local\\DPIBreakControlPanel")).is_err()
            || GetLastError() != ERROR_ALREADY_EXISTS
        {
            return false;
        }
        if let Ok(hwnd) = FindWindowW(None, &HSTRING::from(WINDOW_TITLE)) {
            _ = ShowWindow(hwnd, SW_RESTORE);
            _ = SetForegroundWindow(hwnd);
        }
    }
    true
}

#[cfg(windows)]
fn main() -> eframe::Result {
    if already_running() {
        return Ok(());
    }
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title(WINDOW_TITLE)
            .with_inner_size([1000.0, 660.0])
            .with_min_inner_size([880.0, 580.0]),
        ..Default::default()
    };
    eframe::run_native(
        WINDOW_TITLE,
        options,
        Box::new(|cc| Ok(Box::new(app::App::new(cc)))),
    )
}

#[cfg(not(windows))]
fn main() {
    eprintln!("dpibreak-gui is only available on Windows.");
    std::process::exit(1);
}
