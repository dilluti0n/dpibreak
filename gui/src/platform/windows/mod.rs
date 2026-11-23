// SPDX-License-Identifier: GPL-3.0-or-later

//! Windows backend: Service Control Manager, WinDivert, curl.exe.

pub mod bundle;
pub mod probe;
pub mod process;
pub mod service;

use std::path::PathBuf;

use super::{Chip, Tone};

pub const EXE_NAME: &str = "dpibreak.exe";
pub const EXE_HINT: &str = r"C:\path\to\dpibreak.exe";
pub const AUTO_START_LABEL: &str = "Start with Windows";
pub const STOP_HINT: &str = "Stop protection. The service stays installed; with auto-start on it \
                             starts again with Windows.";
pub const EXE_EDITABLE: bool = true;

pub const HELP_FLAGS: &[(&str, &str)] = &[
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
];

pub fn early_main() -> Option<i32> {
    None
}

/// Allow one panel at a time: two would fight over the service and
/// the settings file. A second launch brings the first one to front.
pub fn already_running(title: &str) -> bool {
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
        if let Ok(hwnd) = FindWindowW(None, &HSTRING::from(title)) {
            _ = ShowWindow(hwnd, SW_RESTORE);
            _ = SetForegroundWindow(hwnd);
        }
    }
    true
}

pub fn settings_path() -> Result<PathBuf, &'static str> {
    std::env::var_os("APPDATA")
        .map(|d| PathBuf::from(d).join("DPIBreak-GUI").join("settings.json"))
        .ok_or("APPDATA is not set")
}

/// Any dpibreak.exe can be used on Windows.
pub fn fixed_exe() -> Option<String> {
    None
}

/// The built-in dpibreak.exe (single-exe build), then one next to the
/// GUI, from the service, or on PATH.
pub fn detect_exe() -> Option<String> {
    if bundle::is_bundled() {
        return Some(bundle::exe_path().display().to_string());
    }
    if let Ok(me) = std::env::current_exe()
        && let Some(dir) = me.parent()
    {
        let candidate = dir.join(EXE_NAME);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    if let Ok(Some(info)) = service::query(service::SERVICE_NAME) {
        let (exe, _) = service::parse_bin_path(&info.bin_path);
        if !exe.is_empty() {
            return Some(exe);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(EXE_NAME))
            .find(|p| p.is_file())
            .map(|p| p.display().to_string())
    })
}

pub fn exe_ready(exe: &str) -> bool {
    std::path::Path::new(exe.trim()).is_file()
}

pub fn clock() -> String {
    // SAFETY: GetLocalTime only writes the returned struct.
    let t = unsafe { windows::Win32::System::SystemInformation::GetLocalTime() };
    format!("{:02}:{:02}:{:02}", t.wHour, t.wMinute, t.wSecond)
}

/// Never leave a test dpibreak.exe running or the service stopped
/// because the window was closed in the middle of a search.
pub fn on_exit(test_pid: Option<u32>, restore_service: bool) {
    if let Some(pid) = test_pid {
        _ = process::terminate(pid);
    }
    if restore_service {
        _ = service::start();
    }
}

pub fn status_extras() -> (Vec<Chip>, Vec<String>) {
    let chip = match service::query(service::DRIVER_SERVICE_NAME).ok().flatten() {
        Some(d) => Chip {
            text: format!("WinDivert {}", d.state.label()),
            tone: match d.state {
                service::SvcState::Running => Tone::Good,
                service::SvcState::Stopped => Tone::Bad,
                _ => Tone::Warn,
            },
            hover: "The packet driver DPIBreak uses".into(),
        },
        None => Chip {
            text: "WinDivert idle".into(),
            tone: Tone::Neutral,
            hover: "The packet driver DPIBreak uses".into(),
        },
    };
    (vec![chip], Vec::new())
}
