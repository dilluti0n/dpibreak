// SPDX-License-Identifier: GPL-3.0-or-later

//! Windows service control.
//!
//! State is read through the Service Control Manager API (locale
//! independent); changes go through `sc.exe`, whose exit code is the
//! Win32 error number and is mapped to an English message.

use std::os::windows::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows::Win32::System::Services::*;
use windows::core::HSTRING;

pub const SERVICE_NAME: &str = "dpibreak";
pub const DRIVER_SERVICE_NAME: &str = "WinDivert";

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvcState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    Other(u32),
}

impl SvcState {
    pub fn label(self) -> String {
        match self {
            SvcState::Stopped => "Stopped".into(),
            SvcState::StartPending => "Starting".into(),
            SvcState::StopPending => "Stopping".into(),
            SvcState::Running => "Running".into(),
            SvcState::Other(n) => format!("State {n}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub state: SvcState,
    pub pid: u32,
    pub auto_start: bool,
    pub bin_path: String,
}

struct ScHandle(SC_HANDLE);

impl Drop for ScHandle {
    fn drop(&mut self) {
        // SAFETY: the handle came from OpenSCManagerW/OpenServiceW and
        // is closed exactly once.
        unsafe {
            _ = CloseServiceHandle(self.0);
        }
    }
}

/// Query a service. `Ok(None)` if it is not installed.
pub fn query(name: &str) -> Result<Option<ServiceInfo>, String> {
    // SAFETY: plain SCM calls with buffers sized as the API requests.
    unsafe {
        let scm = ScHandle(
            OpenSCManagerW(None, None, SC_MANAGER_CONNECT).map_err(|e| e.message().to_string())?,
        );
        let svc = match OpenServiceW(
            scm.0,
            &HSTRING::from(name),
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
        ) {
            Ok(h) => ScHandle(h),
            Err(e) if e.code() == ERROR_SERVICE_DOES_NOT_EXIST.to_hresult() => return Ok(None),
            Err(e) => return Err(e.message().to_string()),
        };

        let mut status_buf = [0u8; size_of::<SERVICE_STATUS_PROCESS>()];
        let mut needed = 0u32;
        QueryServiceStatusEx(
            svc.0,
            SC_STATUS_PROCESS_INFO,
            Some(&mut status_buf),
            &mut needed,
        )
        .map_err(|e| e.message().to_string())?;
        let status: SERVICE_STATUS_PROCESS =
            std::ptr::read_unaligned(status_buf.as_ptr().cast::<SERVICE_STATUS_PROCESS>());

        let state = match status.dwCurrentState {
            SERVICE_STOPPED => SvcState::Stopped,
            SERVICE_START_PENDING => SvcState::StartPending,
            SERVICE_STOP_PENDING => SvcState::StopPending,
            SERVICE_RUNNING => SvcState::Running,
            other => SvcState::Other(other.0),
        };

        // QUERY_SERVICE_CONFIGW holds pointers into the same buffer;
        // use u64 storage so the struct is properly aligned.
        let mut needed = 0u32;
        _ = QueryServiceConfigW(svc.0, None, 0, &mut needed);
        let mut cfg_buf = vec![0u64; (needed as usize).div_ceil(8).max(1)];
        let (bin_path, auto_start) = match QueryServiceConfigW(
            svc.0,
            Some(cfg_buf.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>()),
            (cfg_buf.len() * 8) as u32,
            &mut needed,
        ) {
            Ok(()) => {
                let cfg = &*cfg_buf.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
                (
                    cfg.lpBinaryPathName.to_string().unwrap_or_default(),
                    cfg.dwStartType == SERVICE_AUTO_START,
                )
            }
            Err(_) => (String::new(), false),
        };

        Ok(Some(ServiceInfo {
            state,
            pid: status.dwProcessId,
            auto_start,
            bin_path,
        }))
    }
}

fn sc_error_message(code: i32) -> &'static str {
    match code {
        5 => "access denied (run as administrator)",
        1056 => "the service is already running",
        1060 => "the service is not installed",
        1061 => "the service cannot accept control messages right now",
        1062 => "the service has not been started",
        1072 => "the service is marked for deletion; close services.msc and try again",
        1073 => "the service already exists",
        1053 => "the service did not respond in time",
        _ => "sc.exe failed",
    }
}

fn sc(args: &[&str]) -> Result<(), String> {
    let out = Command::new("sc.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("cannot run sc.exe: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let code = out.status.code().unwrap_or(-1);
    Err(format!(
        "sc {}: {} (error {code})",
        args.first().copied().unwrap_or(""),
        sc_error_message(code)
    ))
}

/// Command line stored in the service: `"<exe>" -d <args>`.
pub fn bin_path_for(exe: &str, args: &str) -> String {
    let exe = exe.trim();
    let args = args.trim();
    if args.is_empty() {
        format!("\"{exe}\" -d")
    } else {
        format!("\"{exe}\" -d {args}")
    }
}

/// Split a service command line into (exe, args), dropping the
/// daemon flag that the GUI adds itself.
pub fn parse_bin_path(bin: &str) -> (String, String) {
    let bin = bin.trim();
    let (exe, rest) = if let Some(stripped) = bin.strip_prefix('"') {
        match stripped.find('"') {
            Some(end) => (&stripped[..end], &stripped[end + 1..]),
            None => (stripped, ""),
        }
    } else {
        // Unquoted paths may contain spaces ("C:\Program Files\..."):
        // the program ends after ".exe".
        let lower = bin.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(i) => (&bin[..i + 4], &bin[i + 4..]),
            None => match bin.find(char::is_whitespace) {
                Some(i) => (&bin[..i], &bin[i..]),
                None => (bin, ""),
            },
        }
    };
    let args: Vec<&str> = rest
        .split_whitespace()
        .filter(|a| !matches!(*a, "-d" | "-D" | "--daemon"))
        .collect();
    (exe.to_string(), args.join(" "))
}

/// Whether an installed command line runs `exe` with `args`, ignoring
/// quoting, the daemon flag and spacing.
pub fn same_command(bin: &str, exe: &str, args: &str) -> bool {
    let (cur_exe, cur_args) = parse_bin_path(bin);
    let want_args: Vec<&str> = args.split_whitespace().collect();
    cur_exe.eq_ignore_ascii_case(exe.trim())
        && cur_args.split_whitespace().eq(want_args.iter().copied())
}

fn start_arg(auto_start: bool) -> &'static str {
    if auto_start { "auto" } else { "demand" }
}

pub fn install(exe: &str, args: &str, auto_start: bool) -> Result<(), String> {
    let bin = bin_path_for(exe, args);
    sc(&[
        "create",
        SERVICE_NAME,
        "binPath=",
        &bin,
        "start=",
        start_arg(auto_start),
        "DisplayName=",
        "DPIBreak",
    ])?;
    _ = sc(&[
        "description",
        SERVICE_NAME,
        "DPIBreak - system-wide DPI circumvention",
    ]);
    Ok(())
}

pub fn reconfigure(exe: &str, args: &str, auto_start: bool) -> Result<(), String> {
    let bin = bin_path_for(exe, args);
    sc(&[
        "config",
        SERVICE_NAME,
        "binPath=",
        &bin,
        "start=",
        start_arg(auto_start),
    ])
}

pub fn uninstall() -> Result<(), String> {
    sc(&["delete", SERVICE_NAME])
}

/// Poll the service until `done` accepts its state. `fail` may end the
/// wait early with an error message (given the time waited so far).
fn wait_until(
    timeout: Duration,
    what: &str,
    done: impl Fn(SvcState) -> bool,
    fail: impl Fn(SvcState, Duration) -> Option<String>,
) -> Result<SvcState, String> {
    let start = Instant::now();
    loop {
        let state = match query(SERVICE_NAME)? {
            Some(info) => info.state,
            None => return Err("the service is not installed".into()),
        };
        if done(state) {
            return Ok(state);
        }
        if let Some(e) = fail(state, start.elapsed()) {
            return Err(e);
        }
        if start.elapsed() >= timeout {
            return Err(format!("timed out waiting for the service to {what}"));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub fn start() -> Result<(), String> {
    match sc(&["start", SERVICE_NAME]) {
        Ok(()) => {}
        // Already running (e.g. started elsewhere meanwhile) is fine.
        Err(e) if e.contains("error 1056") => {}
        Err(e) => return Err(e),
    }
    wait_until(
        Duration::from_secs(15),
        "start",
        |s| s == SvcState::Running,
        // dpibreak exits at once on bad arguments or a missing driver;
        // report that instead of waiting for the timeout.
        |s, waited| {
            (s == SvcState::Stopped && waited > Duration::from_millis(1500)).then(|| {
                "the service stopped right after starting; check its settings \
                 (try them with Find working settings) or the service log"
                    .to_string()
            })
        },
    )
    .map(|_| ())
}

pub fn stop() -> Result<(), String> {
    match sc(&["stop", SERVICE_NAME]) {
        Ok(()) => {}
        // Already stopped is fine.
        Err(e) if e.contains("error 1062") => return Ok(()),
        // Still starting: wait until it settles, then try again.
        Err(e) if e.contains("error 1061") => {
            let state = wait_until(
                Duration::from_secs(15),
                "settle",
                |s| matches!(s, SvcState::Running | SvcState::Stopped),
                |_, _| None,
            )?;
            if state == SvcState::Stopped {
                return Ok(());
            }
            sc(&["stop", SERVICE_NAME])?;
        }
        Err(e) => return Err(e),
    }
    wait_until(
        Duration::from_secs(20),
        "stop",
        |s| s == SvcState::Stopped,
        |_, _| None,
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_path_roundtrip() {
        let bin = bin_path_for(r"F:\DPI Break\dpibreak.exe", "-o 0,5 --fake-ttl 8");
        assert_eq!(bin, r#""F:\DPI Break\dpibreak.exe" -d -o 0,5 --fake-ttl 8"#);
        let (exe, args) = parse_bin_path(&bin);
        assert_eq!(exe, r"F:\DPI Break\dpibreak.exe");
        assert_eq!(args, "-o 0,5 --fake-ttl 8");
    }

    #[test]
    fn same_command_ignores_quoting() {
        let exe = r"F:\DPIBreak\dpibreak.exe";
        assert!(same_command(
            r"F:\DPIBreak\dpibreak.exe -d -o 0,5",
            exe,
            "-o 0,5"
        ));
        assert!(same_command(
            r#""f:\dpibreak\DPIBREAK.exe" -d  -o 0,5"#,
            exe,
            " -o  0,5"
        ));
        assert!(!same_command(
            r"F:\DPIBreak\dpibreak.exe -d -o 0,1",
            exe,
            "-o 0,5"
        ));
    }

    #[test]
    fn parse_unquoted_with_spaces() {
        let (exe, args) = parse_bin_path(r"C:\Program Files\DPIBreak\dpibreak.exe -d -o 0,5");
        assert_eq!(exe, r"C:\Program Files\DPIBreak\dpibreak.exe");
        assert_eq!(args, "-o 0,5");
    }

    #[test]
    fn parse_unquoted() {
        let (exe, args) = parse_bin_path(r"F:\DPIBreak\dpibreak.exe -d -o 0,5");
        assert_eq!(exe, r"F:\DPIBreak\dpibreak.exe");
        assert_eq!(args, "-o 0,5");
    }
}
