// SPDX-License-Identifier: GPL-3.0-or-later

//! systemd service `dpibreak.service`.
//!
//! State is read by the panel itself (`systemctl show` works without
//! root); changes go through the helper, which runs systemctl as root.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use super::client;
use super::proto::{Request, split_args};

pub const SERVICE_NAME: &str = "dpibreak";
pub const UNIT_PATH: &str = "/etc/systemd/system/dpibreak.service";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SvcState {
    Stopped,
    StartPending,
    StopPending,
    Running,
    /// Exited with an error (or waiting to be restarted after one).
    Failed,
}

impl SvcState {
    pub fn label(self) -> String {
        match self {
            SvcState::Stopped => "Stopped".into(),
            SvcState::StartPending => "Starting".into(),
            SvcState::StopPending => "Stopping".into(),
            SvcState::Running => "Running".into(),
            SvcState::Failed => "Failed".into(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceInfo {
    pub state: SvcState,
    pub pid: u32,
    pub auto_start: bool,
    /// `ExecStart` as "<program> <args>".
    pub bin_path: String,
    /// Where the unit file is (it may come from a package).
    pub unit_path: String,
}

pub fn has_systemd() -> bool {
    Path::new("/run/systemd/system").is_dir()
}

/// Why service buttons are disabled, if they are.
pub fn unavailable() -> Option<&'static str> {
    (!has_systemd()).then_some("systemd is not running on this system")
}

fn systemctl_show(name: &str) -> Result<String, String> {
    let out = Command::new("systemctl")
        .args([
            "show",
            "--no-pager",
            "-p",
            "LoadState,ActiveState,SubState,MainPID,UnitFileState,ExecStart,FragmentPath",
            "--",
            name,
        ])
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "systemctl show failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Parse `systemctl show` output. `None` if the unit does not exist.
pub fn parse_show(text: &str) -> Option<ServiceInfo> {
    let mut load = "";
    let mut active = "";
    let mut sub = "";
    let mut pid = 0;
    let mut file_state = "";
    let mut exec = String::new();
    let mut fragment = "";
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "LoadState" => load = v,
            "ActiveState" => active = v,
            "SubState" => sub = v,
            "MainPID" => pid = v.trim().parse().unwrap_or(0),
            "UnitFileState" => file_state = v,
            "FragmentPath" => fragment = v,
            "ExecStart" => exec = parse_exec_start(v),
            _ => {}
        }
    }
    if load.is_empty() || load == "not-found" {
        return None;
    }
    let state = match (active, sub) {
        (_, "auto-restart") => SvcState::Failed,
        ("active", _) | ("reloading", _) => SvcState::Running,
        ("activating", _) => SvcState::StartPending,
        ("deactivating", _) => SvcState::StopPending,
        ("failed", _) => SvcState::Failed,
        _ => SvcState::Stopped,
    };
    Some(ServiceInfo {
        state,
        pid,
        auto_start: matches!(file_state, "enabled" | "enabled-runtime" | "alias"),
        bin_path: exec,
        unit_path: fragment.to_string(),
    })
}

/// `{ path=/x ; argv[]=/x -o 0,1 ; ignore_errors=no ; ... }` → "/x -o 0,1".
fn parse_exec_start(v: &str) -> String {
    v.split(" ; ")
        .find_map(|f| f.trim_start_matches(['{', ' ']).strip_prefix("argv[]="))
        .map(|s| s.trim_end_matches([' ', '}']).trim().to_string())
        .unwrap_or_default()
}

/// Query a service. `Ok(None)` if it is not installed.
pub fn query(name: &str) -> Result<Option<ServiceInfo>, String> {
    if !has_systemd() {
        return Err("systemd is not running".into());
    }
    Ok(parse_show(&systemctl_show(name)?))
}

/// Split a command line into (exe, args), dropping the daemon flag.
pub fn parse_bin_path(bin: &str) -> (String, String) {
    let mut it = bin.split_whitespace();
    let exe = it.next().unwrap_or("").to_string();
    let args: Vec<&str> = it
        .filter(|a| !matches!(*a, "-d" | "-D" | "--daemon"))
        .collect();
    (exe, args.join(" "))
}

/// Whether an installed command line runs `exe` with `args`. A unit
/// that runs dpibreak with `-d` does not match: it must be rewritten.
pub fn same_command(bin: &str, exe: &str, args: &str) -> bool {
    let mut it = bin.split_whitespace();
    it.next() == Some(exe.trim()) && it.eq(args.split_whitespace())
}

/// Quote one word for an `ExecStart=` line: double quotes with `\` and
/// `"` escaped, `%` (specifiers) doubled and `$` (variables) doubled.
pub fn systemd_quote(word: &str) -> String {
    let mut out = String::with_capacity(word.len() + 2);
    out.push('"');
    for c in word.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn unit_text(exe: &str, args: &[String]) -> String {
    let mut exec = systemd_quote(exe);
    for a in args {
        exec.push(' ');
        exec.push_str(&systemd_quote(a));
    }
    format!(
        "# Written by DPIBreak Panel.\n\
         [Unit]\n\
         Description=DPIBreak - system-wide DPI circumvention\n\
         Documentation=https://github.com/dilluti0n/dpibreak\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exec}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

// ------------------------------------------------- panel side (helper)

fn call(req: Request) -> Result<(), String> {
    client::request(req).map(|_| ())
}

pub fn install(exe: &str, args: &str, auto_start: bool) -> Result<(), String> {
    call(Request::Install {
        exe: exe.trim().to_string(),
        args: split_args(args),
        auto_start,
    })
}

pub fn reconfigure(exe: &str, args: &str, auto_start: bool) -> Result<(), String> {
    call(Request::Reconfigure {
        exe: exe.trim().to_string(),
        args: split_args(args),
        auto_start,
    })
}

pub fn uninstall() -> Result<(), String> {
    call(Request::Uninstall)
}

pub fn start() -> Result<(), String> {
    call(Request::Start)
}

pub fn stop() -> Result<(), String> {
    call(Request::Stop)
}

/// Stop the service; the helper starts it again if the panel exits
/// before `resume`.
pub fn pause() -> Result<(), String> {
    call(Request::Pause)
}

pub fn resume() -> Result<(), String> {
    call(Request::Resume)
}

/// Last lines of the service journal.
pub fn read_log(lines: u32) -> Result<String, String> {
    client::request(Request::Logs { lines }).map(|r| r.text.unwrap_or_default())
}

// ------------------------------------------------- helper side (root)

pub fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = Command::new("systemctl")
        .args(args)
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| format!("cannot run systemctl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {}: {}",
            args.first().copied().unwrap_or(""),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn state() -> Result<SvcState, String> {
    match query(SERVICE_NAME)? {
        Some(i) => Ok(i.state),
        None => Err("the service is not installed".into()),
    }
}

/// Start and wait until dpibreak has stayed up for a moment: it exits
/// at once on bad arguments or missing kernel support.
pub fn start_and_wait() -> Result<(), String> {
    // Returns once dpibreak is forked (Type=simple) or failed to start.
    systemctl(&["start", SERVICE_NAME])?;
    let begin = Instant::now();
    let mut running_since: Option<Instant> = None;
    loop {
        match state()? {
            SvcState::Running => {
                let since = *running_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_millis(1500) {
                    return Ok(());
                }
            }
            SvcState::Failed | SvcState::Stopped => {
                return Err(
                    "the service stopped right after starting; check its settings \
                     (try them with Find working settings) or the service log"
                        .into(),
                );
            }
            _ => running_since = None,
        }
        if begin.elapsed() >= Duration::from_secs(15) {
            return Err("timed out waiting for the service to start".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

pub fn stop_and_wait() -> Result<(), String> {
    // Blocks until the unit is inactive; dpibreak removes its rules on
    // SIGTERM. Also clears a pending automatic restart.
    systemctl(&["stop", SERVICE_NAME])?;
    _ = systemctl(&["reset-failed", SERVICE_NAME]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHOW_RUNNING: &str = "LoadState=loaded\nActiveState=active\nSubState=running\n\
        FragmentPath=/etc/systemd/system/dpibreak.service\nUnitFileState=enabled\nMainPID=4242\n\
        ExecStart={ path=/usr/local/lib/dpibreak/dpibreak ; argv[]=/usr/local/lib/dpibreak/dpibreak -o 0,1 --fake-ttl 8 ; ignore_errors=no ; start_time=[Sun 2026-11-22 14:36:06 +03] ; stop_time=[n/a] ; pid=4242 ; code=(null) ; status=0/0 }\n";

    #[test]
    fn show_running() {
        let i = parse_show(SHOW_RUNNING).unwrap();
        assert_eq!(i.state, SvcState::Running);
        assert_eq!(i.pid, 4242);
        assert!(i.auto_start);
        assert_eq!(
            i.bin_path,
            "/usr/local/lib/dpibreak/dpibreak -o 0,1 --fake-ttl 8"
        );
        assert_eq!(i.unit_path, UNIT_PATH);
    }

    #[test]
    fn show_missing_and_states() {
        assert!(parse_show("LoadState=not-found\nActiveState=inactive\n").is_none());
        let s = |a: &str, sub: &str| {
            parse_show(&format!(
                "LoadState=loaded\nActiveState={a}\nSubState={sub}\n"
            ))
            .unwrap()
            .state
        };
        assert_eq!(s("inactive", "dead"), SvcState::Stopped);
        assert_eq!(s("failed", "failed"), SvcState::Failed);
        assert_eq!(s("activating", "auto-restart"), SvcState::Failed);
        assert_eq!(s("activating", "start"), SvcState::StartPending);
        assert_eq!(s("deactivating", "stop-sigterm"), SvcState::StopPending);
    }

    #[test]
    fn bin_path_roundtrip() {
        let exe = "/usr/local/lib/dpibreak/dpibreak";
        // As `systemctl show` reports ExecStart argv[].
        let bin = "/usr/local/lib/dpibreak/dpibreak -o 0,5 --fake-ttl 8";
        assert_eq!(
            parse_bin_path(bin),
            (exe.to_string(), "-o 0,5 --fake-ttl 8".to_string())
        );
        assert!(same_command(bin, exe, " -o 0,5  --fake-ttl 8 "));
        assert!(!same_command(bin, exe, "-o 0,1"));
        assert!(!same_command("/usr/bin/dpibreak -d -o 0,5", exe, "-o 0,5"));
        assert!(!same_command(&format!("{exe} -d -o 0,5"), exe, "-o 0,5"));
    }

    #[test]
    fn quoting() {
        assert_eq!(systemd_quote("-o"), "\"-o\"");
        assert_eq!(systemd_quote(r#"a"b\c"#), r#""a\"b\\c""#);
        assert_eq!(systemd_quote("100%$HOME"), "\"100%%$$HOME\"");
        let unit = unit_text("/usr/local/lib/dpibreak/dpibreak", &split_args("-o 0,1"));
        assert!(unit.contains("ExecStart=\"/usr/local/lib/dpibreak/dpibreak\" \"-o\" \"0,1\"\n"));
        assert!(unit.contains("Type=simple\n"));
        assert!(unit.contains("WantedBy=multi-user.target\n"));
        assert!(!unit.contains(" -d"));
    }
}
