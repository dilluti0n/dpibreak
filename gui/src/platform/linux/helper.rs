// SPDX-License-Identifier: GPL-3.0-or-later

//! The root helper (`--helper`, started through pkexec).
//!
//! Reads one JSON request per line from stdin and answers each with one
//! line on stdout. Only the commands in `proto::Request` exist; programs
//! run with an argv list (never a shell) and only the dpibreak in the
//! install directory is ever installed as a service or started.
//!
//! When stdin closes (the panel exited, crashed or was killed) it stops
//! the test dpibreak and, if it paused the service, starts it again.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use super::proto::{MAX_LINE, Request, Response, Rules, validate_args};
use super::service::{self, SERVICE_NAME, SvcState, UNIT_PATH};
use super::{bundle, sys};

#[derive(Default)]
struct State {
    test: Option<Child>,
    /// The service was paused by `Pause` and must run again on exit.
    restore: bool,
}

pub fn run() -> i32 {
    if sys::geteuid() != 0 {
        eprintln!("--helper must be started through pkexec");
        return 1;
    }
    sys::ignore_terminal_signals();
    sys::set_umask(0o022);
    // SAFETY: still single-threaded; nothing reads the environment
    // concurrently.
    unsafe {
        std::env::set_var(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
        std::env::set_var("LC_ALL", "C");
    }

    let mut state = State::default();
    let stdin = std::io::stdin();
    let mut input = BufReader::new(stdin.lock());
    let mut out = std::io::stdout().lock();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match (&mut input)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if buf.len() > MAX_LINE {
            break;
        }
        let resp = match serde_json::from_slice::<Request>(&buf) {
            Ok(req) => handle(&mut state, req),
            Err(e) => Response::err(format!("unknown request: {e}")),
        };
        let line = serde_json::to_string(&resp).unwrap_or_else(|_| r#"{"ok":false}"#.into());
        if writeln!(out, "{line}").and_then(|()| out.flush()).is_err() {
            break;
        }
    }

    stop_test(&mut state);
    if state.restore {
        _ = service::start_and_wait();
    }
    0
}

fn result(r: Result<(), String>) -> Response {
    match r {
        Ok(()) => Response::ok(),
        Err(e) => Response::err(e),
    }
}

fn handle(state: &mut State, req: Request) -> Response {
    match req {
        Request::Ping => Response::ok(),
        Request::InstallBinary => result(install_binary(state)),
        Request::Install {
            exe,
            args,
            auto_start,
        } => result(write_unit(&exe, &args, auto_start, false)),
        Request::Reconfigure {
            exe,
            args,
            auto_start,
        } => result(write_unit(&exe, &args, auto_start, true)),
        Request::Uninstall => result(uninstall()),
        Request::Start => result(service::start_and_wait()),
        Request::Stop => result(service::stop_and_wait()),
        Request::Pause => result(pause(state)),
        Request::Resume => {
            state.restore = false;
            result(service::start_and_wait())
        }
        Request::TestStart {
            exe,
            args,
            timeout_ms,
        } => match test_start(state, &exe, &args, timeout_ms) {
            Ok(pid) => Response {
                pid: Some(pid),
                ..Response::ok()
            },
            Err(e) => Response::err(e),
        },
        Request::TestStop => {
            stop_test(state);
            Response::ok()
        }
        Request::Kill { pid } => result(kill_dpibreak(state, pid)),
        Request::Logs { lines } => match logs(lines) {
            Ok(text) => Response {
                text: Some(text),
                ..Response::ok()
            },
            Err(e) => Response::err(e),
        },
        Request::Rules => Response {
            rules: Some(rules()),
            ..Response::ok()
        },
    }
}

fn check_exe(exe: &str) -> Result<(), String> {
    if Path::new(exe) != bundle::exe_path() {
        return Err(format!(
            "only {} can be used (got {exe})",
            bundle::exe_path().display()
        ));
    }
    let p = bundle::exe_path();
    if !p.is_file() {
        return Err(format!(
            "{} is not installed; use the single-file panel or install dpibreak there",
            p.display()
        ));
    }
    if !sys::root_controlled(&p) {
        return Err(format!("{} must be owned by root", p.display()));
    }
    Ok(())
}

fn service_info() -> Result<Option<service::ServiceInfo>, String> {
    service::query(SERVICE_NAME)
}

/// Update the installed dpibreak from the embedded copy. If the service
/// runs it, stop it, replace the file and start it again.
fn install_binary(state: &mut State) -> Result<(), String> {
    if bundle::up_to_date() && bundle::installed() {
        return bundle::write_atomically().map(|_| ());
    }
    let exe = bundle::exe_path().display().to_string();
    let running_it = service::has_systemd()
        && service_info()?.is_some_and(|i| {
            i.state == SvcState::Running && service::parse_bin_path(&i.bin_path).0 == exe
        });
    if !running_it {
        return bundle::write_atomically().map(|_| ());
    }
    stop_test(state);
    service::stop_and_wait()?;
    let written = bundle::write_atomically();
    // Start it again even if the update failed.
    let started = service::start_and_wait();
    written.and(started)
}

fn write_unit(exe: &str, args: &[String], auto_start: bool, exists: bool) -> Result<(), String> {
    if !service::has_systemd() {
        return Err("systemd is not running".into());
    }
    check_exe(exe)?;
    validate_args(args)?;
    let info = service_info()?;
    match (&info, exists) {
        (Some(_), false) => return Err("the service is already installed".into()),
        (None, true) => return Err("the service is not installed".into()),
        _ => {}
    }

    let text = service::unit_text(exe, args);
    let tmp = format!("{UNIT_PATH}.new");
    _ = std::fs::remove_file(&tmp);
    std::fs::write(&tmp, text)
        .and_then(|()| std::fs::rename(&tmp, UNIT_PATH))
        .map_err(|e| {
            _ = std::fs::remove_file(&tmp);
            format!("{UNIT_PATH}: {e}")
        })?;
    service::systemctl(&["daemon-reload"])?;
    if auto_start {
        service::systemctl(&["enable", SERVICE_NAME])
    } else {
        service::systemctl(&["disable", SERVICE_NAME])
    }
}

fn uninstall() -> Result<(), String> {
    let Some(info) = service_info()? else {
        return Err("the service is not installed".into());
    };
    if info.unit_path != UNIT_PATH {
        return Err(format!(
            "the unit at {} was not installed by the panel; remove it with your \
             package manager",
            info.unit_path
        ));
    }
    service::stop_and_wait()?;
    _ = service::systemctl(&["disable", SERVICE_NAME]);
    std::fs::remove_file(UNIT_PATH).map_err(|e| format!("{UNIT_PATH}: {e}"))?;
    service::systemctl(&["daemon-reload"])?;
    _ = service::systemctl(&["reset-failed", SERVICE_NAME]);
    Ok(())
}

fn pause(state: &mut State) -> Result<(), String> {
    let was_running = service_info()?.is_some_and(|i| i.state == SvcState::Running);
    service::stop_and_wait()?;
    state.restore |= was_running;
    Ok(())
}

/// Start the installed dpibreak in the foreground and wait until it says
/// it is running. Returns its PID; on failure, the last lines it printed.
fn test_start(
    state: &mut State,
    exe: &str,
    args: &[String],
    timeout_ms: u64,
) -> Result<u32, String> {
    check_exe(exe)?;
    validate_args(args)?;
    stop_test(state);

    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group: terminal signals go to the panel, not here.
        .process_group(0);
    // SAFETY: die_with_parent only calls prctl, which is safe after fork.
    unsafe {
        cmd.pre_exec(sys::die_with_parent);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("cannot start {exe}: {e}"))?;

    let (tx, rx) = mpsc::channel::<String>();
    for stream in [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    {
        let tx = tx.clone();
        // Keep draining after startup so the pipes never fill.
        std::thread::spawn(move || {
            let mut r = BufReader::new(stream);
            let mut line = Vec::new();
            while matches!(r.read_until(b'\n', &mut line), Ok(n) if n > 0) {
                _ = tx.send(String::from_utf8_lossy(&line).trim_end().to_string());
                line.clear();
            }
        });
    }
    drop(tx);

    let deadline = Instant::now() + Duration::from_millis(timeout_ms.clamp(1000, 60_000));
    let mut output = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left.min(Duration::from_millis(200))) {
            Ok(line) if line.contains("is now running") => {
                let pid = child.id();
                state.test = Some(child);
                return Ok(pid);
            }
            Ok(line) if !line.trim().is_empty() => output.push(line),
            Ok(_) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // Both pipes closed: it exited.
                if let Ok(status) = child.wait() {
                    output.push(format!("exited with {status}"));
                }
                break;
            }
        }
        if let Ok(Some(status)) = child.try_wait() {
            // Collect what is still buffered.
            while let Ok(line) = rx.recv_timeout(Duration::from_millis(100)) {
                if !line.trim().is_empty() {
                    output.push(line);
                }
            }
            output.push(format!("exited with {status}"));
            break;
        }
        if Instant::now() >= deadline {
            output.push("did not report running in time".into());
            break;
        }
    }
    terminate(&mut child);
    let tail: Vec<_> = output.iter().rev().take(6).rev().cloned().collect();
    Err(tail.join("\n"))
}

/// SIGTERM (dpibreak removes its rules), then SIGKILL after 3 s.
fn terminate(child: &mut Child) {
    if matches!(child.try_wait(), Ok(None)) {
        _ = sys::kill(child.id(), libc::SIGTERM);
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        _ = child.kill();
    }
    _ = child.wait();
}

fn stop_test(state: &mut State) {
    if let Some(mut child) = state.test.take() {
        terminate(&mut child);
    }
}

fn kill_dpibreak(state: &mut State, pid: u32) -> Result<(), String> {
    if state.test.as_ref().is_some_and(|c| c.id() == pid) {
        stop_test(state);
        return Ok(());
    }
    if sys::comm(pid).as_deref() != Some(super::EXE_NAME) {
        return Err(format!("PID {pid} is not dpibreak"));
    }
    sys::kill(pid, libc::SIGTERM)?;
    let end = Instant::now() + Duration::from_secs(3);
    while sys::alive(pid) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(50));
    }
    if sys::alive(pid) && sys::comm(pid).as_deref() == Some(super::EXE_NAME) {
        sys::kill(pid, libc::SIGKILL)?;
    }
    Ok(())
}

fn logs(lines: u32) -> Result<String, String> {
    let n = lines.clamp(10, 2000).to_string();
    let out = Command::new("journalctl")
        .args([
            "-u",
            SERVICE_NAME,
            "-n",
            &n,
            "--no-pager",
            "-o",
            "short-iso",
        ])
        .output()
        .map_err(|e| format!("cannot run journalctl: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "journalctl: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn quiet_ok(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn rules() -> Rules {
    if quiet_ok("nft", &["list", "table", "inet", "dpibreak"]) {
        Rules::Nftables
    } else if quiet_ok("iptables", &["-t", "mangle", "-S", "DPIBREAK"]) {
        Rules::Iptables
    } else {
        Rules::None
    }
}
