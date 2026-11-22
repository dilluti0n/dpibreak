// SPDX-License-Identifier: GPL-3.0-or-later

//! Panel side of the root helper.
//!
//! The helper is started on the first privileged action with
//! `pkexec <this executable> --helper` (one password prompt) and kept
//! for the rest of the session. Requests are serialized. Closing its
//! stdin ends it; see `helper` for what it cleans up then.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use super::bundle;
use super::proto::{Request, Response, Rules};

struct Conn {
    child: Child,
    rx: Receiver<String>,
}

/// Held for the whole request: one at a time.
static CONN: Mutex<Option<Conn>> = Mutex::new(None);
/// Separate, so `shutdown` never waits behind a long request.
static STDIN: Mutex<Option<ChildStdin>> = Mutex::new(None);
/// Set by `shutdown`; no new helper is started afterwards.
static CLOSED: Mutex<bool> = Mutex::new(false);
/// Last rules backend reported by the helper.
static RULES: Mutex<Option<Rules>> = Mutex::new(None);
/// PID of the running helper (0: none).
static HELPER_PID: AtomicU32 = AtomicU32::new(0);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn spawn() -> Result<Conn, String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find the panel: {e}"))?;
    let exe_s = exe.display().to_string();
    if exe_s.ends_with(" (deleted)") {
        return Err("the panel executable was replaced or deleted; restart it".into());
    }
    let mut child = Command::new("pkexec")
        .arg(&exe)
        .arg("--helper")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                "pkexec was not found; install polkit to manage DPIBreak".to_string()
            }
            _ => format!("cannot run pkexec: {e}"),
        })?;
    let stdin = child.stdin.take().ok_or("no helper stdin")?;
    let stdout = child.stdout.take().ok_or("no helper stdout")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    *lock(&STDIN) = Some(stdin);
    // pkexec execs the helper, so this is the helper's PID.
    HELPER_PID.store(child.id(), Ordering::Relaxed);
    Ok(Conn { child, rx })
}

fn send(conn: &mut Conn, req: &Request, wait: Duration) -> Result<Response, String> {
    let line = serde_json::to_string(req).map_err(|e| e.to_string())?;
    {
        let mut stdin = lock(&STDIN);
        let w = stdin.as_mut().ok_or("the panel is closing")?;
        writeln!(w, "{line}")
            .and_then(|()| w.flush())
            .map_err(|_| "the helper is not running".to_string())?;
    }
    match conn.rx.recv_timeout(wait) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("bad helper reply: {e}")),
        Err(RecvTimeoutError::Timeout) => Err("the helper did not answer in time".into()),
        Err(RecvTimeoutError::Disconnected) => {
            let code = conn.child.wait().ok().and_then(|s| s.code());
            Err(match code {
                Some(126) => "authorization was dismissed".into(),
                Some(127) => "not authorized (wrong password or no permission)".into(),
                Some(c) => format!("the helper exited (code {c})"),
                None => "the helper was killed".into(),
            })
        }
    }
}

fn connected(guard: &mut MutexGuard<'_, Option<Conn>>) -> Result<(), String> {
    if guard.is_some() {
        return Ok(());
    }
    if *lock(&CLOSED) {
        return Err("the panel is closing".into());
    }
    let mut conn = spawn()?;
    // The password prompt is open meanwhile: wait for the user.
    match send(&mut conn, &Request::Ping, Duration::from_secs(600)) {
        Ok(r) if r.ok => {}
        Ok(r) => return Err(r.error.unwrap_or_else(|| "helper refused".into())),
        Err(e) => {
            *lock(&STDIN) = None;
            HELPER_PID.store(0, Ordering::Relaxed);
            return Err(e);
        }
    }
    // Bring the installed dpibreak up to date before anything uses it.
    if !bundle::up_to_date() {
        let r = send(&mut conn, &Request::InstallBinary, Duration::from_secs(90))?;
        if !r.ok {
            return Err(r.error.unwrap_or_default());
        }
    }
    **guard = Some(conn);
    Ok(())
}

/// Send a request, starting the helper first if needed.
pub fn request(req: Request) -> Result<Response, String> {
    let wait = match req {
        Request::Logs { .. } | Request::Rules | Request::Kill { .. } => Duration::from_secs(30),
        _ => Duration::from_secs(120),
    };
    let mut guard = lock(&CONN);
    connected(&mut guard)?;
    let conn = guard.as_mut().ok_or("no helper")?;
    match send(conn, &req, wait) {
        Ok(r) if r.ok => Ok(r),
        Ok(r) => Err(r.error.unwrap_or_else(|| "failed".into())),
        Err(e) => {
            drop_conn(&mut guard);
            Err(e)
        }
    }
}

/// The helper is gone, stuck or out of step (a late reply would be
/// taken for the next one): close it; the next request starts a new one.
fn drop_conn(guard: &mut MutexGuard<'_, Option<Conn>>) {
    **guard = None;
    *lock(&STDIN) = None;
    HELPER_PID.store(0, Ordering::Relaxed);
}

/// PID of the running helper, if any.
pub fn helper_pid() -> Option<u32> {
    match HELPER_PID.load(Ordering::Relaxed) {
        0 => None,
        pid => Some(pid),
    }
}

/// Ask the running helper (never start one) which firewall backend
/// holds dpibreak's rules. Skipped while another request runs.
pub fn rules_backend() -> Option<Rules> {
    if let Ok(mut guard) = CONN.try_lock()
        && let Some(conn) = guard.as_mut()
    {
        let r = match send(conn, &Request::Rules, Duration::from_secs(10)) {
            Ok(r) => r.rules,
            Err(_) => {
                drop_conn(&mut guard);
                None
            }
        };
        *lock(&RULES) = r;
    }
    *lock(&RULES)
}

/// Close the helper's stdin. It finishes the current request, cleans up
/// and exits on its own; the panel does not wait for it.
pub fn shutdown() {
    *lock(&CLOSED) = true;
    *lock(&STDIN) = None;
}
