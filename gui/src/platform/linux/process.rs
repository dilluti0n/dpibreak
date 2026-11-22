// SPDX-License-Identifier: GPL-3.0-or-later

//! Finding, starting and stopping dpibreak processes.
//!
//! dpibreak runs as root, so starting and stopping go through the
//! helper; finding works from /proc (and the pid file of `-d`).

use std::time::Duration;

use super::client;
use super::proto::{Request, split_args};
use super::sys;

const PID_FILE: &str = "/run/dpibreak.pid";

/// PIDs of running processes named `image`, plus the PID in dpibreak's
/// pid file if that process is still dpibreak. The helper's own test
/// instance is left out (it is reported through `on_spawn`).
pub fn find_pids(image: &str) -> Vec<u32> {
    let mut pids = sys::pids_named(image);
    if let Some(pid) = std::fs::read_to_string(PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        && !pids.contains(&pid)
        && sys::comm(pid).as_deref() == Some(image)
    {
        pids.push(pid);
    }
    let helper = client::helper_pid();
    if helper.is_some() {
        pids.retain(|p| sys::ppid(*p) != helper);
    }
    pids
}

pub fn terminate(pid: u32) -> Result<(), String> {
    client::request(Request::Kill { pid }).map(|_| ())
}

/// A dpibreak started by the helper for testing. The helper also stops
/// it when the panel goes away.
pub struct TestInstance {
    running: bool,
}

impl TestInstance {
    /// Start `exe` with `args` and wait until it reports that it is
    /// running. `on_spawn` gets the PID. On failure, returns the output
    /// it printed.
    pub fn start(
        exe: &str,
        args: &str,
        timeout: Duration,
        on_spawn: impl FnOnce(u32),
    ) -> Result<Self, String> {
        let r = client::request(Request::TestStart {
            exe: exe.trim().to_string(),
            args: split_args(args),
            timeout_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
        })?;
        if let Some(pid) = r.pid {
            on_spawn(pid);
        }
        Ok(TestInstance { running: true })
    }

    pub fn stop(&mut self) {
        if std::mem::take(&mut self.running) {
            _ = client::request(Request::TestStop);
        }
    }
}

impl Drop for TestInstance {
    fn drop(&mut self) {
        self.stop();
    }
}
