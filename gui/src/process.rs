// SPDX-License-Identifier: GPL-3.0-or-later

//! Finding, starting and stopping dpibreak.exe processes.

use std::ffi::c_void;
use std::io::{BufRead, BufReader};
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};
use windows::core::PCWSTR;

use crate::service::CREATE_NO_WINDOW;

/// PIDs of all running processes whose image name is `image`.
pub fn find_pids(image: &str) -> Vec<u32> {
    let mut pids = Vec::new();
    // SAFETY: standard ToolHelp snapshot iteration; the entry size is
    // set as required and the snapshot handle is closed.
    unsafe {
        let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return pids;
        };
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        if Process32FirstW(snap, &mut entry).is_ok() {
            loop {
                let len = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                if name.eq_ignore_ascii_case(image) {
                    pids.push(entry.th32ProcessID);
                }
                if Process32NextW(snap, &mut entry).is_err() {
                    break;
                }
            }
        }
        _ = CloseHandle(snap);
    }
    pids
}

pub fn terminate(pid: u32) -> Result<(), String> {
    // SAFETY: the handle is checked and closed.
    unsafe {
        let h = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|e| e.message().to_string())?;
        let r = TerminateProcess(h, 1).map_err(|e| e.message().to_string());
        _ = CloseHandle(h);
        r
    }
}

/// A job object whose processes are killed when the panel exits for
/// any reason (closed, crashed or killed). Created once, never closed.
fn kill_on_exit_job() -> Option<HANDLE> {
    static JOB: OnceLock<Option<usize>> = OnceLock::new();
    let raw = *JOB.get_or_init(|| {
        // SAFETY: plain job object setup with a correctly sized struct.
        unsafe {
            let job = CreateJobObjectW(None, PCWSTR::null()).ok()?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .ok()?;
            Some(job.0 as usize)
        }
    });
    raw.map(|h| HANDLE(h as *mut c_void))
}

/// Forward lines from `stream` to `tx`. Bytes that are not UTF-8
/// (e.g. localized Windows error messages) are replaced rather than
/// ending the reader, so the pipe is always drained.
fn forward_lines(stream: impl std::io::Read, tx: mpsc::Sender<String>) {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buf).trim_end().to_string();
                if tx.send(line).is_err() {
                    break;
                }
            }
        }
    }
}

/// A dpibreak.exe started by the GUI for testing.
pub struct TestInstance {
    child: Child,
}

impl TestInstance {
    /// Start `exe` with `args` and wait until it reports that it is
    /// running. `on_spawn` gets the PID as soon as the process exists.
    /// On failure, returns the output it printed.
    pub fn start(
        exe: &str,
        args: &str,
        timeout: Duration,
        on_spawn: impl FnOnce(u32),
    ) -> Result<Self, String> {
        let mut child = Command::new(exe)
            .args(args.split_whitespace())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("cannot start {exe}: {e}"))?;

        if let Some(job) = kill_on_exit_job() {
            // SAFETY: both handles are valid; the child handle is owned
            // by `child` and outlives this call.
            unsafe {
                _ = AssignProcessToJobObject(job, HANDLE(child.as_raw_handle()));
            }
        }
        on_spawn(child.id());

        let (tx, rx) = mpsc::channel::<String>();
        if let Some(out) = child.stdout.take() {
            let tx = tx.clone();
            std::thread::spawn(move || forward_lines(out, tx));
        }
        if let Some(err) = child.stderr.take() {
            let tx = tx.clone();
            std::thread::spawn(move || forward_lines(err, tx));
        }
        drop(tx);

        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut instance = TestInstance { child };
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match rx.recv_timeout(left.min(Duration::from_millis(200))) {
                Ok(line) => {
                    // Printed right before the packet loop starts.
                    if line.contains("is now running") {
                        // Keep draining in the background so the pipe never fills.
                        std::thread::spawn(move || for _ in rx {});
                        return Ok(instance);
                    }
                    // dpibreak waits for a key after an error; no point
                    // in waiting for the timeout.
                    if line.contains("Press any key") {
                        break;
                    }
                    if !line.is_empty() {
                        output.push(line);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
            }
            if let Ok(Some(status)) = instance.child.try_wait() {
                output.push(format!("exited with {status}"));
                break;
            }
            if Instant::now() >= deadline {
                output.push("did not report running in time".into());
                break;
            }
        }
        instance.stop();
        let tail: Vec<_> = output.iter().rev().take(6).rev().cloned().collect();
        Err(tail.join("\n"))
    }

    pub fn stop(&mut self) {
        _ = self.child.kill();
        _ = self.child.wait();
    }
}

impl Drop for TestInstance {
    fn drop(&mut self) {
        self.stop();
    }
}
