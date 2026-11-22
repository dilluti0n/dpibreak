// SPDX-License-Identifier: GPL-3.0-or-later

//! Finding, starting and stopping dpibreak.exe processes.

use std::io::{BufRead, BufReader};
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

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

/// A dpibreak.exe started by the GUI for testing.
pub struct TestInstance {
    child: Child,
}

impl TestInstance {
    /// Start `exe` with `args` and wait until it reports that it is
    /// running. On failure, returns the output it printed.
    pub fn start(exe: &str, args: &str, timeout: Duration) -> Result<Self, String> {
        let mut child = Command::new(exe)
            .args(args.split_whitespace())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("cannot start {exe}: {e}"))?;

        let (tx, rx) = mpsc::channel::<String>();
        for stream in [
            child
                .stdout
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
            child
                .stderr
                .take()
                .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>),
        ]
        .into_iter()
        .flatten()
        {
            let tx = tx.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(stream).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
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
                    output.push(line);
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

    pub fn pid(&self) -> u32 {
        self.child.id()
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
