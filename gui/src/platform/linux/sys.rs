// SPDX-License-Identifier: GPL-3.0-or-later

//! Small libc and /proc helpers.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

/// Non-blocking exclusive lock; false if another process holds it.
pub fn try_flock(file: &File) -> bool {
    // SAFETY: valid descriptor owned by `file`.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) == 0 }
}

pub fn local_hms() -> (i32, i32, i32) {
    // SAFETY: time(NULL) and localtime_r with a zeroed out struct.
    unsafe {
        let now = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return (0, 0, 0);
        }
        (tm.tm_hour, tm.tm_min, tm.tm_sec)
    }
}

pub fn find_in_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&paths)
        .chain(["/usr/sbin", "/sbin"].map(PathBuf::from))
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Loaded, built in, or present as a module that the kernel loads on
/// demand when dpibreak opens the queue.
pub fn nfqueue_available() -> bool {
    if Path::new("/sys/module/nfnetlink_queue").exists()
        || Path::new("/proc/net/netfilter/nfnetlink_queue").exists()
    {
        return true;
    }
    let Ok(release) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else {
        return true;
    };
    let base = PathBuf::from("/lib/modules").join(release.trim());
    if !base.is_dir() {
        // Unusual layout (containers, NixOS): do not warn on a guess.
        return true;
    }
    ["modules.dep", "modules.builtin"].iter().any(|f| {
        std::fs::read_to_string(base.join(f)).is_ok_and(|t| t.contains("/nfnetlink_queue.ko"))
    })
}

/// Short process name from /proc/<pid>/comm.
pub fn comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim_end().to_string())
}

/// PIDs whose process name is exactly `name`.
pub fn pids_named(name: &str) -> Vec<u32> {
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = dir
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| comm(*pid).as_deref() == Some(name))
        .collect();
    pids.sort_unstable();
    pids
}

/// Parent PID from /proc/<pid>/stat.
pub fn ppid(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // "pid (comm) state ppid ...": comm may contain spaces and parens.
    let rest = &stat[stat.rfind(')')? + 1..];
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub fn alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

pub fn kill(pid: u32, sig: i32) -> Result<(), String> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| "invalid pid".to_string())?;
    if pid <= 1 {
        return Err("invalid pid".into());
    }
    // SAFETY: plain kill(2) on a positive pid.
    if unsafe { libc::kill(pid, sig) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

/// Ignore terminal signals, so Ctrl+C on the panel's terminal does not
/// kill the helper before it has cleaned up.
pub fn ignore_terminal_signals() {
    // SAFETY: setting a signal disposition to SIG_IGN.
    unsafe {
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

pub fn set_umask(mask: u32) {
    // SAFETY: umask has no preconditions.
    unsafe {
        libc::umask(mask as libc::mode_t);
    }
}

/// For `Command::pre_exec`: get SIGTERM when the parent thread exits.
pub fn die_with_parent() -> std::io::Result<()> {
    // SAFETY: prctl(PR_SET_PDEATHSIG) is async-signal-safe.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// True if `path` and every directory above it are owned by root and
/// not writable by group or others (so only root can change what runs).
pub fn root_controlled(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    if !path.is_absolute() {
        return false;
    }
    // Check where symlinks really lead.
    let Ok(path) = path.canonicalize() else {
        return false;
    };
    let mut cur = Some(path.as_path());
    while let Some(p) = cur {
        match std::fs::metadata(p) {
            Ok(m) if m.uid() == 0 && m.mode() & 0o022 == 0 => {}
            _ => return false,
        }
        cur = p.parent();
    }
    true
}
