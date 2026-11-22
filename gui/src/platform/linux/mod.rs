// SPDX-License-Identifier: GPL-3.0-or-later

//! Linux backend.
//!
//! The panel runs as the desktop user. Everything that needs root goes
//! through a helper: this same executable started once with
//! `pkexec <path> --helper`, talking JSON lines over stdin/stdout (see
//! `proto`, `helper` and `client`). The service is a systemd unit.

pub mod bundle;
pub mod client;
pub mod helper;
pub mod probe;
pub mod process;
pub mod proto;
pub mod service;
pub mod sys;

use std::path::{Path, PathBuf};

use super::{Chip, Tone};

pub const EXE_NAME: &str = "dpibreak";
pub const EXE_HINT: &str = "/usr/local/lib/dpibreak/dpibreak";
pub const AUTO_START_LABEL: &str = "Start at boot";
pub const STOP_HINT: &str = "Stop protection. The service stays installed; with auto-start on it \
                             starts again at boot.";
/// The service always runs the copy in the install directory, so the
/// program path is not editable.
pub const EXE_EDITABLE: bool = false;

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
    ("-b site.com", "leave this site untouched"),
    (
        "--forward",
        "also handle forwarded traffic (router, VPN server)",
    ),
    ("--no-rules", "add no firewall rules; you manage nfqueue"),
];

/// Handle the modes that never open a window. Returns the exit code
/// when the process should end here.
pub fn early_main() -> Option<i32> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--helper") {
        return Some(helper::run());
    }
    if sys::geteuid() == 0 {
        eprintln!(
            "Do not run DPIBreak Panel as root. Start it as your normal user; it asks \
             for your password when it needs administrator rights."
        );
        return Some(1);
    }
    None
}

/// Allow one panel at a time: two would fight over the service, the
/// helper and the settings file. The lock lives as long as the process.
pub fn already_running(_title: &str) -> bool {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let path = dir.join("dpibreak-panel.lock");
    let file = match std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&path)
    {
        Ok(f) => f,
        // Cannot lock: better to run than to refuse.
        Err(_) => return false,
    };
    if sys::try_flock(&file) {
        // Keep the descriptor (and the lock) open until exit.
        std::mem::forget(file);
        false
    } else {
        eprintln!("DPIBreak Panel is already running.");
        true
    }
}

pub fn settings_path() -> Result<PathBuf, &'static str> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or("neither XDG_CONFIG_HOME nor HOME is set")?;
    Ok(base.join("dpibreak-gui").join("settings.json"))
}

/// The service and the tests always use the installed copy.
pub fn fixed_exe() -> Option<String> {
    Some(bundle::exe_path().display().to_string())
}

pub fn detect_exe() -> Option<String> {
    fixed_exe()
}

/// Whether `exe` can be run. The built-in copy counts before it is
/// installed: the helper writes it before first use.
pub fn exe_ready(exe: &str) -> bool {
    let p = Path::new(exe.trim());
    p.is_file() || (bundle::is_bundled() && p == bundle::exe_path())
}

pub fn clock() -> String {
    let (h, m, s) = sys::local_hms();
    format!("{h:02}:{m:02}:{s:02}")
}

/// The window is closing. The helper kills any test dpibreak and starts
/// the service again if it paused it, as soon as its stdin closes; this
/// also happens if the panel crashes or is killed.
pub fn on_exit(_test_pid: Option<u32>, _restore_service: bool) {
    client::shutdown();
}

/// Platform chips for the Protection card and hints about missing
/// system pieces.
pub fn status_extras() -> (Vec<Chip>, Vec<String>) {
    let mut chips = Vec::new();
    let mut hints = Vec::new();

    let nft = sys::find_in_path("nft").is_some();
    let ipt = sys::find_in_path("iptables").is_some();
    match client::rules_backend() {
        Some(proto::Rules::Nftables) => chips.push(Chip {
            text: "nftables".into(),
            tone: Tone::Good,
            hover: "dpibreak's rules are active in the nftables table inet dpibreak".into(),
        }),
        Some(proto::Rules::Iptables) => chips.push(Chip {
            text: "iptables".into(),
            tone: Tone::Good,
            hover: "dpibreak's rules are active in the iptables mangle table".into(),
        }),
        _ if nft => chips.push(Chip {
            text: "nftables".into(),
            tone: Tone::Neutral,
            hover: "dpibreak adds its rules with nft (iptables if that fails)".into(),
        }),
        _ if ipt => chips.push(Chip {
            text: "iptables".into(),
            tone: Tone::Warn,
            hover: "nft was not found; dpibreak falls back to iptables".into(),
        }),
        _ => chips.push(Chip {
            text: "No nft/iptables".into(),
            tone: Tone::Bad,
            hover: "dpibreak needs nftables (or iptables) unless run with --no-rules".into(),
        }),
    }

    if !service::has_systemd() {
        hints.push(
            "systemd is not running: the service cannot be installed. Settings can still \
             be tested."
                .into(),
        );
    }
    if !nft && !ipt {
        hints.push("Install nftables (the nft command) so dpibreak can add its rules.".into());
    }
    if !sys::nfqueue_available() {
        hints.push(
            "The nfnetlink_queue kernel module was not found; dpibreak needs it \
             (CONFIG_NETFILTER_NETLINK_QUEUE)."
                .into(),
        );
    }
    (chips, hints)
}
