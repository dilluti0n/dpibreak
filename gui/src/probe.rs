// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTPS reachability probe using the curl.exe shipped with Windows.
//!
//! curl's TLS ClientHello goes through the same WinDivert path as a
//! browser's, so a successful handshake means the bypass works for
//! that host. The curl exit code tells apart the usual ways a block
//! shows up.

use std::os::windows::process::CommandExt;
use std::process::Command;

use crate::service::CREATE_NO_WINDOW;

#[derive(Clone, Debug)]
pub enum Outcome {
    /// TLS handshake completed (any HTTP status counts).
    Ok {
        http: u16,
        secs: f32,
    },
    Dns,
    Connect,
    Timeout,
    TlsFailed,
    Reset,
    BadCert,
    Other(i32),
}

impl Outcome {
    pub fn works(&self) -> bool {
        matches!(self, Outcome::Ok { .. })
    }

    pub fn short(&self) -> String {
        match self {
            Outcome::Ok { http, secs } => format!("OK {http} ({secs:.2}s)"),
            Outcome::Dns => "DNS fail".into(),
            Outcome::Connect => "no connect".into(),
            Outcome::Timeout => "timeout".into(),
            Outcome::TlsFailed => "TLS fail".into(),
            Outcome::Reset => "reset".into(),
            Outcome::BadCert => "bad cert".into(),
            Outcome::Other(c) => format!("curl {c}"),
        }
    }

    pub fn explain(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "TLS handshake succeeded: the site is reachable.",
            Outcome::Dns => {
                "The name did not resolve. This is DNS blocking, which DPIBreak does not \
                 handle: use encrypted DNS (DoH) in Windows or your browser."
            }
            Outcome::Connect => {
                "TCP connection failed: the IP itself is blocked or the host is down. \
                 DPIBreak cannot help with IP blocking."
            }
            Outcome::Timeout => "No answer in time: typical of DPI dropping the ClientHello.",
            Outcome::TlsFailed => {
                "The TLS handshake was interrupted: typical of DPI reacting to the SNI."
            }
            Outcome::Reset => "The connection was reset: typical of DPI injecting a RST.",
            Outcome::BadCert => {
                "The certificate did not match: the DNS answer probably points to a block \
                 page. Use encrypted DNS (DoH)."
            }
            Outcome::Other(_) => "curl reported another error.",
        }
    }
}

pub fn probe(url: &str, max_secs: u32) -> Outcome {
    let out = Command::new("curl.exe")
        .args([
            "-s",
            "-o",
            "NUL",
            "-w",
            "%{http_code} %{time_appconnect}",
            "--connect-timeout",
            "5",
            "--max-time",
            &max_secs.to_string(),
            // Revocation servers may be unreachable on filtered networks;
            // that is not what we are testing.
            "--ssl-no-revoke",
            url,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let out = match out {
        Ok(o) => o,
        Err(_) => return Outcome::Other(-1),
    };
    match out.status.code().unwrap_or(-1) {
        0 => {
            let text = String::from_utf8_lossy(&out.stdout);
            let mut it = text.split_whitespace();
            let http = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let secs = it.next().and_then(|s| s.parse().ok()).unwrap_or(0.0);
            Outcome::Ok { http, secs }
        }
        6 => Outcome::Dns,
        7 => Outcome::Connect,
        28 => Outcome::Timeout,
        35 => Outcome::TlsFailed,
        52 | 55 | 56 => Outcome::Reset,
        51 | 60 => Outcome::BadCert,
        c => Outcome::Other(c),
    }
}
