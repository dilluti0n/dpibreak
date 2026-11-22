// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTPS reachability probe using the curl.exe shipped with Windows.
//!
//! curl's TLS ClientHello goes through the same WinDivert path as a
//! browser's, so a successful handshake means the bypass works for
//! that host. The curl exit code tells apart the usual ways a block
//! shows up.

use std::os::windows::process::CommandExt;
use std::process::Command;

use super::service::CREATE_NO_WINDOW;
use crate::probe::Outcome;

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
