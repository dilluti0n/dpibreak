// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTPS reachability probe results.
//!
//! The probe itself is platform specific (curl.exe on Windows, a Rust
//! TLS client on Linux); both report one of these outcomes.

pub use crate::platform::probe::probe;

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
            #[cfg(windows)]
            Outcome::Other(-1) => "no curl".into(),
            #[cfg(windows)]
            Outcome::Other(c) => format!("curl {c}"),
            #[cfg(not(windows))]
            Outcome::Other(_) => "error".into(),
        }
    }

    pub fn explain(&self) -> &'static str {
        match self {
            Outcome::Ok { .. } => "TLS handshake succeeded: the site is reachable.",
            #[cfg(windows)]
            Outcome::Dns => {
                "The name did not resolve. This is DNS blocking, which DPIBreak does not \
                 handle: use encrypted DNS (DoH) in Windows or your browser."
            }
            #[cfg(not(windows))]
            Outcome::Dns => {
                "The name did not resolve. This is DNS blocking, which DPIBreak does not \
                 handle: use encrypted DNS (DoH/DoT) in your resolver or browser."
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
            #[cfg(windows)]
            Outcome::Other(-1) => {
                "curl.exe could not be started (it ships with Windows 10 1803 and later)."
            }
            #[cfg(windows)]
            Outcome::Other(_) => "curl reported another error.",
            #[cfg(not(windows))]
            Outcome::Other(_) => "The connection failed in another way.",
        }
    }
}
