// SPDX-License-Identifier: GPL-3.0-or-later

//! Messages between the panel and its root helper: one JSON object per
//! line. The helper answers every request with one `Response`, in order.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Longest request line the helper accepts.
pub const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Ping,
    /// Write the dpibreak copy embedded in the panel to the install
    /// directory if it differs (restarting the service if it runs it).
    InstallBinary,
    Install {
        exe: String,
        args: Vec<String>,
        auto_start: bool,
    },
    Reconfigure {
        exe: String,
        args: Vec<String>,
        auto_start: bool,
    },
    Uninstall,
    Start,
    Stop,
    /// Stop the service and start it again on exit if the panel goes
    /// away before `Resume`.
    Pause,
    Resume,
    TestStart {
        exe: String,
        args: Vec<String>,
        timeout_ms: u64,
    },
    TestStop,
    /// SIGTERM a dpibreak process outside the service.
    Kill {
        pid: u32,
    },
    Logs {
        lines: u32,
    },
    Rules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rules {
    Nftables,
    Iptables,
    None,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
}

impl Response {
    pub fn ok() -> Self {
        Self {
            ok: true,
            ..Default::default()
        }
    }

    pub fn err(e: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(e.into()),
            ..Default::default()
        }
    }
}

/// Split the arguments typed in the panel into an argv list.
pub fn split_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(String::from).collect()
}

/// Check dpibreak arguments before they reach a root process or the
/// unit file. `-d` is refused: the service and the tests run dpibreak in
/// the foreground. A custom `--nft-command` must be a plain command
/// name (looked up in root's PATH) or a path only root can change.
pub fn validate_args(args: &[String]) -> Result<(), String> {
    if args.len() > 64 {
        return Err("too many arguments".into());
    }
    let mut it = args.iter().peekable();
    while let Some(a) = it.next() {
        if a.is_empty() || a.len() > 256 {
            return Err("invalid argument length".into());
        }
        if a.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(format!("invalid character in argument {a:?}"));
        }
        match a.as_str() {
            "-d" | "-D" | "--daemon" => {
                return Err(format!(
                    "{a} is not allowed here: the panel runs dpibreak in the foreground"
                ));
            }
            "--nft-command" => {
                let Some(v) = it.next() else {
                    return Err("--nft-command needs a value".into());
                };
                let ok = if v.contains('/') {
                    crate::platform::sys::root_controlled(Path::new(v))
                } else {
                    v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
                };
                if !ok {
                    return Err(format!(
                        "--nft-command {v}: use a command name or a root-owned path"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Vec<String> {
        split_args(s)
    }

    #[test]
    fn args_ok() {
        assert!(validate_args(&v("-o 0,1 --fake-ttl 8 --no-rules")).is_ok());
        assert!(validate_args(&v("--nft-command nft")).is_ok());
        assert!(validate_args(&v("--nft-command /")).is_ok());
        assert!(validate_args(&[]).is_ok());
    }

    #[test]
    fn args_rejected() {
        assert!(validate_args(&v("-o 0,1 -d")).is_err());
        assert!(validate_args(&v("--daemon")).is_err());
        assert!(validate_args(&v("--nft-command")).is_err());
        assert!(validate_args(&v("--nft-command /tmp/x")).is_err());
        assert!(validate_args(&v("--nft-command rm;sh")).is_err());
        assert!(validate_args(&["a\nb".to_string()]).is_err());
        assert!(validate_args(&["a b".to_string()]).is_err());
    }

    #[test]
    fn unknown_commands_rejected() {
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"exec","path":"/bin/sh"}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"kill","pid":1,"sig":9}"#).is_err());
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"kill","pid":-1}"#).is_err());
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"kill","pid":42}"#),
            Ok(Request::Kill { pid: 42 })
        ));
    }
}
