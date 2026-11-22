// SPDX-License-Identifier: GPL-3.0-or-later

//! Settings persisted in %APPDATA%\DPIBreak-GUI\settings.json.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::service;

pub const DEFAULT_URLS: &str = "\
# One URL per line. Lines starting with # are ignored.
# Control sites: normally never blocked, they show the connection works.
https://www.google.com
https://www.cloudflare.com
https://github.com
# Sites that are often blocked by DPI somewhere.
https://discord.com
https://www.roblox.com
https://www.wattpad.com
https://www.torproject.org
https://imgur.com
https://www.youtube.com
https://x.com
https://www.instagram.com
https://telegram.org
https://signal.org
https://proton.me
";

/// Default list shipped by the first version, replaced on load so
/// existing users get the longer list.
const OLD_DEFAULT_URLS: &str = "\
# One URL per line. The first one should be a site that is NOT blocked,
# so a working internet connection can be told apart from a block.
https://www.google.com
https://discord.com
https://www.roblox.com
https://www.wattpad.com
";

pub const DEFAULT_CONFIGS: &str = "\
# One set of dpibreak arguments per line, tried in order.
-o 0,1
-o 0,5
-o 5,0
-o 0,1 --fake-ttl 8
-o 0,5 --fake-ttl 8
-o 0,1 -a
-o 0,5 -a
";

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub exe_path: String,
    pub args: String,
    pub auto_start: bool,
    pub urls: String,
    pub configs: String,
    pub timeout_secs: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            exe_path: String::new(),
            args: "-o 0,1".into(),
            auto_start: true,
            urls: DEFAULT_URLS.into(),
            configs: DEFAULT_CONFIGS.into(),
            timeout_secs: 8,
        }
    }
}

fn path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|d| PathBuf::from(d).join("DPIBreak-GUI").join("settings.json"))
}

impl Settings {
    pub fn load() -> Self {
        let mut s: Settings = path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();

        if s.urls.trim() == OLD_DEFAULT_URLS.trim() {
            s.urls = DEFAULT_URLS.into();
        }

        // Prefer what the installed service actually runs.
        if let Ok(Some(info)) = service::query(service::SERVICE_NAME) {
            let (exe, args) = service::parse_bin_path(&info.bin_path);
            if s.exe_path.is_empty() {
                s.exe_path = exe;
                s.args = args;
            }
            s.auto_start = info.auto_start;
        }
        if s.exe_path.is_empty() {
            s.exe_path = detect_exe().unwrap_or_default();
        }
        s
    }

    pub fn save(&self) -> Result<(), String> {
        let p = path().ok_or("APPDATA is not set")?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let text = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(p, text).map_err(|e| e.to_string())
    }

    pub fn url_list(&self) -> Vec<String> {
        lines(&self.urls)
    }

    pub fn config_list(&self) -> Vec<String> {
        lines(&self.configs)
    }
}

fn lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect()
}

/// dpibreak.exe next to the GUI, from the service, or on PATH.
pub fn detect_exe() -> Option<String> {
    if let Ok(me) = std::env::current_exe()
        && let Some(dir) = me.parent()
    {
        let candidate = dir.join("dpibreak.exe");
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    if let Ok(Some(info)) = service::query(service::SERVICE_NAME) {
        let (exe, _) = service::parse_bin_path(&info.bin_path);
        if !exe.is_empty() {
            return Some(exe);
        }
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join("dpibreak.exe"))
            .find(|p| p.is_file())
            .map(|p| p.display().to_string())
    })
}
