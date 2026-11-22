// SPDX-License-Identifier: GPL-3.0-or-later

//! Single-exe distribution.
//!
//! A bundled build (see build-bundle.ps1) embeds dpibreak.exe and the
//! WinDivert driver files. They are written to
//! `%ProgramData%\DPIBreak\bin` on start, so nothing else needs to be
//! downloaded and the service has a stable path to run from.

use std::path::PathBuf;

#[cfg(bundled)]
const FILES: &[(&str, &[u8])] = &[
    (
        "dpibreak.exe",
        include_bytes!(concat!(env!("DPIBREAK_BUNDLE_DIR"), "/dpibreak.exe")),
    ),
    (
        "WinDivert.dll",
        include_bytes!(concat!(env!("DPIBREAK_BUNDLE_DIR"), "/WinDivert.dll")),
    ),
    (
        "WinDivert64.sys",
        include_bytes!(concat!(env!("DPIBREAK_BUNDLE_DIR"), "/WinDivert64.sys")),
    ),
];

#[cfg(not(bundled))]
const FILES: &[(&str, &[u8])] = &[];

pub fn is_bundled() -> bool {
    !FILES.is_empty()
}

pub fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("DPIBreak").join("bin")
}

/// Path the bundled dpibreak.exe is extracted to.
pub fn exe_path() -> PathBuf {
    install_dir().join("dpibreak.exe")
}

/// Write any bundled file that is missing or differs from the embedded
/// copy. Returns the names written. Fails if a file is in use (e.g. the
/// service runs an older dpibreak.exe from there).
pub fn extract() -> Result<Vec<&'static str>, String> {
    if !is_bundled() {
        return Ok(Vec::new());
    }
    let dir = install_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let mut written = Vec::new();
    for (name, bytes) in FILES {
        let path = dir.join(name);
        if std::fs::read(&path).ok().as_deref() == Some(*bytes) {
            continue;
        }
        std::fs::write(&path, bytes).map_err(|e| format!("{name}: {e}"))?;
        written.push(*name);
    }
    Ok(written)
}

/// Whether the bundled files on disk match the embedded ones.
pub fn up_to_date() -> bool {
    let dir = install_dir();
    FILES
        .iter()
        .all(|(name, bytes)| std::fs::read(dir.join(name)).ok().as_deref() == Some(*bytes))
}
