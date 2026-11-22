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

/// Restrict the install directory to SYSTEM and Administrators (read
/// and execute for Users). The service runs dpibreak.exe from there as
/// SYSTEM, so ordinary users must not be able to replace it. Also
/// repairs a directory created earlier without administrator rights.
pub fn harden() -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    let dir = install_dir();
    if !dir.is_dir() {
        return Ok(());
    }
    let dir = dir.display().to_string();
    let run = |target: &str, args: &[&str]| -> Result<(), String> {
        let out = std::process::Command::new("icacls.exe")
            .arg(target)
            .args(args)
            .creation_flags(crate::service::CREATE_NO_WINDOW)
            .output()
            .map_err(|e| format!("icacls: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("icacls failed ({})", out.status))
        }
    };
    // Administrators own everything, so the creator keeps no extra
    // rights (needs administrator rights; the rest still applies).
    // No /C anywhere: with it icacls exits 0 even when files fail.
    let owner = run(&dir, &["/setowner", "*S-1-5-32-544", "/T", "/Q"]);
    // Inheritable ACL on the directory only: (OI)(CI) flags are invalid
    // on files and would leave them with an empty ACL.
    run(
        &dir,
        &[
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "*S-1-5-32-545:(OI)(CI)RX",
            "/Q",
        ],
    )?;
    // Files take exactly what the directory passes down.
    run(&format!(r"{dir}\*"), &["/reset", "/T", "/Q"])?;
    owner
}

/// Whether the bundled files on disk match the embedded ones.
pub fn up_to_date() -> bool {
    let dir = install_dir();
    FILES
        .iter()
        .all(|(name, bytes)| std::fs::read(dir.join(name)).ok().as_deref() == Some(*bytes))
}
