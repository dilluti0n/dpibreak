// SPDX-License-Identifier: GPL-3.0-or-later

//! Single-file distribution.
//!
//! A bundled build (see build-bundle.sh) embeds a static dpibreak. The
//! helper installs it to `/usr/local/lib/dpibreak/dpibreak` (root:root,
//! 0755) and replaces it atomically when the embedded copy differs.

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[cfg(bundled)]
const DPIBREAK: &[u8] = include_bytes!(concat!(env!("DPIBREAK_BUNDLE_DIR"), "/dpibreak"));

#[cfg(not(bundled))]
const DPIBREAK: &[u8] = &[];

pub const INSTALL_DIR: &str = "/usr/local/lib/dpibreak";

pub fn is_bundled() -> bool {
    !DPIBREAK.is_empty()
}

pub fn install_dir() -> PathBuf {
    PathBuf::from(INSTALL_DIR)
}

pub fn exe_path() -> PathBuf {
    install_dir().join("dpibreak")
}

/// Whether the installed copy matches the embedded one (true for a
/// build without one). Readable without root.
pub fn up_to_date() -> bool {
    !is_bundled() || fs::read(exe_path()).ok().as_deref() == Some(DPIBREAK)
}

pub fn installed() -> bool {
    exe_path().is_file()
}

// ------------------------------------------------- helper side (root)

/// Create the install directory or repair it: a real directory owned by
/// root with mode 0755, under root-controlled parents.
fn prepare_dir(dir: &Path) -> Result<(), String> {
    let parent = dir.parent().ok_or("bad install directory")?;
    fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    if !super::sys::root_controlled(parent) {
        return Err(format!("{} is not root-owned", parent.display()));
    }
    match fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            return Err(format!("{} is not a directory", dir.display()));
        }
        Ok(_) => {}
        Err(_) => fs::create_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?,
    }
    std::os::unix::fs::chown(dir, Some(0), Some(0))
        .map_err(|e| format!("chown {}: {e}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("chmod {}: {e}", dir.display()))
}

/// Write the embedded dpibreak to a temporary file next to the target,
/// then rename it over the target. `Ok(false)` if already up to date.
/// The caller stops a service running the old copy first if it wants
/// the new one to take effect.
pub fn write_atomically() -> Result<bool, String> {
    if !is_bundled() {
        return Ok(false);
    }
    let dir = install_dir();
    prepare_dir(&dir)?;
    let target = exe_path();
    if let Ok(m) = fs::symlink_metadata(&target) {
        if !m.is_file() {
            return Err(format!("{} is not a regular file", target.display()));
        }
        if m.uid() == 0 && fs::read(&target).ok().as_deref() == Some(DPIBREAK) {
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod: {e}"))?;
            return Ok(false);
        }
    }

    let tmp = dir.join(".dpibreak.new");
    _ = fs::remove_file(&tmp);
    let result = (|| -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o700)
            .open(&tmp)?;
        f.write_all(DPIBREAK)?;
        f.sync_all()?;
        std::os::unix::fs::fchown(&f, Some(0), Some(0))?;
        f.set_permissions(fs::Permissions::from_mode(0o755))?;
        fs::rename(&tmp, &target)
    })();
    if let Err(e) = result {
        _ = fs::remove_file(&tmp);
        return Err(format!("installing {}: {e}", target.display()));
    }
    Ok(true)
}

// ------------------------------------------------- panel side

/// Ask the helper to bring the installed copy up to date (it stops and
/// starts the service around the replacement if the service runs it).
pub fn update() -> Result<(), String> {
    super::client::request(super::proto::Request::InstallBinary).map(|_| ())
}
