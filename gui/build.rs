// SPDX-License-Identifier: GPL-3.0-or-later

/// Files embedded into the single-file build, taken from the directory
/// named by DPIBREAK_BUNDLE_DIR (see build-bundle.ps1 / build-bundle.sh).
const WINDOWS_BUNDLE_FILES: &[&str] = &["dpibreak.exe", "WinDivert.dll", "WinDivert64.sys"];
const LINUX_BUNDLE_FILES: &[&str] = &["dpibreak"];

fn dpibreak_version() -> String {
    if let Ok(version) = std::env::var("DPIBREAK_VERSION") {
        return version;
    }

    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../Cargo.toml");
    let Ok(contents) = std::fs::read_to_string(manifest) else {
        return "unknown".into();
    };
    let mut in_package = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package && let Some(value) = line.strip_prefix("version = ") {
            return value.trim_matches('"').to_string();
        }
    }
    "unknown".into()
}

fn main() {
    println!("cargo:rerun-if-changed=../res/app.manifest");
    println!("cargo:rerun-if-changed=../res/myicon.ico");
    println!("cargo:rerun-if-changed=../Cargo.toml");
    println!("cargo:rerun-if-env-changed=DPIBREAK_BUNDLE_DIR");
    println!("cargo:rerun-if-env-changed=DPIBREAK_VERSION");
    println!("cargo::rustc-check-cfg=cfg(bundled)");
    println!("cargo:rustc-env=DPIBREAK_VERSION={}", dpibreak_version());

    if let Ok(dir) = std::env::var("DPIBREAK_BUNDLE_DIR") {
        let dir = std::path::Path::new(&dir);
        let dir = dir
            .canonicalize()
            .unwrap_or_else(|e| panic!("DPIBREAK_BUNDLE_DIR {}: {e}", dir.display()));
        // The target, not the host this script runs on.
        let files = match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
            Ok("windows") => WINDOWS_BUNDLE_FILES,
            Ok("linux") => LINUX_BUNDLE_FILES,
            _ => &[],
        };
        for f in files {
            let p = dir.join(f);
            assert!(p.is_file(), "bundle file missing: {}", p.display());
            println!("cargo:rerun-if-changed={}", p.display());
        }
        // include_bytes! wants a plain path; strip the \\?\ prefix
        // canonicalize adds on Windows.
        let path = dir.display().to_string();
        let path = path.trim_start_matches(r"\\?\").replace('\\', "/");
        println!("cargo:rustc-env=DPIBREAK_BUNDLE_DIR={path}");
        println!("cargo:rustc-cfg=bundled");
    }

    #[cfg(windows)]
    {
        // Same manifest as dpibreak.exe: managing services and running
        // WinDivert both need administrator rights.
        let mut res = winres::WindowsResource::new();
        res.set_manifest_file("../res/app.manifest");
        res.set_icon("../res/myicon.ico");
        res.compile().expect("failed to compile GUI resources");
    }
}
