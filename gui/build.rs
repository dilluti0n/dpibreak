// SPDX-License-Identifier: GPL-3.0-or-later

/// Files embedded into the single-exe build, taken from the directory
/// named by DPIBREAK_BUNDLE_DIR (see build-bundle.ps1).
const BUNDLE_FILES: &[&str] = &["dpibreak.exe", "WinDivert.dll", "WinDivert64.sys"];

fn main() {
    println!("cargo:rerun-if-changed=../res/app.manifest");
    println!("cargo:rerun-if-changed=../res/myicon.ico");
    println!("cargo:rerun-if-env-changed=DPIBREAK_BUNDLE_DIR");
    println!("cargo::rustc-check-cfg=cfg(bundled)");

    if let Ok(dir) = std::env::var("DPIBREAK_BUNDLE_DIR") {
        let dir = std::path::Path::new(&dir);
        let dir = dir
            .canonicalize()
            .unwrap_or_else(|e| panic!("DPIBREAK_BUNDLE_DIR {}: {e}", dir.display()));
        for f in BUNDLE_FILES {
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
