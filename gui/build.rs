// SPDX-License-Identifier: GPL-3.0-or-later

fn main() {
    println!("cargo:rerun-if-changed=../res/app.manifest");
    println!("cargo:rerun-if-changed=../res/myicon.ico");

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
