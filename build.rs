// Copyright 2025-2026 Dillution <hskimse1@gmail.com>.
//
// This file is part of DPIBreak.
//
// DPIBreak is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// DPIBreak is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License
// along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

fn main() {
    if std::env::var_os("DPIBREAK_SKIP_BUILD_RS").is_some() {
        println!("cargo:warning=build.rs skipped (DPIBREAK_SKIP_BUILD_RS is set)");
        return;
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        eprintln!("target_os is not windows");
        return;
    }

    let mut res = winres::WindowsResource::new();

    res.set_manifest_file("res/app.manifest");
    res.set_icon("res/myicon.ico");
    res.compile().expect("Failed to compile manifest resource");
}
