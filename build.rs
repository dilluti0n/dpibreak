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

use std::collections::HashMap;
use std::fs;

fn parse_defaults(src: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for line in src.lines() {
        let line = line.trim();

        let line = if let Some(rest) = line.strip_prefix("#[cfg(") {
            rest.split_once(")] ").map_or(line, |(_, after)| after)
        } else {
            line
        };

        if !line.starts_with("const DEFAULT_") {
            continue;
        }

        // `const DEFAULT_FOO: type = value;`
        let Some(rest) = line.strip_prefix("const ") else { continue };
        let Some((name, rest)) = rest.split_once(':') else { continue };
        let Some((_, value)) = rest.split_once('=') else { continue };

        let name = name.trim();
        let value = value.trim().trim_end_matches(';').trim();
        let value = value.trim_matches('"');

        // `LogLevel::Warning` -> `warning`
        let value = value.split("::").last().unwrap_or(value);
        let value = value.to_lowercase();

        map.insert(name.to_string(), value.to_string());
    }

    map
}

// fn build_date() -> String {
//     chrono::Utc::now().format("%B %Y").to_string()
// }

fn version_for_man() -> String {
    let ver = env!("CARGO_PKG_VERSION"); // "0.3.0"
    let parts: Vec<&str> = ver.splitn(3, '.').collect();
    format!("v{}.{}", parts[0], parts[1])
}

fn main() {
    if std::env::var_os("DPIBREAK_SKIP_BUILD_RS").is_some() {
        println!("cargo:warning=build.rs skipped (DPIBREAK_SKIP_BUILD_RS is set)");
        return;
    }

    // preprocess dpibreak.1.in
    let opt_rs = fs::read_to_string("src/opt.rs").expect("failed to read src/opt.rs");
    let template = fs::read_to_string("dpibreak.1.in").expect("failed to read dpibreak.1.in");

    let mut defaults = parse_defaults(&opt_rs);
    // defaults.insert("BUILD_DATE".to_string(), build_date());
    defaults.insert("VERSION".to_string(), version_for_man());

    let mut out = template;
    for (key, value) in &defaults {
        out = out.replace(&format!("{{{{{key}}}}}"), value);
    }

    fs::write("dpibreak.1", &out).expect("failed to write dpibreak.1");

    // windows
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
