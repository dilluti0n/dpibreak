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
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DPIBREAK_SKIP_BUILD_RS");
    println!("cargo:rerun-if-changed=res/app.manifest");
    println!("cargo:rerun-if-changed=res/myicon.ico");

    if std::env::var_os("DPIBREAK_SKIP_BUILD_RS").is_some() {
        println!("cargo:warning=build.rs skipped (DPIBREAK_SKIP_BUILD_RS is set)");
        return;
    }

    // windows
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        eprintln!("target_os is not windows");
        return;
    }

    let out_dir = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let msg_table = out_dir.join("msg_table.bin");
    std::fs::write(&msg_table, message_table(EVENT_ID, "%1"))
        .expect("Failed to write message table");

    let mut res = winres::WindowsResource::new();

    res.set_manifest_file("res/app.manifest");
    res.set_icon("res/myicon.ico");
    // Event Viewer looks up the event ID here; the message is the
    // first insertion string.
    res.append_rc_content(&format!(
        "1 MESSAGETABLE \"{}\"",
        msg_table.display().to_string().replace('\\', "/")
    ));
    res.compile().expect("Failed to compile manifest resource");
}

/// Must match the event ID passed to ReportEventW in
/// src/platform/windows.rs.
const EVENT_ID: u32 = 1;

/// Build a MESSAGE_RESOURCE_DATA holding a single Unicode message.
fn message_table(id: u32, text: &str) -> Vec<u8> {
    let mut s: Vec<u8> = text
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    s.resize(s.len().next_multiple_of(4), 0);

    let entry_len = u16::try_from(4 + s.len()).unwrap();
    let mut out = Vec::new();
    out.extend(1u32.to_le_bytes()); // NumberOfBlocks
    out.extend(id.to_le_bytes()); // LowId
    out.extend(id.to_le_bytes()); // HighId
    out.extend(16u32.to_le_bytes()); // OffsetToEntries
    out.extend(entry_len.to_le_bytes()); // Length
    out.extend(1u16.to_le_bytes()); // Flags: Unicode
    out.extend(s);
    out
}
