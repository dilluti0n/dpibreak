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

use anyhow::{Result, Context};
use std::sync::{
    atomic::{Ordering, AtomicBool},
};

mod platform;
mod pkt;
mod tls;
mod log;
mod opt;

use log::LogLevel;

const PROJECT_NAME: &str = "DPIBreak";
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const PKG_HOMEPAGE: &str = env!("CARGO_PKG_HOMEPAGE");
const MESSAGE_AT_RUN: &str = r#"DPIBreak is now running.
Press Ctrl+C or close this window to stop.
"#;
static RUNNING: AtomicBool = AtomicBool::new(true);

fn trap_exit() -> Result<()> {
    ctrlc::set_handler(|| {
        RUNNING.store(false, Ordering::SeqCst);
    }).context("handler: ")?;

    Ok(())
}

/// Drop with calling platform::cleanup()
struct EnsureCleanup;

impl Drop for EnsureCleanup {
    fn drop(&mut self) {
        if let Err(e) = platform::cleanup() {
            log_println!(LogLevel::Error, "cleanup failed: {e}");
        }
    }
}

fn splash_banner() {
    splash!("{PROJECT_NAME} v{PKG_VERSION} - {PKG_DESCRIPTION}");
    splash!("{PKG_HOMEPAGE}");
    splash!("");
}

fn main_0() -> Result<()> {
    trap_exit()?;
    opt::parse_args();
    splash_banner();

    let _guard = EnsureCleanup;

    platform::bootstrap()?;
    platform::run()?;

    Ok(())
}

fn main() {
    let code = match main_0() {
        Ok(()) => 0,
        Err(e) => {
            log_println!(LogLevel::Error, "{e}");

            for (i, cause) in e.chain().skip(1).enumerate() {
                log_println!(LogLevel::Error, "caused by[{i}]: {cause}");
            }
            1
        }
    };

    std::process::exit(code);
}
