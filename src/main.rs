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

use anyhow::Result;

mod platform;
mod pkt;
mod tls;
mod log;
mod opt;

const PROJECT_NAME: &str = "DPIBreak";
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");
const PKG_HOMEPAGE: &str = env!("CARGO_PKG_HOMEPAGE");

fn splash_banner() {
    splash!("{PROJECT_NAME} v{PKG_VERSION} - {PKG_DESCRIPTION}");
    splash!("{PKG_HOMEPAGE}");
    splash!("");
}

fn main_1() -> Result<()> {
    let opt = opt::Opt::from_args()?;
    let initialized = opt.set_opt()?;
    splash_banner();
    platform::bootstrap()?;
    crate::info!("{PROJECT_NAME} v{PKG_VERSION}");
    initialized.log();
    platform::run()?;

    Ok(())
}

fn main() {
    let code = match main_1() {
        Ok(()) => 0,
        Err(e) => {
            crate::error!("{e}");

            for (i, cause) in e.chain().skip(1).enumerate() {
                crate::error!("caused by[{i}]: {cause}");
            }
            1
        }
    };

    std::process::exit(code);
}
