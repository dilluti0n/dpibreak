// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic::Ordering;
use anyhow::Result;

use crate::{log::LogLevel, log_println, opt};
use super::{exec_process, INJECT_MARK, IS_U32_SUPPORTED};

const DPIBREAK_TABLE: &str = "dpibreak";

/// Apply nft rules with `nft_command() -f -`.
fn nft(rule: &str) -> Result<()> {
    log_println!(LogLevel::Info, "nft: {rule}");
    exec_process(&[opt::nft_command(), "-f", "-"], Some(rule))
}

pub fn install_nft_rules() -> Result<()> {
    let queue_num = opt::queue_num();
    let rule = format!(
    r#"add table inet {DPIBREAK_TABLE}
add chain inet {DPIBREAK_TABLE} OUTPUT {{ type filter hook output priority 0; policy accept; }}
add rule inet {DPIBREAK_TABLE} OUTPUT meta mark {INJECT_MARK} return
add rule inet {DPIBREAK_TABLE} OUTPUT tcp dport 443 @ih,0,8 0x16 @ih,40,8 0x01 queue num {queue_num} bypass"#
    );
    nft(&rule)?;

    // clienthello filtered by nft
    IS_U32_SUPPORTED.store(true, Ordering::Relaxed);

    Ok(())
}

pub fn cleanup_nftables_rules() -> Result<()> {
    let rule = format!("delete table inet {DPIBREAK_TABLE}");
    nft(&rule)?;

    Ok(())
}
