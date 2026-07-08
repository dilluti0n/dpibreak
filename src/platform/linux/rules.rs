// SPDX-FileCopyrightText: 2026 Dilluti0n <hskim@dilluti0n.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::atomic;
use std::process::{Command, Stdio};
use std::io::Write;
use anyhow::{Result, Context, anyhow};

mod iptables;

use iptables::{IPTables, cleanup_xt_u32};

use crate::opt;
use super::INJECT_MARK;

const DPIBREAK_CHAIN: &str = "DPIBREAK";
const DPIBREAK_TABLE: &str = "dpibreak";
pub static IS_U32_SUPPORTED: atomic::AtomicBool = atomic::AtomicBool::new(false);

fn exec_process(args: &[&str], input: Option<&str>) -> Result<()> {
    if args.is_empty() {
        return Err(anyhow!("command args cannot be empty"));
    }

    let program = args[0];
    let stdin_mode = if input.is_some() { Stdio::piped() } else { Stdio::null() };

    let mut child = Command::new(program)
        .args(&args[1..])
        .stdin(stdin_mode)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn {}", program))?;

    if let Some(data) = input {
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(data.as_bytes())
                .with_context(|| format!("failed to write input to {}", program))?;
        }
    }

    let output = child.wait_with_output()
        .with_context(|| format!("failed to wait for {}", program))?;

    match output.status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(anyhow!("{} exited with status {}: {}", program, code,
            String::from_utf8_lossy(&output.stderr))),
        None => Err(anyhow!("{} terminated by signal", program))
    }
}

/// Apply nft rules with `nft_command() -f -`.
fn nft(rule: &str) -> Result<()> {
    crate::info!("nft: {rule}");
    exec_process(&[opt::nft_command(), "-f", "-"], Some(rule))
}

pub struct InstalledRules {
    is_nft_not_supported: bool,
    ipt: Option<IPTables>,
    ip6: Option<IPTables>
}

fn install_ipt6(is_ipv6: bool) -> Option<IPTables> {
    let ipt = IPTables::new(is_ipv6).map_err(|e| crate::warn!("iptables: {e}")).ok()?;
    if let Err(e) = ipt.install() {
        crate::warn!("iptables: {e}");
        _ = ipt.cleanup(); // partial rules
        return None;
    }
    Some(ipt)
}

pub fn install() -> Result<InstalledRules> {
    let mut is_nft_not_supported = false;
    let mut ipt = None;
    let mut ip6 = None;

    if let Err(e) = install_nft_rules() {
        is_nft_not_supported = true;
        crate::warn!("nftables: {}", e.to_string());
        crate::warn!("fallback to iptables");

        ipt = install_ipt6(false);
        ip6 = install_ipt6(true);

        if ipt.is_none() && ip6.is_none() {
            anyhow::bail!("failed to install rules");
        }
    }

    Ok(InstalledRules{
        is_nft_not_supported,
        ipt,
        ip6
    })
}

impl Drop for InstalledRules {
    fn drop(&mut self) {
        if self.is_nft_not_supported {
            if let Some(ipt) = &self.ipt {
                ipt.cleanup().map_err(|e| crate::warn!("fail to cleanup iptables rules: {e}")).ok();
            }
            if let Some(ipt) = &self.ip6 {
                ipt.cleanup().map_err(|e| crate::warn!("fail to cleanup ip6tables rules: {e}")).ok();
            }
            cleanup_xt_u32().map_err(|e| crate::warn!("fail to cleanup xt_u32: {e}")).ok();
        } else {
            nft_cleanup().map_err(|e| crate::warn!("fail to cleanup nftables rules: {e}")).ok();
        }
    }
}

pub fn ipt6_cleanup(is_ipv6: bool) -> Result<()> {
    let ipt6 = IPTables::new(is_ipv6)?;
    ipt6.cleanup()
}

pub fn nft_cleanup() -> Result<()> {
    let rule = format!("delete table inet {DPIBREAK_TABLE}");
    nft(&rule)?;

    Ok(())
}

fn install_nft_rules() -> Result<()> {
    let queue_num = opt::queue_num();
    let rule = format!(
    r#"add table inet {DPIBREAK_TABLE}
add chain inet {DPIBREAK_TABLE} OUTPUT {{ type filter hook output priority 0; policy accept; }}
add rule inet {DPIBREAK_TABLE} OUTPUT meta mark {INJECT_MARK} return
add rule inet {DPIBREAK_TABLE} OUTPUT tcp dport 443 @ih,0,8 0x16 @ih,40,8 0x01 queue num {queue_num} bypass"#
    );
    nft(&rule)?;

    // clienthello filtered by nft
    IS_U32_SUPPORTED.store(true, atomic::Ordering::Relaxed);

    Ok(())
}

impl IPTables {
    fn install(&self) -> Result<()> {
        let q_num = crate::opt::queue_num().to_string();
        // prevent inf loop
        let mark = format!("{:#x}", INJECT_MARK);

        let mut rule = vec![
            "-p", "tcp", "--dport", "443",
            "-j", "NFQUEUE", "--queue-num", &q_num, "--queue-bypass"
        ];

        if iptables::is_u32_supported(self) {
            const U32: &str = "0>>22&0x3C @ 12>>26&0x3C @ 0>>24&0xFF=0x16 && \
                           0>>22&0x3C @ 12>>26&0x3C @ 2>>24&0xFF=0x01";

            rule.extend_from_slice(&["-m", "u32", "--u32", U32]);
        }

        self.new_chain("mangle", DPIBREAK_CHAIN)?;

        self.insert(
            "mangle",
            DPIBREAK_CHAIN,
            &["-m", "mark", "--mark", &mark, "-j", "RETURN"],
            1
        )?;

        self.append("mangle", DPIBREAK_CHAIN, &rule)?;
        crate::info!("{}: new chain {} on table mangle", self.cmd(), DPIBREAK_CHAIN);

        self.insert("mangle", "POSTROUTING", &["-j", DPIBREAK_CHAIN], 1)?;
        crate::info!("{}: add jump to {} chain on POSTROUTING", self.cmd(), DPIBREAK_CHAIN);

        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        if self.delete("mangle", "POSTROUTING", &["-j", DPIBREAK_CHAIN]).is_ok() {
            crate::info!("{}: delete jump to {} from mangle/POSTROUTING", self.cmd(), DPIBREAK_CHAIN);
        }

        if self.flush_chain("mangle", DPIBREAK_CHAIN).is_ok() {
            crate::info!("{}: flush chain {}", self.cmd(), DPIBREAK_CHAIN);
        }

        if self.delete_chain("mangle", DPIBREAK_CHAIN).is_ok() {
            crate::info!("{}: delete chain {}", self.cmd(), DPIBREAK_CHAIN);
        }

        Ok(())
    }
}
