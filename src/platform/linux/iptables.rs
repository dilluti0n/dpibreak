// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Result, Error};

use std::sync::{
    atomic::{AtomicBool, Ordering}
};

use crate::opt;
use super::{exec_process, INJECT_MARK, IS_U32_SUPPORTED};

static IS_XT_U32_LOADED_BY_US: AtomicBool = AtomicBool::new(false);

const DPIBREAK_CHAIN: &str = "DPIBREAK";

pub struct IPTables {
    cmd: &'static str,
}

impl IPTables {
    pub fn new(is_ipv6: bool) -> Result<Self> {
        Ok(Self {
            cmd: if is_ipv6 { "ip6tables" } else { "iptables" },
        })
    }

    fn run(&self, args: &[&str]) -> Result<()> {
        let mut full_args = Vec::with_capacity(args.len() + 1);

        full_args.push(self.cmd);
        full_args.extend_from_slice(args);

        exec_process(&full_args, None)
    }

    pub fn new_chain(&self, table: &str, chain: &str) -> Result<()> {
        self.run(&["-t", table, "-N", chain])
    }

    pub fn flush_chain(&self, table: &str, chain: &str) -> Result<()> {
        self.run(&["-t", table, "-F", chain])
    }

    pub fn delete_chain(&self, table: &str, chain: &str) -> Result<()> {
        self.run(&["-t", table, "-X", chain])
    }

    pub fn insert(&self, table: &str, chain: &str, rule: &[&str], pos: i32) -> Result<()> {
        let pos_str = pos.to_string();
        let mut args = vec!["-t", table, "-I", chain, &pos_str];
        args.extend_from_slice(rule);
        self.run(&args)
    }

    pub fn append(&self, table: &str, chain: &str, rule: &[&str]) -> Result<()> {
        let mut args = vec!["-t", table, "-A", chain];
        args.extend_from_slice(rule);
        self.run(&args)
    }

    pub fn delete(&self, table: &str, chain: &str, rule: &[&str]) -> Result<()> {
        let mut args = vec!["-t", table, "-D", chain];
        args.extend_from_slice(rule);
        self.run(&args)
    }
}

fn is_xt_u32_loaded() -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().any(|l| l.starts_with("xt_u32 ")))
        .unwrap_or(false)
}

fn ensure_xt_u32() -> Result<()> {
    let before = is_xt_u32_loaded();
    _ = exec_process(&["modprobe", "-q", "xt_u32"], None);
    let after = is_xt_u32_loaded();

    if !before && after {
        IS_XT_U32_LOADED_BY_US.store(true, Ordering::Relaxed);
    }
    Ok(())
}

fn is_u32_supported(ipt: &IPTables) -> bool {
    if IS_U32_SUPPORTED.load(Ordering::Relaxed) {
        return true;
    }

    if ensure_xt_u32().is_err() {
        crate::warn!("xt_u32 not supported");
        return false;
    }

    crate::info!("xt_u32 loaded");

    let rule = ["-m", "u32", "--u32", "0x0=0x0", "-j", "RETURN"];

    match ipt.insert("raw", "PREROUTING", &rule, 1) {
        Ok(_) => {
            _ = ipt.delete("raw", "PREROUTING", &rule);
            IS_U32_SUPPORTED.store(true, Ordering::Relaxed);
            true
        }

        Err(_) => false
    }
}

pub fn iptables_err(e: impl ToString) -> Error {
    Error::msg(format!("iptables: {}", e.to_string()))
}

pub fn install_iptables_rules(ipt: &IPTables) -> Result<()> {
    let q_num = crate::opt::queue_num().to_string();
    // prevent inf loop
    let mark = format!("{:#x}", INJECT_MARK);

    let mut rule = vec![
        "-p", "tcp", "--dport", "443",
        "-j", "NFQUEUE", "--queue-num", &q_num, "--queue-bypass"
    ];

    if is_u32_supported(ipt) {
        const U32: &str = "0>>22&0x3C @ 12>>26&0x3C @ 0>>24&0xFF=0x16 && \
                           0>>22&0x3C @ 12>>26&0x3C @ 2>>24&0xFF=0x01";

        rule.extend_from_slice(&["-m", "u32", "--u32", U32]);
    }

    ipt.new_chain("mangle", DPIBREAK_CHAIN).map_err(iptables_err)?;

    ipt.insert(
        "mangle",
        DPIBREAK_CHAIN,
        &["-m", "mark", "--mark", &mark, "-j", "RETURN"],
        1
    ).map_err(iptables_err)?;

    if opt::fake_autottl() {
        let synack_rule = vec![
            "-p", "tcp",
            "--sport", "443",
            "-m", "tcp", "--tcp-flags", "SYN,ACK", "SYN,ACK",
            "-j", "NFQUEUE", "--queue-num", &q_num, "--queue-bypass",
        ];

        ipt.append("mangle", DPIBREAK_CHAIN, &synack_rule).map_err(iptables_err)?;
        crate::info!("{}: add SYN/ACK learning rule on mangle/{}", ipt.cmd, DPIBREAK_CHAIN);

        ipt.insert("mangle", "INPUT", &["-j", DPIBREAK_CHAIN], 1).map_err(iptables_err)?;
        crate::info!("{}: add jump to {} chain on INPUT", ipt.cmd, DPIBREAK_CHAIN);
    }

    ipt.append("mangle", DPIBREAK_CHAIN, &rule).map_err(iptables_err)?;
    crate::info!("{}: new chain {} on table mangle", ipt.cmd, DPIBREAK_CHAIN);

    ipt.insert("mangle", "POSTROUTING", &["-j", DPIBREAK_CHAIN], 1).map_err(iptables_err)?;
    crate::info!("{}: add jump to {} chain on POSTROUTING", ipt.cmd, DPIBREAK_CHAIN);

    Ok(())
}

pub fn cleanup_iptables_rules(ipt: &IPTables) -> Result<()> {
    if ipt.delete("mangle", "POSTROUTING", &["-j", DPIBREAK_CHAIN]).is_ok() {
        crate::info!("{}: delete jump to {} from mangle/POSTROUTING", ipt.cmd, DPIBREAK_CHAIN);
    }

    if opt::fake_autottl() && ipt.delete("mangle", "INPUT", &["-j", DPIBREAK_CHAIN]).is_ok() {
        crate::info!("{}: delete jump to {} from mangle/INPUT", ipt.cmd, DPIBREAK_CHAIN);
    }

    if ipt.flush_chain("mangle", DPIBREAK_CHAIN).is_ok() {
        crate::info!("{}: flush chain {}", ipt.cmd, DPIBREAK_CHAIN);
    }

    if ipt.delete_chain("mangle", DPIBREAK_CHAIN).is_ok() {
        crate::info!("{}: delete chain {}", ipt.cmd, DPIBREAK_CHAIN);
    }

    Ok(())
}

pub fn cleanup_xt_u32() -> Result<()> {
    if IS_XT_U32_LOADED_BY_US.load(Ordering::Relaxed) {
        exec_process(&["modprobe", "-q", "-r", "xt_u32"], None)?;
        crate::info!("cleanup: unload xt_u32");
    }

    Ok(())
}
