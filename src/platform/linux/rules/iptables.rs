// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::{Result};

use std::sync::{
    atomic::{AtomicBool, Ordering}
};

use super::{exec_process, IS_U32_SUPPORTED};

static IS_XT_U32_LOADED_BY_US: AtomicBool = AtomicBool::new(false);

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

    pub fn cmd(&self) -> &'static str {
        self.cmd
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

pub fn is_u32_supported(ipt: &IPTables) -> bool {
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

pub fn cleanup_xt_u32() -> Result<()> {
    if IS_XT_U32_LOADED_BY_US.load(Ordering::Relaxed) {
        exec_process(&["modprobe", "-q", "-r", "xt_u32"], None)?;
        crate::info!("cleanup: unload xt_u32");
    }

    Ok(())
}
