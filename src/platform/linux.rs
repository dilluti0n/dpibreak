// Copyright 2025 Dillution <hskimse1@gmail.com>.
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

use iptables::IPTables;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
    OnceLock,
    LazyLock
};
use std::process::{Command, Stdio};
use std::io::Write;
use anyhow::{Result, Error, Context, anyhow};
use crate::{log::LogLevel, log_println, splash, MESSAGE_AT_RUN};

pub static IS_U32_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static IS_XT_U32_LOADED_BY_US: AtomicBool = AtomicBool::new(false);
static IS_NFT_NOT_SUPPORTED: AtomicBool = AtomicBool::new(false);

const DPIBREAK_CHAIN: &str = "DPIBREAK";

pub static QUEUE_NUM: OnceLock<u16> = OnceLock::new();
pub static NFT_COMMAND: OnceLock<String> = OnceLock::new();

fn queue_num() -> u16 {
    *QUEUE_NUM.get().expect("QUEUE_NUM not initialized")
}

fn nft_command() -> &'static str {
    NFT_COMMAND.get().expect("NFT_COMMAND not initialized").as_str()
}

/// Apply json format nft rules with `nft_command() -j -f -`.
fn apply_nft_rules(rule: &str) -> Result<()> {
    let mut child = Command::new(nft_command())
        .args(&["-j", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn nft process")?;

    {
        let mut stdin = child.stdin.take().context("failed to take stdin")?;
        stdin.write_all(rule.as_bytes()).context("failed to write rule to nft")?;
    }                           // Close the pipe

    let output = child.wait_with_output().context("failed to wait for nft")?;

    match output.status.code() {
        Some(0) => Ok(()),
        Some(code) =>
            Err(anyhow!("{} exited with status {}: {}", nft_command(), code,
                        String::from_utf8_lossy(&output.stderr))),
        None =>
            Err(anyhow!("{} terminated by signal", nft_command()))
    }
}

fn is_xt_u32_loaded() -> bool {
    std::fs::read_to_string("/proc/modules")
        .map(|s| s.lines().any(|l| l.starts_with("xt_u32 ")))
        .unwrap_or(false)
}

fn ensure_xt_u32() -> Result<()> {

    let before = is_xt_u32_loaded();
    Command::new("modprobe").args(&["-q", "xt_u32"]).status()?;
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
        log_println!(LogLevel::Warning, "xt_u32 not supported");
        return false;
    }

    log_println!(LogLevel::Info, "xt_u32 loaded");

    let rule = "-m u32 --u32 \'0x0=0x0\' -j RETURN";
    match ipt.insert("raw", "PREROUTING", rule, 1) {
        Ok(_) => {
            _ = ipt.delete("raw", "PREROUTING", rule);
            IS_U32_SUPPORTED.store(true, Ordering::Relaxed);
            true
        }

        Err(_) => false
    }
}

fn iptables_err(e: impl ToString) -> Error {
    Error::msg(format!("iptables: {}", e.to_string()))
}

fn install_iptables_rules(ipt: &IPTables) -> Result<()> {
    let base = format!("-p tcp --dport 443 -j NFQUEUE --queue-num {} --queue-bypass", queue_num());

    let rule = if is_u32_supported(ipt) {
        const U32: &str = "-m u32 --u32 \
                           \'0>>22&0x3C @ 12>>26&0x3C @ 0>>24&0xFF=0x16 && \
                           0>>22&0x3C @ 12>>26&0x3C @ 2>>24&0xFF=0x01\'";

        format!("{} {}", base, U32)
    } else {
        base
    };

    ipt.new_chain("mangle", DPIBREAK_CHAIN).map_err(iptables_err)?;
    ipt.append("mangle", DPIBREAK_CHAIN, &rule).map_err(iptables_err)?;
    log_println!(LogLevel::Info, "{}: new chain {} on table mangle", ipt.cmd, DPIBREAK_CHAIN);

    ipt.insert("mangle", "POSTROUTING",
               &format!("-j {}", DPIBREAK_CHAIN), 1).map_err(iptables_err)?;
    log_println!(LogLevel::Info, "{}: add jump to {} chain on POSTROUTING", ipt.cmd, DPIBREAK_CHAIN);

    Ok(())
}

fn cleanup_iptables_rules(ipt: &IPTables) -> Result<()> {
    if ipt.delete("mangle", "POSTROUTING", &format!("-j {}", DPIBREAK_CHAIN)).is_ok() {
        log_println!(LogLevel::Info, "{}: deleted jump from POSTROUTING", ipt.cmd);
    }

    if ipt.flush_chain("mangle", DPIBREAK_CHAIN).is_ok() {
        log_println!(LogLevel::Info, "{}: flush chain {}", ipt.cmd, DPIBREAK_CHAIN);
    }

    if ipt.delete_chain("mangle", DPIBREAK_CHAIN).is_ok() {
        log_println!(LogLevel::Info, "{}: delete chain {}", ipt.cmd, DPIBREAK_CHAIN);
    }

    Ok(())
}

const DPIBREAK_TABLE: &str = "dpibreak";

fn install_nft_rules() -> Result<()> {
    let rule = serde_json::json!(
        {
            "nftables": [
                {"add": {"table": {"family": "inet", "name": DPIBREAK_TABLE}}},
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "name": "OUTPUT",
                            "type": "filter",
                            "hook": "output",
                            "prio": 0,
                            "policy": "accept",
                        }
                    }
                },
                {
                    "add": {
                        "chain": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "name": DPIBREAK_CHAIN
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "chain": "OUTPUT",
                            "expr": [{ "jump": { "target": DPIBREAK_CHAIN }}]
                        }
                    }
                },
                {
                    "add": {
                        "rule": {
                            "family": "inet",
                            "table": DPIBREAK_TABLE,
                            "chain": DPIBREAK_CHAIN,
                            "expr": [
                                {
                                    "match": {
                                        "left": {"payload": { "protocol": "tcp", "field": "dport" }},
                                        "op": "==",
                                        "right": 443
                                    }
                                },
                                // TLS ContentType == 0x16 (Handshake)
                                {
                                    "match": {
                                        "left": { "payload": { "base": "ih", "offset": 0, "len": 8 } },
                                        "op": "==",
                                        "right": 0x16
                                    }
                                },
                                // HandshakeType == 0x01 (ClientHello)
                                {
                                    "match": {
                                        // Note: offset and len are both "bit" unit not byte
                                        "left": { "payload": { "base": "ih", "offset": 40, "len": 8 } },
                                        "op": "==",
                                        "right": 0x01
                                    }
                                },
                                {
                                    "queue": {
                                        "num": queue_num(),
                                        "flags": [ "bypass" ]
                                    }
                                }
                            ]
                        }
                    }
                }
            ]
        }
    );

    apply_nft_rules(&serde_json::to_string(&rule)?)?;

    // clienthello filtered by nft
    IS_U32_SUPPORTED.store(true, Ordering::Relaxed);
    log_println!(LogLevel::Info, "nftables: create table inet {DPIBREAK_TABLE}");

    Ok(())
}

fn install_rules() -> Result<()> {
    match install_nft_rules() {
        Ok(_) => {},
        Err(e) => {
            IS_NFT_NOT_SUPPORTED.store(true, Ordering::Relaxed);
            log_println!(LogLevel::Warning, "nftables: {}", e.to_string());
            log_println!(LogLevel::Warning, "fallback to iptables");

            let ipt = iptables::new(false).map_err(iptables_err)?;
            let ip6 = iptables::new(true).map_err(iptables_err)?;

            install_iptables_rules(&ipt)?;
            // FIXME: using xt_u32 on ipv6 is not supported; (even if it does,
            // the rule should be different)
            install_iptables_rules(&ip6)?;
        }
    }

    Ok(())
}

fn cleanup_rules() -> Result<()> {
    if IS_NFT_NOT_SUPPORTED.load(Ordering::Relaxed) {
        let ipt = iptables::new(false).map_err(iptables_err)?;
        let ip6 = iptables::new(true).map_err(iptables_err)?;

        cleanup_iptables_rules(&ipt)?;
        cleanup_iptables_rules(&ip6)?;
    } else {
        // nft delete table inet dpibreak
        let rule = serde_json::json!({
            "nftables": [
                {"delete": {"table": {"family": "inet", "name": DPIBREAK_TABLE}}}
            ]
        });
        match apply_nft_rules(&serde_json::to_string(&rule)?) {
            Ok(_) =>
                log_println!(LogLevel::Info, "cleanup: nftables: delete table inet {}", DPIBREAK_TABLE),
            Err(e) =>
                log_println!(LogLevel::Warning, "cleanup: nftables: {}", e.to_string().trim()),
        }
    }

    Ok(())
}

pub fn cleanup() -> Result<()> {
    cleanup_rules()?;

    if IS_XT_U32_LOADED_BY_US.load(Ordering::Relaxed) {
        _ = Command::new("modprobe").args(&["-q", "-r", "xt_u32"]).status();
        log_println!(LogLevel::Info, "cleanup: unload xt_u32");
    }

    Ok(())
}

pub fn bootstrap() -> Result<()> {
    _ = cleanup();  // In case the previous execution was not cleaned properly
    install_rules()
}

use socket2::{Domain, Protocol, Socket, Type};

static RAW4: LazyLock<Mutex<Socket>> = LazyLock::new(|| {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .expect("create raw4");
    sock.set_header_included_v4(true)
        .expect("IP_HDRINCL");
    Mutex::new(sock)
});

static RAW6: LazyLock<Mutex<Socket>> = LazyLock::new(|| {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
        .expect("create raw6");
    sock.set_header_included_v6(true)
        .expect("IP_HDRINCL");
    Mutex::new(sock)
});

pub fn send_to_raw(pkt: &[u8]) -> Result<()> {
    use std::net::*;

    match pkt[0] >> 4 {
        4 => {                                   // IPv4
            if pkt.len() < 20 {
                return Err(anyhow!("invalid ipv4 packet"));
            }
            let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
            let addr = SocketAddr::from((dst, 0u16));

            if let Ok(sock) = RAW4.lock() {
                sock.send_to(pkt, &addr.into())?;
            }
        }

        6 => {                                   // IPv6
            if pkt.len() < 40 {
                return Err(anyhow!("invalid ipv6 packet"));
            }
            if let Ok(bytes) = <[u8; 16]>::try_from(&pkt[24..40]) {
                let dst = Ipv6Addr::from(bytes);
                let addr = SocketAddr::from((dst, 0u16));

                if let Ok(sock) = RAW6.lock() {
                    sock.send_to(pkt, &addr.into())?;
                }
            }
        }

        _ => {}
    }

    Ok(())
}

pub fn run() -> Result<()> {
    use std::os::fd::{AsRawFd, AsFd};
    use nix::{
        fcntl::{fcntl, FcntlArg, OFlag},
        poll::{poll, PollFd, PollFlags},
        errno::Errno
    };
    use nfq::Queue;
    use crate::handle_packet;
    use super::PACKET_SIZE_CAP;

    let mut q = Queue::open()?;
    q.bind(queue_num())?;
    log_println!(LogLevel::Info, "nfqueue: bound to queue number {}", queue_num());

    {                           // to check inturrupts
        let raw_fd = q.as_raw_fd();
        let flags = fcntl(raw_fd, FcntlArg::F_GETFL)?;
        let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(raw_fd, FcntlArg::F_SETFL(new_flags))?;
    }

    splash!("{MESSAGE_AT_RUN}");

    let mut buf = Vec::<u8>::with_capacity(PACKET_SIZE_CAP);

    while crate::RUNNING.load(Ordering::SeqCst) {
        {
            let fd = q.as_fd();
            let mut fds = [PollFd::new(&fd, PollFlags::POLLIN)];

            match poll(&mut fds, -1) {
                Ok(_) => {},
                // Why should input ^C twice to halt when this is `continue'?
                // Seems like there is some kind of race in first inturrupt...
                // (maybe ctrlc problem)
                Err(e) if e == Errno::EINTR => break,
                Err(e) => return Err(e.into()),
            }
        }                       // restore BorrowdFd to q

        // flush queue
        while let Ok(mut msg) = q.recv() {
            let verdict = handle_packet!(
                &msg.get_payload(),
                &mut buf,
                handled => nfq::Verdict::Drop,
                rejected => nfq::Verdict::Accept,
            );

            msg.set_verdict(verdict);
            q.verdict(msg)?;
        }
    }
    q.unbind(queue_num())?;

    Ok(())
}
