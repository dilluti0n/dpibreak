// SPDX-FileCopyrightText: 2025-2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
    LazyLock
};
use std::process::{Command, Stdio};
use std::io::Write;
use anyhow::{Result, Context, anyhow};

use crate::{log::LogLevel, log_println, splash, MESSAGE_AT_RUN};

mod iptables;
mod nftables;

use iptables::*;
use nftables::*;

pub static IS_U32_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static IS_NFT_NOT_SUPPORTED: AtomicBool = AtomicBool::new(false);

const INJECT_MARK: u32 = 0xD001;

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

fn install_rules() -> Result<()> {
    match install_nft_rules() {
        Ok(_) => {},
        Err(e) => {
            IS_NFT_NOT_SUPPORTED.store(true, Ordering::Relaxed);
            log_println!(LogLevel::Warning, "nftables: {}", e.to_string());
            log_println!(LogLevel::Warning, "fallback to iptables");

            let ipt = IPTables::new(false).map_err(iptables_err)?;
            let ip6 = IPTables::new(true).map_err(iptables_err)?;

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
        let ipt = IPTables::new(false).map_err(iptables_err)?;
        let ip6 = IPTables::new(true).map_err(iptables_err)?;

        cleanup_iptables_rules(&ipt)?;
        cleanup_iptables_rules(&ip6)?;
    } else {
        cleanup_nftables_rules()?;
    }
    Ok(())
}

pub fn cleanup() -> Result<()> {
    cleanup_rules()?;
    cleanup_xt_u32()?;

    Ok(())
}

pub fn bootstrap() -> Result<()> {
    _ = cleanup(); // In case the previous execution was not cleaned properly
    install_rules()
}

use socket2::{Domain, Protocol, Socket, Type};

static RAW4: LazyLock<Mutex<Socket>> = LazyLock::new(|| {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .expect("create raw4");

    sock.set_header_included_v4(true).expect("IP_HDRINCL");
    sock.set_mark(INJECT_MARK).expect("SO_MARK");

    Mutex::new(sock)
});

static RAW6: LazyLock<Mutex<Socket>> = LazyLock::new(|| {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
        .expect("create raw6");

    sock.set_header_included_v6(true).expect("IP_HDRINCL");
    sock.set_mark(INJECT_MARK).expect("SO_MARK");

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
    q.bind(crate::opt::queue_num())?;
    log_println!(LogLevel::Info, "nfqueue: bound to queue number {}",
                 crate::opt::queue_num());

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
    q.unbind(crate::opt::queue_num())?;

    Ok(())
}

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const DAEMON_PREFIX: &str = "/tmp";

fn daemonize() -> Result<()> {
    use std::fs;
    use daemonize::Daemonize;

    let log_file = fs::File::create(format!("{DAEMON_PREFIX}/{PKG_NAME}.log"))?;
    let pid_file = format!("{DAEMON_PREFIX}/{PKG_NAME}.pid");

    let daemonize = Daemonize::new()
        .pid_file(&pid_file)
        .chown_pid_file(true)
        .working_directory(DAEMON_PREFIX)
        .stdout(log_file);

    daemonize.start()?;

    // TODO: detach damonize and opt.rs and use log_println here
    println!("start as daemon: pid {}", std::process::id());

    Ok(())
}

pub fn daemonize_1() {
    const EXIT_DAEMON_FAIL: i32 = 2;

    match daemonize() {
        Ok(_) => {},
        Err(e) => {
            println!("{PKG_NAME}: fail to start as daemon: {e}");
            std::process::exit(EXIT_DAEMON_FAIL);
        }
    }
}
