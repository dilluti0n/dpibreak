// SPDX-FileCopyrightText: 2025-2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{os::fd::AsRawFd, sync::{
    LazyLock, atomic::{AtomicBool, Ordering}
}};
use std::fs::OpenOptions;
use std::process::{Command, Stdio};
use std::io::Write;

use anyhow::{Result, Context, anyhow};
use socket2::{Domain, Protocol, Socket, Type};

use crate::{log::LogLevel, log_println, splash, MESSAGE_AT_RUN, opt};

mod iptables;
mod nftables;
mod rxring;

use iptables::*;
use nftables::*;
use libc::sock_filter;
use crate::pkt;

pub static IS_U32_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static IS_NFT_NOT_SUPPORTED: AtomicBool = AtomicBool::new(false);

const INJECT_MARK: u32 = 0xD001;
const PID_FILE: &str = "/run/dpibreak.pid"; // TODO: unmagic this
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

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

fn lock_pid_file() -> Result<()> {
    use nix::fcntl::{flock, FlockArg};

    let pid_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(PID_FILE)?;

    if flock(pid_file.as_raw_fd(), FlockArg::LockExclusiveNonblock).is_err() {
        let existing_pid = std::fs::read_to_string(PID_FILE)?;
        anyhow::bail!("Fail to lock {PID_FILE}: {PKG_NAME} already running with PID {}", existing_pid.trim());
    }

    pid_file.set_len(0)?;
    writeln!(&pid_file, "{}", std::process::id())?;
    pid_file.sync_all()?;

    std::mem::forget(pid_file); // Tell std to do not close the file

    Ok(())
}

fn exit_if_not_root() {
    if !nix::unistd::geteuid().is_root() {
        log_println!(LogLevel::Error, "{PKG_NAME} must be run as root. Try sudo.");
        std::process::exit(3);
    }
}

/// Bootstraps that don't require cleanup after load global opts
pub fn bootstrap() -> Result<()> {
    exit_if_not_root();
    if !opt::daemon() {
        lock_pid_file()?;
    } else {
        daemonize();
    }

    Ok(())
}

static RAW4: LazyLock<Socket> = LazyLock::new(|| {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
        .expect("create raw4");

    sock.set_header_included_v4(true).expect("IP_HDRINCL");
    sock.set_mark(INJECT_MARK).expect("SO_MARK");

    sock
});

static RAW6: LazyLock<Socket> = LazyLock::new(|| {
    let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
        .expect("create raw6");

    sock.set_header_included_v6(true).expect("IP_HDRINCL");
    sock.set_mark(INJECT_MARK).expect("SO_MARK");

    sock
});

pub fn send_to_raw(pkt: &[u8], dst: std::net::IpAddr) -> Result<()> {
    use std::net::*;

    match dst {
        IpAddr::V4(dst) => {
            let addr = SocketAddr::from((dst, 0u16));

            RAW4.send_to(pkt, &addr.into())?;
        }
        IpAddr::V6(dst) => {
            let addr = SocketAddr::from((dst, 0u16));

            RAW6.send_to(pkt, &addr.into())?;
        }
    }

    Ok(())
}

fn open_nfqueue() -> Result<nfq::Queue> {
    use std::os::fd::AsRawFd;
    use nix::fcntl::{fcntl, FcntlArg, OFlag};

    let mut q = nfq::Queue::open()?;
    q.bind(crate::opt::queue_num())?;
    log_println!(LogLevel::Info, "nfqueue: bound to queue number {}", crate::opt::queue_num());

    // to check inturrupts
    let raw_fd = q.as_raw_fd();
    let flags = fcntl(raw_fd, FcntlArg::F_GETFL)?;
    let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
    fcntl(raw_fd, FcntlArg::F_SETFL(new_flags))?;

    Ok(q)
}

fn open_rxring() -> Result<rxring::RxRing> {
    /// cBPF filter for TCP and sport=443 and SYN,ACK packets
    ///
    /// Produced by
    /// tcpdump -dd '(ip and tcp src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack))'
    /// FIXME: add IPv6; seems like tcpdump cannot produce rules for it correctly.
    const SYNACK_443_CBPF: &[sock_filter] = &[
        sock_filter { code: 0x28, jt: 0, jf: 0,  k: 0x0000000c },
        sock_filter { code: 0x15, jt: 0, jf: 11, k: 0x00000800 },
        sock_filter { code: 0x30, jt: 0, jf: 0,  k: 0x00000017 },
        sock_filter { code: 0x15, jt: 0, jf: 9,  k: 0x00000006 },
        sock_filter { code: 0x28, jt: 0, jf: 0,  k: 0x00000014 },
        sock_filter { code: 0x45, jt: 7, jf: 0,  k: 0x00001fff },
        sock_filter { code: 0xb1, jt: 0, jf: 0,  k: 0x0000000e },
        sock_filter { code: 0x48, jt: 0, jf: 0,  k: 0x0000000e },
        sock_filter { code: 0x15, jt: 0, jf: 4,  k: 0x000001bb },
        sock_filter { code: 0x50, jt: 0, jf: 0,  k: 0x0000001b },
        sock_filter { code: 0x54, jt: 0, jf: 0,  k: 0x00000012 },
        sock_filter { code: 0x15, jt: 0, jf: 1,  k: 0x00000012 },
        sock_filter { code: 0x6,  jt: 0, jf: 0,  k: 0x00040000 },
        sock_filter { code: 0x6,  jt: 0, jf: 0,  k: 0x00000000 },
    ];

    let rx = rxring::RxRing::new(SYNACK_443_CBPF)?;

    log_println!(LogLevel::Info, "rxring: initialized");
    log_println!(LogLevel::Debug,
        "rxring: tcp src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) == (tcp-syn|tcp-ack)");

    Ok(rx)
}

enum PollResult {
    Ready { q: bool, rx: bool },
    Interrupted,
}

fn poll_once(q: &nfq::Queue, rx: Option<&rxring::RxRing>) -> Result<PollResult> {
    use std::io::Error;
    use std::os::fd::AsRawFd;

    let mut fds = [libc::pollfd { fd: -1, events: libc::POLLIN, revents: 0 }; 2];

    fds[0].fd = q.as_raw_fd();
    if let Some(rx) = rx { fds[1].fd = rx.as_raw_fd() };

    match unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, -1) } {
        -1 => {
            let e = Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                return Ok(PollResult::Interrupted);
            }
            Err(e.into())
        },
        _ => Ok(PollResult::Ready {
            q: fds[0].revents & libc::POLLIN != 0,

            // false if rx is None (fd=-1, revents set to 0 by poll)
            rx: fds[1].revents & libc::POLLIN != 0
        })
    }
}

pub fn run() -> Result<()> {
    use crate::handle_packet;
    use super::PACKET_SIZE_CAP;

    _ = cleanup(); // In case the previous execution was not cleaned properly
    install_rules()?;

    let mut q = open_nfqueue()?;
    let mut rx = if opt::fake_autottl() { Some(open_rxring()?) } else { None };
    let mut buf = Vec::<u8>::with_capacity(PACKET_SIZE_CAP);

    splash!("{MESSAGE_AT_RUN}");

    while crate::RUNNING.load(Ordering::SeqCst) {
        let (q_ready, rx_ready) = match poll_once(&q, rx.as_ref())? {
            PollResult::Ready { q, rx } => (q, rx),
            PollResult::Interrupted => break,
        };

        if q_ready {
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

        if rx_ready && let Some(ref mut rx) = rx {
            while let Some(pkt) = rx.current_packet() {
                pkt::put_hop(pkt);
                rx.advance();
            }
        }
    }

    q.unbind(crate::opt::queue_num())?;

    Ok(())
}

const DAEMON_PREFIX: &str = "/var/log";

// TODO: detach daemonize crate and lock pid file with lock_pid_file
fn daemonize_1() -> Result<()> {
    use std::fs;
    use daemonize::Daemonize;

    fs::create_dir_all(DAEMON_PREFIX).context("daemonize")?;
    let log_file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(format!("{DAEMON_PREFIX}/{PKG_NAME}.log"))?;

    let daemonize = Daemonize::new()
        .pid_file(PID_FILE)
        .chown_pid_file(true)
        .working_directory(DAEMON_PREFIX)
        .stdout(log_file.try_clone()?);

    daemonize.start()?;
    log_file.set_len(0)?;

    log_println!(LogLevel::Info, "start as daemon: pid {}", std::process::id());

    Ok(())
}

fn daemonize() {
    const EXIT_DAEMON_FAIL: i32 = 2;

    match daemonize_1() {
        Ok(_) => {},
        Err(e) => {
            log_println!(LogLevel::Error, "fail to start as daemon: {e}");
            std::process::exit(EXIT_DAEMON_FAIL);
        }
    }
}
