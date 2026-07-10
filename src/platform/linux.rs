// SPDX-FileCopyrightText: 2025-2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    os::fd::{AsRawFd, OwnedFd},
    sync::{LazyLock, atomic}
};
use std::fs::OpenOptions;
use std::io::Write;

use anyhow::{Result, Context};
use socket2::{Domain, Protocol, Socket, Type};

mod rules;
mod rxring;
#[macro_use] mod libc_s;

use crate::pkt;
use crate::opt;

const INJECT_MARK: u32 = 0xD001;
const PID_FILE: &str = "/run/dpibreak.pid"; // TODO: unmagic this
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

fn lock_pid_file() -> Result<()> {
    use libc_s::flock;

    let pid_file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(PID_FILE)?;

    if flock(pid_file.as_raw_fd(), libc::LOCK_NB | libc::LOCK_EX).is_err() {
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
    if libc_s::geteuid() != 0 {
        crate::error!("{PKG_NAME} must be run as root. Try sudo.");
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

    if let Err(e) = sock.set_header_included_v6(true) {
        crate::warn!("Failed to set IPV6_HDRINCL. Maybe old kernel version? IPv6 header manipulation disabled.");
        crate::warn!("Cause: {e}");
    }
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
    use libc_s::{fcntl, FcntlArg};

    let mut q = nfq::Queue::open()?;
    q.bind(opt::queue_num())?;
    crate::info!("nfqueue: bound to queue number {}", opt::queue_num());

    // to check inturrupts
    let fd = q.as_raw_fd();
    let fl = fcntl(fd, FcntlArg::F_GETFL)?;
    fcntl(fd, FcntlArg::F_SETFL(fl | libc::O_NONBLOCK))?;

    Ok(q)
}

/// Open AF_PACKET RX ring for syn/ack packets
fn open_rxring() -> Result<rxring::RxRing> {
    use libc::sock_filter;

    /// cBPF filter for TCP and sport=443 and SYN,ACK packets
    ///
    /// Produced by
    /// tcpdump -dd '(ip and tcp src port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack)
    /// == (tcp-syn|tcp-ack)) or (ip6 and tcp src port 443 and ip6[53] & 0x12 == 0x12)'
    const SYNACK_443_CBPF: &[sock_filter] = &[
        sock_filter { code: 0x28, jt: 0,  jf: 0,  k: 0x0000000c },
        sock_filter { code: 0x15, jt: 0,  jf: 10, k: 0x00000800 },
        sock_filter { code: 0x30, jt: 0,  jf: 0,  k: 0x00000017 },
        sock_filter { code: 0x15, jt: 0,  jf: 17, k: 0x00000006 },
        sock_filter { code: 0x28, jt: 0,  jf: 0,  k: 0x00000014 },
        sock_filter { code: 0x45, jt: 15, jf: 0,  k: 0x00001fff },
        sock_filter { code: 0xb1, jt: 0,  jf: 0,  k: 0x0000000e },
        sock_filter { code: 0x48, jt: 0,  jf: 0,  k: 0x0000000e },
        sock_filter { code: 0x15, jt: 0,  jf: 12, k: 0x000001bb },
        sock_filter { code: 0x50, jt: 0,  jf: 0,  k: 0x0000001b },
        sock_filter { code: 0x54, jt: 0,  jf: 0,  k: 0x00000012 },
        sock_filter { code: 0x15, jt: 8,  jf: 9,  k: 0x00000012 },
        sock_filter { code: 0x15, jt: 0,  jf: 8,  k: 0x000086dd },
        sock_filter { code: 0x30, jt: 0,  jf: 0,  k: 0x00000014 },
        sock_filter { code: 0x15, jt: 0,  jf: 6,  k: 0x00000006 },
        sock_filter { code: 0x28, jt: 0,  jf: 0,  k: 0x00000036 },
        sock_filter { code: 0x15, jt: 0,  jf: 4,  k: 0x000001bb },
        sock_filter { code: 0x30, jt: 0,  jf: 0,  k: 0x00000043 },
        sock_filter { code: 0x54, jt: 0,  jf: 0,  k: 0x00000012 },
        sock_filter { code: 0x15, jt: 0,  jf: 1,  k: 0x00000012 },
        sock_filter { code: 0x6,  jt: 0,  jf: 0,  k: 0x00040000 },
        sock_filter { code: 0x6,  jt: 0,  jf: 0,  k: 0x00000000 },
    ];
    const BLOCK_SIZE: u32 = 4096 * 4; // 16 KB
    const BLOCK_NR:   u32 = 4;

    /// tpacket_hdr (~66) + eth(14) + ipv6(40) + tcp with options(60) = ~180
    const FRAME_SIZE: u32 = 256;

    let rx = rxring::RxRing::new(SYNACK_443_CBPF, BLOCK_SIZE, BLOCK_NR, FRAME_SIZE)?;
    crate::info!("rxring: initialized");

    Ok(rx)
}

/// open signalfd for SIGINT and SIGTERM
fn open_signalfd() -> Result<OwnedFd> {
    use libc::*;
    use std::os::fd::FromRawFd;

    // SAFETY: sigaddset fails only when signum is invalid
    unsafe {
        let mut mask: sigset_t = std::mem::zeroed();
        sigemptyset(&mut mask);
        sigaddset(&mut mask, SIGTERM);
        sigaddset(&mut mask, SIGINT);

        syscall!(pthread_sigmask(SIG_BLOCK, &mask, core::ptr::null_mut()))?;
        let raw = syscall!(signalfd(-1, &mask, 0))?;

        Ok(OwnedFd::from_raw_fd(raw))
    }
}

pub fn run() -> Result<()> {
    use crate::handle_packet;
    use super::PACKET_SIZE_CAP;

    // In case the previous execution was not cleaned properly
    _ = rules::nft_cleanup();
    _ = rules::ipt6_cleanup(false);
    _ = rules::ipt6_cleanup(true);

    let _rule = rules::install()?;

    let sfd = open_signalfd()?;
    let mut q = open_nfqueue()?;
    let mut rx = if opt::fake_autottl() { Some(open_rxring()?) } else { None };
    let mut buf = Vec::<u8>::with_capacity(PACKET_SIZE_CAP);

    let mut fds = [
        libc::pollfd { fd: sfd.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: q.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd {
            fd: rx.as_ref().map_or(-1, |r| r.as_raw_fd()),
            events: libc::POLLIN,
            revents: 0
        },
    ];

    crate::splash!("{}", super::MESSAGE_AT_RUN);

    loop {
        libc_s::poll(&mut fds, -1)?;

        let is_intr: bool = fds[0].revents & libc::POLLIN != 0;
        let q_ready: bool = fds[1].revents & libc::POLLIN != 0;
        let rx_ready: bool = fds[2].revents & libc::POLLIN != 0;

        if is_intr {
            break;
        }

        if rx_ready && let Some(ref mut rx) = rx {
            while let Some(pkt) = rx.current_packet() {
                match pkt.net() {
                    Ok(p) => pkt::put_hop(p),
                    Err(e) => crate::warn!("Failed to recv from rxring: {e}")
                };
            }
        }

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
    }

    q.unbind(opt::queue_num())?;

    Ok(())
}

// TODO: detach daemonize crate and lock pid file with lock_pid_file
fn daemonize_1() -> Result<()> {
    use std::fs;
    use daemonize::Daemonize;

    const DAEMON_PREFIX: &str = "/var/log";

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

    crate::info!("start as daemon: pid {}", std::process::id());

    Ok(())
}

fn daemonize() {
    const EXIT_DAEMON_FAIL: i32 = 2;

    match daemonize_1() {
        Ok(_) => {},
        Err(e) => {
            crate::error!("fail to start as daemon: {e}");
            std::process::exit(EXIT_DAEMON_FAIL);
        }
    }
}

pub fn local_time() -> (i32, u8, u8, u8, u8, u8) {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if t == -1 || libc::localtime_r(&t, &mut tm).is_null() {
            return (0, 0, 0, 0, 0, 0);
        };
        (tm.tm_year + 1900, (tm.tm_mon + 1) as u8, tm.tm_mday as u8,
         tm.tm_hour as u8, tm.tm_min as u8, tm.tm_sec as u8)
    }
}

pub fn is_kernel_filtered_clienthello() -> bool {
    rules::IS_U32_SUPPORTED.load(atomic::Ordering::Relaxed)
}
