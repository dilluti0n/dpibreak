use iptables::IPTables;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
    OnceLock,
    LazyLock
};
use std::process::Command;
use anyhow::{Result, Error, anyhow};

pub static IS_U32_SUPPORTED: AtomicBool = AtomicBool::new(false);
pub static IS_XT_U32_LOADED_BY_US: AtomicBool = AtomicBool::new(false);

pub static QUEUE_NUM: OnceLock<u16> = OnceLock::new();

fn queue_num() -> u16 {
    *QUEUE_NUM.get().expect("QUEUE_NUM not initialized")
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
        return false;
    }

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

fn install_rules(ipt: &IPTables) -> Result<()> {
    let base = format!("-p tcp --dport 443 -j NFQUEUE --queue-num {} --queue-bypass", queue_num());

    let rule = if is_u32_supported(ipt) {
        const U32: &str = "-m u32 --u32 \
                           \'0>>22&0x3C @ 12>>26&0x3C @ 0>>24&0xFF=0x16 && \
                           0>>22&0x3C @ 12>>26&0x3C @ 2>>24&0xFF=0x01\'";

        format!("{} {}", base, U32)
    } else {
        base
    };

    ipt.new_chain("mangle", "DPIBREAK").map_err(iptables_err)?;
    ipt.insert("mangle", "POSTROUTING", "-j DPIBREAK", 1).map_err(iptables_err)?;
    ipt.append("mangle", "DPIBREAK", &rule).map_err(iptables_err)?;
    Ok(())
}

fn cleanup_rules(ipt: &IPTables) -> Result<()> {
    _ = ipt.delete("mangle", "POSTROUTING", "-j DPIBREAK");
    _ = ipt.flush_chain("mangle", "DPIBREAK");
    _ = ipt.delete_chain("mangle", "DPIBREAK");

    Ok(())
}

pub fn cleanup() -> Result<()> {
    let ipt = iptables::new(false).map_err(iptables_err)?;
    let ip6 = iptables::new(true).map_err(iptables_err)?;

    cleanup_rules(&ip6)?;
    cleanup_rules(&ipt)?;

    if IS_XT_U32_LOADED_BY_US.load(Ordering::Relaxed) {
        _ = Command::new("modprobe").args(&["-q", "-r", "xt_u32"]).status();
    }

    Ok(())
}

pub fn bootstrap() -> Result<()> {
    let ipt = iptables::new(false).map_err(iptables_err)?;
    let ip6 = iptables::new(true).map_err(iptables_err)?;

    cleanup().ok();
    install_rules(&ipt)?;
    // FIXME: using xt_u32 on ipv6 is not supported; (even if it does,
    // the rule should be different)
    install_rules(&ip6)?;
    Ok(())
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

    let mut q = Queue::open()?;
    q.bind(queue_num())?;

    {                           // to check inturrupts
        let raw_fd = q.as_raw_fd();
        let flags = fcntl(raw_fd, FcntlArg::F_GETFL)?;
        let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(raw_fd, FcntlArg::F_SETFL(new_flags))?;
    }

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
