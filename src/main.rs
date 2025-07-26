use std::error::Error;
use std::sync::{
    atomic::{AtomicBool, Ordering},
};
use anyhow::Result;

#[cfg(target_os = "linux")]
mod platform {
    use iptables::IPTables;
    use once_cell::sync::Lazy;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    };
    use std::process::Command;
    use std::error::Error;
    use anyhow::Result;

    pub static IS_U32_SUPPORTED: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));
    pub static IS_XT_U32_LOADED_BY_US: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

    pub fn is_xt_u32_loaded() -> bool {
        std::fs::read_to_string("/proc/modules")
            .map(|s| s.lines().any(|l| l.starts_with("xt_u32 ")))
            .unwrap_or(false)
    }

    pub fn ensure_xt_u32() -> Result<()> {

        let before = is_xt_u32_loaded();
        Command::new("modprobe").args(&["-q", "xt_u32"]).status()?;
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

    pub fn install_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
        let rule = if is_u32_supported(ipt) {
            concat! (
                "-p tcp --dport 443 -j NFQUEUE --queue-num 0 --queue-bypass ",
                "-m u32 --u32 ",
                "\'0>>22&0x3C @ 12>>26&0x3C @ 0>>24&0xFF=0x16 && ",
                "0>>22&0x3C @ 12>>26&0x3C @ 2>>24&0xFF=0x01\'", // clienthello
            )
        } else {
            "-p tcp --dport 443 -j NFQUEUE --queue-num 0 --queue-bypass"
        };

        ipt.new_chain("mangle", "DPIBREAK")?;
        ipt.insert("mangle", "POSTROUTING", "-j DPIBREAK", 1)?;
        ipt.append("mangle", "DPIBREAK", rule)?;

        Ok(())
    }

    pub fn cleanup_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
        _ = ipt.delete("mangle", "POSTROUTING", "-j DPIBREAK");
        _ = ipt.flush_chain("mangle", "DPIBREAK");
        _ = ipt.delete_chain("mangle", "DPIBREAK");

        Ok(())
    }

    pub fn cleanup() -> Result<(), Box<dyn Error>> {
        let ipt = iptables::new(false)?;
        let ip6 = iptables::new(true)?;

        cleanup_rules(&ip6)?;
        cleanup_rules(&ipt)?;

        if IS_XT_U32_LOADED_BY_US.load(Ordering::Relaxed) {
            _ = Command::new("modprobe").args(&["-q", "-r", "xt_u32"]).status();
        }

        Ok(())
    }

    pub fn bootstrap() -> Result<(), Box<dyn Error>> {
        let ipt = iptables::new(false)?;
        let ip6 = iptables::new(true)?;

        cleanup().ok();
        install_rules(&ipt)?;
        install_rules(&ip6)?;
        Ok(())
    }

    use socket2::{Domain, Protocol, Socket, Type};

    static RAW4: Lazy<Mutex<Socket>> = Lazy::new(|| {
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))
            .expect("create raw4");
        sock.set_header_included_v4(true)
            .expect("IP_HDRINCL");
        Mutex::new(sock)
    });

    static RAW6: Lazy<Mutex<Socket>> = Lazy::new(|| {
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
            .expect("create raw6");
        sock.set_header_included_v6(true)
            .expect("IP_HDRINCL");
        Mutex::new(sock)
    });

    pub fn send_to_raw(pkt: &[u8]) {
        use std::net::*;

        match pkt[0] >> 4 {
            4 => {                                   // IPv4
                if pkt.len() < 20 {
                    return;
                }
                let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
                let addr = SocketAddr::from((dst, 0u16));

                if let Ok(sock) = RAW4.lock() {
                    let _ = sock.send_to(pkt, &addr.into());
                }
            }

            6 => {                                   // IPv6
                if pkt.len() < 40 {
                    return;
                }
                if let Ok(bytes) = <[u8; 16]>::try_from(&pkt[24..40]) {
                    let dst = Ipv6Addr::from(bytes);
                    let addr = SocketAddr::from((dst, 0u16));

                    if let Ok(sock) = RAW6.lock() {
                        let _ = sock.send_to(pkt, &addr.into());
                    }
                }
            }

            _ => {}
        }
    }
}

use platform::*;

fn bytes_to_usize(bytes: &[u8], size: usize) -> Option<usize> {
    Some(match size {
        1 => bytes[0] as usize,
        2 => u16::from_be_bytes(bytes.try_into().ok()?) as usize,
        3 => {
            ((bytes[0] as usize) << 16)
                | ((bytes[1] as usize) << 8)
                | (bytes[2] as usize)
        }
        4 => u32::from_be_bytes(bytes.try_into().ok()?) as usize,
        8 => u64::from_be_bytes(bytes.try_into().ok()?) as usize,
        _ => return None,
    })
}

struct TLSMsg<'a> {
    ptr: usize,
    payload: &'a [u8]
}

impl<'a> TLSMsg<'a> {
    fn new(payload: &'a [u8]) -> Self {
        Self { ptr: 0, payload }
    }

    fn pass(&mut self, size: usize) {
        self.ptr += size;
    }

    fn get_bytes(&mut self, size: usize) -> Option<&'a [u8]> {
        if size == 0 || self.ptr + size > self.payload.len() {
            return None;
        }

        let end = self.ptr + size;
        let ret = &self.payload[self.ptr..end];
        self.ptr = end;
        Some(ret)
    }

    fn get_uint(&mut self, size: usize) -> Option<usize> {
        bytes_to_usize(self.get_bytes(size)?, size)
    }

    fn get_vector(&mut self, size: usize) -> Option<&'a [u8]> {
        let orig_ptr = self.ptr;
        let len_bytes = self.get_bytes(size)?;
        let length: usize = match bytes_to_usize(len_bytes, size) {
            Some(val) => val,
            None => {
                self.ptr = orig_ptr;
                return None;
            },
        };

        self.get_bytes(length)
    }
}

fn is_client_hello(payload: &[u8]) -> bool {
    if TLSMsg::new({
        let mut record = TLSMsg::new(payload);
        if record.get_uint(1) != Some(22) { // type
            return false;                   // not handshake
        }

        record.pass(2);                 // legacy_record_version
        record.pass(2);                 // length

        if record.ptr >= payload.len() {
            return false;
        }

        &record.payload[record.ptr..] // fragment
    }).get_uint(1) != Some(1) { // msg_type
        return false;                     // not clienthello
    }

    true
}

fn split_packet(pkt: &[u8], start: u32, end: Option<u32>) -> Option<Vec<u8>> {
    use etherparse::*;

    let ip = IpSlice::from_slice(pkt).ok()?;
    let tcp = TcpSlice::from_slice(ip.payload().payload).ok()?;
    let payload = tcp.payload();

    let end = end.unwrap_or(payload.len().try_into().ok()?);

    if start > end || payload.len() < end as usize {
        return None;
    }

    let opts = tcp.options();
    let mut tcp_hdr = tcp.to_header();
    tcp_hdr.sequence_number += start;

    let builder = match ip {
            IpSlice::Ipv4(hdr) =>
                PacketBuilder::ip(IpHeaders::Ipv4(
                    hdr.header().to_header(),
                    hdr.extensions().to_header()
                )),

            IpSlice::Ipv6(hdr) =>
                PacketBuilder::ip(IpHeaders::Ipv6(
                    hdr.header().to_header(),
                    Default::default()
                ))
    }.tcp_header(tcp_hdr).options_raw(opts).ok()?;

    let payload = &payload[start as usize..end as usize];
    let mut p = Vec::<u8>::with_capacity(builder.size(payload.len()));

    builder.write(&mut p, payload).ok()?;

    Some(p)
}

fn handle_packet(msg: &nfq::Message) -> nfq::Verdict {
    use nfq::Verdict;
    use std::{thread, time::Duration};

    let payload = msg.get_payload();

    let decision = (|| -> Option<Verdict> {
        let should_split = IS_U32_SUPPORTED.load(Ordering::Relaxed) ||
        {
            use etherparse::*;

            let ip = IpSlice::from_slice(payload).ok()?;
            let tcp = TcpSlice::from_slice(ip.payload().payload).ok()?;
            is_client_hello(tcp.payload())
        };

        if !should_split {
            return None;
        }

        // TODO: if clienthello packet has been (unlikely) fragmented,
        // we should find the second part and drop, reassemble it here.

        let first = split_packet(payload, 0, Some(1))?;
        let second = split_packet(payload, 1, None)?;

        send_to_raw(&first);
        thread::sleep(Duration::from_micros(100));
        send_to_raw(&second);

        Some(Verdict::Drop)
    })();

    decision.unwrap_or(Verdict::Accept)
}

fn main() -> Result<(), Box<dyn Error>> {
    use std::os::fd::{AsRawFd, AsFd};
    use std::sync::Arc;
    use nix::{
        fcntl::{fcntl, FcntlArg, OFlag},
        poll::{poll, PollFd, PollFlags},
        errno::Errno
    };

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); })?;
    }
    bootstrap()?;

    #[cfg(target_os = "linux")]
    {
        use nfq::Queue;

        let mut q = Queue::open()?;
        q.bind(0)?;

        {                           // to check inturrupts
            let raw_fd = q.as_raw_fd();
            let flags = fcntl(raw_fd, FcntlArg::F_GETFL)?;
            let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
            fcntl(raw_fd, FcntlArg::F_SETFL(new_flags))?;
        }

        while running.load(Ordering::Relaxed) {
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
                msg.set_verdict(handle_packet(&msg));
                q.verdict(msg)?;
            }
        }
        q.unbind(0)?;
    }

    #[cfg(windows)]
    {
        unimplemented!("main");
    }

    cleanup()?;

    Ok(())
}
