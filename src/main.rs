use std::sync::atomic::{AtomicBool, Ordering};
use anyhow::{Result, anyhow};

mod platform;
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

fn split_packet(pkt: &[u8], start: u32, end: Option<u32>) -> Result<Vec<u8>> {
    use etherparse::*;

    let ip = IpSlice::from_slice(pkt)?;
    let tcp = TcpSlice::from_slice(ip.payload().payload)?;
    let payload = tcp.payload();

    let end = end.unwrap_or(payload.len().try_into()?);

    if start > end || payload.len() < end as usize {
        return Err(anyhow!("invaild index"));
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
    }.tcp_header(tcp_hdr).options_raw(opts)?;

    let payload = &payload[start as usize..end as usize];
    let mut p = Vec::<u8>::with_capacity(builder.size(payload.len()));

    builder.write(&mut p, payload)?;

    Ok(p)
}

/// Return Ok(true) if packet is handled
fn handle_packet(pkt: &[u8]) -> Result<bool> {

    #[cfg(target_os = "linux")]
    let is_filtered = IS_U32_SUPPORTED.load(Ordering::Relaxed);

    #[cfg(windows)]
    let is_filtered = false;

    let should_split = is_filtered ||
    {
        use etherparse::*;

        let ip = IpSlice::from_slice(pkt)?;
        let tcp = TcpSlice::from_slice(ip.payload().payload)?;
        is_client_hello(tcp.payload())
    };

    if !should_split {
        return Ok(false);
    }

    // TODO: if clienthello packet has been (unlikely) fragmented,
    // we should find the second part and drop, reassemble it here.

    let first = split_packet(pkt, 0, Some(1))?;
    let second = split_packet(pkt, 1, None)?;

    send_to_raw(&first)?;
    send_to_raw(&second)?;

    #[cfg(debug_assertions)]
    println!("packet is handled, len={}", pkt.len());

    Ok(true)
}

macro_rules! handle_packet {
    ($bytes:expr, handled => $on_handled:expr, rejected => $on_rejected:expr $(,)?) => {{
        match handle_packet($bytes) {
            Ok(true) => { $on_handled }
            Ok(false) => { $on_rejected }
            Err(e) => {
                eprintln!("warning: handle_packet: {e}");
                $on_rejected
            }
        }
    }};
}

fn main() -> Result<()> {
    use std::sync::Arc;

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); })?;
    }
    bootstrap()?;

    #[cfg(target_os = "linux")]
    {
        use std::os::fd::{AsRawFd, AsFd};
        use nix::{
            fcntl::{fcntl, FcntlArg, OFlag},
            poll::{poll, PollFd, PollFlags},
            errno::Errno
        };
        use nfq::Queue;

        let mut q = Queue::open()?;
        q.bind(QUEUE_NUM)?;

        {                           // to check inturrupts
            let raw_fd = q.as_raw_fd();
            let flags = fcntl(raw_fd, FcntlArg::F_GETFL)?;
            let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
            fcntl(raw_fd, FcntlArg::F_SETFL(new_flags))?;
        }

        while running.load(Ordering::SeqCst) {
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
        q.unbind(QUEUE_NUM)?;
    }

    #[cfg(windows)]
    {
        let mut buf = vec![0u8; 65536];

        while running.load(Ordering::SeqCst) {
            let pkt = WINDIVERT_HANDLE.recv(Some(&mut buf))?;

            handle_packet!(
                &pkt.data,
                handled => {},
                rejected => { WINDIVERT_HANDLE.send(&pkt)?; }
            );
        }
    }

    cleanup()?;

    Ok(())
}
