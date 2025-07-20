use std::error::Error;
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::process::Command;

use iptables::IPTables;
use nfq::Queue;
use anyhow::Result;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use once_cell::sync::Lazy;

static IS_U32_SUPPORTED: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));
static IS_XT_U32_LOADED_BY_US: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

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

    let rule = "-m u32 --u32 \"0x0=0x0\" -j RETURN";
    match ipt.insert("raw", "PREROUTING", rule, 1) {
        Ok(_) => {
            _ = ipt.delete("raw", "PREROUTING", rule);
            IS_U32_SUPPORTED.store(true, Ordering::Relaxed);
            true
        }

        Err(_) => false
    }
}

fn bootstrap(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
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

fn cleanup(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    _ = ipt.delete("mangle", "POSTROUTING", "-j DPIBREAK");
    _ = ipt.flush_chain("mangle", "DPIBREAK");
    _ = ipt.delete_chain("mangle", "DPIBREAK");

    if IS_XT_U32_LOADED_BY_US.load(Ordering::Relaxed) {
        _ = Command::new("modprobe").args(&["-q", "-r", "xt_u32"]).status();
    }

    Ok(())
}

struct TLSMsg<'a> {
    ptr: usize,
    payload: &'a [u8]
}

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

fn get_tcp_payload(pkt: &[u8]) -> Option<&[u8]> {
    // IPv4
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 20 { return None; }      // minimal TCP header 20B
    let tcp_offset = ihl;
    let data_offset = (((pkt[tcp_offset + 12] & 0xF0) >> 4) as usize) * 4;
    let start = tcp_offset + data_offset;
    if pkt.len() <= start { return None; }
    Some(&pkt[start..])
}

fn is_client_hello(payload: &[u8]) -> bool {
    if IS_U32_SUPPORTED.load(Ordering::Relaxed) {
        return true;            // already filtered on xt_u32
    }

    if TLSMsg::new({
        let mut record = TLSMsg::new(payload);
        if record.get_uint(1) != Some(22) { // type
            return false;                   // not handshake
        }

        record.pass(2);                 // legacy_record_version
        record.pass(2);                 // length

        &record.payload[record.ptr..] // fragment
    }).get_uint(1) != Some(1) { // msg_type
        return false;                     // not clienthello
    }

    true
}

fn handle_packet(msg: &mut nfq::Message) -> Result<()> {
    match get_tcp_payload(msg.get_payload()) {
        Some(payload) if is_client_hello(payload) => {
            // TODO: do some fun stuffs!
            msg.set_verdict(nfq::Verdict::Drop)
        },

        _ => msg.set_verdict(nfq::Verdict::Accept),
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    cleanup(&ipt).ok();
    bootstrap(&ipt)?;
    let mut q = Queue::open()?;
    q.bind(0)?;

    {                           // to check ctrlc
        let fd = q.as_raw_fd();
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;
        let new_flags = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
    }

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); })?;
    }

    while running.load(Ordering::SeqCst) {
        match q.recv() {
            Ok(mut msg) => {
                handle_packet(&mut msg)?;
                q.verdict(msg)?;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // no packet; get some rest...
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Err(e) => return Err(e.into()),
        }
    }

    q.unbind(0)?;
    cleanup(&ipt)?;
    Ok(())
}
