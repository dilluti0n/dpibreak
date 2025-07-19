use std::error::Error;
use std::os::fd::AsRawFd;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use iptables::IPTables;
use nfq::Queue;
use anyhow::Result;
use nix::fcntl::{fcntl, FcntlArg, OFlag};

fn install_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    ipt.new_chain("mangle", "DPIBREAK")?;
    ipt.insert("mangle", "POSTROUTING", "-j DPIBREAK", 1)?;
    ipt.append("mangle", "DPIBREAK",
               "-p tcp --dport 443 -j NFQUEUE --queue-num 0 --queue-bypass")?;
    Ok(())
}

fn cleanup_rules(ipt: &IPTables) -> Result<(), Box<dyn Error>> {
    _ = ipt.delete("mangle", "POSTROUTING", "-j DPIBREAK");
    _ = ipt.flush_chain("mangle", "DPIBREAK");
    _ = ipt.delete_chain("mangle", "DPIBREAK");

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
        if size == 0 {
            return None;
        }

        let end = self.ptr + size;
        // TODO; refactor this to more official-like way...
        let end = if end > self.payload.len() { self.payload.len() } else { end };
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

macro_rules! try_ret {
    ($e:expr, $ret:expr) => {
        match $e {
            Some(val) => val,
            None => return $ret,
        }
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
    let mut handshake = TLSMsg::new({
        let mut record = TLSMsg::new(payload);
        _ = match record.get_uint(1) { // type
            Some(22) => {},
            _ => return false          // not handshake
        };

        record.pass(2);                 // legacy_record_version
        let length: usize = try_ret!(record.get_uint(2), false);
        let fragment: &[u8] = try_ret!(record.get_bytes(length), false);

        fragment
    });

    _ = match handshake.get_uint(1) { // msg_type
        Some(1) => {},
        _ => return false          // not clienthello
    };

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
    cleanup_rules(&ipt).ok();
    install_rules(&ipt)?;
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
    cleanup_rules(&ipt)?;
    Ok(())
}
