use std::error::Error;
use iptables::IPTables;
use tokio::{signal, select};
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;
use anyhow::Result;

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
    let payload = msg.get_payload();

    if is_client_hello(&payload) {
        msg.set_verdict(nfq::Verdict::Drop);
    } else {
        msg.set_verdict(nfq::Verdict::Accept);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let ipt = iptables::new(false)?;
    _ = cleanup_rules(&ipt); // in case bad exit without cleanup
    install_rules(&ipt)?;

    let mut q = nfq::Queue::open()?;
    q.bind(0)?;
    let raw_fd: RawFd = q.as_raw_fd();
    let async_q = AsyncFd::new(raw_fd)?;

    loop {
        select! {
            _ = signal::ctrl_c() => {
                break;
            }

            res = async_q.readable() => {
                _ = res?;
                loop {
                    match q.recv() {
                        Ok(mut msg) => {
                            handle_packet(&mut msg)?;
                            q.verdict(msg)?;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
        }
    };

    q.unbind(0)?;
    cleanup_rules(&ipt)?;
    Ok(())
}
