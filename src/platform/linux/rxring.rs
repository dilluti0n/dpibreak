use std::os::fd::{RawFd, BorrowedFd, AsFd, OwnedFd, FromRawFd, AsRawFd};
use std::io::Error;
use libc::*;

pub struct RxRing {
    fd: OwnedFd,
    ring: *mut u8,

    /// Bytes of mmap'd [`ring`]
    ring_size: usize,
    req: tpacket_req,

    /// Current frame index in the ring buffer (0..req.tp_frame_nr)
    current: usize
}

fn attach_filter(sockfd: RawFd, filter: &[sock_filter]) -> Result<(), Error> {
    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut sock_filter,
    };

    let ret = unsafe {
        setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER,
            &prog as *const _ as *const _,
            std::mem::size_of::<sock_fprog>() as socklen_t)
    };

    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(())
}

/// Make [`sockfd`] as mmapable rxring with size of [`BLOCK_SIZE`] * [`BLOCK_NR`]
/// and single frame [`FRAME_SIZE`] (each packet goes to frame).
/// Since we only need to seek ip header here, 128 bytes are
/// enough.
fn setup_rxring(sockfd: RawFd) -> Result<tpacket_req, Error> {
    const BLOCK_SIZE: u32 = 4096 * 4; // 16 KB
    const BLOCK_NR:   u32 = 4;

    // tp_net is typically ~66 (32 B of tpacket_hdr + padding + ether header)
    // we only need IP header (20 B) here so 128 is enough.
    const FRAME_SIZE: u32 = 128;

    let req = tpacket_req {
        tp_block_size: BLOCK_SIZE,
        tp_block_nr:   BLOCK_NR,
        tp_frame_size: FRAME_SIZE,
        tp_frame_nr:   BLOCK_SIZE / FRAME_SIZE * BLOCK_NR,
    };

    let ret = unsafe {
        setsockopt(sockfd, SOL_PACKET, PACKET_RX_RING,
            &req as *const _ as *const _,
            std::mem::size_of::<tpacket_req>() as socklen_t)
    };

    if ret < 0 {
        return Err(Error::last_os_error());
    }

    Ok(req)
}

impl RxRing {
    pub fn new(filter: &[libc::sock_filter]) -> Result<Self, Error> {
        let raw = unsafe {
            socket(
                AF_PACKET,
                SOCK_RAW,
                (ETH_P_ALL as u16).to_be() as i32 // big-endian
            )
        };
        if raw < 0 { return Err(Error::last_os_error()); }

        // SAFETY: we just opened raw.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        attach_filter(fd.as_raw_fd(), filter)?;
        let req = setup_rxring(fd.as_raw_fd())?;
        let ring_size = (req.tp_block_size * req.tp_block_nr) as usize;

        let ring = unsafe {
            mmap(
                std::ptr::null_mut(),
                ring_size,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_LOCKED,
                fd.as_raw_fd(),
                0
            )
        };
        if ring == MAP_FAILED { return Err(Error::last_os_error()); }

        Ok(RxRing {
            fd,
            ring: ring as *mut u8,
            ring_size,
            req,
            current: 0,
        })
    }

    fn current_frame(&self) -> *mut tpacket_hdr {
        let frame_size = self.req.tp_frame_size as usize;

        // SAFETY: current < frame_nr guaranteed by modular increment on advance.
        // ring is valid mmap'd memory from new(), munmapped by Drop.
        unsafe { self.ring.add(self.current * frame_size) as *mut tpacket_hdr }
    }

    pub fn current_packet(&self) -> Option<&[u8]> {
        let hdr = unsafe { &*(self.current_frame()) };

        // Check if we have permission from kernel to use current frame.
        if hdr.tp_status & TP_STATUS_USER as u64 == 0 {
            return None;
        }

        // SAFETY: tp_net and tp_snaplen are valid when tp_status == TP_STATUS_USER.
        let data = unsafe {
            let ptr = (hdr as *const tpacket_hdr as *const u8).add(hdr.tp_net as usize);
            std::slice::from_raw_parts(ptr, (*hdr).tp_snaplen as usize)
        };

        Some(data)
    }

    pub fn advance(&mut self) {
        // SAFETY: see current_frame
        unsafe { (*self.current_frame()).tp_status = TP_STATUS_KERNEL as u64; }

        self.current = (self.current + 1) % self.req.tp_frame_nr as usize;
    }
}

impl AsFd for RxRing {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl AsRawFd for RxRing {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
   }
}

// SAFETY: ring was mmap'd with ring_size bytes.
// This guarantees munmap() happens before OwnedFd closes the fd.
impl Drop for RxRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring as *mut _, self.ring_size);
        }
    }
}
