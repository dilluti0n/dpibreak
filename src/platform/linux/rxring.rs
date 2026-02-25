use std::os::fd::{RawFd, BorrowedFd, AsFd, OwnedFd, FromRawFd, AsRawFd};
use std::io::Error;
use libc::*;

pub struct RxRing {
    fd: OwnedFd,
    ring: *mut u8,
    ring_size: usize
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
                (ETH_P_IP as u16).to_be() as i32 // big-endian
            )
        };
        if raw < 0 { return Err(Error::last_os_error()); }

        // SAFETY: raw is a valid fd, negative case handled above.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        attach_filter(fd.as_raw_fd(), filter)?;
        let req = setup_rxring(fd.as_raw_fd())?;
        let ring_size = (req.tp_block_size * req.tp_block_nr) as usize;

        // SAFETY: ring is valid mmap'd memory, ring_size matches allocation.
        // MAP_FAILED guarded.
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
        })
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        unimplemented!("RxRing::next_packet");
    }
}

impl AsFd for RxRing {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
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
