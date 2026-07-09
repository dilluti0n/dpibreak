// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::fd::{RawFd, BorrowedFd, AsFd, OwnedFd, AsRawFd};
use std::io::Error;
use std::sync::atomic::{AtomicUsize, Ordering};

use libc::*;

use super::libc_s;

use libc_s::{setsockopt, SockOpt};

pub struct RxRing {
    fd: OwnedFd,
    ring: *mut u8,

    /// Bytes of mmap'd [`ring`]
    ring_size: usize,
    req: tpacket_req,

    /// Current frame index in the ring buffer (0..req.tp_frame_nr)
    current: usize
}

/// Make [`sockfd`] as mmapable rxring with size of [`tp_block_size`] * [`tp_block_nr`]
/// and single frame [`tp_frame_size`] (each packet goes to frame).
fn setup_rxring(sockfd: RawFd,
    tp_block_size: u32, tp_block_nr: u32, tp_frame_size: u32
) -> Result<tpacket_req, Error> {
    if tp_frame_size == 0 {     // to prevent div0
        return Err(Error::from_raw_os_error(EINVAL));
    }

    let req = tpacket_req {
        tp_block_size,
        tp_block_nr,
        tp_frame_size,
        tp_frame_nr: tp_block_size / tp_frame_size * tp_block_nr,
    };

    setsockopt(sockfd, SockOpt::PACKET_RX_RING(&req))?;

    Ok(req)
}

impl RxRing {
    pub fn new(
        filter: &[libc::sock_filter],
        tp_block_size: u32, tp_block_nr: u32, tp_frame_size: u32
    ) -> Result<Self, Error> {
        let fd = libc_s::socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32)?;
        let raw = fd.as_raw_fd();

        setsockopt(raw, SockOpt::SO_ATTACH_FILTER(&filter))?;
        let req = setup_rxring(raw, tp_block_size, tp_block_nr, tp_frame_size)?;
        let ring_size = req.tp_block_size as usize * req.tp_block_nr as usize;

        // SAFETY: we munmap this when RxRing is dropped
        let ring = unsafe {libc_s::mmap(
            std::ptr::null_mut(),
            ring_size,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_LOCKED,
            raw,
            0
        )}?;

        Ok(RxRing {
            fd,
            ring: ring as *mut u8,
            ring_size,
            req,
            current: 0,
        })
    }

    #[inline]
    fn current_frame(&self) -> *mut u8 {
        let frame_size = self.req.tp_frame_size as usize;

        self.ring.wrapping_add(self.current * frame_size) as *mut u8
    }

    #[inline]
    fn status(&self) -> &AtomicUsize {
        // SAFETY:
        // * Align: frame starts on TPACKET_ALIGNMENT(16) boundary in a page-aligned mmap
        // * Valid r/w for 'a: ring outlives &self, currrent < frame_nr keeps the offset in-bounds
        // * Memory model: on TPACKET_V1 tp_status is unsigned long == usize
        unsafe { AtomicUsize::from_ptr(self.current_frame() as *mut usize) }
    }

    pub fn current_packet(&self) -> Option<&[u8]> {
        if self.status().load(Ordering::Acquire) & TP_STATUS_USER as usize == 0 {
            return None;
        }

        let hdr = self.current_frame() as *const tpacket_hdr;

        // SAFETY:
        //   See status() and https://www.kernel.org/doc/html/latest/networking/packet_mmap.html
        //   Also hdr->tp_net always fit isize so we can use pointer::add() here
        let data = unsafe {
            let ptr = (hdr as *const u8).add((*hdr).tp_net as usize);
            std::slice::from_raw_parts(ptr, (*hdr).tp_snaplen as usize)
        };

        Some(data)
    }

    pub fn advance(&mut self) {
        self.status().store(TP_STATUS_KERNEL as usize, Ordering::Release);
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

impl Drop for RxRing {
    fn drop(&mut self) {
        // SAFETY: ring was mmap'd with ring_size bytes
        match unsafe { libc_s::munmap(self.ring as *mut _, self.ring_size) } {
            Err(e) => crate::warn!("rxring: cannot munmap: {}", e.kind()),
            Ok(_) => {}
        }
    }
}
