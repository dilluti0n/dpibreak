// SPDX-FileCopyrightText: 2026 Dilluti0n <hskimse1@gmail.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::fd::{RawFd, BorrowedFd, AsFd, OwnedFd, AsRawFd};
use std::io::Error;
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
        let ring_size = (req.tp_block_size * req.tp_block_nr) as usize;

        // SAFETY: we munmap this segment when RxRing is dropped.
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

    fn current_frame(&self) -> *mut tpacket_hdr {
        let frame_size = self.req.tp_frame_size as usize;

        // SAFETY: current < frame_nr guaranteed by modular increment on advance.
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

impl Drop for RxRing {
    fn drop(&mut self) {
        // SAFETY: ring was mmap'd with ring_size bytes.
        match unsafe { libc_s::munmap(self.ring as *mut _, self.ring_size) } {
            Err(e) => crate::warn!("rxring: cannot munmap: {}", e.kind()),
            Ok(_) => {}
        }
    }
}
