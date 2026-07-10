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

#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum PktError {
    #[error("malformed frame (mac/net/snaplen inconsistent)")]
    Malformed,
}

pub struct Pkt<'a> {
    rx: &'a mut RxRing,

    /// L3 packet
    net: Result<&'a [u8], PktError>,
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
        self.ring.wrapping_add(self.current * self.req.tp_frame_size as usize)
    }

    #[inline]
    fn status(&self) -> &AtomicUsize {
        // SAFETY:
        // * Align: frame starts on TPACKET_ALIGNMENT(16) boundary in a page-aligned mmap
        // * Valid r/w for 'a: ring outlives &self, currrent < frame_nr keeps the offset in-bounds
        // * Memory model: on TPACKET_V1 tp_status is unsigned long == usize
        unsafe { AtomicUsize::from_ptr(self.current_frame() as *mut usize) }
    }

    pub fn current_packet(&mut self) -> Option<Pkt<'_>> {
        let status = self.status().load(Ordering::Acquire);
        if status & TP_STATUS_USER as usize == 0 {
            return None;
        }

        let hdr = self.current_frame() as *const tpacket_hdr;

        // [ tpacket_hdr |      payload        ]
        // |<--tp_mac--->|<---tp_snaplen------>|
        // |<--tp_net------------>|
        // |             |<--mo-->|
        // |                      |<-net_len-->|
        // hdr                   net
        let (tp_mac, tp_net, tp_snaplen) = unsafe {
            ((*hdr).tp_mac as usize, (*hdr).tp_net as usize, (*hdr).tp_snaplen as usize)
        };

        let net = tp_net.checked_sub(tp_mac)
            .and_then(|mo| tp_snaplen.checked_sub(mo))
            .map(|net_len| unsafe {
                std::slice::from_raw_parts((hdr as *const u8).add(tp_net), net_len)
            })
            .ok_or(PktError::Malformed);

        Some(Pkt { rx: self, net })
    }

    /// Return the current frame to kernel and move cursor. This must be called
    /// only when the current state is TP_STATUS_USER. If not, ring protocol
    /// may corrupted.
    pub fn advance(&mut self) {
        debug_assert!(
            self.status().load(Ordering::Acquire) & TP_STATUS_USER as usize != 0,
            "advance() on a frame not owned by user"
        );
        self.status().store(TP_STATUS_KERNEL as usize, Ordering::Release);
        self.current = (self.current + 1) % self.req.tp_frame_nr as usize;
    }
}

impl Pkt<'_> {
    pub fn net(&self) -> Result<&[u8], PktError> {
        self.net
    }
}

impl Drop for Pkt<'_> {
    fn drop(&mut self) {
        self.rx.advance()
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
