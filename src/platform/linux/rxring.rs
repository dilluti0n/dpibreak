use std::os::fd::{RawFd, BorrowedFd, AsFd};

pub struct RxRing {
    fd: RawFd,
    ring: *mut u8,
    ring_size: usize
}

impl RxRing {
    pub fn new(filter: &[libc::sock_filter]) -> Result<Self, std::io::Error> {
        _ = filter;
        unimplemented!("RxRing::new");
    }

    pub fn next_packet(&mut self) -> Option<&[u8]> {
        unimplemented!("RxRing::next_packet");
    }
}

impl AsFd for RxRing {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl Drop for RxRing {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ring as *mut _, self.ring_size);
            libc::close(self.fd);
        }
    }
}
