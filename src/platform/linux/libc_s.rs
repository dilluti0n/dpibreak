// SPDX-FileCopyrightText: 2026 Dilluti0n <hskim@dilluti0n.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::fd::RawFd;
use std::io::Error;

use std::ffi::{c_int, c_void};
use std::mem;

macro_rules! syscall {
    ($call:expr) => {
        match $call {
            -1 => Err(::std::io::Error::last_os_error()),
            res => Ok(res),
        }
    };
}

#[allow(non_camel_case_types)]
pub enum FcntlArg {
    F_GETFL,
    F_SETFL(c_int),
}

pub fn fcntl(fd: RawFd, op: FcntlArg) -> Result<c_int, Error> {
    use libc::fcntl;

    syscall!(match op {
        FcntlArg::F_GETFL => unsafe { fcntl(fd, libc::F_GETFL) },
        FcntlArg::F_SETFL(flags) => unsafe { fcntl(fd, libc::F_SETFL, flags) }
    })
}

pub fn flock(fd: RawFd, op: c_int) -> Result<(), Error> {
    syscall!(unsafe { libc::flock(fd, op) }).map(drop)
}

pub fn geteuid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

pub fn poll(fds: &mut [libc::pollfd], timeout: c_int) -> Result<(), Error> {
    syscall!(unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) }).map(drop)
}

unsafe fn setsockopt_1<T>(sockfd: RawFd, level: c_int, optname: c_int, optval: &T) -> c_int {
    unsafe {
        libc::setsockopt(sockfd, level, optname,
            (optval as *const T).cast() as *const c_void,
            mem::size_of::<T>() as libc::socklen_t)
    }
}

#[allow(non_camel_case_types)]
pub enum SockOpt<'a> {
    SO_ATTACH_FILTER(&'a [libc::sock_filter]),
    PACKET_RX_RING(&'a libc::tpacket_req),
}

pub fn setsockopt(
    sockfd: RawFd,
    opt: SockOpt
) -> Result<(), Error> {
    syscall!(match opt {
        SockOpt::SO_ATTACH_FILTER(val) => {
            let prog = libc::sock_fprog {
                len: val.len() as u16,
                filter: val.as_ptr() as *mut libc::sock_filter
            };

            unsafe {setsockopt_1(sockfd, libc::SOL_SOCKET, libc::SO_ATTACH_FILTER, &prog)}
        },
        SockOpt::PACKET_RX_RING(optval) => unsafe {
            setsockopt_1(sockfd, libc::SOL_PACKET, libc::PACKET_RX_RING, optval)
        }
    }).map(drop)
}
