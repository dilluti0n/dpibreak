// SPDX-FileCopyrightText: 2026 Dilluti0n <hskim@dilluti0n.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::fd::RawFd;
use std::io::Error;

use std::ffi::{c_int, c_void};

#[allow(non_camel_case_types)]
pub enum FcntlArg {
    F_GETFL,
    F_SETFL(c_int),
}

pub fn fcntl(fd: RawFd, op: FcntlArg) -> Result<c_int, Error> {
    use libc::fcntl;

    let res = match op {
        FcntlArg::F_GETFL => unsafe { fcntl(fd, libc::F_GETFL) },
        FcntlArg::F_SETFL(flags) => unsafe { fcntl(fd, libc::F_SETFL, flags) }
    };

    if res == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(res)
    }
}

pub fn flock(fd: RawFd, op: c_int) -> Result<(), Error> {
    let res = unsafe { libc::flock(fd, op) };

    if res == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn geteuid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

pub fn poll(fds: &mut [libc::pollfd], timeout: c_int) -> Result<(), Error> {
    // SAFETY: fds.len() is fds's length
    if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, timeout) } == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}

#[allow(non_camel_case_types)]
pub enum SockOpt<'a> {
    SO_ATTACH_FILTER(&'a libc::sock_fprog),
}

pub fn setsockopt(
    sockfd: RawFd,
    level: c_int,
    opt: SockOpt
) -> Result<(), Error> {
    use libc::{setsockopt, socklen_t};
    use std::mem;

    let res = match opt {
        SockOpt::SO_ATTACH_FILTER(optval) => unsafe {
            setsockopt(sockfd, level,
                libc::SO_ATTACH_FILTER, optval as *const _ as *const c_void,
                mem::size_of::<libc::sock_fprog>() as socklen_t)
        }
    };

    if res == -1 {
        Err(Error::last_os_error())
    } else {
        Ok(())
    }
}
