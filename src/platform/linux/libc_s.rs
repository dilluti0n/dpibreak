// SPDX-FileCopyrightText: 2026 Dilluti0n <hskim@dilluti0n.com>
// SPDX-License-Identifier: GPL-3.0-or-later

use std::os::fd::RawFd;
use std::io::Error;

use libc::c_int;

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
