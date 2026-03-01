// Copyright 2025-2026 Dillution <hskimse1@gmail.com>.
//
// This file is part of DPIBreak.
//
// DPIBreak is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// DPIBreak is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
// for more details.
//
// You should have received a copy of the GNU General Public License
// along with DPIBreak. If not, see <https://www.gnu.org/licenses/>.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error, // Unrecoverable
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let p = match self {
            LogLevel::Debug   => "[DEBUG]",
            LogLevel::Info    => "[INFO]",
            LogLevel::Warning => "[WARNING]",
            LogLevel::Error   => "[ERROR]",
        };
        write!(f, "{p}")
    }
}

#[derive(Debug)]
pub struct ParseLogLevelError;

impl fmt::Display for ParseLogLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid log level (use: debug|info|warn|warning|err|error)")
    }
}
impl std::error::Error for ParseLogLevelError {}

impl std::str::FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "debug"   => Ok(LogLevel::Debug),
            "info"    => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warning),
            "err"  | "error"   => Ok(LogLevel::Error),
            _ => Err(ParseLogLevelError),
        }
    }
}

#[cfg(unix)]
pub fn local_time() -> (i32, u8, u8, u8, u8, u8) {
    unsafe {
        let t = libc::time(std::ptr::null_mut());
        let mut tm: libc::tm = std::mem::zeroed();
        if t == -1 || libc::localtime_r(&t, &mut tm).is_null() {
            return (0, 0, 0, 0, 0, 0);
        };
        (tm.tm_year + 1900, (tm.tm_mon + 1) as u8, tm.tm_mday as u8,
         tm.tm_hour as u8, tm.tm_min as u8, tm.tm_sec as u8)
    }
}

#[cfg(windows)]
pub fn local_time() -> (i32, u8, u8, u8, u8, u8) {
    use std::mem::zeroed;
    #[repr(C)]
    struct SYSTEMTIME { y: u16, m: u16, _dow: u16, d: u16, h: u16, min: u16, s: u16, _ms: u16 }
    unsafe extern "system" { fn GetLocalTime(st: *mut SYSTEMTIME); }
    unsafe {
        let mut st: SYSTEMTIME = zeroed();
        GetLocalTime(&mut st);
        (st.y as i32, st.m as u8, st.d as u8, st.h as u8, st.min as u8, st.s as u8)
    }
}

#[macro_export]
macro_rules! log_println {
    ($level:expr, $($arg:tt)*) => {{
        if $level >= crate::opt::log_level() {
            let (y, mo, d, h, mi, s) = crate::log::local_time();
            println!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} {} {}",
                $level, format_args!($($arg)*));
        }
    }};
}

#[macro_export] macro_rules! debug { ($($arg:tt)*) => { log_println!(LogLevel::Debug, $($arg)*) } }
#[macro_export] macro_rules! info { ($($arg:tt)*) => { log_println!(LogLevel::Info,  $($arg)*) } }
#[macro_export] macro_rules! warn { ($($arg:tt)*) => { log_println!(LogLevel::Warning,$($arg)*) } }
#[macro_export] macro_rules! error { ($($arg:tt)*) => { log_println!(LogLevel::Error,  $($arg)*) } }

#[macro_export]
macro_rules! splash {
    ($($arg:tt)*) => {{
        if !crate::opt::no_splash() {
            println!($($arg)*);
        }
    }};
}
