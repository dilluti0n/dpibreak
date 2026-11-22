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
use std::fs::File;
use std::io::Write;
use std::sync::{Mutex, OnceLock, PoisonError};

/// When set, log output goes to this file instead of stdout.
static LOG_SINK: OnceLock<Mutex<File>> = OnceLock::new();

/// Returns `false` if a sink is already installed.
#[cfg(windows)]
pub fn set_sink(file: File) -> bool {
    LOG_SINK.set(Mutex::new(file)).is_ok()
}

/// Write one line to the log sink if set, otherwise to stdout.
#[doc(hidden)]
pub fn write_line(args: fmt::Arguments<'_>) {
    match LOG_SINK.get() {
        Some(m) => {
            let mut f = m.lock().unwrap_or_else(PoisonError::into_inner);
            _ = writeln!(f, "{args}");
            _ = f.flush();
        }
        None => println!("{args}"),
    }
}

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
            LogLevel::Debug => "[DEBUG]",
            LogLevel::Info => "[INFO]",
            LogLevel::Warning => "[WARNING]",
            LogLevel::Error => "[ERROR]",
        };
        write!(f, "{p}")
    }
}

#[derive(Debug)]
pub struct ParseLogLevelError;

impl fmt::Display for ParseLogLevelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "invalid log level (use: debug|info|warn|warning|err|error)"
        )
    }
}
impl std::error::Error for ParseLogLevelError {}

impl std::str::FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Ok(LogLevel::Debug),
            "info" => Ok(LogLevel::Info),
            "warn" | "warning" => Ok(LogLevel::Warning),
            "err" | "error" => Ok(LogLevel::Error),
            _ => Err(ParseLogLevelError),
        }
    }
}

#[macro_export]
macro_rules! log_println {
    ($level:expr, $($arg:tt)*) => {{
        if $level >= $crate::opt::log_level() {
            let (y, mo, d, h, mi, s) = $crate::platform::local_time();
            $crate::log::write_line(format_args!(
                "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} {} {}",
                $level, format_args!($($arg)*)));
        }
    }};
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::log_println!($crate::log::LogLevel::Debug, $($arg)*)
    }
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log_println!($crate::log::LogLevel::Info, $($arg)*)
    }
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log_println!($crate::log::LogLevel::Warning, $($arg)*)
    }
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log_println!($crate::log::LogLevel::Error, $($arg)*)
    }
}

#[macro_export]
macro_rules! splash {
    ($($arg:tt)*) => {{
        if !$crate::opt::no_splash() {
            $crate::log::write_line(format_args!($($arg)*));
        }
    }};
}
