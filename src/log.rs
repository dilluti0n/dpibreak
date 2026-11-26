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

impl From<LogLevel> for ::log::LevelFilter {
    fn from(l: LogLevel) -> Self {
        match l {
            LogLevel::Debug => ::log::LevelFilter::Debug,
            LogLevel::Info => ::log::LevelFilter::Info,
            LogLevel::Warning => ::log::LevelFilter::Warn,
            LogLevel::Error => ::log::LevelFilter::Error,
        }
    }
}

impl From<::log::Level> for LogLevel {
    fn from(l: ::log::Level) -> Self {
        match l {
            ::log::Level::Trace | ::log::Level::Debug => LogLevel::Debug,
            ::log::Level::Info => LogLevel::Info,
            ::log::Level::Warn => LogLevel::Warning,
            ::log::Level::Error => LogLevel::Error,
        }
    }
}

struct Logger;

impl ::log::Log for Logger {
    fn enabled(&self, _: &::log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &::log::Record) {
        let level = LogLevel::from(record.level());
        let (y, mo, d, h, mi, s) = crate::platform::local_time();
        println!(
            "{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} {level} {}",
            record.args()
        );
    }

    fn flush(&self) {}
}

/// Install the logger at the default level.
pub fn init() {
    _ = ::log::set_logger(&Logger);
    set_level(crate::opt::log_level());
}

pub fn set_level(level: LogLevel) {
    ::log::set_max_level(level.into());
}

#[macro_export]
macro_rules! splash {
    ($($arg:tt)*) => {{
        if !$crate::opt::no_splash() {
            println!($($arg)*);
        }
    }};
}
