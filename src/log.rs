// Copyright 2025 Dillution <hskimse1@gmail.com>.
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
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error, // Unrecoverable
}

const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Warning;

static LOG_LEVEL_OVERRIDE: OnceLock<LogLevel> = OnceLock::new();

pub fn set_log_level(level: LogLevel) -> Result<(), &'static str> {
    LOG_LEVEL_OVERRIDE.set(level).map_err(|_| "LOG_LEVEL already initialized")
}

pub fn current_log_level() -> LogLevel {
    *LOG_LEVEL_OVERRIDE.get().unwrap_or(&DEFAULT_LOG_LEVEL)
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

static NO_SPLASH: OnceLock<bool> = OnceLock::new();

pub fn set_no_splash(no_splash: bool) -> Result<(), &'static str> {
    NO_SPLASH.set(no_splash).map_err(|_| "NO_SPLASH already initialized")
}

pub fn no_splash() -> bool {
    *NO_SPLASH.get().unwrap_or(&false)
}

#[macro_export]
macro_rules! log_println {
    ($level:expr, $($arg:tt)*) => {{
        if $level >= crate::log::current_log_level() {
            println!("{} {}", $level, format_args!($($arg)*));
        }
    }};
}

#[macro_export]
macro_rules! splash {
    ($($arg:tt)*) => {{
        if !crate::log::no_splash() {
            println!($($arg)*);
        }
    }};
}
