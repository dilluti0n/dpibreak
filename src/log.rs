use std::fmt;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error, // Unrecoverable
}

#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: LogLevel = LogLevel::Debug;

#[cfg(not(debug_assertions))]
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

#[macro_export]
macro_rules! log_println {
    ($level:expr, $($arg:tt)*) => {{
        if $level >= crate::log::current_log_level() {
            println!("{} {}", $level, format_args!($($arg)*));
        }
    }};
}
