use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warning,
    Error,                      // Unrecovable
}

#[cfg(debug_assertions)]
pub static LOG_LEVEL: LogLevel = LogLevel::Debug;

#[cfg(not(debug_assertions))]
pub static LOG_LEVEL: LogLevel = LogLevel::Warning;


impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let prefix = match self {
            LogLevel::Debug   => "[DEBUG]",
            LogLevel::Info    => "[INFO]",
            LogLevel::Warning => "[WARNING]",
            LogLevel::Error   => "[ERROR]",
        };
        write!(f, "{}", prefix)
    }
}

#[macro_export]
macro_rules! log_println {
    ($level:expr, $($arg:tt)*) => {{
        if crate::log::LOG_LEVEL <= $level {
            println!("{} {}", $level, format!($($arg)*));
        }
    }};
}
