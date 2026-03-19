use std::fmt;

/// Log severity level from `>LOG:` notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogLevel {
    /// Informational message (`I`).
    Info,

    /// Debug message (`D`).
    Debug,

    /// Warning (`W`).
    Warning,

    /// Non-fatal error (`N`).
    NonFatal,

    /// Fatal error (`F`).
    Fatal,

    /// An unrecognized log flag (forward compatibility).
    Custom(String),
}

impl LogLevel {
    /// Parse a wire log-flag string into a typed variant.
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "I" => Self::Info,
            "D" => Self::Debug,
            "W" => Self::Warning,
            "N" => Self::NonFatal,
            "F" => Self::Fatal,
            other => Self::Custom(other.to_owned()),
        }
    }
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => f.write_str("I"),
            Self::Debug => f.write_str("D"),
            Self::Warning => f.write_str("W"),
            Self::NonFatal => f.write_str("N"),
            Self::Fatal => f.write_str("F"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}
