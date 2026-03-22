use std::str::FromStr;

/// Error returned when a string is not a recognized log level.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized log level: {0:?}")]
pub struct ParseLogLevelError(pub String);

/// Log severity level from `>LOG:` notifications.
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
pub enum LogLevel {
    /// Informational message (`I`).
    #[strum(to_string = "I")]
    Info,

    /// Debug message (`D`).
    #[strum(to_string = "D")]
    Debug,

    /// Warning (`W`).
    #[strum(to_string = "W")]
    Warning,

    /// Non-fatal error (`N`).
    #[strum(to_string = "N")]
    NonFatal,

    /// Fatal error (`F`).
    #[strum(to_string = "F")]
    Fatal,

    /// An unrecognized log flag (forward compatibility).
    #[strum(default)]
    Unknown(String),
}

impl LogLevel {
    /// Human-readable label (e.g. `"INFO"`, `"WARN"`).
    pub fn label(&self) -> &str {
        match self {
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
            Self::Warning => "WARN",
            Self::NonFatal => "NFATAL",
            Self::Fatal => "FATAL",
            Self::Unknown(s) => s,
        }
    }
}

impl FromStr for LogLevel {
    type Err = ParseLogLevelError;

    /// Parse a recognized log-flag string: `I`, `D`, `W`, `N`, `F`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "I" => Ok(Self::Info),
            "D" => Ok(Self::Debug),
            "W" => Ok(Self::Warning),
            "N" => Ok(Self::NonFatal),
            "F" => Ok(Self::Fatal),
            other => Err(ParseLogLevelError(other.to_string())),
        }
    }
}
