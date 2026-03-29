use std::str::FromStr;

/// Error returned when a string is not a recognized log level.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized log level: {0:?}")]
pub struct ParseLogLevelError(String);

/// Log severity level from `>LOG:` notifications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, strum::Display)]
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
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "I" => Ok(Self::Info),
            "D" => Ok(Self::Debug),
            "W" => Ok(Self::Warning),
            "N" => Ok(Self::NonFatal),
            "F" => Ok(Self::Fatal),
            other => Err(ParseLogLevelError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case("I" => LogLevel::Info)]
    #[test_case("D" => LogLevel::Debug)]
    #[test_case("W" => LogLevel::Warning)]
    #[test_case("N" => LogLevel::NonFatal)]
    #[test_case("F" => LogLevel::Fatal)]
    fn parse_roundtrip(flag: &str) -> LogLevel {
        flag.parse().unwrap()
    }

    #[test]
    fn parse_invalid() {
        let err = "X".parse::<LogLevel>().unwrap_err();
        assert_eq!(err.to_string(), r#"unrecognized log level: "X""#);
    }

    #[test]
    fn label_known_variants() {
        assert_eq!(LogLevel::Info.label(), "INFO");
        assert_eq!(LogLevel::Debug.label(), "DEBUG");
        assert_eq!(LogLevel::Warning.label(), "WARN");
        assert_eq!(LogLevel::NonFatal.label(), "NFATAL");
        assert_eq!(LogLevel::Fatal.label(), "FATAL");
    }

    #[test]
    fn label_unknown_returns_inner() {
        let level = LogLevel::Unknown("Z".to_string());
        assert_eq!(level.label(), "Z");
    }

    #[test]
    fn display_unknown_uses_strum_default() {
        let level = LogLevel::Unknown("Q".to_string());
        assert_eq!(level.to_string(), "Q");
    }
}
