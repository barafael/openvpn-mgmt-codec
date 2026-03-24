use std::fmt;
use std::str::FromStr;

/// Error returned when a string is not a recognized stream mode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized stream mode: {0:?}")]
pub struct ParseStreamModeError(pub String);

/// Mode selector for commands that share the on/off/all/on-all/N grammar.
/// This is used by `log`, `state`, and `echo`, all of which support
/// identical sub-commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMode {
    /// Enable real-time notifications.
    On,

    /// Disable real-time notifications.
    Off,

    /// Dump the entire history buffer.
    All,

    /// Atomically enable real-time notifications AND dump history.
    /// This guarantees no messages are missed between the dump and
    /// the start of real-time streaming.
    OnAll,

    /// Show the N most recent history entries.
    Recent(u32),
}

impl fmt::Display for StreamMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::On => f.write_str("on"),
            Self::Off => f.write_str("off"),
            Self::All => f.write_str("all"),
            Self::OnAll => f.write_str("on all"),
            Self::Recent(n) => write!(f, "{n}"),
        }
    }
}

impl FromStr for StreamMode {
    type Err = ParseStreamModeError;

    /// Parse a stream mode string: `on`, `off`, `all`, `on all`, or a number.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            "all" => Ok(Self::All),
            "on all" => Ok(Self::OnAll),
            other => other
                .parse::<u32>()
                .map(Self::Recent)
                .map_err(|_| ParseStreamModeError(input.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(StreamMode::On)]
    #[test_case(StreamMode::Off)]
    #[test_case(StreamMode::All)]
    #[test_case(StreamMode::OnAll)]
    #[test_case(StreamMode::Recent(42))]
    fn parse_roundtrip(mode: StreamMode) {
        let string = mode.to_string();
        assert_eq!(string.parse::<StreamMode>().unwrap(), mode);
    }

    #[test]
    fn parse_invalid() {
        assert!("bogus".parse::<StreamMode>().is_err());
    }
}
