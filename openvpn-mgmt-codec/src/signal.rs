use std::str::FromStr;

/// Error returned when a string is not a recognized signal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized signal: {0:?}")]
pub struct ParseSignalError(pub String);

/// Signals that can be sent to the OpenVPN daemon via the management
/// interface. These are sent as string names, not actual Unix signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display)]
pub enum Signal {
    /// Soft restart — re-read config, renegotiate TLS.
    #[strum(to_string = "SIGHUP")]
    SigHup,

    /// Graceful shutdown.
    #[strum(to_string = "SIGTERM")]
    SigTerm,

    /// Conditional restart (only if config changed).
    #[strum(to_string = "SIGUSR1")]
    SigUsr1,

    /// Print connection statistics to the log.
    #[strum(to_string = "SIGUSR2")]
    SigUsr2,
}

impl FromStr for Signal {
    type Err = ParseSignalError;

    /// Parse a signal name: `SIGHUP`, `SIGTERM`, `SIGUSR1`, or `SIGUSR2`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "SIGHUP" => Ok(Self::SigHup),
            "SIGTERM" => Ok(Self::SigTerm),
            "SIGUSR1" => Ok(Self::SigUsr1),
            "SIGUSR2" => Ok(Self::SigUsr2),
            other => Err(ParseSignalError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(Signal::SigHup)]
    #[test_case(Signal::SigTerm)]
    #[test_case(Signal::SigUsr1)]
    #[test_case(Signal::SigUsr2)]
    fn parse_roundtrip(sig: Signal) {
        let string = sig.to_string();
        assert_eq!(string.parse::<Signal>().unwrap(), sig);
    }

    #[test]
    fn parse_invalid() {
        assert!("SIGKILL".parse::<Signal>().is_err());
    }
}
