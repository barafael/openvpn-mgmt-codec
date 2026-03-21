use std::fmt;
use std::str::FromStr;

/// Signals that can be sent to the OpenVPN daemon via the management
/// interface. These are sent as string names, not actual Unix signals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signal {
    /// Soft restart — re-read config, renegotiate TLS.
    SigHup,

    /// Graceful shutdown.
    SigTerm,

    /// Conditional restart (only if config changed).
    SigUsr1,

    /// Print connection statistics to the log.
    SigUsr2,
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SigHup => f.write_str("SIGHUP"),
            Self::SigTerm => f.write_str("SIGTERM"),
            Self::SigUsr1 => f.write_str("SIGUSR1"),
            Self::SigUsr2 => f.write_str("SIGUSR2"),
        }
    }
}

impl FromStr for Signal {
    type Err = String;

    /// Parse a signal name: `SIGHUP`, `SIGTERM`, `SIGUSR1`, or `SIGUSR2`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHUP" => Ok(Self::SigHup),
            "SIGTERM" => Ok(Self::SigTerm),
            "SIGUSR1" => Ok(Self::SigUsr1),
            "SIGUSR2" => Ok(Self::SigUsr2),
            _ => Err(format!(
                "unknown signal: {s} (use SIGHUP/SIGTERM/SIGUSR1/SIGUSR2)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_roundtrip() {
        for sig in [
            Signal::SigHup,
            Signal::SigTerm,
            Signal::SigUsr1,
            Signal::SigUsr2,
        ] {
            let s = sig.to_string();
            assert_eq!(s.parse::<Signal>().unwrap(), sig);
        }
    }

    #[test]
    fn parse_invalid() {
        assert!("SIGKILL".parse::<Signal>().is_err());
    }
}
