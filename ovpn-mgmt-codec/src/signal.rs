use std::fmt;

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
