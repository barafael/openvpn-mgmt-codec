use std::fmt;

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
