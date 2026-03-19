use std::fmt;

/// Transport protocol as reported in `>REMOTE:` and `>PROXY:` notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProtocol {
    /// UDP transport.
    Udp,

    /// TCP transport.
    Tcp,

    /// An unrecognized protocol (forward compatibility).
    Custom(String),
}

impl TransportProtocol {
    /// Parse a wire protocol string into a typed variant.
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "udp" | "UDP" => Self::Udp,
            "tcp" | "TCP" => Self::Tcp,
            other => Self::Custom(other.to_owned()),
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp => f.write_str("udp"),
            Self::Tcp => f.write_str("tcp"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}
