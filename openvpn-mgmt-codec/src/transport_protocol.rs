use std::str::FromStr;

/// Error returned when a string is not a recognized transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized transport protocol: {0:?}")]
pub struct ParseTransportProtocolError(pub String);

/// Transport protocol as reported in `>REMOTE:` and `>PROXY:` notifications.
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum TransportProtocol {
    /// UDP transport.
    Udp,

    /// TCP transport.
    Tcp,

    /// An unrecognized protocol (forward compatibility).
    #[strum(default)]
    Unknown(String),
}

impl FromStr for TransportProtocol {
    type Err = ParseTransportProtocolError;

    /// Parse a recognized protocol string (case-insensitive: `udp`/`UDP`,
    /// `tcp`/`TCP`).
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "udp" | "UDP" => Ok(Self::Udp),
            "tcp" | "TCP" => Ok(Self::Tcp),
            other => Err(ParseTransportProtocolError(other.to_string())),
        }
    }
}
