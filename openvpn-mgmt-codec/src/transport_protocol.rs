use std::str::FromStr;

/// Error returned when a string is not a recognized transport protocol.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized transport protocol: {0:?}")]
pub struct ParseTransportProtocolError(String);

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_lowercase() {
        assert_eq!(
            "udp".parse::<TransportProtocol>().unwrap(),
            TransportProtocol::Udp
        );
        assert_eq!(
            "tcp".parse::<TransportProtocol>().unwrap(),
            TransportProtocol::Tcp
        );
    }

    #[test]
    fn parse_uppercase() {
        assert_eq!(
            "UDP".parse::<TransportProtocol>().unwrap(),
            TransportProtocol::Udp
        );
        assert_eq!(
            "TCP".parse::<TransportProtocol>().unwrap(),
            TransportProtocol::Tcp
        );
    }

    #[test]
    fn mixed_case_is_err() {
        assert!("Udp".parse::<TransportProtocol>().is_err());
        assert!("Tcp".parse::<TransportProtocol>().is_err());
    }

    #[test]
    fn display_roundtrip() {
        // strum Display serializes as lowercase
        assert_eq!(TransportProtocol::Udp.to_string(), "udp");
        assert_eq!(TransportProtocol::Tcp.to_string(), "tcp");
        assert_eq!(
            "udp".parse::<TransportProtocol>().unwrap(),
            TransportProtocol::Udp
        );
        assert_eq!(
            "tcp".parse::<TransportProtocol>().unwrap(),
            TransportProtocol::Tcp
        );
    }

    #[test]
    fn unknown_protocol_is_err() {
        assert!("sctp".parse::<TransportProtocol>().is_err());
    }

    #[test]
    fn display_unknown() {
        let u = TransportProtocol::Unknown("quic".to_string());
        assert_eq!(u.to_string(), "quic");
    }

    #[test]
    fn error_preserves_input() {
        let err = "sctp".parse::<TransportProtocol>().unwrap_err();
        assert_eq!(err.0, "sctp");
    }
}
