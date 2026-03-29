use std::str::FromStr;

/// Error returned when a string is not a recognized OpenVPN state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized OpenVPN state: {0:?}")]
pub struct ParseOpenVpnStateError(String);

/// OpenVPN connection state as reported in `>STATE:` notifications.
#[derive(Debug, Clone, PartialEq, Eq, Hash, strum::Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenVpnState {
    /// Initial connection in progress.
    Connecting,

    /// Waiting for initial response from server.
    Wait,

    /// Authenticating with server.
    Auth,

    /// Downloading configuration from server.
    GetConfig,

    /// Assigning IP address to virtual network interface.
    AssignIp,

    /// Adding routes to system routing table.
    AddRoutes,

    /// Connection established and operational.
    Connected,

    /// Connection lost, reconnecting.
    Reconnecting,

    /// Graceful exit in progress.
    Exiting,

    /// Establishing TCP connection to remote.
    TcpConnect,

    /// Resolving remote hostname.
    Resolve,

    /// Waiting for authentication to complete (OpenVPN 2.5+).
    AuthPending,

    /// An unrecognized state (forward compatibility).
    #[strum(default)]
    Unknown(String),
}

impl FromStr for OpenVpnState {
    type Err = ParseOpenVpnStateError;

    /// Parse a recognized state string.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "CONNECTING" => Ok(Self::Connecting),
            "WAIT" => Ok(Self::Wait),
            "AUTH" => Ok(Self::Auth),
            "GET_CONFIG" => Ok(Self::GetConfig),
            "ASSIGN_IP" => Ok(Self::AssignIp),
            "ADD_ROUTES" => Ok(Self::AddRoutes),
            "CONNECTED" => Ok(Self::Connected),
            "RECONNECTING" => Ok(Self::Reconnecting),
            "EXITING" => Ok(Self::Exiting),
            "TCP_CONNECT" => Ok(Self::TcpConnect),
            "RESOLVE" => Ok(Self::Resolve),
            "AUTH_PENDING" => Ok(Self::AuthPending),
            other => Err(ParseOpenVpnStateError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_KNOWN: &[(&str, OpenVpnState)] = &[
        ("CONNECTING", OpenVpnState::Connecting),
        ("WAIT", OpenVpnState::Wait),
        ("AUTH", OpenVpnState::Auth),
        ("GET_CONFIG", OpenVpnState::GetConfig),
        ("ASSIGN_IP", OpenVpnState::AssignIp),
        ("ADD_ROUTES", OpenVpnState::AddRoutes),
        ("CONNECTED", OpenVpnState::Connected),
        ("RECONNECTING", OpenVpnState::Reconnecting),
        ("EXITING", OpenVpnState::Exiting),
        ("TCP_CONNECT", OpenVpnState::TcpConnect),
        ("RESOLVE", OpenVpnState::Resolve),
        ("AUTH_PENDING", OpenVpnState::AuthPending),
    ];

    #[test]
    fn parse_all_known_states() {
        for (wire, expected) in ALL_KNOWN {
            assert_eq!(
                wire.parse::<OpenVpnState>().unwrap(),
                *expected,
                "failed for {wire}"
            );
        }
    }

    #[test]
    fn display_roundtrip() {
        for (_, variant) in ALL_KNOWN {
            let s = variant.to_string();
            assert_eq!(s.parse::<OpenVpnState>().unwrap(), *variant);
        }
    }

    #[test]
    fn unknown_state_is_err() {
        assert!("BOGUS".parse::<OpenVpnState>().is_err());
        assert!("connected".parse::<OpenVpnState>().is_err()); // case-sensitive
    }

    #[test]
    fn display_unknown() {
        let u = OpenVpnState::Unknown("FUTURE_STATE".to_string());
        assert_eq!(u.to_string(), "FUTURE_STATE");
    }

    #[test]
    fn error_preserves_input() {
        let err = "NOPE".parse::<OpenVpnState>().unwrap_err();
        assert_eq!(err.0, "NOPE");
        assert!(err.to_string().contains("NOPE"));
    }
}
