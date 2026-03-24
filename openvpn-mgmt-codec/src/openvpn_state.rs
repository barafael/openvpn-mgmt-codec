use std::str::FromStr;

/// Error returned when a string is not a recognized OpenVPN state.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized OpenVPN state: {0:?}")]
pub struct ParseOpenVpnStateError(pub String);

/// OpenVPN connection state as reported in `>STATE:` notifications.
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
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
