use std::fmt;

/// OpenVPN connection state as reported in `>STATE:` notifications.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    Custom(String),
}

impl OpenVpnState {
    /// Parse a wire state string into a typed variant.
    pub(crate) fn parse(s: &str) -> Self {
        match s {
            "CONNECTING" => Self::Connecting,
            "WAIT" => Self::Wait,
            "AUTH" => Self::Auth,
            "GET_CONFIG" => Self::GetConfig,
            "ASSIGN_IP" => Self::AssignIp,
            "ADD_ROUTES" => Self::AddRoutes,
            "CONNECTED" => Self::Connected,
            "RECONNECTING" => Self::Reconnecting,
            "EXITING" => Self::Exiting,
            "TCP_CONNECT" => Self::TcpConnect,
            "RESOLVE" => Self::Resolve,
            "AUTH_PENDING" => Self::AuthPending,
            other => Self::Custom(other.to_string()),
        }
    }
}

impl fmt::Display for OpenVpnState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => f.write_str("CONNECTING"),
            Self::Wait => f.write_str("WAIT"),
            Self::Auth => f.write_str("AUTH"),
            Self::GetConfig => f.write_str("GET_CONFIG"),
            Self::AssignIp => f.write_str("ASSIGN_IP"),
            Self::AddRoutes => f.write_str("ADD_ROUTES"),
            Self::Connected => f.write_str("CONNECTED"),
            Self::Reconnecting => f.write_str("RECONNECTING"),
            Self::Exiting => f.write_str("EXITING"),
            Self::TcpConnect => f.write_str("TCP_CONNECT"),
            Self::Resolve => f.write_str("RESOLVE"),
            Self::AuthPending => f.write_str("AUTH_PENDING"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}
