#![doc = include_str!("../README.md")]
#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Authentication credential types and retry strategies.
pub mod auth;
/// High-level management client with notification dispatch.
pub mod client;
/// Typed client-deny command with builder support.
pub mod client_deny;
/// Client notification event types (CONNECT, REAUTH, etc.).
pub mod client_event;
/// The [`OvpnCodec`] encoder/decoder implementation.
pub mod codec;
/// Typed management-interface commands ([`OvpnCommand`]).
pub mod command;
/// Builder for outgoing CRV1 dynamic-challenge strings.
pub mod crv1_challenge;
/// Client kill-target addressing.
pub mod kill_target;
/// Log severity levels (Info, Debug, Warning, etc.).
pub mod log_level;
/// Decoded messages and real-time notifications.
pub mod message;
/// Responses to `>NEED-OK:` prompts.
pub mod need_ok;
/// OpenVPN connection states (CONNECTING, CONNECTED, etc.).
pub mod openvpn_state;
/// Typed parsers for `SUCCESS:` payloads and multi-line responses.
pub mod parsed_response;
/// Proxy configuration for `>PROXY:` responses.
pub mod proxy_action;
/// A wrapper type that masks sensitive values in debug/display output.
pub mod redacted;
/// Remote-override actions for `>REMOTE:` responses.
pub mod remote_action;
/// Daemon signals (HUP, TERM, USR1, USR2).
pub mod signal;
/// Typed parsers for `status` command responses (client table, routing, stats).
pub mod status;
/// Status output format versions (V1/V2/V3).
pub mod status_format;
/// Stream adapter categorizing messages as responses or notifications.
pub mod stream;
/// Stream mode selectors (on/off/all/recent).
pub mod stream_mode;
/// Lightweight UTC timestamp formatting.
pub mod timestamp;
/// Transport protocol (UDP, TCP) for remote/proxy notifications.
pub mod transport_protocol;
/// Error classification for unrecognized protocol lines.
pub mod unrecognized;
/// Parsed version information from the `version` command.
pub mod version_info;

pub use auth::{AuthRetryMode, AuthType, ParseAuthRetryModeError, ParseAuthTypeError};
pub use client_deny::ClientDeny;
pub use client_event::{ClientEvent, ParseClientEventError};
pub use codec::{AccumulationLimit, EncodeError, EncoderMode, OvpnCodec};
pub use command::{CommandParseError, OvpnCommand, RemoteEntryRange};
pub use crv1_challenge::Crv1Challenge;
pub use kill_target::KillTarget;
pub use log_level::{LogLevel, ParseLogLevelError};
pub use message::{Notification, OvpnMessage, PasswordNotification};
pub use need_ok::NeedOkResponse;
pub use openvpn_state::{OpenVpnState, ParseOpenVpnStateError};
pub use proxy_action::ProxyAction;
pub use redacted::Redacted;
pub use remote_action::RemoteAction;
pub use signal::{ParseSignalError, Signal};
pub use status_format::{ParseStatusFormatError, StatusFormat};
pub use stream_mode::{ParseStreamModeError, StreamMode};
pub use transport_protocol::{ParseTransportProtocolError, TransportProtocol};
pub use unrecognized::UnrecognizedKind;
pub use version_info::VersionInfo;

// Re-export key items from sub-modules for convenience.
pub use client::{ClientError, ManagementClient};
pub use command::{connection_sequence, server_connection_sequence};
pub use parsed_response::{LoadStats, ParseResponseError, StateEntry};
pub use status::{
    ClientStatistics, ConnectedClient, ParseStatusError, RoutingEntry, StatusResponse,
    parse_client_statistics, parse_status,
};
pub use stream::{ClassifyExt, ManagementEvent};
