#![doc = include_str!("../README.md")]

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Authentication credential types and retry strategies.
pub mod auth;
/// The [`OvpnCodec`] encoder/decoder implementation.
pub mod codec;
/// Typed management-interface commands ([`OvpnCommand`]).
pub mod command;
/// Client kill-target addressing.
pub mod kill_target;
/// Decoded messages and real-time notifications.
pub mod message;
/// Responses to `>NEED-OK:` prompts.
pub mod need_ok;
/// Proxy configuration for `>PROXY:` responses.
pub mod proxy_action;
/// Remote-override actions for `>REMOTE:` responses.
pub mod remote_action;
/// Daemon signals (HUP, TERM, USR1, USR2).
pub mod signal;
/// Status output format versions (V1/V2/V3).
pub mod status_format;
/// Stream mode selectors (on/off/all/recent).
pub mod stream_mode;
/// Error classification for unrecognized protocol lines.
pub mod unrecognized;

pub use auth::{AuthRetryMode, AuthType};
pub use codec::OvpnCodec;
pub use command::OvpnCommand;
pub use kill_target::KillTarget;
pub use message::{Notification, OvpnMessage, PasswordNotification};
pub use need_ok::NeedOkResponse;
pub use proxy_action::ProxyAction;
pub use remote_action::RemoteAction;
pub use signal::Signal;
pub use status_format::StatusFormat;
pub use stream_mode::StreamMode;
pub use unrecognized::UnrecognizedKind;
