use std::str::FromStr;

/// Error returned when a string is not a recognized client event.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized client event: {0:?}")]
pub struct ParseClientEventError(pub String);

/// The sub-type of a `>CLIENT:` notification.
#[derive(Debug, Clone, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum ClientEvent {
    /// A new client is connecting (`>CLIENT:CONNECT`).
    Connect,

    /// An existing client is re-authenticating (`>CLIENT:REAUTH`).
    Reauth,

    /// A client connection has been fully established (`>CLIENT:ESTABLISHED`).
    Established,

    /// A client has disconnected (`>CLIENT:DISCONNECT`).
    Disconnect,

    /// A client challenge-response (`>CLIENT:CR_RESPONSE,{CID},{KID},{base64}`).
    ///
    /// The base64-encoded response is carried inline because it appears as
    /// the third comma-separated field on the header line (after CID and KID),
    /// not in the ENV block. Both cedws/openvpn-mgmt-go and
    /// jkroepke/openvpn-auth-oauth2 handle this as a distinct event type.
    CrResponse(String),

    /// An unrecognized event type (forward compatibility).
    #[strum(default)]
    Unknown(String),
}

impl FromStr for ClientEvent {
    type Err = ParseClientEventError;

    /// Parse a recognized client event string.
    ///
    /// Recognized values: `CONNECT`, `REAUTH`, `ESTABLISHED`, `DISCONNECT`.
    /// Returns `Err` for anything else — use [`ClientEvent::Unknown`]
    /// explicitly if forward-compatible fallback is desired.
    ///
    /// Note: `CR_RESPONSE` is handled separately in the codec because it
    /// carries an inline base64 field; it is not recognized by `FromStr`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "CONNECT" => Ok(Self::Connect),
            "REAUTH" => Ok(Self::Reauth),
            "ESTABLISHED" => Ok(Self::Established),
            "DISCONNECT" => Ok(Self::Disconnect),
            other => Err(ParseClientEventError(other.to_string())),
        }
    }
}
