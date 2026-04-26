//! Parser for incoming CRV1 dynamic-challenge responses.
//!
//! When a client answers a CRV1 challenge issued via
//! [`Crv1Challenge`](crate::Crv1Challenge), it sends the answer back as the
//! password value of an `--auth-user-pass-verify` exchange.  The wire format
//! mirrors the challenge:
//!
//! ```text
//! CRV1:{flags}:{state_id_b64}:{username_b64}:{response_text}
//! ```
//!
//! In the client→server direction `flags` and `username_b64` are commonly
//! empty (`CRV1::<state>::<response>`), but the parser accepts populated
//! values too so that it round-trips with [`Crv1Challenge`].
//!
//! # Example
//!
//! ```
//! use openvpn_mgmt_codec::Crv1Response;
//!
//! let wire = "CRV1::T20wMXU3Rmg0THJHQlM3dWgwU1dtendhYlVpR2lXNmw=::123456";
//! let parsed: Crv1Response = wire.parse().unwrap();
//!
//! assert_eq!(parsed.flags, "");
//! assert_eq!(parsed.username, "");
//! assert_eq!(parsed.response, "123456");
//! ```

use base64::Engine;
use std::fmt;
use std::str::FromStr;

/// Errors produced when parsing a CRV1 response string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseCrv1ResponseError {
    /// String did not start with the `CRV1:` prefix.
    #[error("missing CRV1 prefix")]
    MissingPrefix,

    /// Wire format did not contain the expected five colon-separated fields.
    #[error("expected 5 colon-separated fields, got {0}")]
    WrongFieldCount(usize),

    /// `state_id` segment was not valid base64.
    #[error("state_id is not valid base64: {0}")]
    StateIdNotBase64(#[source] base64::DecodeError),

    /// `state_id` decoded successfully but was not valid UTF-8.
    #[error("state_id is not valid UTF-8: {0}")]
    StateIdNotUtf8(#[source] std::string::FromUtf8Error),

    /// `username` segment was not valid base64.
    #[error("username is not valid base64: {0}")]
    UsernameNotBase64(#[source] base64::DecodeError),

    /// `username` decoded successfully but was not valid UTF-8.
    #[error("username is not valid UTF-8: {0}")]
    UsernameNotUtf8(#[source] std::string::FromUtf8Error),
}

/// A parsed CRV1 response — the answer a client sends back to a
/// [`Crv1Challenge`](crate::Crv1Challenge).
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crv1Response {
    /// Flags echoed from the challenge. Typically empty in client→server
    /// direction.
    pub flags: String,

    /// State identifier, base64-decoded from the wire.
    pub state_id: String,

    /// Username, base64-decoded from the wire. Typically empty in
    /// client→server direction.
    pub username: String,

    /// Response text the user typed (e.g. an OTP code). Sent in clear text.
    pub response: String,
}

impl FromStr for Crv1Response {
    type Err = ParseCrv1ResponseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let rest = input
            .strip_prefix("CRV1:")
            .ok_or(ParseCrv1ResponseError::MissingPrefix)?;

        // After stripping `CRV1:` we expect 4 colon-separated fields:
        // flags : state_id_b64 : username_b64 : response_text.
        // The response itself may contain colons, so use splitn(4, ':').
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        if parts.len() != 4 {
            // Total field count including the CRV1 prefix.
            return Err(ParseCrv1ResponseError::WrongFieldCount(parts.len() + 1));
        }

        let engine = base64::engine::general_purpose::STANDARD;

        let state_id_bytes = engine
            .decode(parts[1])
            .map_err(ParseCrv1ResponseError::StateIdNotBase64)?;
        let state_id =
            String::from_utf8(state_id_bytes).map_err(ParseCrv1ResponseError::StateIdNotUtf8)?;

        let username_bytes = engine
            .decode(parts[2])
            .map_err(ParseCrv1ResponseError::UsernameNotBase64)?;
        let username =
            String::from_utf8(username_bytes).map_err(ParseCrv1ResponseError::UsernameNotUtf8)?;

        Ok(Self {
            flags: parts[0].to_string(),
            state_id,
            username,
            response: parts[3].to_string(),
        })
    }
}

impl fmt::Display for Crv1Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let engine = base64::engine::general_purpose::STANDARD;
        write!(
            f,
            "CRV1:{}:{}:{}:{}",
            self.flags,
            engine.encode(&self.state_id),
            engine.encode(&self.username),
            self.response,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Crv1Challenge;

    #[test]
    fn parses_suse_plugin_example() {
        // From SUSE openvpn-mfa-plugin: a real-world client→server response
        // with empty flags & username.
        let wire = "CRV1::T20wMXU3Rmg0THJHQlM3dWgwU1dtendhYlVpR2lXNmw=::123456";
        let parsed: Crv1Response = wire.parse().unwrap();

        assert_eq!(parsed.flags, "");
        assert_eq!(parsed.username, "");
        assert_eq!(parsed.response, "123456");
        // state_id base64-decodes to ASCII text in this fixture.
        assert_eq!(parsed.state_id, "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l");
    }

    #[test]
    fn missing_prefix_is_rejected() {
        assert_eq!(
            "FOO::abc::123".parse::<Crv1Response>(),
            Err(ParseCrv1ResponseError::MissingPrefix),
        );
    }

    #[test]
    fn too_few_fields_is_rejected() {
        // "CRV1:a:b:c" — only 3 fields after the CRV1 prefix.
        let err = "CRV1:a:b:c".parse::<Crv1Response>();
        assert_eq!(err, Err(ParseCrv1ResponseError::WrongFieldCount(4)));
    }

    #[test]
    fn invalid_base64_state_id() {
        let result = "CRV1::!!!not-base64!!!::123456".parse::<Crv1Response>();
        assert!(matches!(
            result,
            Err(ParseCrv1ResponseError::StateIdNotBase64(_))
        ));
    }

    #[test]
    fn invalid_base64_username() {
        // Valid empty state_id, invalid base64 username.
        let result = "CRV1:::!!!not-base64!!!:123456".parse::<Crv1Response>();
        assert!(matches!(
            result,
            Err(ParseCrv1ResponseError::UsernameNotBase64(_))
        ));
    }

    #[test]
    fn response_may_contain_colons() {
        // OTP codes are plain text; the response field uses splitn(4) so any
        // remaining colons stay in the response.
        let wire = "CRV1::c2Vzc2lvbg==::abc:def:ghi";
        let parsed: Crv1Response = wire.parse().unwrap();
        assert_eq!(parsed.state_id, "session");
        assert_eq!(parsed.response, "abc:def:ghi");
    }

    #[test]
    fn roundtrips_through_display() {
        let original = Crv1Response {
            flags: "R,E".to_string(),
            state_id: "session-xyz".to_string(),
            username: "alice".to_string(),
            response: "789012".to_string(),
        };

        let wire = original.to_string();
        let parsed: Crv1Response = wire.parse().unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn roundtrips_with_challenge_builder() {
        // The wire format is symmetric with Crv1Challenge — building a
        // challenge string and parsing it as a response should preserve all
        // fields.
        let challenge = Crv1Challenge::builder()
            .flags("R,E")
            .state_id("session-abc-123")
            .username("jdoe")
            .challenge_text("Enter your OTP code")
            .build();

        let wire = challenge.to_string();
        let parsed: Crv1Response = wire.parse().unwrap();

        assert_eq!(parsed.flags, challenge.flags);
        assert_eq!(parsed.state_id, challenge.state_id);
        assert_eq!(parsed.username, challenge.username);
        assert_eq!(parsed.response, challenge.challenge_text);
    }

    #[test]
    fn roundtrip_typical_client_response() {
        // The shape SUSE's plugin emits: empty flags & username, base64 state,
        // numeric OTP. Round-trip should be lossless.
        let original = Crv1Response {
            flags: String::new(),
            state_id: "opaque-state-id".to_string(),
            username: String::new(),
            response: "654321".to_string(),
        };

        let wire = original.to_string();
        assert!(wire.starts_with("CRV1::"));
        let reparsed: Crv1Response = wire.parse().unwrap();
        assert_eq!(reparsed, original);
    }
}
