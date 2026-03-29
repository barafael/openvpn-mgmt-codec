use std::str::FromStr;

/// Error returned when a string is not a recognized auth type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized auth type: {0:?}")]
pub struct ParseAuthTypeError(String);

/// Error returned when a string is not a recognized auth retry mode.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unrecognized auth retry mode: {0:?}")]
pub struct ParseAuthRetryModeError(String);

/// Authentication credential type. OpenVPN identifies credential requests
/// by a quoted type string — usually `"Auth"` or `"Private Key"`, but
/// plugins can define custom types.
#[derive(Debug, Clone, PartialEq, Eq, Hash, strum::Display)]
pub enum AuthType {
    /// Standard `--auth-user-pass` credentials. Wire: `"Auth"`.
    Auth,

    /// Private key passphrase (encrypted key file). Wire: `"Private Key"`.
    #[strum(to_string = "Private Key")]
    PrivateKey,

    /// HTTP proxy credentials. Wire: `"HTTP Proxy"`.
    #[strum(to_string = "HTTP Proxy")]
    HttpProxy,

    /// SOCKS proxy credentials. Wire: `"SOCKS Proxy"`.
    #[strum(to_string = "SOCKS Proxy")]
    SocksProxy,

    /// Plugin-defined or otherwise unrecognized auth type.
    #[strum(default)]
    Unknown(String),
}

impl FromStr for AuthType {
    type Err = ParseAuthTypeError;

    /// Parse a recognized auth type string.
    ///
    /// Recognized values: `Auth`, `Private Key`, `HTTP Proxy`, `SOCKS Proxy`.
    /// Returns `Err` for anything else — use [`AuthType::Unknown`] explicitly
    /// if forward-compatible fallback is desired.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "Auth" => Ok(Self::Auth),
            "Private Key" => Ok(Self::PrivateKey),
            "HTTP Proxy" => Ok(Self::HttpProxy),
            "SOCKS Proxy" => Ok(Self::SocksProxy),
            other => Err(ParseAuthTypeError(other.to_string())),
        }
    }
}

/// Controls how OpenVPN retries after authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum AuthRetryMode {
    /// Don't retry — exit on auth failure.
    None,

    /// Retry, re-prompting for credentials.
    Interact,

    /// Retry without re-prompting.
    #[strum(to_string = "nointeract")]
    NoInteract,
}

impl FromStr for AuthRetryMode {
    type Err = ParseAuthRetryModeError;

    /// Parse an auth-retry mode: `none`, `interact`, or `nointeract`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "none" => Ok(Self::None),
            "interact" => Ok(Self::Interact),
            "nointeract" => Ok(Self::NoInteract),
            other => Err(ParseAuthRetryModeError(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(AuthType::Auth)]
    #[test_case(AuthType::PrivateKey)]
    #[test_case(AuthType::HttpProxy)]
    #[test_case(AuthType::SocksProxy)]
    fn auth_type_roundtrip(at: AuthType) {
        let string = at.to_string();
        assert_eq!(string.parse::<AuthType>().unwrap(), at);
    }

    #[test]
    fn auth_type_phantom_aliases_are_rejected() {
        assert!("PrivateKey".parse::<AuthType>().is_err());
        assert!("HTTPProxy".parse::<AuthType>().is_err());
        assert!("SOCKSProxy".parse::<AuthType>().is_err());
    }

    #[test]
    fn auth_type_unknown_is_err() {
        assert!("MyPlugin".parse::<AuthType>().is_err());
    }

    #[test_case(AuthRetryMode::None)]
    #[test_case(AuthRetryMode::Interact)]
    #[test_case(AuthRetryMode::NoInteract)]
    fn auth_retry_roundtrip(mode: AuthRetryMode) {
        let string = mode.to_string();
        assert_eq!(string.parse::<AuthRetryMode>().unwrap(), mode);
    }

    #[test]
    fn auth_retry_invalid() {
        assert!("bogus".parse::<AuthRetryMode>().is_err());
    }
}
