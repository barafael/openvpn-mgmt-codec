use std::fmt;
use std::str::FromStr;

/// Authentication credential type. OpenVPN identifies credential requests
/// by a quoted type string — usually `"Auth"` or `"Private Key"`, but
/// plugins can define custom types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthType {
    /// Standard `--auth-user-pass` credentials. Wire: `"Auth"`.
    Auth,

    /// Private key passphrase (encrypted key file). Wire: `"Private Key"`.
    PrivateKey,

    /// HTTP proxy credentials. Wire: `"HTTP Proxy"`.
    HttpProxy,

    /// SOCKS proxy credentials. Wire: `"SOCKS Proxy"`.
    SocksProxy,

    /// Plugin-defined or otherwise unrecognized auth type.
    Custom(String),
}

impl fmt::Display for AuthType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auth => f.write_str("Auth"),
            Self::PrivateKey => f.write_str("Private Key"),
            Self::HttpProxy => f.write_str("HTTP Proxy"),
            Self::SocksProxy => f.write_str("SOCKS Proxy"),
            Self::Custom(s) => f.write_str(s),
        }
    }
}

impl FromStr for AuthType {
    type Err = std::convert::Infallible;

    /// Parse an auth type string. Recognized values: `Auth`, `PrivateKey` /
    /// `Private Key`, `HTTPProxy` / `HTTP Proxy`, `SOCKSProxy` / `SOCKS Proxy`.
    /// Anything else becomes [`AuthType::Custom`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Auth" => Self::Auth,
            "PrivateKey" | "Private Key" => Self::PrivateKey,
            "HTTPProxy" | "HTTP Proxy" => Self::HttpProxy,
            "SOCKSProxy" | "SOCKS Proxy" => Self::SocksProxy,
            other => Self::Custom(other.to_string()),
        })
    }
}

/// Controls how OpenVPN retries after authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRetryMode {
    /// Don't retry — exit on auth failure.
    None,

    /// Retry, re-prompting for credentials.
    Interact,

    /// Retry without re-prompting.
    NoInteract,
}

impl fmt::Display for AuthRetryMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::Interact => f.write_str("interact"),
            Self::NoInteract => f.write_str("nointeract"),
        }
    }
}

impl FromStr for AuthRetryMode {
    type Err = String;

    /// Parse an auth-retry mode: `none`, `interact`, or `nointeract`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "interact" => Ok(Self::Interact),
            "nointeract" => Ok(Self::NoInteract),
            _ => Err(format!(
                "invalid auth-retry mode: {s} (use none/interact/nointeract)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_type_roundtrip() {
        for at in [
            AuthType::Auth,
            AuthType::PrivateKey,
            AuthType::HttpProxy,
            AuthType::SocksProxy,
        ] {
            let s = at.to_string();
            assert_eq!(s.parse::<AuthType>().unwrap(), at);
        }
    }

    #[test]
    fn auth_type_aliases() {
        assert_eq!(
            "PrivateKey".parse::<AuthType>().unwrap(),
            AuthType::PrivateKey
        );
        assert_eq!(
            "Private Key".parse::<AuthType>().unwrap(),
            AuthType::PrivateKey
        );
        assert_eq!(
            "HTTPProxy".parse::<AuthType>().unwrap(),
            AuthType::HttpProxy
        );
        assert_eq!(
            "SOCKSProxy".parse::<AuthType>().unwrap(),
            AuthType::SocksProxy
        );
    }

    #[test]
    fn auth_type_custom_fallback() {
        assert_eq!(
            "MyPlugin".parse::<AuthType>().unwrap(),
            AuthType::Custom("MyPlugin".to_string())
        );
    }

    #[test]
    fn auth_retry_roundtrip() {
        for mode in [
            AuthRetryMode::None,
            AuthRetryMode::Interact,
            AuthRetryMode::NoInteract,
        ] {
            let s = mode.to_string();
            assert_eq!(s.parse::<AuthRetryMode>().unwrap(), mode);
        }
    }

    #[test]
    fn auth_retry_invalid() {
        assert!("bogus".parse::<AuthRetryMode>().is_err());
    }
}
