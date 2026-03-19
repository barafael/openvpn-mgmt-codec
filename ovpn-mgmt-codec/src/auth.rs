use std::fmt;

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
