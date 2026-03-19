/// Proxy configuration for the `proxy` command (sent in response to a
/// `>PROXY:` notification, requires `--management-query-proxy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyAction {
    /// Connect directly, no proxy.
    None,
    /// Use an HTTP proxy.
    Http {
        /// Proxy hostname or IP.
        host: String,
        /// Proxy port.
        port: u16,
        /// If true, pass the `"nct"` flag to allow only non-cleartext
        /// authentication with the proxy.
        non_cleartext_only: bool,
    },
    /// Use a SOCKS proxy.
    Socks {
        /// Proxy hostname or IP.
        host: String,
        /// Proxy port.
        port: u16,
    },
}
