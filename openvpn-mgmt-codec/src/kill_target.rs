/// How to identify a client to kill (server mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillTarget {
    /// Kill by Common Name from the client's TLS certificate.
    CommonName(String),

    /// Kill by exact `protocol:IP:port` of the client's real address.
    /// Wire: `kill tcp:1.2.3.4:4000`
    Address {
        /// Transport protocol (`"tcp"` or `"udp"`).
        protocol: String,
        /// Client IP address.
        ip: String,
        /// Client source port.
        port: u16,
    },
}
