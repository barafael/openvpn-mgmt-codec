use crate::auth::AuthType;
use crate::client_event::ClientEvent;
use crate::log_level::LogLevel;
use crate::openvpn_state::OpenVpnState;
use crate::transport_protocol::TransportProtocol;

/// Sub-types of `>PASSWORD:` notifications. The password notification
/// has several distinct forms with completely different structures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordNotification {
    /// `>PASSWORD:Need 'Auth' username/password`
    NeedAuth {
        /// The credential set being requested.
        auth_type: AuthType,
    },

    /// `>PASSWORD:Need 'Private Key' password`
    NeedPassword {
        /// The credential set being requested.
        auth_type: AuthType,
    },

    /// `>PASSWORD:Verification Failed: 'Auth'`
    VerificationFailed {
        /// The credential set that failed verification.
        auth_type: AuthType,
    },

    /// Static challenge: `>PASSWORD:Need 'Auth' username/password SC:{echo},{challenge}`
    StaticChallenge {
        /// Whether to echo the user's response (from the `echo` flag: `0` or `1`).
        echo: bool,
        /// The challenge text presented to the user.
        challenge: String,
    },

    /// Dynamic challenge (CRV1):
    /// `>PASSWORD:Need 'Auth' username/password CRV1:{flags}:{state_id}:{username_b64}:{challenge}`
    DynamicChallenge {
        /// Comma-separated CRV1 flags.
        flags: String,
        /// Opaque state identifier for the auth backend.
        state_id: String,
        /// Base64-encoded username.
        username_b64: String,
        /// The challenge text presented to the user.
        challenge: String,
    },
}

/// A parsed real-time notification from OpenVPN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notification {
    /// A multi-line `>CLIENT:` notification (CONNECT, REAUTH, ESTABLISHED,
    /// DISCONNECT). The header and all ENV key=value pairs are accumulated
    /// into a single struct before this is emitted.
    Client {
        /// The client event sub-type.
        event: ClientEvent,
        /// Client ID (sequential, assigned by OpenVPN).
        cid: u64,
        /// Key ID (present for CONNECT/REAUTH, absent for ESTABLISHED/DISCONNECT).
        kid: Option<u64>,
        /// Accumulated ENV pairs, in order. Each `>CLIENT:ENV,key=val` line
        /// becomes one `(key, val)` entry. The terminating `>CLIENT:ENV,END`
        /// is consumed but not included.
        env: Vec<(String, String)>,
    },

    /// A single-line `>CLIENT:ADDRESS` notification.
    ClientAddress {
        /// Client ID.
        cid: u64,
        /// Assigned virtual address.
        addr: String,
        /// Whether this is the primary address for the client.
        primary: bool,
    },

    /// `>STATE:timestamp,name,description,local_ip,remote_ip[,local_port,remote_port]`
    State {
        /// Unix timestamp of the state change.
        timestamp: u64,
        /// State name (e.g. `Connected`, `Reconnecting`).
        name: OpenVpnState,
        /// Verbose description of the state.
        description: String,
        /// Local tunnel IP address (may be empty).
        local_ip: String,
        /// Remote server IP address (may be empty).
        remote_ip: String,
        /// Local port (may be empty, OpenVPN 2.1+).
        local_port: String,
        /// Remote port (may be empty, OpenVPN 2.1+).
        remote_port: String,
    },

    /// `>BYTECOUNT:bytes_in,bytes_out` (client mode)
    ByteCount {
        /// Bytes received since last reset.
        bytes_in: u64,
        /// Bytes sent since last reset.
        bytes_out: u64,
    },

    /// `>BYTECOUNT_CLI:cid,bytes_in,bytes_out` (server mode, per-client)
    ByteCountCli {
        /// Client ID.
        cid: u64,
        /// Bytes received from this client.
        bytes_in: u64,
        /// Bytes sent to this client.
        bytes_out: u64,
    },

    /// `>LOG:timestamp,level,message`
    Log {
        /// Unix timestamp of the log entry.
        timestamp: u64,
        /// Log severity level.
        level: LogLevel,
        /// The log message text.
        message: String,
    },

    /// `>ECHO:timestamp,param_string`
    Echo {
        /// Unix timestamp.
        timestamp: u64,
        /// The echoed parameter string.
        param: String,
    },

    /// `>HOLD:Waiting for hold release[:N]`
    Hold {
        /// The hold message text.
        text: String,
    },

    /// `>FATAL:message`
    Fatal {
        /// The fatal error message.
        message: String,
    },

    /// `>PKCS11ID-COUNT:count`
    Pkcs11IdCount {
        /// Number of available PKCS#11 identities.
        count: u32,
    },

    /// `>NEED-OK:Need 'name' confirmation MSG:message`
    NeedOk {
        /// The prompt name.
        name: String,
        /// The prompt message to display.
        message: String,
    },

    /// `>NEED-STR:Need 'name' input MSG:message`
    NeedStr {
        /// The prompt name.
        name: String,
        /// The prompt message to display.
        message: String,
    },

    /// `>RSA_SIGN:base64_data`
    RsaSign {
        /// Base64-encoded data to be signed.
        data: String,
    },

    /// `>REMOTE:host,port,protocol`
    Remote {
        /// Remote server hostname or IP.
        host: String,
        /// Remote server port.
        port: u16,
        /// Transport protocol.
        protocol: TransportProtocol,
    },

    /// `>PROXY:proto_num,proto_type,host[,port]`
    Proxy {
        /// Numeric protocol identifier.
        proto_num: u32,
        /// Transport protocol type.
        proto_type: TransportProtocol,
        /// Server hostname or IP.
        host: String,
        /// Server port (`0` if not provided by the server).
        port: u16,
    },

    /// `>PASSWORD:...` — see [`PasswordNotification`] for the sub-types.
    Password(PasswordNotification),

    /// Fallback for any notification type not explicitly modeled above.
    /// Kept for forward compatibility with future OpenVPN versions.
    Simple {
        /// The notification type keyword (e.g. `"BYTECOUNT"`).
        kind: String,
        /// Everything after the first colon.
        payload: String,
    },
}

/// A fully decoded message from the OpenVPN management interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OvpnMessage {
    /// A success response: `SUCCESS: [text]`.
    Success(String),

    /// An error response: `ERROR: [text]`.
    Error(String),

    /// A multi-line response block (from `status`, `version`, `help`, etc.).
    /// The terminating `END` line is consumed but not included.
    MultiLine(Vec<String>),

    /// A single non-SUCCESS/ERROR value line (from bare `hold`, bare `state`,
    /// etc.).
    SingleValue(String),

    /// Parsed response from `pkcs11-id-get`. The wire format is:
    /// `PKCS11ID-ENTRY:'index', ID:'id', BLOB:'base64_cert'`
    Pkcs11IdEntry {
        /// Certificate index.
        index: String,
        /// PKCS#11 identifier.
        id: String,
        /// Base64-encoded certificate blob.
        blob: String,
    },

    /// A real-time notification, either single-line or accumulated multi-line.
    Notification(Notification),

    /// The `>INFO:` banner sent when the management socket first connects.
    /// Technically a notification, but surfaced separately since it's always
    /// the first thing you see and is useful for version detection.
    Info(String),

    /// Management interface password prompt. Sent when `--management` is
    /// configured with a password file. The client must respond with the
    /// password (via [`crate::OvpnCommand::ManagementPassword`]) before any
    /// commands are accepted.
    PasswordPrompt,

    /// A line that could not be classified into any known message type.
    /// Contains the raw line and a description of what went wrong.
    Unrecognized {
        /// The raw line that could not be parsed.
        line: String,
        /// Why the line was not recognized.
        kind: crate::unrecognized::UnrecognizedKind,
    },
}
