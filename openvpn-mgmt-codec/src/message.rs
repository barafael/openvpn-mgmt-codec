use std::fmt;

use crate::auth::AuthType;
use crate::client_event::ClientEvent;
use crate::log_level::LogLevel;
use crate::openvpn_state::OpenVpnState;
use crate::redacted::Redacted;

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

    /// Static challenge: `>PASSWORD:Need 'Auth' username/password SC:{flag},{challenge}`
    /// The flag is a multi-bit integer: bit 0 = ECHO, bit 1 = FORMAT.
    StaticChallenge {
        /// Whether to echo the user's response (bit 0 of the SC flag).
        echo: bool,
        /// Whether the response should be concatenated with the password
        /// as plain text (bit 1 of the SC flag). When `false`, the response
        /// and password are base64-encoded per the SCRV1 format.
        response_concat: bool,
        /// The challenge text presented to the user.
        challenge: String,
    },

    /// `>PASSWORD:Auth-Token:{token}`
    ///
    /// Pushed by the server when `--auth-token` is active. The client should
    /// store this token and use it in place of the original password on
    /// subsequent re-authentications.
    ///
    /// Source: OpenVPN `manage.c` — `management_auth_token()`.
    AuthToken {
        /// The opaque auth-token string (redacted in debug output).
        token: Redacted,
    },

    /// Dynamic challenge (CRV1):
    /// `>PASSWORD:Verification Failed: 'Auth' ['CRV1:{flags}:{state_id}:{username_b64}:{challenge}']`
    DynamicChallenge {
        /// Comma-separated CRV1 flags.
        flags: String,
        /// Opaque state identifier for the auth backend.
        state_id: String,
        /// Base64-encoded username. Note: visible in [`Debug`] output — callers
        /// handling PII should avoid logging this variant without filtering.
        username_b64: String,
        /// The challenge text presented to the user.
        challenge: String,
    },
}

/// ENV key names whose values are masked in `Debug` output to prevent
/// accidental exposure in logs. Used by `RedactedEnv` below (invoked from
/// `derive_more::Debug` on [`Notification::Client::env`]).
#[allow(dead_code)] // used via derive_more::Debug attribute
const SENSITIVE_ENV_KEYS: &[&str] = &["password"];

/// A parsed real-time notification from OpenVPN.
///
/// The [`Debug`] implementation masks the values of known sensitive ENV
/// keys (e.g. `password`) in [`Client`](Notification::Client) notifications,
/// printing `<redacted>` instead.
#[derive(derive_more::Debug, Clone, PartialEq, Eq)]
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
        #[debug("{:?}", RedactedEnv(env))]
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

    /// `>STATE:timestamp,name,desc,local_ip,remote_ip,remote_port,local_addr,local_port,local_ipv6`
    ///
    /// Field order per management-notes.txt: (a) timestamp, (b) state name,
    /// (c) description, (d) TUN/TAP local IPv4, (e) remote server address,
    /// (f) remote server port, (g) local address, (h) local port,
    /// (i) TUN/TAP local IPv6.
    State {
        /// (a) Unix timestamp of the state change.
        timestamp: u64,
        /// (b) State name (e.g. `Connected`, `Reconnecting`).
        name: OpenVpnState,
        /// (c) Verbose description (mostly for RECONNECTING/EXITING).
        description: String,
        /// (d) TUN/TAP local IPv4 address (may be empty).
        local_ip: String,
        /// (e) Remote server address (may be empty).
        remote_ip: String,
        /// (f) Remote server port (empty in many states).
        remote_port: Option<u16>,
        /// (g) Local address (may be empty).
        local_addr: String,
        /// (h) Local port (empty in many states).
        local_port: Option<u16>,
        /// (i) TUN/TAP local IPv6 address (may be empty).
        local_ipv6: String,
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

    /// `>PK_SIGN:base64_data[,algorithm]`
    ///
    /// Sent by OpenVPN 2.5+ when `--management-external-key` is active and
    /// a signature is needed. The management client responds with
    /// [`PkSig`](crate::OvpnCommand::PkSig).
    ///
    /// The `algorithm` field is present only when the management client
    /// announced version > 2 via the `version` command.
    ///
    /// Source: [`management-notes.txt`](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt),
    /// [`ssl_openssl.c` `get_sig_from_man()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_openssl.c).
    PkSign {
        /// Base64-encoded data to be signed.
        data: String,
        /// Signing algorithm (e.g. `RSA_PKCS1_PADDING`, `EC`).
        /// Only present when management client version > 2.
        algorithm: Option<String>,
    },

    /// `>INFO:message`
    ///
    /// Informational notification sent at any time (not just the initial banner).
    /// Notable sub-types include `>INFO:WEB_AUTH::url` for web-based authentication.
    ///
    /// The initial `>INFO:` banner on connect is still surfaced as
    /// [`OvpnMessage::Info`] (before the codec enters notification mode).
    /// This variant captures all subsequent `>INFO:` messages.
    Info {
        /// The info message content.
        message: String,
    },

    /// `>REMOTE:host,port,protocol`
    Remote {
        /// Remote server hostname or IP.
        host: String,
        /// Remote server port.
        port: u16,
        /// Transport protocol.
        protocol: crate::transport_protocol::TransportProtocol,
    },

    /// `>PROXY:index,proxy_type,host`
    ///
    /// Sent when OpenVPN needs proxy information (requires
    /// `--management-query-proxy`). The management client responds
    /// with a `proxy` command.
    Proxy {
        /// Connection index (1-based).
        index: u32,
        /// Proxy type (e.g. `TCP`, `UDP`).
        proxy_type: crate::transport_protocol::TransportProtocol,
        /// Server hostname or IP to connect through.
        host: String,
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

/// Helper for Debug output: displays env entries, masking sensitive keys.
/// Constructed by `derive_more::Debug` on [`Notification::Client::env`].
#[allow(dead_code)] // used via derive_more::Debug attribute
struct RedactedEnv<'a>(&'a [(String, String)]);

impl fmt::Debug for RedactedEnv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(k, v)| {
                if SENSITIVE_ENV_KEYS.contains(&k.as_str()) {
                    (k.as_str(), "<redacted>")
                } else {
                    (k.as_str(), v.as_str())
                }
            }))
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_protocol::TransportProtocol;
    // --- Debug redaction ---

    #[test]
    fn debug_redacts_password_env_key() {
        let notif = Notification::Client {
            event: ClientEvent::Connect,
            cid: 1,
            kid: Some(0),
            env: vec![
                ("common_name".to_string(), "alice".to_string()),
                ("password".to_string(), "s3cret".to_string()),
            ],
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("alice"), "non-sensitive values should appear");
        assert!(
            !dbg.contains("s3cret"),
            "password value must not appear in Debug output"
        );
        assert!(
            dbg.contains("<redacted>"),
            "password value should be replaced with <redacted>"
        );
    }

    #[test]
    fn debug_does_not_redact_non_sensitive_keys() {
        let notif = Notification::Client {
            event: ClientEvent::Disconnect,
            cid: 5,
            kid: None,
            env: vec![("untrusted_ip".to_string(), "10.0.0.1".to_string())],
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("10.0.0.1"));
    }

    // --- PasswordNotification variants ---

    #[test]
    fn password_notification_debug_redacts_token() {
        let notif = PasswordNotification::AuthToken {
            token: Redacted::new("super-secret-token".to_string()),
        };
        let dbg = format!("{notif:?}");
        assert!(
            !dbg.contains("super-secret-token"),
            "auth token must not appear in Debug output"
        );
    }

    #[test]
    fn password_notification_eq() {
        let a = PasswordNotification::NeedAuth {
            auth_type: AuthType::Auth,
        };
        let b = PasswordNotification::NeedAuth {
            auth_type: AuthType::Auth,
        };
        assert_eq!(a, b);

        let c = PasswordNotification::NeedPassword {
            auth_type: AuthType::PrivateKey,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn password_notification_static_challenge_fields() {
        let sc = PasswordNotification::StaticChallenge {
            echo: true,
            response_concat: false,
            challenge: "Enter PIN".to_string(),
        };
        if let PasswordNotification::StaticChallenge {
            echo,
            response_concat,
            challenge,
        } = sc
        {
            assert!(echo);
            assert!(!response_concat);
            assert_eq!(challenge, "Enter PIN");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn password_notification_dynamic_challenge_fields() {
        let dc = PasswordNotification::DynamicChallenge {
            flags: "R,E".to_string(),
            state_id: "abc123".to_string(),
            username_b64: "dXNlcg==".to_string(),
            challenge: "Enter OTP".to_string(),
        };
        if let PasswordNotification::DynamicChallenge {
            flags,
            state_id,
            challenge,
            ..
        } = dc
        {
            assert_eq!(flags, "R,E");
            assert_eq!(state_id, "abc123");
            assert_eq!(challenge, "Enter OTP");
        } else {
            panic!("wrong variant");
        }
    }

    // --- Notification Debug output for each variant ---

    #[test]
    fn debug_state_notification() {
        let notif = Notification::State {
            timestamp: 1700000000,
            name: OpenVpnState::Connected,
            description: "SUCCESS".to_string(),
            local_ip: "10.0.0.2".to_string(),
            remote_ip: "1.2.3.4".to_string(),
            remote_port: Some(1194),
            local_addr: "192.168.1.5".to_string(),
            local_port: Some(51234),
            local_ipv6: String::new(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("State"));
        assert!(dbg.contains("Connected"));
        assert!(dbg.contains("10.0.0.2"));
    }

    #[test]
    fn debug_bytecount() {
        let notif = Notification::ByteCount {
            bytes_in: 1024,
            bytes_out: 2048,
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("1024"));
        assert!(dbg.contains("2048"));
    }

    #[test]
    fn debug_bytecount_cli() {
        let notif = Notification::ByteCountCli {
            cid: 7,
            bytes_in: 100,
            bytes_out: 200,
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("ByteCountCli"));
        assert!(dbg.contains("7"));
    }

    #[test]
    fn debug_log() {
        let notif = Notification::Log {
            timestamp: 1700000000,
            level: LogLevel::Warning,
            message: "something happened".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Log"));
        assert!(dbg.contains("something happened"));
    }

    #[test]
    fn debug_echo() {
        let notif = Notification::Echo {
            timestamp: 123,
            param: "push-update".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Echo"));
        assert!(dbg.contains("push-update"));
    }

    #[test]
    fn debug_hold() {
        let notif = Notification::Hold {
            text: "Waiting for hold release".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Hold"));
    }

    #[test]
    fn debug_fatal() {
        let notif = Notification::Fatal {
            message: "cannot allocate TUN/TAP".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Fatal"));
        assert!(dbg.contains("cannot allocate TUN/TAP"));
    }

    #[test]
    fn debug_remote() {
        let notif = Notification::Remote {
            host: "vpn.example.com".to_string(),
            port: 1194,
            protocol: TransportProtocol::Udp,
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Remote"));
        assert!(dbg.contains("vpn.example.com"));
    }

    #[test]
    fn debug_proxy() {
        let notif = Notification::Proxy {
            index: 1,
            proxy_type: TransportProtocol::Tcp,
            host: "proxy.local".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Proxy"));
        assert!(dbg.contains("proxy.local"));
    }

    #[test]
    fn debug_pk_sign_with_algorithm() {
        let notif = Notification::PkSign {
            data: "dGVzdA==".to_string(),
            algorithm: Some("RSA_PKCS1_PADDING".to_string()),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("PkSign"));
        assert!(dbg.contains("RSA_PKCS1_PADDING"));
        assert!(dbg.contains("dGVzdA=="));
    }

    #[test]
    fn debug_pk_sign_without_algorithm() {
        let notif = Notification::PkSign {
            data: "dGVzdA==".to_string(),
            algorithm: None,
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("PkSign"));
        assert!(dbg.contains("None"));
    }

    #[test]
    fn debug_info_notification() {
        let notif = Notification::Info {
            message: "WEB_AUTH::https://example.com/auth".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("Info"));
        assert!(dbg.contains("WEB_AUTH"));
    }

    #[test]
    fn debug_simple_fallback() {
        let notif = Notification::Simple {
            kind: "FUTURE_TYPE".to_string(),
            payload: "some data".to_string(),
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("FUTURE_TYPE"));
        assert!(dbg.contains("some data"));
    }

    #[test]
    fn debug_client_address() {
        let notif = Notification::ClientAddress {
            cid: 42,
            addr: "10.8.0.6".to_string(),
            primary: true,
        };
        let dbg = format!("{notif:?}");
        assert!(dbg.contains("ClientAddress"));
        assert!(dbg.contains("10.8.0.6"));
        assert!(dbg.contains("true"));
    }

    // --- OvpnMessage variants ---

    #[test]
    fn ovpn_message_eq() {
        assert_eq!(
            OvpnMessage::Success("pid=42".to_string()),
            OvpnMessage::Success("pid=42".to_string()),
        );
        assert_ne!(
            OvpnMessage::Success("a".to_string()),
            OvpnMessage::Error("a".to_string()),
        );
    }

    #[test]
    fn ovpn_message_pkcs11_entry() {
        let msg = OvpnMessage::Pkcs11IdEntry {
            index: "0".to_string(),
            id: "slot_0".to_string(),
            blob: "AQID".to_string(),
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("Pkcs11IdEntry"));
        assert!(dbg.contains("slot_0"));
    }

    #[test]
    fn ovpn_message_password_prompt() {
        assert_eq!(OvpnMessage::PasswordPrompt, OvpnMessage::PasswordPrompt);
    }

    #[test]
    fn ovpn_message_unrecognized() {
        let msg = OvpnMessage::Unrecognized {
            line: "garbage".to_string(),
            kind: crate::unrecognized::UnrecognizedKind::UnexpectedLine,
        };
        let dbg = format!("{msg:?}");
        assert!(dbg.contains("garbage"));
    }
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

    /// Parsed response from `>PKCS11ID-ENTRY:` notification (sent by
    /// `pkcs11-id-get`). Wire: `>PKCS11ID-ENTRY:'index', ID:'id', BLOB:'blob'`
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
