use std::fmt;
use std::str::FromStr;

use crate::{
    auth::{AuthRetryMode, AuthType, ParseAuthRetryModeError},
    kill_target::KillTarget,
    need_ok::NeedOkResponse,
    proxy_action::ProxyAction,
    redacted::Redacted,
    remote_action::RemoteAction,
    signal::{ParseSignalError, Signal},
    status_format::StatusFormat,
    stream_mode::{ParseStreamModeError, StreamMode},
    transport_protocol::TransportProtocol,
};
use tracing::warn;

/// Error returned when parsing a command string fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommandParseError {
    /// Unrecognized signal name.
    #[error(transparent)]
    Signal(#[from] ParseSignalError),

    /// Unrecognized stream mode.
    #[error(transparent)]
    StreamMode(#[from] ParseStreamModeError),

    /// Unrecognized auth retry mode.
    #[error(transparent)]
    AuthRetryMode(#[from] ParseAuthRetryModeError),

    /// Malformed command syntax (wrong number of arguments, non-numeric
    /// values where numbers are expected, etc.).
    #[error("{0}")]
    Syntax(String),
}

/// Range selector for `remote-entry-get`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEntryRange {
    /// A single entry by index.
    Single(u32),
    /// A range of entries `[from, to)`.
    Range {
        /// Start index (inclusive).
        from: u32,
        /// End index (exclusive).
        to: u32,
    },
    /// All entries.
    All,
}

impl fmt::Display for RemoteEntryRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Single(i) => write!(f, "{i}"),
            Self::Range { from, to } => write!(f, "{from} {to}"),
            Self::All => f.write_str("all"),
        }
    }
}

/// Every command the management interface accepts, modeled as a typed enum.
///
/// The encoder handles all serialization — escaping, quoting, multi-line
/// block framing — so callers never assemble raw strings. The `Raw` variant
/// exists as an escape hatch for commands not yet modeled here.
///
/// Sensitive fields (passwords, tokens, challenge responses) are wrapped in
/// [`Redacted`] so they are masked in [`Debug`] and [`Display`](std::fmt::Display)
/// output. Use [`Redacted::expose`] to access the raw value for wire encoding.
#[derive(Debug, Clone, PartialEq, Eq, strum::IntoStaticStr)]
#[strum(serialize_all = "kebab-case")]
pub enum OvpnCommand {
    // --- Informational ---
    /// Request connection status in the given format.
    /// Wire: `status` / `status 2` / `status 3`
    Status(StatusFormat),

    /// Print current state (single comma-delimited line).
    /// Wire: `state`
    State,

    /// Control real-time state notifications and/or dump history.
    /// Wire: `state on` / `state off` / `state all` / `state on all` / `state 3`
    StateStream(StreamMode),

    /// Print the OpenVPN and management interface version.
    /// Wire: `version`
    Version,

    /// Show the PID of the OpenVPN process.
    /// Wire: `pid`
    Pid,

    /// List available management commands.
    /// Wire: `help`
    Help,

    /// Get or set the log verbosity level (0–15).
    /// `Verb(None)` queries the current level; `Verb(Some(n))` sets it.
    /// Wire: `verb` / `verb 4`
    Verb(Option<u8>),

    /// Get or set the mute threshold (suppress repeating messages).
    /// Wire: `mute` / `mute 40`
    Mute(Option<u32>),

    /// (Windows only) Show network adapter list and routing table.
    /// Wire: `net`
    Net,

    // --- Real-time notification control ---
    /// Control real-time log streaming and/or dump log history.
    /// Wire: `log on` / `log off` / `log all` / `log on all` / `log 20`
    ///
    /// # Pitfall
    ///
    /// At `verb 4` or above, [`StreamMode::All`] and [`StreamMode::OnAll`]
    /// can produce an extremely large — or effectively unbounded — history
    /// dump, because OpenVPN logs its own management I/O at that verbosity.
    /// Prefer [`StreamMode::On`] (no history) or [`StreamMode::Recent`] to
    /// cap the dump size.
    Log(StreamMode),

    /// Control real-time echo parameter notifications.
    /// Wire: `echo on` / `echo off` / `echo all` / `echo on all`
    Echo(StreamMode),

    /// Enable/disable byte count notifications at N-second intervals.
    /// Pass 0 to disable.
    /// Wire: `bytecount 5` / `bytecount 0`
    ByteCount(u32),

    // --- Connection control ---
    /// Send a signal to the OpenVPN daemon.
    /// Wire: `signal SIGUSR1`
    Signal(Signal),

    /// Kill a specific client connection (server mode).
    /// Wire: `kill Test-Client` / `kill 1.2.3.4:4000`
    Kill(KillTarget),

    /// Query the current hold flag.
    /// Wire: `hold`
    /// Response: `SUCCESS: hold=0` or `SUCCESS: hold=1`
    HoldQuery,

    /// Set the hold flag on — future restarts will pause until released.
    /// Wire: `hold on`
    HoldOn,

    /// Clear the hold flag.
    /// Wire: `hold off`
    HoldOff,

    /// Release from hold state and start OpenVPN. Does not change the
    /// hold flag itself.
    /// Wire: `hold release`
    HoldRelease,

    // --- Authentication ---
    /// Supply a username for the given auth type.
    /// Wire: `username "Auth" myuser`
    Username {
        /// Which credential set this username belongs to.
        auth_type: AuthType,
        /// The username value (redacted in debug output).
        value: Redacted,
    },

    /// Supply a password for the given auth type. The value is escaped
    /// and double-quoted per the OpenVPN config-file lexer rules.
    /// Wire: `password "Private Key" "foo\"bar"`
    Password {
        /// Which credential set this password belongs to.
        auth_type: AuthType,
        /// The password value (redacted in debug output, escaped on the wire).
        value: Redacted,
    },

    /// Set the auth-retry strategy.
    /// Wire: `auth-retry interact`
    AuthRetry(AuthRetryMode),

    /// Forget all passwords entered during this management session.
    /// Wire: `forget-passwords`
    ForgetPasswords,

    // --- Challenge-response authentication ---
    /// Respond to a CRV1 dynamic challenge.
    /// Wire: `password "Auth" "CRV1::state_id::response"`
    ChallengeResponse {
        /// The opaque state ID from the `>PASSWORD:` CRV1 notification.
        state_id: String,
        /// The user's response to the challenge (redacted in debug output).
        response: Redacted,
    },

    /// Respond to a static challenge (SC).
    /// Wire: `password "Auth" "SCRV1::base64_password::base64_response"`
    ///
    /// The caller must pre-encode password and response as base64 —
    /// this crate does not include a base64 dependency.
    StaticChallengeResponse {
        /// Base64-encoded password (redacted in debug output).
        password_b64: Redacted,
        /// Base64-encoded challenge response (redacted in debug output).
        response_b64: Redacted,
    },

    // --- Interactive prompts (OpenVPN 2.1+) ---
    /// Respond to a `>NEED-OK:` prompt.
    /// Wire: `needok token-insertion-request ok` / `needok ... cancel`
    NeedOk {
        /// The prompt name from the `>NEED-OK:` notification.
        name: String,
        /// Accept or cancel.
        response: NeedOkResponse,
    },

    /// Respond to a `>NEED-STR:` prompt with a string value.
    /// Wire: `needstr name "John"`
    NeedStr {
        /// The prompt name from the `>NEED-STR:` notification.
        name: String,
        /// The string value to send (will be escaped on the wire).
        value: String,
    },

    // --- PKCS#11 (OpenVPN 2.1+) ---
    /// Query available PKCS#11 certificate count.
    /// Wire: `pkcs11-id-count`
    Pkcs11IdCount,

    /// Retrieve a PKCS#11 certificate by index.
    /// Wire: `pkcs11-id-get 1`
    Pkcs11IdGet(u32),

    // --- External key / RSA signature (OpenVPN 2.3+) ---
    /// Provide an RSA signature in response to `>RSA_SIGN:`.
    /// This is a multi-line command: the encoder writes `rsa-sig`,
    /// then each base64 line, then `END`.
    RsaSig {
        /// Base64-encoded signature lines.
        base64_lines: Vec<String>,
    },

    // --- Client management (server mode, OpenVPN 2.1+) ---
    /// Authorize a `>CLIENT:CONNECT` or `>CLIENT:REAUTH` and push config
    /// directives. Multi-line command: header, config lines, `END`.
    /// An empty `config_lines` produces a null block (header + immediate END),
    /// which is equivalent to `client-auth-nt` in effect.
    ClientAuth {
        /// Client ID from the `>CLIENT:` notification.
        cid: u64,
        /// Key ID from the `>CLIENT:` notification.
        kid: u64,
        /// Config directives to push (e.g. `push "route ..."`).
        config_lines: Vec<String>,
    },

    /// Authorize a client without pushing any config.
    /// Wire: `client-auth-nt {CID} {KID}`
    ClientAuthNt {
        /// Client ID.
        cid: u64,
        /// Key ID.
        kid: u64,
    },

    /// Deny a `>CLIENT:CONNECT` or `>CLIENT:REAUTH`.
    /// Wire: `client-deny {CID} {KID} "reason" ["client-reason"]`
    ClientDeny {
        /// Client ID.
        cid: u64,
        /// Key ID.
        kid: u64,
        /// Server-side reason string (logged but not sent to client).
        reason: String,
        /// Optional message sent to the client as part of AUTH_FAILED.
        client_reason: Option<String>,
    },

    /// Kill a client session by CID, optionally with a custom message.
    /// Wire: `client-kill {CID}` or `client-kill {CID} {message}`
    /// Default message is `RESTART` if omitted.
    ClientKill {
        /// Client ID.
        cid: u64,
        /// Optional kill message (e.g. `"HALT"`, `"RESTART"`). Defaults to
        /// `RESTART` on the server if `None`.
        message: Option<String>,
    },

    // --- Remote/Proxy override ---
    /// Respond to a `>REMOTE:` notification (requires `--management-query-remote`).
    /// Wire: `remote ACCEPT` / `remote SKIP` / `remote MOD host port`
    Remote(RemoteAction),

    /// Respond to a `>PROXY:` notification (requires `--management-query-proxy`).
    /// Wire: `proxy NONE` / `proxy HTTP host port [nct]` / `proxy SOCKS host port`
    Proxy(ProxyAction),

    // --- Server statistics ---
    /// Request aggregated server stats.
    /// Wire: `load-stats`
    /// Response: `SUCCESS: nclients=N,bytesin=N,bytesout=N`
    LoadStats,

    // --- Extended client management (OpenVPN 2.5+) ---
    /// Defer authentication for a client, allowing async auth backends.
    /// Wire: `client-pending-auth {CID} {KID} {EXTRA} {TIMEOUT}`
    ClientPendingAuth {
        /// Client ID.
        cid: u64,
        /// Key ID.
        kid: u64,
        /// Extra opaque string passed to the auth backend.
        extra: String,
        /// Timeout in seconds before the pending auth expires.
        timeout: u32,
    },

    /// Respond to a CR_TEXT challenge (client-side, OpenVPN 2.6+).
    /// Wire: `cr-response {base64-response}`
    CrResponse {
        /// The base64-encoded challenge-response answer (redacted in debug output).
        response: Redacted,
    },

    // --- External key signature (OpenVPN 2.5+, management v2+) ---
    /// Provide a signature in response to `>PK_SIGN:`. Replacement for
    /// `rsa-sig` that supports ECDSA, RSA-PSS, and other key types.
    /// Multi-line command: `pk-sig`, base64 lines, `END`.
    PkSig {
        /// Base64-encoded signature lines.
        base64_lines: Vec<String>,
    },

    // --- ENV filter (OpenVPN 2.6+) ---
    /// Set the env-var filter level for `>CLIENT:ENV` blocks.
    /// Level 0 = all vars, higher levels filter more.
    /// Wire: `env-filter [level]`
    /// Response: `SUCCESS: env_filter_level=N`
    EnvFilter(u32),

    // --- Remote entry queries (management v3+) ---
    /// Query the number of `--remote` entries configured.
    /// Wire: `remote-entry-count`
    /// Response: multi-line (count, then `END`).
    RemoteEntryCount,

    /// Retrieve `--remote` entries by index or all at once.
    /// Wire: `remote-entry-get i|all [j]`
    /// Response: multi-line (`index,remote_string` per line, then `END`).
    RemoteEntryGet(RemoteEntryRange),

    // --- Push updates (OpenVPN 2.7+, server mode) ---
    /// Broadcast a push option update to all connected clients.
    /// Wire: `push-update-broad "options"`
    PushUpdateBroad {
        /// Quoted options string (e.g. `"route 10.0.0.0, -dns"`).
        options: String,
    },

    /// Push an option update to a specific client by CID.
    /// Wire: `push-update-cid CID "options"`
    PushUpdateCid {
        /// Client ID.
        cid: u64,
        /// Quoted options string.
        options: String,
    },

    // --- External certificate (OpenVPN 2.4+) ---
    /// Supply an external certificate in response to `>NEED-CERTIFICATE`.
    /// Multi-line command: header, PEM lines, `END`.
    /// Wire: `certificate\n{pem_lines}\nEND`
    Certificate {
        /// PEM-encoded certificate lines.
        pem_lines: Vec<String>,
    },

    // --- Management interface authentication ---
    /// Authenticate to the management interface itself. Sent as a bare
    /// line (no command prefix, no quoting) in response to
    /// [`crate::OvpnMessage::PasswordPrompt`].
    /// Wire: `{password}\n`
    ManagementPassword(Redacted),

    // --- Session lifecycle ---
    /// Close the management session. OpenVPN keeps running and resumes
    /// listening for new management connections.
    Exit,

    /// Identical to `Exit`.
    Quit,

    // --- Escape hatch ---
    /// Send a raw command string for anything not yet modeled above.
    /// The decoder expects a `SUCCESS:`/`ERROR:` response.
    Raw(String),

    /// Send a raw command string, expecting a multi-line (END-terminated)
    /// response.
    ///
    /// Like [`Raw`](Self::Raw), the string is passed through the encoder's
    /// wire-safety gate before sending (see [`crate::EncoderMode`]). Unlike
    /// `Raw`, the decoder accumulates the response into
    /// [`OvpnMessage::MultiLine`](crate::OvpnMessage::MultiLine).
    RawMultiLine(String),
}

/// What kind of response the decoder should expect after a given command.
/// This is the core of the command-tracking mechanism that resolves the
/// protocol's ambiguity around single-line vs. multi-line responses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseKind {
    /// Expect a `SUCCESS:` or `ERROR:` line.
    SuccessOrError,

    /// Expect multiple lines terminated by a bare `END`.
    MultiLine,

    /// No response expected (connection may close).
    NoResponse,
}

impl OvpnCommand {
    /// Determine what kind of response this command produces, so the
    /// decoder knows how to frame the next incoming bytes.
    pub(crate) fn expected_response(&self) -> ResponseKind {
        match self {
            // These always produce multi-line (END-terminated) responses.
            Self::Status(_)
            | Self::Version
            | Self::Help
            | Self::Net
            | Self::RemoteEntryCount
            | Self::RemoteEntryGet(_) => ResponseKind::MultiLine,

            // state/log/echo: depends on the specific sub-mode.
            Self::StateStream(mode) | Self::Log(mode) | Self::Echo(mode) => match mode {
                StreamMode::All | StreamMode::OnAll | StreamMode::Recent(_) => {
                    ResponseKind::MultiLine
                }
                StreamMode::On | StreamMode::Off => ResponseKind::SuccessOrError,
            },

            // Bare `state` returns state history (END-terminated).
            Self::State => ResponseKind::MultiLine,

            // Raw multi-line expects END-terminated response.
            Self::RawMultiLine(_) => ResponseKind::MultiLine,

            // exit/quit close the connection.
            Self::Exit | Self::Quit => ResponseKind::NoResponse,

            // Everything else (including Raw) produces SUCCESS: or ERROR:.
            _ => ResponseKind::SuccessOrError,
        }
    }
}

impl FromStr for OvpnCommand {
    type Err = CommandParseError;

    /// Parse a human-readable command string into an [`OvpnCommand`].
    ///
    /// This accepts the same syntax used by interactive management clients:
    /// a command name followed by space-separated arguments.
    ///
    /// Commands that cannot be represented as a single line (multi-line bodies
    /// like `rsa-sig`, `client-auth` config lines, `certificate` PEM) are
    /// parsed with comma-separated lines in the argument position.
    ///
    /// Unrecognized commands fall through to [`OvpnCommand::Raw`].
    ///
    /// # Examples
    ///
    /// ```
    /// use openvpn_mgmt_codec::OvpnCommand;
    ///
    /// let cmd: OvpnCommand = "version".parse().unwrap();
    /// assert_eq!(cmd, OvpnCommand::Version);
    ///
    /// let cmd: OvpnCommand = "state on all".parse().unwrap();
    /// assert_eq!(cmd, OvpnCommand::StateStream(openvpn_mgmt_codec::StreamMode::OnAll));
    /// ```
    fn from_str(line: &str) -> Result<Self, Self::Err> {
        /// Shorthand for `Err(CommandParseError::Syntax(...))`.
        fn cmd_err<T>(msg: impl Into<String>) -> Result<T, CommandParseError> {
            Err(CommandParseError::Syntax(msg.into()))
        }

        let line = line.trim();
        let (cmd, args) = line
            .split_once(char::is_whitespace)
            .map(|(c, a)| (c, a.trim()))
            .unwrap_or((line, ""));

        match cmd {
            // --- Informational ---
            "version" => Ok(Self::Version),
            "pid" => Ok(Self::Pid),
            "help" => Ok(Self::Help),
            "net" => Ok(Self::Net),
            "load-stats" => Ok(Self::LoadStats),

            "status" => match args {
                "" | "1" => Ok(Self::Status(StatusFormat::V1)),
                "2" => Ok(Self::Status(StatusFormat::V2)),
                "3" => Ok(Self::Status(StatusFormat::V3)),
                _ => cmd_err(format!("invalid status format: {args} (use 1, 2, or 3)")),
            },

            "state" => match args {
                "" => Ok(Self::State),
                other => Ok(Self::StateStream(other.parse::<StreamMode>()?)),
            },

            "log" => Ok(Self::Log(args.parse::<StreamMode>()?)),
            "echo" => Ok(Self::Echo(args.parse::<StreamMode>()?)),

            "verb" => {
                if args.is_empty() {
                    Ok(Self::Verb(None))
                } else {
                    args.parse::<u8>()
                        .map(|n| Self::Verb(Some(n)))
                        .map_err(|_| {
                            CommandParseError::Syntax(format!("invalid verbosity: {args} (0-15)"))
                        })
                }
            }

            "mute" => {
                if args.is_empty() {
                    Ok(Self::Mute(None))
                } else {
                    args.parse::<u32>()
                        .map(|n| Self::Mute(Some(n)))
                        .map_err(|_| {
                            CommandParseError::Syntax(format!("invalid mute value: {args}"))
                        })
                }
            }

            "bytecount" => args.parse::<u32>().map(Self::ByteCount).map_err(|_| {
                CommandParseError::Syntax(format!("bytecount requires a number, got: {args}"))
            }),

            // --- Connection control ---
            "signal" => Ok(Self::Signal(args.parse::<Signal>()?)),

            "kill" => {
                if args.is_empty() {
                    return cmd_err("kill requires a target (common name or proto:ip:port)");
                }
                let parts: Vec<&str> = args.splitn(3, ':').collect();
                if parts.len() == 3
                    && let Ok(port) = parts[2].parse::<u16>()
                {
                    return Ok(Self::Kill(KillTarget::Address {
                        protocol: parts[0]
                            .parse()
                            .inspect_err(|error| warn!(%error, "unknown transport protocol"))
                            .unwrap_or_else(|_| TransportProtocol::Unknown(parts[0].to_string())),
                        ip: parts[1].to_string(),
                        port,
                    }));
                }
                Ok(Self::Kill(KillTarget::CommonName(args.to_string())))
            }

            "hold" => match args {
                "" => Ok(Self::HoldQuery),
                "on" => Ok(Self::HoldOn),
                "off" => Ok(Self::HoldOff),
                "release" => Ok(Self::HoldRelease),
                _ => cmd_err(format!("invalid hold argument: {args}")),
            },

            // --- Authentication ---
            "username" => {
                let (auth_type, value) =
                    args.split_once(char::is_whitespace)
                        .ok_or(CommandParseError::Syntax(
                            "usage: username <auth-type> <value>".into(),
                        ))?;
                Ok(Self::Username {
                    auth_type: auth_type
                        .parse()
                        .inspect_err(|error| warn!(%error, "unknown auth type"))
                        .unwrap_or_else(|_| AuthType::Unknown(auth_type.to_string())),
                    value: value.trim().into(),
                })
            }

            "password" => {
                let (auth_type, value) =
                    args.split_once(char::is_whitespace)
                        .ok_or(CommandParseError::Syntax(
                            "usage: password <auth-type> <value>".into(),
                        ))?;
                Ok(Self::Password {
                    auth_type: auth_type
                        .parse()
                        .inspect_err(|error| warn!(%error, "unknown auth type"))
                        .unwrap_or_else(|_| AuthType::Unknown(auth_type.to_string())),
                    value: value.trim().into(),
                })
            }

            "auth-retry" => Ok(Self::AuthRetry(args.parse::<AuthRetryMode>()?)),

            "forget-passwords" => Ok(Self::ForgetPasswords),

            // --- Interactive prompts ---
            "needok" => {
                let (name, resp) =
                    args.rsplit_once(char::is_whitespace)
                        .ok_or(CommandParseError::Syntax(
                            "usage: needok <name> ok|cancel".into(),
                        ))?;
                let response = match resp {
                    "ok" => NeedOkResponse::Ok,
                    "cancel" => NeedOkResponse::Cancel,
                    _ => {
                        return cmd_err(format!("invalid needok response: {resp} (use ok/cancel)"));
                    }
                };
                Ok(Self::NeedOk {
                    name: name.trim().to_string(),
                    response,
                })
            }

            "needstr" => {
                let (name, value) =
                    args.split_once(char::is_whitespace)
                        .ok_or(CommandParseError::Syntax(
                            "usage: needstr <name> <value>".into(),
                        ))?;
                Ok(Self::NeedStr {
                    name: name.to_string(),
                    value: value.trim().to_string(),
                })
            }

            // --- PKCS#11 ---
            "pkcs11-id-count" => Ok(Self::Pkcs11IdCount),

            "pkcs11-id-get" => args.parse::<u32>().map(Self::Pkcs11IdGet).map_err(|_| {
                CommandParseError::Syntax(format!("pkcs11-id-get requires a number, got: {args}"))
            }),

            // --- Client management (server mode) ---
            "client-auth" => {
                let mut parts = args.splitn(3, char::is_whitespace);
                let cid = parts
                    .next()
                    .ok_or(CommandParseError::Syntax(
                        "usage: client-auth <cid> <kid> [config-lines]".into(),
                    ))?
                    .parse::<u64>()
                    .map_err(|_| CommandParseError::Syntax("cid must be a number".into()))?;
                let kid = parts
                    .next()
                    .ok_or(CommandParseError::Syntax(
                        "usage: client-auth <cid> <kid> [config-lines]".into(),
                    ))?
                    .parse::<u64>()
                    .map_err(|_| CommandParseError::Syntax("kid must be a number".into()))?;
                let config_lines = match parts.next() {
                    Some(rest) => rest.split(',').map(|s| s.trim().to_string()).collect(),
                    None => vec![],
                };
                Ok(Self::ClientAuth {
                    cid,
                    kid,
                    config_lines,
                })
            }

            "client-auth-nt" => {
                let (cid_s, kid_s) =
                    args.split_once(char::is_whitespace)
                        .ok_or(CommandParseError::Syntax(
                            "usage: client-auth-nt <cid> <kid>".into(),
                        ))?;
                Ok(Self::ClientAuthNt {
                    cid: cid_s
                        .parse()
                        .map_err(|_| CommandParseError::Syntax("cid must be a number".into()))?,
                    kid: kid_s
                        .trim()
                        .parse()
                        .map_err(|_| CommandParseError::Syntax("kid must be a number".into()))?,
                })
            }

            "client-deny" => {
                let mut parts = args.splitn(4, char::is_whitespace);
                let cid = parts
                    .next()
                    .ok_or(CommandParseError::Syntax(
                        "usage: client-deny <cid> <kid> <reason> [client-reason]".into(),
                    ))?
                    .parse::<u64>()
                    .map_err(|_| CommandParseError::Syntax("cid must be a number".into()))?;
                let kid = parts
                    .next()
                    .ok_or(CommandParseError::Syntax(
                        "usage: client-deny <cid> <kid> <reason> [client-reason]".into(),
                    ))?
                    .parse::<u64>()
                    .map_err(|_| CommandParseError::Syntax("kid must be a number".into()))?;
                let reason = parts
                    .next()
                    .ok_or(CommandParseError::Syntax(
                        "usage: client-deny <cid> <kid> <reason> [client-reason]".into(),
                    ))?
                    .to_string();
                let client_reason = parts.next().map(|s| s.to_string());
                Ok(Self::ClientDeny {
                    cid,
                    kid,
                    reason,
                    client_reason,
                })
            }

            "client-kill" => {
                let (cid_str, message) = match args.split_once(char::is_whitespace) {
                    Some((c, m)) => (c, Some(m.trim().to_string())),
                    None => (args, None),
                };
                let cid = cid_str.parse::<u64>().map_err(|_| {
                    CommandParseError::Syntax(format!(
                        "client-kill requires a CID number, got: {cid_str}"
                    ))
                })?;
                Ok(Self::ClientKill { cid, message })
            }

            // --- Remote/Proxy override ---
            "remote" => match args.split_whitespace().collect::<Vec<_>>().as_slice() {
                ["accept" | "ACCEPT"] => Ok(Self::Remote(RemoteAction::Accept)),
                ["skip" | "SKIP"] => Ok(Self::Remote(RemoteAction::Skip)),
                ["mod" | "MOD", host, port] => Ok(Self::Remote(RemoteAction::Modify {
                    host: host.to_string(),
                    port: port
                        .parse()
                        .map_err(|_| CommandParseError::Syntax("port must be a number".into()))?,
                })),
                _ => cmd_err("usage: remote accept|skip|mod <host> <port>"),
            },

            "proxy" => match args.split_whitespace().collect::<Vec<_>>().as_slice() {
                ["none" | "NONE"] => Ok(Self::Proxy(ProxyAction::None)),
                ["http" | "HTTP", host, port] => Ok(Self::Proxy(ProxyAction::Http {
                    host: host.to_string(),
                    port: port
                        .parse()
                        .map_err(|_| CommandParseError::Syntax("port must be a number".into()))?,
                    non_cleartext_only: false,
                })),
                ["http" | "HTTP", host, port, "nct"] => Ok(Self::Proxy(ProxyAction::Http {
                    host: host.to_string(),
                    port: port
                        .parse()
                        .map_err(|_| CommandParseError::Syntax("port must be a number".into()))?,
                    non_cleartext_only: true,
                })),
                ["socks" | "SOCKS", host, port] => Ok(Self::Proxy(ProxyAction::Socks {
                    host: host.to_string(),
                    port: port
                        .parse()
                        .map_err(|_| CommandParseError::Syntax("port must be a number".into()))?,
                })),
                _ => cmd_err("usage: proxy none|http <host> <port> [nct]|socks <host> <port>"),
            },

            // --- ENV filter ---
            "env-filter" => {
                let level = if args.is_empty() {
                    0
                } else {
                    args.parse::<u32>().map_err(|_| {
                        CommandParseError::Syntax(format!("invalid env-filter level: {args}"))
                    })?
                };
                Ok(Self::EnvFilter(level))
            }

            // --- Remote entry queries ---
            "remote-entry-count" => Ok(Self::RemoteEntryCount),

            "remote-entry-get" => {
                if args.is_empty() {
                    return cmd_err("usage: remote-entry-get i|all [j]");
                }
                let range = if args == "all" {
                    RemoteEntryRange::All
                } else {
                    let mut parts = args.splitn(2, char::is_whitespace);
                    let from = parts.next().unwrap().parse::<u32>().map_err(|_| {
                        CommandParseError::Syntax(format!(
                            "remote-entry-get index must be a number or 'all', got: {args}"
                        ))
                    })?;
                    match parts.next() {
                        Some(to_str) => {
                            let to = to_str.trim().parse::<u32>().map_err(|_| {
                                CommandParseError::Syntax(format!(
                                    "remote-entry-get end index must be a number, got: {to_str}"
                                ))
                            })?;
                            RemoteEntryRange::Range { from, to }
                        }
                        None => RemoteEntryRange::Single(from),
                    }
                };
                Ok(Self::RemoteEntryGet(range))
            }

            // --- Push updates ---
            "push-update-broad" => {
                if args.is_empty() {
                    return cmd_err("usage: push-update-broad <options>");
                }
                Ok(Self::PushUpdateBroad {
                    options: args.to_string(),
                })
            }

            "push-update-cid" => {
                let (cid_str, options) =
                    args.split_once(char::is_whitespace)
                        .ok_or(CommandParseError::Syntax(
                            "usage: push-update-cid <cid> <options>".into(),
                        ))?;
                let cid = cid_str.parse::<u64>().map_err(|_| {
                    CommandParseError::Syntax("push-update-cid: cid must be a number".into())
                })?;
                Ok(Self::PushUpdateCid {
                    cid,
                    options: options.trim().to_string(),
                })
            }

            // --- Raw multi-line ---
            "raw-ml" => {
                if args.is_empty() {
                    return cmd_err("usage: raw-ml <command>");
                }
                Ok(Self::RawMultiLine(args.to_string()))
            }

            // --- Lifecycle ---
            "exit" => Ok(Self::Exit),
            "quit" => Ok(Self::Quit),

            // --- Fallback: send as raw command ---
            _ => Ok(Self::Raw(line.to_string())),
        }
    }
}

/// The standard startup sequence that most management clients send after
/// connecting.
///
/// This is the pattern used by `node-openvpn` and other clients: enable
/// log streaming, request the PID, start byte-count notifications, and
/// release the hold so OpenVPN begins connecting.
///
/// # Arguments
///
/// * `bytecount_interval` — seconds between `>BYTECOUNT:` notifications
///   (pass `0` to skip enabling byte counts).
///
/// # Initial state
///
/// The sequence uses [`StreamMode::OnAll`] for log and state, which
/// enables real-time streaming **and** dumps the history buffer as a
/// multi-line response. The state history response contains the current
/// state as its last entry — use
/// [`parse_current_state`](crate::parsed_response::parse_current_state)
/// to extract it. Do **not** rely solely on `>STATE:` notifications for
/// the initial state, because notifications only fire on *transitions*.
///
/// # Pitfall: `log on all` at high verbosity
///
/// At `verb 4` or above, the log history dump from `log on all` can be
/// extremely large (OpenVPN logs its own management I/O at that level).
/// The dump may grow faster than it drains, effectively hanging the
/// multi-line accumulation. Prefer [`StreamMode::On`] (no history) at
/// high verbosity, or use [`StreamMode::Recent`] to cap the dump size.
///
/// # Notification interleaving
///
/// The commands produce a mix of multi-line and single-line responses.
/// Asynchronous notifications (`>STATE:`, `>LOG:`, `>HOLD:`, etc.) can
/// arrive between any command and its response. The codec handles this
/// transparently, but consumers reading from the stream must handle
/// [`OvpnMessage::Notification`](crate::OvpnMessage::Notification) variants at any point.
///
/// # Examples
///
/// ```
/// use openvpn_mgmt_codec::command::connection_sequence;
/// use openvpn_mgmt_codec::OvpnCommand;
///
/// let cmds = connection_sequence(5);
/// assert!(cmds.iter().any(|c| matches!(c, OvpnCommand::HoldRelease)));
/// ```
///
/// To send these over a framed connection:
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use tokio::net::TcpStream;
/// use tokio_util::codec::Framed;
/// use futures::SinkExt;
/// use openvpn_mgmt_codec::{OvpnCodec, OvpnCommand};
/// use openvpn_mgmt_codec::command::connection_sequence;
///
/// let stream = TcpStream::connect("127.0.0.1:7505").await?;
/// let mut framed = Framed::new(stream, OvpnCodec::new());
///
/// for cmd in connection_sequence(5) {
///     framed.send(cmd).await?;
/// }
/// # Ok(())
/// # }
/// ```
pub fn connection_sequence(bytecount_interval: u32) -> Vec<OvpnCommand> {
    let mut cmds = vec![
        OvpnCommand::Log(StreamMode::OnAll),
        OvpnCommand::StateStream(StreamMode::OnAll),
        OvpnCommand::Pid,
    ];
    if bytecount_interval > 0 {
        cmds.push(OvpnCommand::ByteCount(bytecount_interval));
    }
    cmds.push(OvpnCommand::HoldRelease);
    cmds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn into_static_str_labels() {
        let label: &str = (&OvpnCommand::State).into();
        assert_eq!(label, "state");

        let label: &str = (&OvpnCommand::ForgetPasswords).into();
        assert_eq!(label, "forget-passwords");

        let label: &str = (&OvpnCommand::ByteCount(5)).into();
        assert_eq!(label, "byte-count");
    }

    // --- connection_sequence ---

    #[test]
    fn connection_sequence_with_bytecount() {
        let cmds = connection_sequence(5);
        assert_eq!(
            cmds,
            vec![
                OvpnCommand::Log(StreamMode::OnAll),
                OvpnCommand::StateStream(StreamMode::OnAll),
                OvpnCommand::Pid,
                OvpnCommand::ByteCount(5),
                OvpnCommand::HoldRelease,
            ]
        );
    }

    #[test]
    fn connection_sequence_without_bytecount() {
        let cmds = connection_sequence(0);
        assert_eq!(
            cmds,
            vec![
                OvpnCommand::Log(StreamMode::OnAll),
                OvpnCommand::StateStream(StreamMode::OnAll),
                OvpnCommand::Pid,
                OvpnCommand::HoldRelease,
            ]
        );
    }

    // --- FromStr: informational commands ---

    #[test]
    fn parse_simple_commands() {
        assert_eq!("version".parse(), Ok(OvpnCommand::Version));
        assert_eq!("pid".parse(), Ok(OvpnCommand::Pid));
        assert_eq!("help".parse(), Ok(OvpnCommand::Help));
        assert_eq!("net".parse(), Ok(OvpnCommand::Net));
        assert_eq!("load-stats".parse(), Ok(OvpnCommand::LoadStats));
        assert_eq!("forget-passwords".parse(), Ok(OvpnCommand::ForgetPasswords));
        assert_eq!("pkcs11-id-count".parse(), Ok(OvpnCommand::Pkcs11IdCount));
        assert_eq!("exit".parse(), Ok(OvpnCommand::Exit));
        assert_eq!("quit".parse(), Ok(OvpnCommand::Quit));
    }

    #[test]
    fn parse_status() {
        assert_eq!("status".parse(), Ok(OvpnCommand::Status(StatusFormat::V1)));
        assert_eq!(
            "status 1".parse(),
            Ok(OvpnCommand::Status(StatusFormat::V1))
        );
        assert_eq!(
            "status 2".parse(),
            Ok(OvpnCommand::Status(StatusFormat::V2))
        );
        assert_eq!(
            "status 3".parse(),
            Ok(OvpnCommand::Status(StatusFormat::V3))
        );
        assert!("status 4".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: state / log / echo stream modes ---

    #[test]
    fn parse_state_bare() {
        assert_eq!("state".parse(), Ok(OvpnCommand::State));
    }

    #[test]
    fn parse_state_stream_modes() {
        assert_eq!(
            "state on".parse(),
            Ok(OvpnCommand::StateStream(StreamMode::On))
        );
        assert_eq!(
            "state off".parse(),
            Ok(OvpnCommand::StateStream(StreamMode::Off))
        );
        assert_eq!(
            "state all".parse(),
            Ok(OvpnCommand::StateStream(StreamMode::All))
        );
        assert_eq!(
            "state on all".parse(),
            Ok(OvpnCommand::StateStream(StreamMode::OnAll))
        );
        assert_eq!(
            "state 5".parse(),
            Ok(OvpnCommand::StateStream(StreamMode::Recent(5)))
        );
    }

    #[test]
    fn parse_log_and_echo() {
        assert_eq!("log on".parse(), Ok(OvpnCommand::Log(StreamMode::On)));
        assert_eq!(
            "log on all".parse(),
            Ok(OvpnCommand::Log(StreamMode::OnAll))
        );
        assert_eq!("echo off".parse(), Ok(OvpnCommand::Echo(StreamMode::Off)));
        assert_eq!(
            "echo 10".parse(),
            Ok(OvpnCommand::Echo(StreamMode::Recent(10)))
        );
    }

    // --- FromStr: verb / mute / bytecount ---

    #[test]
    fn parse_verb() {
        assert_eq!("verb".parse(), Ok(OvpnCommand::Verb(None)));
        assert_eq!("verb 4".parse(), Ok(OvpnCommand::Verb(Some(4))));
        assert!("verb abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_mute() {
        assert_eq!("mute".parse(), Ok(OvpnCommand::Mute(None)));
        assert_eq!("mute 40".parse(), Ok(OvpnCommand::Mute(Some(40))));
        assert!("mute abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_bytecount() {
        assert_eq!("bytecount 5".parse(), Ok(OvpnCommand::ByteCount(5)));
        assert_eq!("bytecount 0".parse(), Ok(OvpnCommand::ByteCount(0)));
        assert!("bytecount".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: signal ---

    #[test]
    fn parse_signal() {
        assert_eq!(
            "signal SIGHUP".parse(),
            Ok(OvpnCommand::Signal(Signal::SigHup))
        );
        assert_eq!(
            "signal SIGTERM".parse(),
            Ok(OvpnCommand::Signal(Signal::SigTerm))
        );
        assert_eq!(
            "signal SIGUSR1".parse(),
            Ok(OvpnCommand::Signal(Signal::SigUsr1))
        );
        assert_eq!(
            "signal SIGUSR2".parse(),
            Ok(OvpnCommand::Signal(Signal::SigUsr2))
        );
        assert!("signal SIGKILL".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: kill ---

    #[test]
    fn parse_kill_common_name() {
        assert_eq!(
            "kill TestClient".parse(),
            Ok(OvpnCommand::Kill(KillTarget::CommonName(
                "TestClient".to_string()
            )))
        );
    }

    #[test]
    fn parse_kill_address() {
        assert_eq!(
            "kill tcp:1.2.3.4:4000".parse(),
            Ok(OvpnCommand::Kill(KillTarget::Address {
                protocol: TransportProtocol::Tcp,
                ip: "1.2.3.4".to_string(),
                port: 4000,
            }))
        );
    }

    #[test]
    fn parse_kill_empty_is_err() {
        assert!("kill".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: hold ---

    #[test]
    fn parse_hold() {
        assert_eq!("hold".parse(), Ok(OvpnCommand::HoldQuery));
        assert_eq!("hold on".parse(), Ok(OvpnCommand::HoldOn));
        assert_eq!("hold off".parse(), Ok(OvpnCommand::HoldOff));
        assert_eq!("hold release".parse(), Ok(OvpnCommand::HoldRelease));
        assert!("hold bogus".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: authentication ---

    #[test]
    fn parse_username() {
        let cmd: OvpnCommand = "username Auth alice".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::Username {
                auth_type: AuthType::Auth,
                value: "alice".into(),
            }
        );
    }

    #[test]
    fn parse_password() {
        let cmd: OvpnCommand = "password PrivateKey s3cret".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::Password {
                auth_type: AuthType::PrivateKey,
                value: "s3cret".into(),
            }
        );
    }

    #[test]
    fn parse_username_missing_value_is_err() {
        assert!("username".parse::<OvpnCommand>().is_err());
        assert!("username Auth".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_auth_retry() {
        assert_eq!(
            "auth-retry none".parse(),
            Ok(OvpnCommand::AuthRetry(AuthRetryMode::None))
        );
        assert_eq!(
            "auth-retry interact".parse(),
            Ok(OvpnCommand::AuthRetry(AuthRetryMode::Interact))
        );
        assert_eq!(
            "auth-retry nointeract".parse(),
            Ok(OvpnCommand::AuthRetry(AuthRetryMode::NoInteract))
        );
        assert!("auth-retry bogus".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: interactive prompts ---

    #[test]
    fn parse_needok() {
        assert_eq!(
            "needok token-insertion ok".parse(),
            Ok(OvpnCommand::NeedOk {
                name: "token-insertion".to_string(),
                response: NeedOkResponse::Ok,
            })
        );
        assert_eq!(
            "needok token-insertion cancel".parse(),
            Ok(OvpnCommand::NeedOk {
                name: "token-insertion".to_string(),
                response: NeedOkResponse::Cancel,
            })
        );
        assert!("needok".parse::<OvpnCommand>().is_err());
        assert!("needok name bogus".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_needstr() {
        assert_eq!(
            "needstr prompt-name John".parse(),
            Ok(OvpnCommand::NeedStr {
                name: "prompt-name".to_string(),
                value: "John".to_string(),
            })
        );
        assert!("needstr".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: PKCS#11 ---

    #[test]
    fn parse_pkcs11_id_get() {
        assert_eq!("pkcs11-id-get 1".parse(), Ok(OvpnCommand::Pkcs11IdGet(1)));
        assert!("pkcs11-id-get abc".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: client management ---

    #[test]
    fn parse_client_auth() {
        assert_eq!(
            "client-auth 42 7".parse(),
            Ok(OvpnCommand::ClientAuth {
                cid: 42,
                kid: 7,
                config_lines: vec![],
            })
        );
    }

    #[test]
    fn parse_client_auth_with_config() {
        let cmd: OvpnCommand = "client-auth 1 2 push route 10.0.0.0,ifconfig-push 10.0.1.1"
            .parse()
            .unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::ClientAuth {
                cid: 1,
                kid: 2,
                config_lines: vec![
                    "push route 10.0.0.0".to_string(),
                    "ifconfig-push 10.0.1.1".to_string(),
                ],
            }
        );
    }

    #[test]
    fn parse_client_auth_nt() {
        assert_eq!(
            "client-auth-nt 5 3".parse(),
            Ok(OvpnCommand::ClientAuthNt { cid: 5, kid: 3 })
        );
        assert!("client-auth-nt abc 3".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_client_deny() {
        assert_eq!(
            "client-deny 1 2 rejected".parse(),
            Ok(OvpnCommand::ClientDeny {
                cid: 1,
                kid: 2,
                reason: "rejected".to_string(),
                client_reason: None,
            })
        );
        assert_eq!(
            "client-deny 1 2 rejected sorry".parse(),
            Ok(OvpnCommand::ClientDeny {
                cid: 1,
                kid: 2,
                reason: "rejected".to_string(),
                client_reason: Some("sorry".to_string()),
            })
        );
    }

    #[test]
    fn parse_client_kill() {
        assert_eq!(
            "client-kill 99".parse(),
            Ok(OvpnCommand::ClientKill {
                cid: 99,
                message: None,
            })
        );
        assert_eq!(
            "client-kill 99 HALT".parse(),
            Ok(OvpnCommand::ClientKill {
                cid: 99,
                message: Some("HALT".to_string()),
            })
        );
        assert!("client-kill abc".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: remote / proxy ---

    #[test]
    fn parse_remote() {
        assert_eq!(
            "remote accept".parse(),
            Ok(OvpnCommand::Remote(RemoteAction::Accept))
        );
        assert_eq!(
            "remote SKIP".parse(),
            Ok(OvpnCommand::Remote(RemoteAction::Skip))
        );
        assert_eq!(
            "remote MOD example.com 443".parse(),
            Ok(OvpnCommand::Remote(RemoteAction::Modify {
                host: "example.com".to_string(),
                port: 443,
            }))
        );
        assert!("remote".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_proxy() {
        assert_eq!(
            "proxy none".parse(),
            Ok(OvpnCommand::Proxy(ProxyAction::None))
        );
        assert_eq!(
            "proxy HTTP proxy.local 8080".parse(),
            Ok(OvpnCommand::Proxy(ProxyAction::Http {
                host: "proxy.local".to_string(),
                port: 8080,
                non_cleartext_only: false,
            }))
        );
        assert_eq!(
            "proxy http proxy.local 8080 nct".parse(),
            Ok(OvpnCommand::Proxy(ProxyAction::Http {
                host: "proxy.local".to_string(),
                port: 8080,
                non_cleartext_only: true,
            }))
        );
        assert_eq!(
            "proxy socks socks.local 1080".parse(),
            Ok(OvpnCommand::Proxy(ProxyAction::Socks {
                host: "socks.local".to_string(),
                port: 1080,
            }))
        );
        assert!("proxy".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: raw / raw-ml / fallback ---

    #[test]
    fn parse_raw_ml() {
        assert_eq!(
            "raw-ml some-cmd".parse(),
            Ok(OvpnCommand::RawMultiLine("some-cmd".to_string()))
        );
        assert!("raw-ml".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_unrecognized_falls_through_to_raw() {
        assert_eq!(
            "unknown-cmd foo bar".parse(),
            Ok(OvpnCommand::Raw("unknown-cmd foo bar".to_string()))
        );
    }

    #[test]
    fn parse_trims_whitespace() {
        assert_eq!("  version  ".parse(), Ok(OvpnCommand::Version));
        assert_eq!(
            "  state  on  ".parse(),
            Ok(OvpnCommand::StateStream(StreamMode::On))
        );
    }

    // --- FromStr: error paths ---

    #[test]
    fn parse_state_invalid_stream_mode() {
        assert!("state bogus".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_log_invalid_stream_mode() {
        assert!("log bogus".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_echo_invalid_stream_mode() {
        assert!("echo bogus".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_kill_unknown_protocol_falls_back() {
        let cmd: OvpnCommand = "kill sctp:1.2.3.4:4000".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::Kill(KillTarget::Address {
                protocol: TransportProtocol::Unknown("sctp".to_string()),
                ip: "1.2.3.4".to_string(),
                port: 4000,
            })
        );
    }

    #[test]
    fn parse_username_unknown_auth_type_falls_back() {
        let cmd: OvpnCommand = "username MyPlugin alice".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::Username {
                auth_type: AuthType::Unknown("MyPlugin".to_string()),
                value: "alice".into(),
            }
        );
    }

    #[test]
    fn parse_password_unknown_auth_type_falls_back() {
        let cmd: OvpnCommand = "password MyPlugin s3cret".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::Password {
                auth_type: AuthType::Unknown("MyPlugin".to_string()),
                value: "s3cret".into(),
            }
        );
    }

    #[test]
    fn parse_password_missing_value_is_err() {
        assert!("password".parse::<OvpnCommand>().is_err());
        assert!("password Auth".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_client_auth_non_numeric_cid() {
        assert!("client-auth abc 1".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_client_auth_non_numeric_kid() {
        assert!("client-auth 1 abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_client_auth_nt_non_numeric_kid() {
        assert!("client-auth-nt 1 abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_client_deny_missing_args() {
        assert!("client-deny".parse::<OvpnCommand>().is_err());
        assert!("client-deny 1".parse::<OvpnCommand>().is_err());
        assert!("client-deny 1 2".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_client_deny_non_numeric_ids() {
        assert!("client-deny abc 1 reason".parse::<OvpnCommand>().is_err());
        assert!("client-deny 1 abc reason".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_remote_non_numeric_port() {
        assert!("remote mod host abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_proxy_non_numeric_port() {
        assert!("proxy http host abc".parse::<OvpnCommand>().is_err());
        assert!("proxy http host abc nct".parse::<OvpnCommand>().is_err());
        assert!("proxy socks host abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_pkcs11_id_get_missing_arg() {
        assert!("pkcs11-id-get".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_bytecount_non_numeric() {
        assert!("bytecount abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_needstr_missing_value() {
        assert!("needstr".parse::<OvpnCommand>().is_err());
    }

    // --- FromStr: new commands ---

    #[test]
    fn parse_env_filter() {
        assert_eq!("env-filter 2".parse(), Ok(OvpnCommand::EnvFilter(2)));
        assert_eq!("env-filter 0".parse(), Ok(OvpnCommand::EnvFilter(0)));
        assert_eq!("env-filter".parse(), Ok(OvpnCommand::EnvFilter(0)));
        assert!("env-filter abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_remote_entry_count() {
        assert_eq!(
            "remote-entry-count".parse(),
            Ok(OvpnCommand::RemoteEntryCount)
        );
    }

    #[test]
    fn parse_remote_entry_get() {
        assert_eq!(
            "remote-entry-get 0".parse(),
            Ok(OvpnCommand::RemoteEntryGet(RemoteEntryRange::Single(0)))
        );
        assert_eq!(
            "remote-entry-get 0 3".parse(),
            Ok(OvpnCommand::RemoteEntryGet(RemoteEntryRange::Range {
                from: 0,
                to: 3
            }))
        );
        assert_eq!(
            "remote-entry-get all".parse(),
            Ok(OvpnCommand::RemoteEntryGet(RemoteEntryRange::All))
        );
        assert!("remote-entry-get".parse::<OvpnCommand>().is_err());
        assert!("remote-entry-get abc".parse::<OvpnCommand>().is_err());
        assert!("remote-entry-get 0 abc".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_push_update_broad() {
        let cmd: OvpnCommand = "push-update-broad route 10.0.0.0".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::PushUpdateBroad {
                options: "route 10.0.0.0".to_string()
            }
        );
        assert!("push-update-broad".parse::<OvpnCommand>().is_err());
    }

    #[test]
    fn parse_push_update_cid() {
        let cmd: OvpnCommand = "push-update-cid 42 route 10.0.0.0".parse().unwrap();
        assert_eq!(
            cmd,
            OvpnCommand::PushUpdateCid {
                cid: 42,
                options: "route 10.0.0.0".to_string()
            }
        );
        assert!("push-update-cid".parse::<OvpnCommand>().is_err());
        assert!("push-update-cid abc opts".parse::<OvpnCommand>().is_err());
    }
}
