use crate::auth::{AuthRetryMode, AuthType};
use crate::kill_target::KillTarget;
use crate::need_ok::NeedOkResponse;
use crate::proxy_action::ProxyAction;
use crate::remote_action::RemoteAction;
use crate::signal::Signal;
use crate::status_format::StatusFormat;
use crate::stream_mode::StreamMode;

/// Every command the management interface accepts, modeled as a typed enum.
///
/// The encoder handles all serialization — escaping, quoting, multi-line
/// block framing — so callers never assemble raw strings. The `Raw` variant
/// exists as an escape hatch for commands not yet modeled here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OvpnCommand {
    // ── Informational ────────────────────────────────────────────
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

    // ── Real-time notification control ───────────────────────────
    /// Control real-time log streaming and/or dump log history.
    /// Wire: `log on` / `log off` / `log all` / `log on all` / `log 20`
    Log(StreamMode),

    /// Control real-time echo parameter notifications.
    /// Wire: `echo on` / `echo off` / `echo all` / `echo on all`
    Echo(StreamMode),

    /// Enable/disable byte count notifications at N-second intervals.
    /// Pass 0 to disable.
    /// Wire: `bytecount 5` / `bytecount 0`
    ByteCount(u32),

    // ── Connection control ───────────────────────────────────────
    /// Send a signal to the OpenVPN daemon.
    /// Wire: `signal SIGUSR1`
    Signal(Signal),

    /// Kill a specific client connection (server mode).
    /// Wire: `kill Test-Client` / `kill 1.2.3.4:4000`
    Kill(KillTarget),

    /// Query the current hold flag. Returns `0` (off) or `1` (on).
    /// Wire: `hold`
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

    // ── Authentication ───────────────────────────────────────────
    /// Supply a username for the given auth type.
    /// Wire: `username "Auth" myuser`
    Username {
        /// Which credential set this username belongs to.
        auth_type: AuthType,
        /// The username value.
        value: String,
    },

    /// Supply a password for the given auth type. The value is escaped
    /// and double-quoted per the OpenVPN config-file lexer rules.
    /// Wire: `password "Private Key" "foo\"bar"`
    Password {
        /// Which credential set this password belongs to.
        auth_type: AuthType,
        /// The password value (will be escaped on the wire).
        value: String,
    },

    /// Set the auth-retry strategy.
    /// Wire: `auth-retry interact`
    AuthRetry(AuthRetryMode),

    /// Forget all passwords entered during this management session.
    /// Wire: `forget-passwords`
    ForgetPasswords,

    // ── Challenge-response authentication ────────────────────────
    /// Respond to a CRV1 dynamic challenge.
    /// Wire: `password "Auth" "CRV1::state_id::response"`
    ChallengeResponse {
        /// The opaque state ID from the `>PASSWORD:` CRV1 notification.
        state_id: String,
        /// The user's response to the challenge.
        response: String,
    },

    /// Respond to a static challenge (SC).
    /// Wire: `password "Auth" "SCRV1::base64_password::base64_response"`
    ///
    /// The caller must pre-encode password and response as base64 —
    /// this crate does not include a base64 dependency.
    StaticChallengeResponse {
        /// Base64-encoded password.
        password_b64: String,
        /// Base64-encoded challenge response.
        response_b64: String,
    },

    // ── Interactive prompts (OpenVPN 2.1+) ───────────────────────
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

    // ── PKCS#11 (OpenVPN 2.1+) ──────────────────────────────────
    /// Query available PKCS#11 certificate count.
    /// Wire: `pkcs11-id-count`
    Pkcs11IdCount,

    /// Retrieve a PKCS#11 certificate by index.
    /// Wire: `pkcs11-id-get 1`
    Pkcs11IdGet(u32),

    // ── External key / RSA signature (OpenVPN 2.3+) ──────────────
    /// Provide an RSA signature in response to `>RSA_SIGN:`.
    /// This is a multi-line command: the encoder writes `rsa-sig`,
    /// then each base64 line, then `END`.
    RsaSig {
        /// Base64-encoded signature lines.
        base64_lines: Vec<String>,
    },

    // ── Client management (server mode, OpenVPN 2.1+) ────────────
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

    /// Immediately kill a client session by CID.
    /// Wire: `client-kill {CID}`
    ClientKill {
        /// Client ID.
        cid: u64,
    },

    /// Push a packet filter to a specific client. Multi-line command:
    /// header, filter block, `END`. Requires `--management-client-pf`.
    ClientPf {
        /// Client ID.
        cid: u64,
        /// Packet filter rules (e.g. `[CLIENTS ACCEPT]`, `+10.0.0.0/8`).
        filter_lines: Vec<String>,
    },

    // ── Remote/Proxy override ────────────────────────────────────
    /// Respond to a `>REMOTE:` notification (requires `--management-query-remote`).
    /// Wire: `remote ACCEPT` / `remote SKIP` / `remote MOD host port`
    Remote(RemoteAction),

    /// Respond to a `>PROXY:` notification (requires `--management-query-proxy`).
    /// Wire: `proxy NONE` / `proxy HTTP host port [nct]` / `proxy SOCKS host port`
    Proxy(ProxyAction),

    // ── Server statistics ─────────────────────────────────────────
    /// Request aggregated server stats.
    /// Wire: `load-stats`
    /// Response: `SUCCESS: nclients=N,bytesin=N,bytesout=N`
    LoadStats,

    // ── Extended client management (OpenVPN 2.5+) ────────────────
    /// Defer authentication for a client, allowing async auth backends.
    /// Wire: `client-pending-auth {CID} {KID} {TIMEOUT} {EXTRA}`
    ClientPendingAuth {
        /// Client ID.
        cid: u64,
        /// Key ID.
        kid: u64,
        /// Timeout in seconds before the pending auth expires.
        timeout: u32,
        /// Extra opaque string passed to the auth backend.
        extra: String,
    },

    /// Extended deny with optional redirect URL (OpenVPN 2.5+).
    /// Wire: `client-deny-v2 {CID} {KID} "reason" ["client-reason"] ["redirect-url"]`
    ClientDenyV2 {
        /// Client ID.
        cid: u64,
        /// Key ID.
        kid: u64,
        /// Server-side reason string.
        reason: String,
        /// Optional message sent to the client.
        client_reason: Option<String>,
        /// Optional URL the client should be redirected to.
        redirect_url: Option<String>,
    },

    /// Respond to a challenge-response authentication (OpenVPN 2.5+).
    /// Wire: `cr-response {CID} {KID} {RESPONSE}`
    CrResponse {
        /// Client ID.
        cid: u64,
        /// Key ID.
        kid: u64,
        /// The challenge-response answer.
        response: String,
    },

    // ── External certificate (OpenVPN 2.4+) ──────────────────────
    /// Supply an external certificate in response to `>NEED-CERTIFICATE`.
    /// Multi-line command: header, PEM lines, `END`.
    /// Wire: `certificate\n{pem_lines}\nEND`
    Certificate {
        /// PEM-encoded certificate lines.
        pem_lines: Vec<String>,
    },

    // ── Windows service bypass message ──────────────────────────
    /// (Windows only) Send a bypass message to the OpenVPN service.
    /// Wire: `bypass-message "message"`
    BypassMessage(String),

    // ── Management interface authentication ────────────────────────
    /// Authenticate to the management interface itself. Sent as a bare
    /// line (no command prefix, no quoting) in response to
    /// [`crate::OvpnMessage::PasswordPrompt`].
    /// Wire: `{password}\n`
    ManagementPassword(String),

    // ── Session lifecycle ────────────────────────────────────────
    /// Close the management session. OpenVPN keeps running and resumes
    /// listening for new management connections.
    Exit,

    /// Identical to `Exit`.
    Quit,

    // ── Escape hatch ─────────────────────────────────────────────
    /// Send a raw command string for anything not yet modeled above.
    Raw(String),
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
    /// Expect a single non-SUCCESS/ERROR value line (e.g. bare `hold` → "0").
    SingleValue,
    /// No response expected (connection may close).
    NoResponse,
}

impl OvpnCommand {
    /// Determine what kind of response this command produces, so the
    /// decoder knows how to frame the next incoming bytes.
    pub(crate) fn expected_response(&self) -> ResponseKind {
        match self {
            // These always produce multi-line (END-terminated) responses.
            Self::Status(_) | Self::Version | Self::Help | Self::Net => ResponseKind::MultiLine,

            // state/log/echo: depends on the specific sub-mode.
            Self::StateStream(mode) | Self::Log(mode) | Self::Echo(mode) => match mode {
                StreamMode::All | StreamMode::OnAll | StreamMode::Recent(_) => {
                    ResponseKind::MultiLine
                }
                StreamMode::On | StreamMode::Off => ResponseKind::SuccessOrError,
            },

            // Bare `state` returns a single comma-delimited state line.
            Self::State => ResponseKind::SingleValue,

            // Bare `hold` returns "0" or "1".
            Self::HoldQuery => ResponseKind::SingleValue,

            // `pkcs11-id-get N` returns a single PKCS11ID-ENTRY line.
            Self::Pkcs11IdGet(_) => ResponseKind::SingleValue,

            // exit/quit close the connection.
            Self::Exit | Self::Quit => ResponseKind::NoResponse,

            // Everything else produces SUCCESS: or ERROR:.
            _ => ResponseKind::SuccessOrError,
        }
    }
}
