use std::{borrow::Cow, collections::BTreeMap, collections::VecDeque, io};

use bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};
use tracing::{debug, warn};

use crate::{
    auth::AuthType,
    client_event::ClientEvent,
    command::{OvpnCommand, ResponseKind},
    kill_target::KillTarget,
    log_level::LogLevel,
    message::{Notification, OvpnMessage, PasswordNotification},
    openvpn_state::OpenVpnState,
    proxy_action::ProxyAction,
    redacted::Redacted,
    remote_action::RemoteAction,
    status_format::StatusFormat,
    transport_protocol::TransportProtocol,
    unrecognized::UnrecognizedKind,
};

/// Characters that are unsafe in the line-oriented management protocol:
/// `\n` and `\r` split commands; `\0` truncates at the C layer.
const WIRE_UNSAFE: &[char] = &['\n', '\r', '\0'];

/// Controls how the encoder handles characters that are unsafe for the
/// line-oriented management protocol (`\n`, `\r`, `\0`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncoderMode {
    /// Silently strip unsafe characters (default, defensive).
    ///
    /// `\n`, `\r`, and `\0` are removed from all user-supplied strings.
    /// Block body lines equaling `"END"` are escaped to `" END"`.
    #[default]
    Sanitize,

    /// Reject inputs containing unsafe characters with an error.
    ///
    /// [`Encoder::encode`] returns `Err(io::Error)` if any field contains
    /// `\n`, `\r`, or `\0`, or if a block body line equals `"END"`.
    /// The inner error can be downcast to [`EncodeError`] for structured
    /// matching.
    Strict,
}

/// Structured error for encoder-side validation failures.
///
/// Returned as the inner error of [`std::io::Error`] when [`EncoderMode::Strict`]
/// is active and the input contains characters that would corrupt the wire protocol.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    /// A field contains `\n`, `\r`, or `\0`.
    #[error("{0} contains characters unsafe for the management protocol (\\n, \\r, or \\0)")]
    UnsafeCharacters(&'static str),

    /// A multi-line block body line equals `"END"`.
    #[error("block body line equals \"END\", which would terminate the block early")]
    EndInBlockBody,
}

/// Ensure a string is safe for the wire protocol.
///
/// In [`EncoderMode::Sanitize`]: strips `\n`, `\r`, and `\0`, returning
/// the cleaned string (or borrowing the original if already clean).
///
/// In [`EncoderMode::Strict`]: returns `Err` if any unsafe characters
/// are present.
fn wire_safe<'a>(
    s: &'a str,
    field: &'static str,
    mode: EncoderMode,
) -> Result<Cow<'a, str>, io::Error> {
    if !s.contains(WIRE_UNSAFE) {
        return Ok(Cow::Borrowed(s));
    }
    match mode {
        EncoderMode::Sanitize => Ok(Cow::Owned(
            s.chars().filter(|chr| !WIRE_UNSAFE.contains(chr)).collect(),
        )),
        EncoderMode::Strict => Err(io::Error::other(EncodeError::UnsafeCharacters(field))),
    }
}

/// Backslash-escape `\` and `"` per the OpenVPN config-file lexer rules
/// ("Command Parsing" section):
///   `\` → `\\`
///   `"` → `\"`
///
/// This function performs *only* lexer escaping. Wire-safety validation
/// or sanitization must happen upstream via [`wire_safe`].
fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// Wrap an already-escaped string in double quotes for the wire format.
///
/// This is required for any user-supplied string that might contain
/// whitespace, backslashes, or quotes — passwords, reason strings,
/// needstr values, etc.
fn quote(s: &str) -> String {
    format!("\"{s}\"")
}

/// Codec-internal state for accumulating multi-line `>CLIENT:` notifications.
#[derive(Debug)]
struct ClientNotificationAccumulator {
    event: ClientEvent,
    cid: u64,
    kid: Option<u64>,
    env: BTreeMap<String, String>,
}

/// Controls how many items the decoder will accumulate in a multi-line
/// response or `>CLIENT:` ENV block before returning an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccumulationLimit {
    /// No limit on accumulated items (the default).
    Unlimited,

    /// At most this many items before the decoder returns an error.
    Max(usize),
}

/// Tokio codec for the OpenVPN management interface.
///
/// The **encoder** serializes typed [`OvpnCommand`] values into correct wire-format
/// bytes, including proper escaping and multi-line block framing.
///
/// The **decoder** performs the opposite operation.
/// It uses command-tracking state to correctly distinguish single-line from
/// multi-line responses, and accumulates multi-line `>CLIENT:` notifications
/// into a single [`OvpnMessage`] before emitting them.
///
/// # Sequential usage and pipelining
///
/// The OpenVPN management protocol is strictly sequential: the server
/// processes one command at a time and sends its response before reading
/// the next command. The codec maintains a **queue** of expected response
/// kinds — one per encoded command. This allows callers to pipeline
/// multiple commands (encode A, then B, then C) without waiting for each
/// response, as long as responses arrive in the same order.
/// Outgoing bytes are not buffered by the codec itself —
/// the [`Encoder`] implementation writes into the `BytesMut` that
/// `tokio_util::codec::Framed` owns, and `Framed` flushes them to the
/// socket.
///
/// Encoding while a multi-line response or `>CLIENT:` notification is
/// being accumulated is still discouraged (and logged as a warning),
/// because it means the caller is not draining the stream (emptying the
/// read half of the codec).
///
/// # Notification interleaving
///
/// Real-time notifications (`>STATE:`, `>LOG:`, `>BYTECOUNT:`, etc.) can
/// arrive at **any** time, including in the middle of a multi-line command
/// response. The decoder emits these immediately as
/// [`OvpnMessage::Notification`] without disrupting the ongoing
/// accumulation. The completed multi-line response is emitted afterward
/// with the interleaved notification lines excluded.
///
/// Consumers should always be prepared to handle `Notification` variants
/// between sending a command and receiving its response.
#[derive(better_default::Default)]
pub struct OvpnCodec {
    /// FIFO queue of expected response kinds — one per encoded command that
    /// has not yet been fully decoded.  The encoder pushes to the back; the
    /// decoder peeks / pops from the front.  This resolves the protocol's
    /// ambiguity: when the decoder sees a line that is not `SUCCESS:`,
    /// `ERROR:`, or a `>` notification, the front of this queue tells it
    /// whether to start multi-line accumulation or emit an error.
    ///
    /// When the queue is empty (no pending command), the decoder falls back
    /// to [`ResponseKind::SuccessOrError`].
    expected_queue: VecDeque<ResponseKind>,

    /// Accumulator for multi-line (END-terminated) command responses.
    multi_line_buf: Option<Vec<String>>,

    /// Accumulator for multi-line `>CLIENT:` notifications. When this is
    /// `Some(...)`, the decoder is waiting for `>CLIENT:ENV,END`.
    client_notification: Option<ClientNotificationAccumulator>,

    /// Maximum lines to accumulate in a multi-line response.
    ///
    /// Defaults to `Max(10_000)` — a safety net against unbounded growth
    /// when a history dump floods the response (e.g. `log on all` at high
    /// verbosity). Use [`with_max_multi_line_lines`](Self::with_max_multi_line_lines)
    /// to override.
    #[default(AccumulationLimit::Max(10_000))]
    max_multi_line_lines: AccumulationLimit,

    /// Maximum ENV entries to accumulate for a `>CLIENT:` notification.
    #[default(AccumulationLimit::Unlimited)]
    max_client_env_entries: AccumulationLimit,

    /// How the encoder handles unsafe characters in user-supplied strings.
    encoder_mode: EncoderMode,

    /// Whether the initial `>INFO:` banner has been seen. The first `>INFO:`
    /// is surfaced as [`OvpnMessage::Info`]; subsequent ones become
    /// [`Notification::Info`].
    seen_info: bool,
}

impl OvpnCodec {
    /// Create a new codec with default state, ready to encode commands and
    /// decode responses.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of lines accumulated in a multi-line
    /// response before the decoder returns an error.
    pub fn with_max_multi_line_lines(mut self, limit: AccumulationLimit) -> Self {
        self.max_multi_line_lines = limit;
        self
    }

    /// Set the maximum number of ENV entries accumulated for
    /// `>CLIENT:` notifications before the decoder returns an error.
    pub fn with_max_client_env_entries(mut self, limit: AccumulationLimit) -> Self {
        self.max_client_env_entries = limit;
        self
    }

    /// Set the encoder mode for handling unsafe characters in user-supplied
    /// strings.
    ///
    /// The default is [`EncoderMode::Sanitize`], which silently strips
    /// `\n`, `\r`, and `\0`. Use [`EncoderMode::Strict`] to reject inputs
    /// containing those characters with an error instead.
    pub fn with_encoder_mode(mut self, mode: EncoderMode) -> Self {
        self.encoder_mode = mode;
        self
    }

    /// Peek at the expected response kind for the next unmatched command.
    /// Falls back to `SuccessOrError` when no command is pending (defensive;
    /// self-describing SUCCESS/ERROR lines will still decode correctly).
    fn expected_front(&self) -> ResponseKind {
        self.expected_queue
            .front()
            .copied()
            .unwrap_or(ResponseKind::SuccessOrError)
    }

    /// Pop the front response kind after a complete response has been
    /// decoded (Success, Error, MultiLine, or NoResponse).
    fn consume_expected(&mut self) {
        self.expected_queue.pop_front();
    }
}

/// The decoder accumulated more items than its configured limit allows.
#[derive(Debug, thiserror::Error)]
#[error("{what} accumulation limit exceeded ({max})")]
struct AccumulationLimitExceeded {
    what: &'static str,
    max: usize,
}

fn check_accumulation_limit(
    current_len: usize,
    limit: AccumulationLimit,
    what: &'static str,
) -> Result<(), io::Error> {
    if let AccumulationLimit::Max(max) = limit
        && current_len >= max
    {
        return Err(io::Error::other(AccumulationLimitExceeded { what, max }));
    }
    Ok(())
}

// --- Encoder ---

impl Encoder<OvpnCommand> for OvpnCodec {
    type Error = io::Error;

    fn encode(&mut self, item: OvpnCommand, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if self.multi_line_buf.is_some() || self.client_notification.is_some() {
            warn!(
                "encode() called while the decoder is mid-accumulation \
                 (multi_line_buf or client_notification is active). \
                 Drain decode() before sending a new command."
            );
        }

        // Push the expected response kind onto the queue so the decoder
        // knows how to frame the corresponding response when it arrives.
        let response_kind = item.expected_response();
        self.expected_queue.push_back(response_kind);
        let cmd: &str = (&item).into();
        debug!(%cmd, expected = ?response_kind, queue_depth = self.expected_queue.len(), "encoding command");

        let mode = self.encoder_mode;

        match item {
            // --- Informational ---
            OvpnCommand::Status(StatusFormat::V1) => write_line(dst, "status"),
            OvpnCommand::Status(ref fmt) => write_line(dst, &format!("status {fmt}")),
            OvpnCommand::State => write_line(dst, "state"),
            OvpnCommand::StateStream(ref m) => write_line(dst, &format!("state {m}")),
            OvpnCommand::Version => write_line(dst, "version"),
            OvpnCommand::SetVersion(n) => write_line(dst, &format!("version {n}")),
            OvpnCommand::Pid => write_line(dst, "pid"),
            OvpnCommand::Help => write_line(dst, "help"),
            OvpnCommand::Net => write_line(dst, "net"),
            OvpnCommand::Verb(Some(n)) => write_line(dst, &format!("verb {n}")),
            OvpnCommand::Verb(None) => write_line(dst, "verb"),
            OvpnCommand::Mute(Some(n)) => write_line(dst, &format!("mute {n}")),
            OvpnCommand::Mute(None) => write_line(dst, "mute"),

            // --- Real-time notification control ---
            OvpnCommand::Log(ref m) => write_line(dst, &format!("log {m}")),
            OvpnCommand::Echo(ref m) => write_line(dst, &format!("echo {m}")),
            OvpnCommand::ByteCount(n) => write_line(dst, &format!("bytecount {n}")),

            // --- Connection control ---
            OvpnCommand::Signal(sig) => write_line(dst, &format!("signal {sig}")),
            OvpnCommand::Kill(KillTarget::CommonName(ref common_name)) => {
                let kill = format!("kill {}", wire_safe(common_name, "kill CN", mode)?);
                write_line(dst, &kill);
            }
            OvpnCommand::Kill(KillTarget::Address {
                ref protocol,
                ref ip,
                port,
            }) => {
                let safe_ip = wire_safe(ip, "kill address ip", mode)?;
                write_line(dst, &format!("kill {protocol}:{safe_ip}:{port}",));
            }
            OvpnCommand::HoldQuery => write_line(dst, "hold"),
            OvpnCommand::HoldOn => write_line(dst, "hold on"),
            OvpnCommand::HoldOff => write_line(dst, "hold off"),
            OvpnCommand::HoldRelease => write_line(dst, "hold release"),

            // --- Authentication ---
            //
            // Both username and password values MUST be properly escaped.
            // The auth type is always double-quoted on the wire.
            OvpnCommand::Username {
                ref auth_type,
                ref value,
            } => {
                // Per the doc: username "Auth" foo
                // Values containing special chars must be quoted+escaped:
                //   username "Auth" "foo\"bar"
                let auth_quoted = quote(&escape(&wire_safe(
                    &auth_type.to_string(),
                    "username auth_type",
                    mode,
                )?));
                let val = quote(&escape(&wire_safe(value.expose(), "username value", mode)?));
                write_line(dst, &format!("username {auth_quoted} {val}"));
            }
            OvpnCommand::Password {
                ref auth_type,
                ref value,
            } => {
                let auth_quoted = quote(&escape(&wire_safe(
                    &auth_type.to_string(),
                    "password auth_type",
                    mode,
                )?));
                let val = quote(&escape(&wire_safe(value.expose(), "password value", mode)?));
                write_line(dst, &format!("password {auth_quoted} {val}"));
            }
            OvpnCommand::AuthRetry(auth_retry_mode) => {
                write_line(dst, &format!("auth-retry {auth_retry_mode}"));
            }
            OvpnCommand::ForgetPasswords => write_line(dst, "forget-passwords"),

            // --- Challenge-response ---
            OvpnCommand::ChallengeResponse {
                ref state_id,
                ref response,
            } => {
                let sid = wire_safe(state_id, "challenge-response state_id", mode)?;
                let resp = wire_safe(response.expose(), "challenge-response response", mode)?;
                let value = format!("CRV1::{sid}::{resp}");
                let escaped = quote(&escape(&value));
                write_line(dst, &format!("password \"Auth\" {escaped}"));
            }
            OvpnCommand::StaticChallengeResponse {
                ref password,
                ref response,
            } => {
                use base64::Engine;
                let password_b64 =
                    base64::engine::general_purpose::STANDARD.encode(password.expose());
                let response_b64 =
                    base64::engine::general_purpose::STANDARD.encode(response.expose());
                let value = format!("SCRV1:{password_b64}:{response_b64}");
                let escaped = quote(&escape(&value));
                write_line(dst, &format!("password \"Auth\" {escaped}"));
            }

            // --- Interactive prompts ---
            OvpnCommand::NeedOk { ref name, response } => {
                let name = wire_safe(name, "needok name", mode)?;
                write_line(dst, &format!("needok {name} {response}"));
            }
            OvpnCommand::NeedStr {
                ref name,
                ref value,
            } => {
                let name = wire_safe(name, "needstr name", mode)?;
                let escaped = quote(&escape(&wire_safe(value, "needstr value", mode)?));
                write_line(dst, &format!("needstr {name} {escaped}"));
            }

            // --- PKCS#11 ---
            OvpnCommand::Pkcs11IdCount => write_line(dst, "pkcs11-id-count"),
            OvpnCommand::Pkcs11IdGet(idx) => write_line(dst, &format!("pkcs11-id-get {idx}")),

            // --- External key (multi-line command) ---
            //
            // Wire format:
            //   rsa-sig
            //   BASE64_LINE_1
            //   BASE64_LINE_2
            //   END
            OvpnCommand::RsaSig { ref base64_lines } => {
                write_block(dst, "rsa-sig", base64_lines, mode)?;
            }

            // --- External key signature (pk-sig) ---
            OvpnCommand::PkSig { ref base64_lines } => {
                write_block(dst, "pk-sig", base64_lines, mode)?;
            }

            // --- ENV filter ---
            OvpnCommand::EnvFilter(level) => write_line(dst, &format!("env-filter {level}")),

            // --- Remote entry queries ---
            OvpnCommand::RemoteEntryCount => write_line(dst, "remote-entry-count"),
            OvpnCommand::RemoteEntryGet(ref range) => {
                write_line(dst, &format!("remote-entry-get {range}"));
            }

            // --- Push updates ---
            OvpnCommand::PushUpdateBroad { ref options } => {
                let options = wire_safe(options, "push-update-broad options", mode)?;
                let opts = quote(&escape(&options));
                write_line(dst, &format!("push-update-broad {opts}"));
            }
            OvpnCommand::PushUpdateCid { cid, ref options } => {
                let options = wire_safe(options, "push-update-cid options", mode)?;
                let opts = quote(&escape(&options));
                write_line(dst, &format!("push-update-cid {cid} {opts}"));
            }

            // --- Client management ---
            //
            // client-auth is a multi-line command:
            //   client-auth {CID} {KID}
            //   push "route 10.0.0.0 255.255.0.0"
            //   END
            // An empty config_lines produces header + immediate END.
            OvpnCommand::ClientAuth {
                cid,
                kid,
                ref config_lines,
            } => {
                write_block(dst, &format!("client-auth {cid} {kid}"), config_lines, mode)?;
            }

            OvpnCommand::ClientAuthNt { cid, kid } => {
                write_line(dst, &format!("client-auth-nt {cid} {kid}"));
            }

            OvpnCommand::ClientDeny(ref deny) => {
                let reason_quoted = quote(&escape(&wire_safe(
                    &deny.reason,
                    "client-deny reason",
                    mode,
                )?));
                match deny.client_reason {
                    Some(ref client_reason_str) => {
                        let options =
                            wire_safe(client_reason_str, "client-deny client_reason", mode)?;
                        let client_reason_quoted = quote(&escape(&options));
                        write_line(
                            dst,
                            &format!(
                                "client-deny {} {} {reason_quoted} {client_reason_quoted}",
                                deny.cid, deny.kid
                            ),
                        );
                    }
                    None => write_line(
                        dst,
                        &format!("client-deny {} {} {reason_quoted}", deny.cid, deny.kid),
                    ),
                }
            }

            OvpnCommand::ClientKill { cid, ref message } => match message {
                Some(msg) => write_line(
                    dst,
                    &format!(
                        "client-kill {cid} {}",
                        wire_safe(msg, "client-kill message", mode)?
                    ),
                ),
                None => write_line(dst, &format!("client-kill {cid}")),
            },

            // --- Server statistics ---
            OvpnCommand::LoadStats => write_line(dst, "load-stats"),

            // --- Extended client management ---
            OvpnCommand::ClientPendingAuth {
                cid,
                kid,
                ref extra,
                timeout,
            } => {
                // Real-world limit discovered by jkroepke/openvpn-auth-oauth2
                // (used for WEB_AUTH URLs). Not documented in management-notes.txt.
                if extra.len() > 245 {
                    warn!(
                        len = extra.len(),
                        max = 245,
                        "client-pending-auth extra exceeds 245-character limit; \
                         OpenVPN may truncate or reject it"
                    );
                }
                let extra = wire_safe(extra, "client-pending-auth extra", mode)?;
                let pending_auth = format!("client-pending-auth {cid} {kid} {extra} {timeout}");
                write_line(dst, &pending_auth)
            }

            OvpnCommand::CrResponse { ref response } => {
                let response = wire_safe(response.expose(), "cr-response", mode)?;
                write_line(dst, &format!("cr-response {response}"));
            }

            // --- External certificate ---
            OvpnCommand::Certificate { ref pem_lines } => {
                write_block(dst, "certificate", pem_lines, mode)?;
            }

            // --- Remote/Proxy ---
            OvpnCommand::Remote(RemoteAction::Accept) => write_line(dst, "remote ACCEPT"),
            OvpnCommand::Remote(RemoteAction::Skip) => write_line(dst, "remote SKIP"),
            OvpnCommand::Remote(RemoteAction::SkipN(n)) => {
                write_line(dst, &format!("remote SKIP {n}"));
            }
            OvpnCommand::Remote(RemoteAction::Modify { ref host, port }) => {
                let host = wire_safe(host, "remote MOD host", mode)?;
                write_line(dst, &format!("remote MOD {host} {port}"));
            }
            OvpnCommand::Proxy(ProxyAction::None) => write_line(dst, "proxy NONE"),
            OvpnCommand::Proxy(ProxyAction::Http {
                ref host,
                port,
                non_cleartext_only,
            }) => {
                let nct = if non_cleartext_only { " nct" } else { "" };
                let host = wire_safe(host, "proxy HTTP host", mode)?;
                write_line(dst, &format!("proxy HTTP {host} {port}{nct}"));
            }
            OvpnCommand::Proxy(ProxyAction::Socks { ref host, port }) => {
                let host = wire_safe(host, "proxy SOCKS host", mode)?;
                write_line(dst, &format!("proxy SOCKS {host} {port}"));
            }

            // --- Management interface auth ---
            // Bare line, no quoting — the management password protocol
            // does not use the config-file lexer.
            OvpnCommand::ManagementPassword(ref pw) => {
                write_line(dst, &wire_safe(pw.expose(), "management password", mode)?);
            }

            // --- Lifecycle ---
            OvpnCommand::Exit => write_line(dst, "exit"),
            OvpnCommand::Quit => write_line(dst, "quit"),

            // --- Escape hatch ---
            OvpnCommand::Raw(ref cmd) | OvpnCommand::RawMultiLine(ref cmd) => {
                write_line(dst, &wire_safe(cmd, "raw command", mode)?);
            }
        }

        Ok(())
    }
}

/// Write a single line followed by `\n`.
fn write_line(dst: &mut BytesMut, s: &str) {
    dst.reserve(s.len() + 1);
    dst.put_slice(s.as_bytes());
    dst.put_u8(b'\n');
}

/// Write a multi-line block: header line, body lines, and a terminating `END`.
///
/// In [`EncoderMode::Sanitize`] mode, body lines have `\n`, `\r`, and `\0`
/// stripped, and any line that would be exactly `"END"` is escaped to
/// `" END"` so the server does not treat it as the block terminator.
///
/// In [`EncoderMode::Strict`] mode, body lines containing unsafe characters
/// or equaling `"END"` cause an error.
fn write_block(
    dst: &mut BytesMut,
    header: &str,
    lines: &[String],
    mode: EncoderMode,
) -> Result<(), io::Error> {
    // Upper-bound byte count for the entire block on the wire:
    //   header.len()  — header line text (e.g. ">client-auth 7 42")
    //   + 1           — '\n' terminating the header
    //   + Σ(l.len()+2)— each body line's text + "\r\n" (2 bytes)
    //   + 4           — "END\n" block terminator
    // This is a conservative estimate: sanitized lines may shrink or grow
    // slightly, but over-reserving is harmless — only written bytes count.
    let total: usize =
        header.len() + 1 + lines.iter().map(|line| line.len() + 2).sum::<usize>() + 4;
    dst.reserve(total);
    dst.put_slice(header.as_bytes());
    dst.put_u8(b'\n');
    for line in lines {
        let clean = wire_safe(line, "block body line", mode)?;
        if *clean == *"END" {
            match mode {
                EncoderMode::Sanitize => {
                    dst.put_slice(b" END");
                    dst.put_u8(b'\n');
                    continue;
                }
                EncoderMode::Strict => {
                    return Err(io::Error::other(EncodeError::EndInBlockBody));
                }
            }
        }
        dst.put_slice(clean.as_bytes());
        dst.put_u8(b'\n');
    }
    dst.put_slice(b"END\n");
    Ok(())
}

/// The password prompt.
///
/// May arrive without a trailing newline
/// (OpenVPN ≥ 2.6 sends it as an interactive prompt, expecting
/// the password on the same line).
/// Handle this only when no complete line is available —
/// if `\n` is in the buffer,
/// the normal line-based path below handles it correctly.
const PW_PROMPT: &[u8] = b"ENTER PASSWORD:";

// --- Decoder ---

impl Decoder for OvpnCodec {
    type Item = OvpnMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            // Find the next complete line.
            let Some(newline_pos) = src.iter().position(|&b| b == b'\n') else {
                // No complete line yet. Check for a password prompt
                // without a trailing newline (OpenVPN ≥ 2.6 sends it as
                // an interactive prompt with no line terminator).
                // We accept any buffer that starts with the prompt text
                // since no `\n` is present (checked above). Consume the
                // prompt and any trailing `\r`.
                if src.starts_with(PW_PROMPT) {
                    let mut consume = PW_PROMPT.len();
                    if src.get(consume) == Some(&b'\r') {
                        consume += 1;
                    }
                    src.advance(consume);
                    return Ok(Some(OvpnMessage::PasswordPrompt));
                }
                // Hint to Framed: reserve enough for a typical management
                // protocol line so the next read_buf doesn't micro-allocate.
                if src.capacity() - src.len() < 256 {
                    src.reserve(256);
                }
                return Ok(None); // Need more data.
            };

            // Extract the line and advance the buffer past the newline.
            let line_bytes = src.split_to(newline_pos + 1);
            let line = match std::str::from_utf8(&line_bytes) {
                Ok(text) => text,
                Err(error) => {
                    // Reset all accumulation state so the decoder doesn't
                    // remain stuck in a half-finished multi-line block.
                    self.multi_line_buf = None;
                    self.client_notification = None;
                    self.expected_queue.clear();
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            }
            .trim_end_matches(['\r', '\n'])
            .to_string();

            // Bare newlines (empty lines) carry no information when the
            // decoder is not inside an accumulation context AND is not
            // expecting a multi-line response. Skip them silently rather
            // than emitting Unrecognized. This also absorbs the trailing
            // `\n` when the password prompt was already consumed without
            // a line terminator (OpenVPN ≥ 2.6).
            if line.is_empty()
                && self.multi_line_buf.is_none()
                && self.client_notification.is_none()
                && !matches!(self.expected_front(), ResponseKind::MultiLine)
            {
                continue;
            }

            // --- Phase 1: Multi-line >CLIENT: accumulation ---
            //
            // When we're accumulating a CLIENT notification, >CLIENT:ENV
            // lines belong to it. The block terminates with >CLIENT:ENV,END.
            // The spec guarantees atomicity for CLIENT notifications, so
            // interleaving here should not occur. Any other line (SUCCESS,
            // ERROR, other notifications) falls through to normal processing
            // as a defensive measure.
            if let Some(ref mut accum) = self.client_notification
                && let Some(rest) = line.strip_prefix(">CLIENT:ENV,")
            {
                if rest == "END" {
                    let finished = self.client_notification.take().expect("guarded by if-let");
                    debug!(event = ?finished.event, cid = finished.cid, env_count = finished.env.len(), "decoded CLIENT notification");
                    return Ok(Some(OvpnMessage::Notification(Notification::Client {
                        event: finished.event,
                        cid: finished.cid,
                        kid: finished.kid,
                        env: finished.env,
                    })));
                } else {
                    // Parse "key=value" (value may contain '=').
                    let (k, v) = rest
                        .split_once('=')
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .unwrap_or_else(|| (rest.to_string(), String::new()));
                    check_accumulation_limit(
                        accum.env.len(),
                        self.max_client_env_entries,
                        "client ENV",
                    )?;
                    accum.env.insert(k, v);
                    continue; // Next line.
                }
            }
            // Not a >CLIENT:ENV line — fall through to normal processing.
            // This handles interleaved notifications or unexpected output.

            // --- Phase 2: Multi-line command response accumulation ---
            if let Some(ref mut buf) = self.multi_line_buf {
                if line == "END" {
                    let lines = self.multi_line_buf.take().expect("guarded by if-let");
                    self.consume_expected();
                    debug!(line_count = lines.len(), "decoded multi-line response");
                    return Ok(Some(OvpnMessage::MultiLine(lines)));
                }
                // The spec only guarantees atomicity for CLIENT notifications,
                // not for command responses — real-time notifications (>STATE:,
                // >LOG:, etc.) can arrive mid-response. Emit them immediately
                // without breaking the accumulation.
                if line.starts_with('>') {
                    if let Some(msg) = self.parse_notification(&line) {
                        return Ok(Some(msg));
                    }
                    // parse_notification returns None when it starts a CLIENT
                    // accumulation. Loop to read the next line.
                    continue;
                }
                check_accumulation_limit(
                    buf.len(),
                    self.max_multi_line_lines,
                    "multi-line response",
                )?;
                buf.push(line);
                continue; // Next line.
            }

            // --- Phase 3: Self-describing lines ---
            //
            // SUCCESS: and ERROR: are unambiguous. We match on "SUCCESS:"
            // without requiring a trailing space — the doc shows
            // "SUCCESS: [text]" but text could be empty.
            if let Some(rest) = line.strip_prefix("SUCCESS:") {
                self.consume_expected();
                return Ok(Some(OvpnMessage::Success(
                    rest.strip_prefix(' ').unwrap_or(rest).to_string(),
                )));
            }
            if let Some(rest) = line.strip_prefix("ERROR:") {
                self.consume_expected();
                return Ok(Some(OvpnMessage::Error(
                    rest.strip_prefix(' ').unwrap_or(rest).to_string(),
                )));
            }

            // Management interface password prompt (no `>` prefix).
            if line == "ENTER PASSWORD:" {
                return Ok(Some(OvpnMessage::PasswordPrompt));
            }

            // Real-time notifications.
            if line.starts_with('>') {
                if let Some(msg) = self.parse_notification(&line) {
                    return Ok(Some(msg));
                }
                // Started CLIENT notification accumulation — loop for ENV lines.
                continue;
            }

            // --- Phase 4: Ambiguous lines — use command tracking ---
            //
            // The line is not self-describing (no SUCCESS/ERROR/> prefix).
            // Use the expected-response state from the last encoded command
            // to decide how to frame it.
            match self.expected_front() {
                ResponseKind::MultiLine => {
                    if line == "END" {
                        // Edge case: empty multi-line block (header-less).
                        self.consume_expected();
                        return Ok(Some(OvpnMessage::MultiLine(Vec::new())));
                    }
                    self.multi_line_buf = Some(vec![line]);
                    continue; // Accumulate until END.
                }
                ResponseKind::SuccessOrError | ResponseKind::NoResponse => {
                    self.consume_expected();
                    warn!(line = %line, "unrecognized line from server");
                    return Ok(Some(OvpnMessage::Unrecognized {
                        line,
                        kind: UnrecognizedKind::UnexpectedLine,
                    }));
                }
            }
        }
    }
}

impl OvpnCodec {
    /// Parse a `>` notification line. Returns `Some(msg)` for single-line
    /// notifications and `None` when a multi-line CLIENT accumulation has
    /// been started (the caller should continue reading lines).
    fn parse_notification(&mut self, line: &str) -> Option<OvpnMessage> {
        let inner = &line[1..]; // Strip leading `>`

        let Some((kind, payload)) = inner.split_once(':') else {
            // Malformed notification — no colon.
            warn!(line = %line, "malformed notification (no colon)");
            return Some(OvpnMessage::Unrecognized {
                line: line.to_string(),
                kind: UnrecognizedKind::MalformedNotification,
            });
        };

        // >INFO: on the very first line is the connection banner — surface
        // it as OvpnMessage::Info. All subsequent >INFO: lines (e.g.
        // >INFO:WEB_AUTH::url) are routed to Notification::Info.
        if kind == "INFO" {
            if !self.seen_info {
                self.seen_info = true;
                return Some(OvpnMessage::Info(payload.to_string()));
            }
            return Some(OvpnMessage::Notification(Notification::Info {
                message: payload.to_string(),
            }));
        }

        // >CLIENT: may be multi-line. Inspect the sub-type to decide.
        if kind == "CLIENT" {
            let (event, args) = payload
                .split_once(',')
                .map(|(event_str, args_str)| (event_str.to_string(), args_str.to_string()))
                .unwrap_or_else(|| (payload.to_string(), String::new()));

            // ADDRESS notifications are always single-line (no ENV block).
            if event == "ADDRESS" {
                let mut parts = args.splitn(3, ',');
                let cid = parts
                    .next()
                    .and_then(|field| parse_field(field, "client address cid"))
                    .unwrap_or(0);
                let addr = parts.next().unwrap_or("").to_string();
                let primary = parts.next() == Some("1");
                return Some(OvpnMessage::Notification(Notification::ClientAddress {
                    cid,
                    addr,
                    primary,
                }));
            }

            // CONNECT, REAUTH, ESTABLISHED, DISCONNECT, and CR_RESPONSE all
            // have ENV blocks. Parse CID, optional KID, and (for CR_RESPONSE)
            // the trailing base64 response from the args.
            let mut id_parts = args.splitn(3, ',');
            let cid = id_parts
                .next()
                .and_then(|field| parse_field(field, "client cid"))
                .unwrap_or(0);
            let kid = id_parts
                .next()
                .and_then(|field| parse_field(field, "client kid"));

            let parsed_event = if event == "CR_RESPONSE" {
                let response = id_parts.next().unwrap_or("").to_string();
                ClientEvent::CrResponse(response)
            } else {
                event
                    .parse()
                    .inspect_err(|error| warn!(%error, "unknown client event"))
                    .unwrap_or_else(|_| ClientEvent::Unknown(event.clone()))
            };

            // Start accumulation — don't emit anything yet.
            self.client_notification = Some(ClientNotificationAccumulator {
                event: parsed_event,
                cid,
                kid,
                env: BTreeMap::new(),
            });
            return None; // Signal to the caller to keep reading.
        }

        // Dispatch to typed parsers. On parse failure, fall back to Simple.
        let notification = match kind {
            "STATE" => parse_state(payload),
            "BYTECOUNT" => parse_bytecount(payload),
            "BYTECOUNT_CLI" => parse_bytecount_cli(payload),
            "LOG" => parse_log(payload),
            "ECHO" => parse_echo(payload),
            "HOLD" => Some(Notification::Hold {
                text: payload.to_string(),
            }),
            "FATAL" => Some(Notification::Fatal {
                message: payload.to_string(),
            }),
            "PKCS11ID-COUNT" => parse_pkcs11id_count(payload),
            "NEED-OK" => parse_need_ok(payload),
            "NEED-STR" => parse_need_str(payload),
            "RSA_SIGN" => Some(Notification::RsaSign {
                data: payload.to_string(),
            }),
            "PK_SIGN" => parse_pk_sign(payload),
            "INFOMSG" => Some(Notification::InfoMsg {
                extra: payload.to_string(),
            }),
            "NEED-CERTIFICATE" => Some(Notification::NeedCertificate {
                hint: payload.to_string(),
            }),
            "REMOTE" => parse_remote(payload),
            "PROXY" => parse_proxy(payload),
            "PASSWORD" => parse_password(payload),
            "PKCS11ID-ENTRY" => {
                return parse_pkcs11id_entry_notif(payload).or_else(|| {
                    Some(OvpnMessage::Notification(Notification::Simple {
                        kind: kind.to_string(),
                        payload: payload.to_string(),
                    }))
                });
            }
            _ => None,
        };

        Some(OvpnMessage::Notification(notification.unwrap_or(
            Notification::Simple {
                kind: kind.to_string(),
                payload: payload.to_string(),
            },
        )))
    }
}

// --- Notification parsers ---
//
// Each returns `Option<Notification>`. `None` means "could not parse,
// fall back to Simple". This is intentional — the protocol varies
// across OpenVPN versions and we never want a parse failure to
// produce an error.

/// Parse a port field that may be empty. Empty or whitespace-only strings
/// yield `None`; non-empty non-numeric strings also yield `None` (the STATE
/// notification degrades gracefully via the caller's `?` on other fields).
fn parse_optional_port(input: &str) -> Option<u16> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed
        .parse()
        .inspect_err(
            |error| warn!(%error, port = trimmed, "non-numeric port in STATE notification"),
        )
        .ok()
}

/// Parse a string into `T`, logging a warning on failure and returning `None`.
///
/// Used by the notification parsers that degrade to `Notification::Simple`
/// rather than failing hard.
fn parse_field<T: std::str::FromStr>(value: &str, field: &str) -> Option<T>
where
    T::Err: std::fmt::Display,
{
    value
        .parse()
        .inspect_err(|error| warn!(%error, value, field, "failed to parse notification field"))
        .ok()
}

fn parse_state(payload: &str) -> Option<Notification> {
    // Wire format per management-notes.txt:
    //   (a) timestamp, (b) state, (c) desc, (d) local_ip, (e) remote_ip,
    //   (f) remote_port, (g) local_addr, (h) local_port, (i) local_ipv6
    let mut parts = payload.splitn(9, ',');
    let timestamp =
        crate::timestamp::UtcTimestamp(parse_field(parts.next()?, "state timestamp")?);
    let state_str = parts.next()?;
    let name = state_str
        .parse()
        .inspect_err(|error| warn!(%error, "unknown OpenVPN state"))
        .unwrap_or_else(|_| OpenVpnState::Unknown(state_str.to_string()));
    let description = parts.next()?.to_string();
    let local_ip = parts.next()?.to_string();
    let remote_ip = parts.next()?.to_string();
    let remote_port = parse_optional_port(parts.next().unwrap_or(""));
    let local_addr = parts.next().unwrap_or("").to_string();
    let local_port = parse_optional_port(parts.next().unwrap_or(""));
    let local_ipv6 = parts.next().unwrap_or("").to_string();
    Some(Notification::State(crate::parsed_response::StateEntry {
        timestamp,
        name,
        description,
        local_ip,
        remote_ip,
        remote_port,
        local_addr,
        local_port,
        local_ipv6,
    }))
}

fn parse_bytecount(payload: &str) -> Option<Notification> {
    let (a, b) = payload.split_once(',')?;
    Some(Notification::ByteCount {
        bytes_in: parse_field(a, "bytecount bytes_in")?,
        bytes_out: parse_field(b, "bytecount bytes_out")?,
    })
}

fn parse_bytecount_cli(payload: &str) -> Option<Notification> {
    let mut parts = payload.splitn(3, ',');
    let cid = parse_field(parts.next()?, "bytecount_cli cid")?;
    let bytes_in = parse_field(parts.next()?, "bytecount_cli bytes_in")?;
    let bytes_out = parse_field(parts.next()?, "bytecount_cli bytes_out")?;
    Some(Notification::ByteCountCli {
        cid,
        bytes_in,
        bytes_out,
    })
}

fn parse_log(payload: &str) -> Option<Notification> {
    let (ts_str, rest) = payload.split_once(',')?;
    let timestamp = crate::timestamp::UtcTimestamp(parse_field(ts_str, "log timestamp")?);
    let (level_str, message) = rest.split_once(',')?;
    Some(Notification::Log {
        timestamp,
        level: level_str
            .parse()
            .inspect_err(|error| warn!(%error, "unknown log level"))
            .unwrap_or_else(|_| LogLevel::Unknown(level_str.to_string())),
        message: message.to_string(),
    })
}

fn parse_echo(payload: &str) -> Option<Notification> {
    let (ts_str, param) = payload.split_once(',')?;
    let timestamp = crate::timestamp::UtcTimestamp(parse_field(ts_str, "echo timestamp")?);
    Some(Notification::Echo {
        timestamp,
        param: param.to_string(),
    })
}

fn parse_pkcs11id_count(payload: &str) -> Option<Notification> {
    let count = parse_field(payload.trim(), "pkcs11id_count")?;
    Some(Notification::Pkcs11IdCount { count })
}

/// Parse `>PKCS11ID-ENTRY:'idx', ID:'id', BLOB:'blob'` from the notification
/// payload (after the kind and colon have been stripped).
fn parse_pkcs11id_entry_notif(payload: &str) -> Option<OvpnMessage> {
    let rest = payload.strip_prefix('\'')?;
    let (index, rest) = rest.split_once("', ID:'")?;
    let (id, rest) = rest.split_once("', BLOB:'")?;
    let blob = rest.strip_suffix('\'')?;
    Some(OvpnMessage::Pkcs11IdEntry {
        index: index.to_string(),
        id: id.to_string(),
        blob: blob.to_string(),
    })
}

/// Parse `Need 'name' ... MSG:message` from NEED-OK payload.
fn parse_need_ok(payload: &str) -> Option<Notification> {
    // Format: Need 'name' confirmation MSG:message
    let rest = payload.strip_prefix("Need '")?;
    let (name, rest) = rest.split_once('\'')?;
    let msg = rest.split_once("MSG:")?.1;
    Some(Notification::NeedOk {
        name: name.to_string(),
        message: msg.to_string(),
    })
}

/// Parse `Need 'name' input MSG:message` from NEED-STR payload.
fn parse_need_str(payload: &str) -> Option<Notification> {
    let rest = payload.strip_prefix("Need '")?;
    let (name, rest) = rest.split_once('\'')?;
    let msg = rest.split_once("MSG:")?.1;
    Some(Notification::NeedStr {
        name: name.to_string(),
        message: msg.to_string(),
    })
}

/// Parse `>PK_SIGN:base64_data[,algorithm]`.
///
/// The algorithm field is only present when the management client announced
/// version > 2 via the `version` command.
///
/// Source: [`management-notes.txt`](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt),
/// [`ssl_openssl.c` `get_sig_from_man()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_openssl.c).
fn parse_pk_sign(payload: &str) -> Option<Notification> {
    if payload.is_empty() {
        return None;
    }
    let (data, algorithm) = match payload.split_once(',') {
        Some((d, a)) => (d.to_string(), Some(a.to_string())),
        None => (payload.to_string(), None),
    };
    Some(Notification::PkSign { data, algorithm })
}

fn parse_remote(payload: &str) -> Option<Notification> {
    let mut parts = payload.splitn(3, ',');
    let host = parts.next()?.to_string();
    let port = parse_field(parts.next()?, "remote port")?;
    let proto_str = parts.next()?;
    let protocol = proto_str
        .parse()
        .inspect_err(|error| warn!(%error, "unknown transport protocol"))
        .unwrap_or_else(|_| TransportProtocol::Unknown(proto_str.to_string()));
    Some(Notification::Remote {
        host,
        port,
        protocol,
    })
}

fn parse_proxy(payload: &str) -> Option<Notification> {
    // Wire: >PROXY:{index},{type},{host}  (3 fields per init.c)
    let mut parts = payload.splitn(3, ',');
    let index = parse_field(parts.next()?, "proxy index")?;
    let pt_str = parts.next()?;
    let proxy_type = pt_str
        .parse()
        .inspect_err(|error| warn!(%error, "unknown proxy type"))
        .unwrap_or_else(|_| TransportProtocol::Unknown(pt_str.to_string()));
    let host = parts.next()?.to_string();
    Some(Notification::Proxy {
        index,
        proxy_type,
        host,
    })
}

/// Map a wire auth-type string to the typed enum.
fn parse_auth_type(s: &str) -> AuthType {
    s.parse()
        .inspect_err(|error| warn!(%error, "unknown auth type"))
        .unwrap_or_else(|_| AuthType::Unknown(s.to_string()))
}

fn parse_password(payload: &str) -> Option<Notification> {
    // Auth-Token:{token}
    // Source: manage.c management_auth_token()
    if let Some(token) = payload.strip_prefix("Auth-Token:") {
        return Some(Notification::Password(PasswordNotification::AuthToken {
            token: Redacted::new(token),
        }));
    }

    // Verification Failed: 'Auth' ['CRV1:flags:state_id:user_b64:challenge']
    // Verification Failed: 'Auth'
    if let Some(rest) = payload.strip_prefix("Verification Failed: '") {
        // Check for CRV1 dynamic challenge data
        if let Some((auth_part, crv1_part)) = rest.split_once("' ['CRV1:") {
            debug_assert_eq!(auth_part, "Auth", "CRV1 auth type should always be 'Auth'");
            let crv1_data = crv1_part.strip_suffix("']")?;
            let mut parts = crv1_data.splitn(4, ':');
            let flags = parts.next()?.to_string();
            let state_id = parts.next()?.to_string();
            let username_b64 = parts.next()?.to_string();
            let challenge = parts.next()?.to_string();
            return Some(Notification::Password(
                PasswordNotification::DynamicChallenge {
                    flags,
                    state_id,
                    username_b64,
                    challenge,
                },
            ));
        }
        // Bare verification failure
        let auth_type = rest.strip_suffix('\'')?;
        return Some(Notification::Password(
            PasswordNotification::VerificationFailed {
                auth_type: parse_auth_type(auth_type),
            },
        ));
    }

    // Need 'type' username/password [SC:...]
    // Need 'type' password
    let rest = payload.strip_prefix("Need '")?;
    let (auth_type_str, rest) = rest.split_once('\'')?;
    let rest = rest.trim_start();

    if let Some(after_up) = rest.strip_prefix("username/password") {
        let after_up = after_up.trim_start();

        // Static challenge: SC:flag,challenge_text
        // flag is a multi-bit integer: bit 0 = ECHO, bit 1 = FORMAT/CONCAT
        if let Some(sc) = after_up.strip_prefix("SC:") {
            let (flag_str, challenge) = sc.split_once(',')?;
            let flags: u32 = parse_field(flag_str, "static challenge flags")?;
            return Some(Notification::Password(
                PasswordNotification::StaticChallenge {
                    echo: flags & 1 != 0,
                    response_concat: flags & 2 != 0,
                    challenge: challenge.to_string(),
                },
            ));
        }

        // Plain username/password request
        return Some(Notification::Password(PasswordNotification::NeedAuth {
            auth_type: parse_auth_type(auth_type_str),
        }));
    }

    // Need 'type' password
    if rest.starts_with("password") {
        return Some(Notification::Password(PasswordNotification::NeedPassword {
            auth_type: parse_auth_type(auth_type_str),
        }));
    }

    None // Unrecognized PASSWORD sub-format — fall back to Simple
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        auth::AuthType, client_deny::ClientDeny, client_event::ClientEvent,
        message::PasswordNotification, parsed_response::StateEntry, signal::Signal,
        status_format::StatusFormat, stream_mode::StreamMode, timestamp::UtcTimestamp,
    };

    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};
    use tracing_test::traced_test;

    /// Helper: encode a command and return the wire bytes as a string.
    fn encode_to_string(cmd: OvpnCommand) -> String {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(cmd, &mut buf).unwrap();
        String::from_utf8(buf.to_vec()).unwrap()
    }

    /// Helper: feed raw bytes into a fresh codec and collect all decoded messages.
    fn decode_all(input: &str) -> Vec<OvpnMessage> {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::from(input);
        let mut msgs = Vec::new();
        while let Some(msg) = codec.decode(&mut buf).unwrap() {
            msgs.push(msg);
        }
        msgs
    }

    /// Helper: encode a command, then feed raw response bytes, collecting messages.
    fn encode_then_decode(cmd: OvpnCommand, response: &str) -> Vec<OvpnMessage> {
        let mut codec = OvpnCodec::new();
        let mut enc_buf = BytesMut::new();
        codec.encode(cmd, &mut enc_buf).unwrap();
        let mut dec_buf = BytesMut::from(response);
        let mut msgs = Vec::new();
        while let Some(msg) = codec.decode(&mut dec_buf).unwrap() {
            msgs.push(msg);
        }
        msgs
    }

    // --- Encoder tests ---

    #[test]
    fn encode_status_v1() {
        assert_eq!(
            encode_to_string(OvpnCommand::Status(StatusFormat::V1)),
            "status\n"
        );
    }

    #[test]
    fn encode_status_v3() {
        assert_eq!(
            encode_to_string(OvpnCommand::Status(StatusFormat::V3)),
            "status 3\n"
        );
    }

    #[test]
    fn encode_signal() {
        assert_eq!(
            encode_to_string(OvpnCommand::Signal(Signal::SigUsr1)),
            "signal SIGUSR1\n"
        );
    }

    #[test]
    fn encode_state_on_all() {
        assert_eq!(
            encode_to_string(OvpnCommand::StateStream(StreamMode::OnAll)),
            "state on all\n"
        );
    }

    #[test]
    fn encode_state_recent() {
        assert_eq!(
            encode_to_string(OvpnCommand::StateStream(StreamMode::Recent(5))),
            "state 5\n"
        );
    }

    #[test]
    fn encode_password_escaping() {
        // A password containing a backslash and a double quote must be
        // properly escaped on the wire.
        let wire = encode_to_string(OvpnCommand::Password {
            auth_type: AuthType::PrivateKey,
            value: r#"foo\"bar"#.into(),
        });
        assert_eq!(wire, "password \"Private Key\" \"foo\\\\\\\"bar\"\n");
    }

    #[test]
    fn encode_password_simple() {
        let wire = encode_to_string(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "hunter2".into(),
        });
        assert_eq!(wire, "password \"Auth\" \"hunter2\"\n");
    }

    #[test]
    fn encode_client_auth_with_config() {
        let wire = encode_to_string(OvpnCommand::ClientAuth {
            cid: 42,
            kid: 0,
            config_lines: vec![
                "push \"route 10.0.0.0 255.255.0.0\"".to_string(),
                "push \"dhcp-option DNS 10.0.0.1\"".to_string(),
            ],
        });
        assert_eq!(
            wire,
            "client-auth 42 0\n\
             push \"route 10.0.0.0 255.255.0.0\"\n\
             push \"dhcp-option DNS 10.0.0.1\"\n\
             END\n"
        );
    }

    #[test]
    fn encode_client_auth_empty_config() {
        let wire = encode_to_string(OvpnCommand::ClientAuth {
            cid: 1,
            kid: 0,
            config_lines: vec![],
        });
        assert_eq!(wire, "client-auth 1 0\nEND\n");
    }

    #[test]
    fn encode_client_deny_with_client_reason() {
        let wire = encode_to_string(OvpnCommand::ClientDeny(ClientDeny {
            cid: 5,
            kid: 0,
            reason: "cert revoked".to_string(),
            client_reason: Some("Your access has been revoked.".to_string()),
        }));
        assert_eq!(
            wire,
            "client-deny 5 0 \"cert revoked\" \"Your access has been revoked.\"\n"
        );
    }

    #[test]
    fn encode_client_pending_auth() {
        let wire = encode_to_string(OvpnCommand::ClientPendingAuth {
            cid: 42,
            kid: 1,
            extra: "WEB_AUTH::https://example.com".to_string(),
            timeout: 120,
        });
        assert_eq!(
            wire,
            "client-pending-auth 42 1 WEB_AUTH::https://example.com 120\n"
        );
    }

    #[test]
    #[traced_test]
    fn encode_client_pending_auth_long_extra_warns() {
        let long_extra = "W".repeat(246);
        let wire = encode_to_string(OvpnCommand::ClientPendingAuth {
            cid: 1,
            kid: 0,
            extra: long_extra.clone(),
            timeout: 60,
        });
        assert_eq!(wire, format!("client-pending-auth 1 0 {long_extra} 60\n"));
        assert!(logs_contain("exceeds 245-character limit"));
    }

    #[test]
    #[traced_test]
    fn encode_client_pending_auth_at_limit_no_warning() {
        let extra = "W".repeat(245);
        encode_to_string(OvpnCommand::ClientPendingAuth {
            cid: 1,
            kid: 0,
            extra,
            timeout: 60,
        });
        assert!(!logs_contain("exceeds 245-character limit"));
    }

    #[test]
    fn encode_rsa_sig() {
        let wire = encode_to_string(OvpnCommand::RsaSig {
            base64_lines: vec!["AAAA".to_string(), "BBBB".to_string()],
        });
        assert_eq!(wire, "rsa-sig\nAAAA\nBBBB\nEND\n");
    }

    #[test]
    fn encode_remote_modify() {
        let wire = encode_to_string(OvpnCommand::Remote(RemoteAction::Modify {
            host: "vpn.example.com".to_string(),
            port: 1234,
        }));
        assert_eq!(wire, "remote MOD vpn.example.com 1234\n");
    }

    #[test]
    fn encode_pk_sig() {
        let wire = encode_to_string(OvpnCommand::PkSig {
            base64_lines: vec!["AAAA".to_string(), "BBBB".to_string()],
        });
        assert_eq!(wire, "pk-sig\nAAAA\nBBBB\nEND\n");
    }

    #[test]
    fn encode_env_filter() {
        assert_eq!(
            encode_to_string(OvpnCommand::EnvFilter(2)),
            "env-filter 2\n"
        );
    }

    #[test]
    fn encode_remote_entry_count() {
        assert_eq!(
            encode_to_string(OvpnCommand::RemoteEntryCount),
            "remote-entry-count\n"
        );
    }

    #[test]
    fn encode_remote_entry_get() {
        use crate::command::RemoteEntryRange;
        assert_eq!(
            encode_to_string(OvpnCommand::RemoteEntryGet(RemoteEntryRange::Single(0))),
            "remote-entry-get 0\n"
        );
        assert_eq!(
            encode_to_string(OvpnCommand::RemoteEntryGet(RemoteEntryRange::Range {
                from: 0,
                end: 3
            })),
            "remote-entry-get 0 3\n"
        );
        assert_eq!(
            encode_to_string(OvpnCommand::RemoteEntryGet(RemoteEntryRange::All)),
            "remote-entry-get all\n"
        );
    }

    #[test]
    fn encode_push_update_broad() {
        let wire = encode_to_string(OvpnCommand::PushUpdateBroad {
            options: "route 10.0.0.0".to_string(),
        });
        assert_eq!(wire, "push-update-broad \"route 10.0.0.0\"\n");
    }

    #[test]
    fn encode_push_update_cid() {
        let wire = encode_to_string(OvpnCommand::PushUpdateCid {
            cid: 42,
            options: "route 10.0.0.0".to_string(),
        });
        assert_eq!(wire, "push-update-cid 42 \"route 10.0.0.0\"\n");
    }

    #[test]
    fn encode_proxy_http_nct() {
        let wire = encode_to_string(OvpnCommand::Proxy(ProxyAction::Http {
            host: "proxy.local".to_string(),
            port: 8080,
            non_cleartext_only: true,
        }));
        assert_eq!(wire, "proxy HTTP proxy.local 8080 nct\n");
    }

    #[test]
    fn encode_needok() {
        use crate::need_ok::NeedOkResponse;
        let wire = encode_to_string(OvpnCommand::NeedOk {
            name: "token-insertion-request".to_string(),
            response: NeedOkResponse::Ok,
        });
        assert_eq!(wire, "needok token-insertion-request ok\n");
    }

    #[test]
    fn encode_needstr() {
        let wire = encode_to_string(OvpnCommand::NeedStr {
            name: "name".to_string(),
            value: "John".to_string(),
        });
        assert_eq!(wire, "needstr name \"John\"\n");
    }

    #[test]
    fn encode_forget_passwords() {
        assert_eq!(
            encode_to_string(OvpnCommand::ForgetPasswords),
            "forget-passwords\n"
        );
    }

    #[test]
    fn encode_hold_query() {
        assert_eq!(encode_to_string(OvpnCommand::HoldQuery), "hold\n");
    }

    #[test]
    fn encode_echo_on_all() {
        assert_eq!(
            encode_to_string(OvpnCommand::Echo(StreamMode::OnAll)),
            "echo on all\n"
        );
    }

    // --- Decoder tests ---

    #[test]
    fn decode_success() {
        let msgs = decode_all("SUCCESS: pid=12345\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "pid=12345"));
    }

    #[test]
    fn decode_success_bare() {
        // Edge case: SUCCESS: with no trailing text.
        let msgs = decode_all("SUCCESS:\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.is_empty()));
    }

    #[test]
    fn decode_error() {
        let msgs = decode_all("ERROR: unknown command\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s == "unknown command"));
    }

    #[test]
    fn decode_info_notification() {
        let msgs = decode_all(">INFO:OpenVPN Management Interface Version 5\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Info(s) if s == "OpenVPN Management Interface Version 5"
        ));
    }

    #[test]
    fn decode_state_notification() {
        let msgs = decode_all(">STATE:1234567890,CONNECTED,SUCCESS,,10.0.0.1\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::State(StateEntry {
                timestamp: UtcTimestamp(1234567890),
                name: OpenVpnState::Connected,
                description,
                local_ip,
                remote_ip,
                ..
            })) if description == "SUCCESS" && local_ip.is_empty() && remote_ip == "10.0.0.1"
        ));
    }

    #[test]
    fn decode_multiline_with_command_tracking() {
        // After encoding a `status` command, the codec expects a multi-line
        // response. Lines that would otherwise be ambiguous are correctly
        // accumulated until END.
        let msgs = encode_then_decode(
            OvpnCommand::Status(StatusFormat::V1),
            "OpenVPN CLIENT LIST\nCommon Name,Real Address\ntest,1.2.3.4:1234\nEND\n",
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::MultiLine(lines)
                if lines.len() == 3
                && lines[0] == "OpenVPN CLIENT LIST"
                && lines[2] == "test,1.2.3.4:1234"
        ));
    }

    #[test]
    fn decode_hold_query_success() {
        // Bare `hold` returns SUCCESS: hold=0 or SUCCESS: hold=1
        let msgs = encode_then_decode(OvpnCommand::HoldQuery, "SUCCESS: hold=0\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "hold=0"));
    }

    #[test]
    fn decode_bare_state_multiline() {
        // Bare `state` returns state history lines + END
        let msgs = encode_then_decode(
            OvpnCommand::State,
            "1234567890,CONNECTED,SUCCESS,,10.0.0.1,,,,\nEND\n",
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::MultiLine(lines)
                if lines.len() == 1 && lines[0].starts_with("1234567890")
        ));
    }

    #[test]
    fn decode_notification_during_multiline() {
        // A notification can arrive in the middle of a multi-line response.
        // It should be emitted immediately without breaking the accumulation.
        let msgs = encode_then_decode(
            OvpnCommand::Status(StatusFormat::V1),
            "header line\n>BYTECOUNT:1000,2000\ndata line\nEND\n",
        );
        assert_eq!(msgs.len(), 2);
        // First emitted message: the interleaved notification.
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::ByteCount {
                bytes_in: 1000,
                bytes_out: 2000
            })
        ));
        // Second: the completed multi-line block (notification is not included).
        assert!(matches!(
            &msgs[1],
            OvpnMessage::MultiLine(lines) if lines == &["header line", "data line"]
        ));
    }

    #[test]
    fn decode_client_connect_multiline_notification() {
        let input = "\
            >CLIENT:CONNECT,0,1\n\
            >CLIENT:ENV,untrusted_ip=1.2.3.4\n\
            >CLIENT:ENV,common_name=TestClient\n\
            >CLIENT:ENV,END\n";
        let msgs = decode_all(input);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Connect,
                cid: 0,
                kid: Some(1),
                env,
            }) if env.len() == 2
                && env.get("untrusted_ip").map(String::as_str) == Some("1.2.3.4")
                && env.get("common_name").map(String::as_str) == Some("TestClient")
        ));
    }

    #[test]
    fn decode_client_address_single_line() {
        let msgs = decode_all(">CLIENT:ADDRESS,3,10.0.0.5,1\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::ClientAddress {
                cid: 3,
                addr,
                primary: true,
            }) if addr == "10.0.0.5"
        ));
    }

    #[test]
    fn decode_client_disconnect() {
        let input = "\
            >CLIENT:DISCONNECT,5\n\
            >CLIENT:ENV,bytes_received=12345\n\
            >CLIENT:ENV,bytes_sent=67890\n\
            >CLIENT:ENV,END\n";
        let msgs = decode_all(input);
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Disconnect,
                cid: 5,
                kid: None,
                env,
            }) if env.len() == 2
        ));
    }

    #[test]
    fn decode_password_prompt_no_newline_with_cr() {
        // OpenVPN sends "ENTER PASSWORD:" without \n. Some builds may
        // include a trailing \r. The decoder must consume the \r and
        // still produce PasswordPrompt.
        let msgs = decode_all("ENTER PASSWORD:\r");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], OvpnMessage::PasswordPrompt);
    }

    #[test]
    fn decode_password_prompt_with_cr_fully_consumes_buffer() {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::from("ENTER PASSWORD:\r");
        let msg = codec.decode(&mut buf).unwrap();
        assert_eq!(msg, Some(OvpnMessage::PasswordPrompt));
        assert!(
            buf.is_empty(),
            "trailing \\r was not consumed; {remaining} bytes remain",
            remaining = buf.len(),
        );
    }

    #[test]
    fn decode_password_prompt_no_newline_without_cr() {
        let msgs = decode_all("ENTER PASSWORD:");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0], OvpnMessage::PasswordPrompt);
    }

    #[test]
    fn decode_password_notification() {
        let msgs = decode_all(">PASSWORD:Need 'Auth' username/password\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedAuth {
                auth_type: AuthType::Auth,
            }))
        ));
    }

    #[test]
    fn escape_and_quote_special_chars() {
        assert_eq!(quote(&escape(r#"foo"bar"#)), r#""foo\"bar""#);
        assert_eq!(quote(&escape(r"a\b")), r#""a\\b""#);
        assert_eq!(quote(&escape("simple")), r#""simple""#);
    }

    #[test]
    fn decode_empty_multiline() {
        // Some commands can return an empty multi-line block (just "END").
        let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), "END\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.is_empty()));
    }

    #[test]
    fn decode_need_ok_notification() {
        let msgs = decode_all(
            ">NEED-OK:Need 'token-insertion-request' confirmation MSG:Please insert your token\n",
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::NeedOk { name, message })
                if name == "token-insertion-request" && message == "Please insert your token"
        ));
    }

    #[test]
    fn decode_hold_notification() {
        let msgs = decode_all(">HOLD:Waiting for hold release\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::Hold { text })
                if text == "Waiting for hold release"
        ));
    }

    // --- RawMultiLine tests ---

    #[test]
    fn encode_raw_multiline() {
        assert_eq!(
            encode_to_string(OvpnCommand::RawMultiLine("custom-cmd arg".to_string())),
            "custom-cmd arg\n"
        );
    }

    #[test]
    fn raw_multiline_expects_multiline_response() {
        let msgs = encode_then_decode(
            OvpnCommand::RawMultiLine("custom".to_string()),
            "line1\nline2\nEND\n",
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::MultiLine(lines) if lines == &["line1", "line2"]
        ));
    }

    #[test]
    fn raw_multiline_sanitizes_newlines() {
        // Default mode is Sanitize — newlines are stripped.
        let wire = encode_to_string(OvpnCommand::RawMultiLine("cmd\ninjected".to_string()));
        assert_eq!(wire, "cmdinjected\n");
    }

    #[test]
    fn raw_multiline_strict_rejects_newlines() {
        let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
        let mut buf = BytesMut::new();
        let result = codec.encode(
            OvpnCommand::RawMultiLine("cmd\ninjected".to_string()),
            &mut buf,
        );
        assert!(result.is_err());
    }

    // --- Sequential encode/decode tests ---

    #[test]
    #[traced_test]
    fn encode_during_multiline_accumulation_warns_but_succeeds() {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        // Encode a command that expects multi-line response.
        codec
            .encode(OvpnCommand::Status(StatusFormat::V1), &mut buf)
            .unwrap();
        // Feed partial multi-line response (no END yet).
        let mut dec = BytesMut::from("header line\n");
        codec.decode(&mut dec).unwrap(); // starts multi_line_buf accumulation
        // Encoding again while accumulating logs a warning but succeeds.
        codec.encode(OvpnCommand::Pid, &mut buf).unwrap();
        assert_eq!(
            codec.expected_queue.len(),
            2,
            "both pending: first mid-accumulation, second queued"
        );
        assert!(logs_contain("mid-accumulation"));
    }

    #[test]
    #[traced_test]
    fn encode_during_client_notif_accumulation_warns_but_succeeds() {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        // Feed a CLIENT header — starts client_notification accumulation.
        let mut dec = BytesMut::from(">CLIENT:CONNECT,0,1\n");
        codec.decode(&mut dec).unwrap();
        // Encoding while client_notification is active logs a warning but succeeds.
        codec.encode(OvpnCommand::Pid, &mut buf).unwrap();
        assert_eq!(codec.expected_queue.len(), 1);
        assert!(logs_contain("mid-accumulation"));
    }

    /// Sending two commands before any response arrives — the response
    /// kind queue ensures each response is decoded with the correct kind.
    #[test]
    fn pipelined_commands_decode_correctly() {
        let mut codec = OvpnCodec::new();
        let mut enc = BytesMut::new();
        // Encode two commands: Status (multi-line) then Pid (success/error).
        codec
            .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc)
            .unwrap();
        codec.encode(OvpnCommand::Pid, &mut enc).unwrap();
        assert_eq!(codec.expected_queue.len(), 2);

        // Feed the Status multi-line response followed by the Pid response.
        let mut dec = BytesMut::from("TITLE\nheader\ndata\nEND\nSUCCESS: pid=42\n");
        let mut msgs = Vec::new();
        while let Some(msg) = codec.decode(&mut dec).unwrap() {
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 2);
        assert!(
            matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines == &["TITLE", "header", "data"]),
            "first response should be MultiLine, got {:?}",
            msgs[0]
        );
        assert!(
            matches!(&msgs[1], OvpnMessage::Success(s) if s == "pid=42"),
            "second response should be Success, got {:?}",
            msgs[1]
        );
        assert!(codec.expected_queue.is_empty());
    }

    // --- Accumulation limit tests ---

    #[test]
    fn default_accumulation_limit_allows_reasonable_responses() {
        let mut codec = OvpnCodec::new();
        let mut enc = BytesMut::new();
        codec
            .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc)
            .unwrap();
        // Feed 500 lines + END — well within the default Max(10_000).
        let mut data = String::new();
        for i in 0..500 {
            data.push_str(&format!("line {i}\n"));
        }
        data.push_str("END\n");
        let mut dec = BytesMut::from(data.as_str());
        let mut msgs = Vec::new();
        while let Some(msg) = codec.decode(&mut dec).unwrap() {
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::MultiLine(lines) if lines.len() == 500
        ));
    }

    #[test]
    fn multi_line_limit_exceeded() {
        let mut codec = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(3));
        let mut enc = BytesMut::new();
        codec
            .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc)
            .unwrap();
        let mut dec = BytesMut::from("a\nb\nc\nd\nEND\n");
        let result = loop {
            match codec.decode(&mut dec) {
                Ok(Some(msg)) => break Ok(msg),
                Ok(None) => continue,
                Err(error) => break Err(error),
            }
        };
        assert!(result.is_err(), "expected error when limit exceeded");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("multi-line response"),
            "error should mention multi-line: {err}"
        );
    }

    #[test]
    fn multi_line_limit_exact_boundary_passes() {
        let mut codec = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(3));
        let mut enc = BytesMut::new();
        codec
            .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc)
            .unwrap();
        // Exactly 3 lines should succeed.
        let mut dec = BytesMut::from("a\nb\nc\nEND\n");
        let mut msgs = Vec::new();
        while let Some(msg) = codec.decode(&mut dec).unwrap() {
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 1);
        assert!(matches!(
            &msgs[0],
            OvpnMessage::MultiLine(lines) if lines.len() == 3
        ));
    }

    #[test]
    fn client_env_limit_exceeded() {
        let mut codec = OvpnCodec::new().with_max_client_env_entries(AccumulationLimit::Max(2));
        let mut dec = BytesMut::from(
            ">CLIENT:CONNECT,0,1\n\
             >CLIENT:ENV,a=1\n\
             >CLIENT:ENV,b=2\n\
             >CLIENT:ENV,c=3\n\
             >CLIENT:ENV,END\n",
        );
        let result = loop {
            match codec.decode(&mut dec) {
                Ok(Some(msg)) => break Ok(msg),
                Ok(None) => continue,
                Err(error) => break Err(error),
            }
        };
        assert!(
            result.is_err(),
            "expected error when client ENV limit exceeded"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("client ENV"),
            "error should mention client ENV: {err}"
        );
    }

    // --- UTF-8 error state reset tests ---

    #[test]
    fn utf8_error_resets_multiline_state() {
        let mut codec = OvpnCodec::new();
        let mut enc = BytesMut::new();
        codec
            .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc)
            .unwrap();
        // Feed a valid first line to start multi-line accumulation.
        let mut dec = BytesMut::from("header\n");
        assert!(codec.decode(&mut dec).unwrap().is_none());
        // Feed invalid UTF-8.
        dec.extend_from_slice(b"bad \xff line\n");
        assert!(codec.decode(&mut dec).is_err());
        // State should be reset — next valid line should decode cleanly
        // as an Unrecognized (since expected was reset to SuccessOrError).
        dec.extend_from_slice(b"SUCCESS: recovered\n");
        let msg = codec
            .decode(&mut dec)
            .unwrap()
            .expect("should produce a message");
        assert!(
            matches!(&msg, OvpnMessage::Success(s) if s.contains("recovered")),
            "expected Success containing 'recovered', got {msg:?}"
        );
    }

    #[test]
    fn utf8_error_resets_client_notif_state() {
        let mut codec = OvpnCodec::new();
        // Start CLIENT accumulation.
        let mut dec = BytesMut::from(">CLIENT:CONNECT,0,1\n");
        assert!(codec.decode(&mut dec).unwrap().is_none());
        // Feed invalid UTF-8 within the ENV block.
        dec.extend_from_slice(b">CLIENT:ENV,\xff\n");
        assert!(codec.decode(&mut dec).is_err());
        // State should be reset.
        dec.extend_from_slice(b"SUCCESS: ok\n");
        let msg = codec
            .decode(&mut dec)
            .unwrap()
            .expect("should produce a message");
        assert!(
            matches!(&msg, OvpnMessage::Success(_)),
            "expected Success after UTF-8 reset, got {msg:?}"
        );
    }

    #[test]
    fn encode_set_version() {
        assert_eq!(encode_to_string(OvpnCommand::SetVersion(2)), "version 2\n");
        assert_eq!(encode_to_string(OvpnCommand::SetVersion(4)), "version 4\n");
    }

    #[test]
    fn encode_remote_skip_n() {
        assert_eq!(
            encode_to_string(OvpnCommand::Remote(RemoteAction::SkipN(3))),
            "remote SKIP 3\n"
        );
    }
}
