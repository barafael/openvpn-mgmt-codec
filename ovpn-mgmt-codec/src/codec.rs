use bytes::{BufMut, BytesMut};
use std::io;
use tokio_util::codec::{Decoder, Encoder};

use crate::command::{OvpnCommand, ResponseKind};
use crate::kill_target::KillTarget;
use crate::message::{Notification, OvpnMessage};
use crate::proxy_action::ProxyAction;
use crate::remote_action::RemoteAction;
use crate::status_format::StatusFormat;
use crate::unrecognized::UnrecognizedKind;

/// Escape a string value per the OpenVPN config-file lexer rules and
/// wrap it in double quotes. This is required for any user-supplied
/// string that might contain whitespace, backslashes, or quotes —
/// passwords, reason strings, needstr values, etc.
///
/// The escaping rules from the "Command Parsing" section:
///   `\` → `\\`
///   `"` → `\"`
fn quote_and_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

use crate::client_event::ClientEvent;
use crate::log_level::LogLevel;
use crate::openvpn_state::OpenVpnState;
use crate::transport_protocol::TransportProtocol;

/// Internal state for accumulating multi-line `>CLIENT:` notifications.
#[derive(Debug)]
struct ClientNotifAccum {
    event: ClientEvent,
    cid: u64,
    kid: Option<u64>,
    env: Vec<(String, String)>,
}

/// Tokio codec for the OpenVPN management interface.
///
/// The encoder serializes typed `OvpnCommand` values into correct wire-format
/// bytes, including proper escaping and multi-line block framing. The decoder
/// uses command-tracking state to correctly distinguish single-line from
/// multi-line responses, and accumulates multi-line `>CLIENT:` notifications
/// into a single `OvpnMessage` before emitting them.
pub struct OvpnCodec {
    /// What kind of response we expect from the last command we encoded.
    /// This resolves the protocol's ambiguity: when we see a line that is
    /// not `SUCCESS:`, `ERROR:`, or a `>` notification, this field tells
    /// us whether to treat it as the start of a multi-line block or as a
    /// standalone value.
    expected: ResponseKind,

    /// Accumulator for multi-line (END-terminated) command responses.
    multi_line_buf: Option<Vec<String>>,

    /// Accumulator for multi-line `>CLIENT:` notifications. When this is
    /// `Some(...)`, the decoder is waiting for `>CLIENT:ENV,END`.
    client_notif: Option<ClientNotifAccum>,
}

impl OvpnCodec {
    /// Create a new codec with default state, ready to encode commands and
    /// decode responses.
    pub fn new() -> Self {
        Self {
            // Before any command is sent, OpenVPN sends a greeting
            // (`>INFO:...` notification). SuccessOrError is a safe default
            // because SUCCESS/ERROR/notifications are all self-describing —
            // this field only matters for ambiguous (non-prefixed) lines.
            expected: ResponseKind::SuccessOrError,
            multi_line_buf: None,
            client_notif: None,
        }
    }
}

impl Default for OvpnCodec {
    fn default() -> Self {
        Self::new()
    }
}

// ── Encoder ───────────────────────────────────────────────────────

impl Encoder<OvpnCommand> for OvpnCodec {
    type Error = io::Error;

    fn encode(&mut self, item: OvpnCommand, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Record the expected response kind BEFORE writing, so the decoder
        // is ready when data starts arriving.
        self.expected = item.expected_response();

        match item {
            // ── Informational ────────────────────────────────────
            OvpnCommand::Status(StatusFormat::V1) => write_line(dst, "status"),
            OvpnCommand::Status(ref fmt) => write_line(dst, &format!("status {fmt}")),
            OvpnCommand::State => write_line(dst, "state"),
            OvpnCommand::StateStream(ref m) => write_line(dst, &format!("state {}", m)),
            OvpnCommand::Version => write_line(dst, "version"),
            OvpnCommand::Pid => write_line(dst, "pid"),
            OvpnCommand::Help => write_line(dst, "help"),
            OvpnCommand::Net => write_line(dst, "net"),
            OvpnCommand::Verb(Some(n)) => write_line(dst, &format!("verb {n}")),
            OvpnCommand::Verb(None) => write_line(dst, "verb"),
            OvpnCommand::Mute(Some(n)) => write_line(dst, &format!("mute {n}")),
            OvpnCommand::Mute(None) => write_line(dst, "mute"),

            // ── Real-time notification control ───────────────────
            OvpnCommand::Log(ref m) => write_line(dst, &format!("log {}", m)),
            OvpnCommand::Echo(ref m) => write_line(dst, &format!("echo {}", m)),
            OvpnCommand::ByteCount(n) => write_line(dst, &format!("bytecount {n}")),

            // ── Connection control ───────────────────────────────
            OvpnCommand::Signal(sig) => write_line(dst, &format!("signal {sig}")),
            OvpnCommand::Kill(KillTarget::CommonName(ref cn)) => {
                write_line(dst, &format!("kill {cn}"))
            }
            OvpnCommand::Kill(KillTarget::Address { ref ip, port }) => {
                write_line(dst, &format!("kill {ip}:{port}"))
            }
            OvpnCommand::HoldQuery => write_line(dst, "hold"),
            OvpnCommand::HoldOn => write_line(dst, "hold on"),
            OvpnCommand::HoldOff => write_line(dst, "hold off"),
            OvpnCommand::HoldRelease => write_line(dst, "hold release"),

            // ── Authentication ───────────────────────────────────
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
                let escaped = quote_and_escape(value);
                write_line(dst, &format!("username \"{auth_type}\" {escaped}"))
            }
            OvpnCommand::Password {
                ref auth_type,
                ref value,
            } => {
                let escaped = quote_and_escape(value);
                write_line(dst, &format!("password \"{auth_type}\" {escaped}"))
            }
            OvpnCommand::AuthRetry(mode) => write_line(dst, &format!("auth-retry {mode}")),
            OvpnCommand::ForgetPasswords => write_line(dst, "forget-passwords"),

            // ── Challenge-response ──────────────────────────────
            OvpnCommand::ChallengeResponse {
                ref state_id,
                ref response,
            } => {
                let value = format!("CRV1::{state_id}::{response}");
                let escaped = quote_and_escape(&value);
                write_line(dst, &format!("password \"Auth\" {escaped}"))
            }
            OvpnCommand::StaticChallengeResponse {
                ref password_b64,
                ref response_b64,
            } => {
                let value = format!("SCRV1:{password_b64}:{response_b64}");
                let escaped = quote_and_escape(&value);
                write_line(dst, &format!("password \"Auth\" {escaped}"))
            }

            // ── Interactive prompts ──────────────────────────────
            OvpnCommand::NeedOk { ref name, response } => {
                write_line(dst, &format!("needok {name} {response}"))
            }
            OvpnCommand::NeedStr {
                ref name,
                ref value,
            } => {
                let escaped = quote_and_escape(value);
                write_line(dst, &format!("needstr {name} {escaped}"))
            }

            // ── PKCS#11 ─────────────────────────────────────────
            OvpnCommand::Pkcs11IdCount => write_line(dst, "pkcs11-id-count"),
            OvpnCommand::Pkcs11IdGet(idx) => write_line(dst, &format!("pkcs11-id-get {idx}")),

            // ── External key (multi-line command) ────────────────
            //
            // Wire format:
            //   rsa-sig
            //   BASE64_LINE_1
            //   BASE64_LINE_2
            //   END
            OvpnCommand::RsaSig { ref base64_lines } => write_block(dst, "rsa-sig", base64_lines),

            // ── Client management ────────────────────────────────
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
            } => write_block(dst, &format!("client-auth {cid} {kid}"), config_lines),

            OvpnCommand::ClientAuthNt { cid, kid } => {
                write_line(dst, &format!("client-auth-nt {cid} {kid}"))
            }

            OvpnCommand::ClientDeny {
                cid,
                kid,
                ref reason,
                ref client_reason,
            } => {
                let r = quote_and_escape(reason);
                match client_reason {
                    Some(cr) => {
                        let cr_esc = quote_and_escape(cr);
                        write_line(dst, &format!("client-deny {cid} {kid} {r} {cr_esc}"))
                    }
                    None => write_line(dst, &format!("client-deny {cid} {kid} {r}")),
                }
            }

            OvpnCommand::ClientKill { cid } => write_line(dst, &format!("client-kill {cid}")),

            // client-pf is also a multi-line command:
            //   client-pf {CID}
            //   [CLIENTS ACCEPT]
            //   ...
            //   [END]
            //   END
            OvpnCommand::ClientPf {
                cid,
                ref filter_lines,
            } => write_block(dst, &format!("client-pf {cid}"), filter_lines),

            // ── Server statistics ─────────────────────────────────
            OvpnCommand::LoadStats => write_line(dst, "load-stats"),

            // ── Extended client management ───────────────────────
            OvpnCommand::ClientPendingAuth {
                cid,
                kid,
                timeout,
                ref extra,
            } => write_line(
                dst,
                &format!("client-pending-auth {cid} {kid} {timeout} {extra}"),
            ),

            OvpnCommand::ClientDenyV2 {
                cid,
                kid,
                ref reason,
                ref client_reason,
                ref redirect_url,
            } => {
                let r = quote_and_escape(reason);
                let mut cmd = format!("client-deny-v2 {cid} {kid} {r}");
                if let Some(cr) = client_reason {
                    cmd.push(' ');
                    cmd.push_str(&quote_and_escape(cr));
                    if let Some(url) = redirect_url {
                        cmd.push(' ');
                        cmd.push_str(&quote_and_escape(url));
                    }
                }
                write_line(dst, &cmd)
            }

            OvpnCommand::CrResponse {
                cid,
                kid,
                ref response,
            } => write_line(dst, &format!("cr-response {cid} {kid} {response}")),

            // ── External certificate ─────────────────────────────
            OvpnCommand::Certificate { ref pem_lines } => {
                write_block(dst, "certificate", pem_lines)
            }

            // ── Windows service bypass ───────────────────────────
            OvpnCommand::BypassMessage(ref msg) => {
                let escaped = quote_and_escape(msg);
                write_line(dst, &format!("bypass-message {escaped}"))
            }

            // ── Remote/Proxy ─────────────────────────────────────
            OvpnCommand::Remote(RemoteAction::Accept) => write_line(dst, "remote ACCEPT"),
            OvpnCommand::Remote(RemoteAction::Skip) => write_line(dst, "remote SKIP"),
            OvpnCommand::Remote(RemoteAction::Modify { ref host, port }) => {
                write_line(dst, &format!("remote MOD {host} {port}"))
            }
            OvpnCommand::Proxy(ProxyAction::None) => write_line(dst, "proxy NONE"),
            OvpnCommand::Proxy(ProxyAction::Http {
                ref host,
                port,
                non_cleartext_only,
            }) => {
                let nct = if non_cleartext_only { " nct" } else { "" };
                write_line(dst, &format!("proxy HTTP {host} {port}{nct}"))
            }
            OvpnCommand::Proxy(ProxyAction::Socks { ref host, port }) => {
                write_line(dst, &format!("proxy SOCKS {host} {port}"))
            }

            // ── Management interface auth ─────────────────────────
            // Bare line, no quoting — the management password protocol
            // does not use the config-file lexer.
            OvpnCommand::ManagementPassword(ref pw) => write_line(dst, pw),

            // ── Lifecycle ────────────────────────────────────────
            OvpnCommand::Exit => write_line(dst, "exit"),
            OvpnCommand::Quit => write_line(dst, "quit"),

            // ── Escape hatch ─────────────────────────────────────
            OvpnCommand::Raw(ref cmd) => write_line(dst, cmd),
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
fn write_block(dst: &mut BytesMut, header: &str, lines: &[String]) {
    let total: usize = header.len() + 1 + lines.iter().map(|l| l.len() + 1).sum::<usize>() + 4;
    dst.reserve(total);
    dst.put_slice(header.as_bytes());
    dst.put_u8(b'\n');
    for line in lines {
        dst.put_slice(line.as_bytes());
        dst.put_u8(b'\n');
    }
    dst.put_slice(b"END\n");
}

// ── Decoder ───────────────────────────────────────────────────────

impl Decoder for OvpnCodec {
    type Item = OvpnMessage;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            // Find the next complete line.
            let newline_pos = match src.iter().position(|&b| b == b'\n') {
                Some(pos) => pos,
                None => return Ok(None), // Need more data.
            };

            // Extract the line and advance the buffer past the newline.
            let line_bytes = src.split_to(newline_pos + 1);
            let line = std::str::from_utf8(&line_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .trim_end_matches(['\r', '\n'])
                .to_owned();

            // ── Phase 1: Multi-line >CLIENT: accumulation ────────
            //
            // When we're accumulating a CLIENT notification, >CLIENT:ENV
            // lines belong to it. The block terminates with >CLIENT:ENV,END.
            // The spec guarantees atomicity for CLIENT notifications, so
            // interleaving here should not occur. Any other line (SUCCESS,
            // ERROR, other notifications) falls through to normal processing
            // as a defensive measure.
            if let Some(ref mut accum) = self.client_notif
                && let Some(rest) = line.strip_prefix(">CLIENT:ENV,") {
                    if rest == "END" {
                        let finished = self.client_notif.take().unwrap();
                        return Ok(Some(OvpnMessage::Notification(Notification::Client {
                            event: finished.event,
                            cid: finished.cid,
                            kid: finished.kid,
                            env: finished.env,
                        })));
                    } else {
                        // Parse "key=value" (value may contain '=').
                        let (k, v) = match rest.split_once('=') {
                            Some((k, v)) => (k.to_owned(), v.to_owned()),
                            None => (rest.to_owned(), String::new()),
                        };
                        accum.env.push((k, v));
                        continue; // Next line.
                    }
                }
                // Not a >CLIENT:ENV line — fall through to normal processing.
                // This handles interleaved notifications or unexpected output.

            // ── Phase 2: Multi-line command response accumulation ─
            if let Some(ref mut buf) = self.multi_line_buf {
                if line == "END" {
                    let lines = self.multi_line_buf.take().unwrap();
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
                buf.push(line);
                continue; // Next line.
            }

            // ── Phase 3: Self-describing lines ───────────────────
            //
            // SUCCESS: and ERROR: are unambiguous. We match on "SUCCESS:"
            // without requiring a trailing space — the doc shows
            // "SUCCESS: [text]" but text could be empty.
            if let Some(rest) = line.strip_prefix("SUCCESS:") {
                return Ok(Some(OvpnMessage::Success(
                    rest.strip_prefix(' ').unwrap_or(rest).to_owned(),
                )));
            }
            if let Some(rest) = line.strip_prefix("ERROR:") {
                return Ok(Some(OvpnMessage::Error(
                    rest.strip_prefix(' ').unwrap_or(rest).to_owned(),
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

            // ── Phase 4: Ambiguous lines — use command tracking ──
            //
            // The line is not self-describing (no SUCCESS/ERROR/> prefix).
            // Use the expected-response state from the last encoded command
            // to decide how to frame it.
            match self.expected {
                ResponseKind::MultiLine => {
                    if line == "END" {
                        // Edge case: empty multi-line block (header-less).
                        return Ok(Some(OvpnMessage::MultiLine(Vec::new())));
                    }
                    self.multi_line_buf = Some(vec![line]);
                    continue; // Accumulate until END.
                }
                ResponseKind::SingleValue => {
                    if let Some(parsed) = parse_pkcs11id_entry(&line) {
                        return Ok(Some(parsed));
                    }
                    return Ok(Some(OvpnMessage::SingleValue(line)));
                }
                ResponseKind::SuccessOrError | ResponseKind::NoResponse => {
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

        let (kind, payload) = match inner.split_once(':') {
            Some((k, p)) => (k, p),
            // Malformed notification — no colon.
            None => {
                return Some(OvpnMessage::Unrecognized {
                    line: line.to_owned(),
                    kind: UnrecognizedKind::MalformedNotification,
                });
            }
        };

        // >INFO: gets its own message variant for convenience (it's always
        // the first thing you see on connect).
        if kind == "INFO" {
            return Some(OvpnMessage::Info(payload.to_owned()));
        }

        // >CLIENT: may be multi-line. Inspect the sub-type to decide.
        if kind == "CLIENT" {
            let (event, args) = match payload.split_once(',') {
                Some((e, a)) => (e.to_owned(), a.to_owned()),
                None => (payload.to_owned(), String::new()),
            };

            // ADDRESS notifications are always single-line (no ENV block).
            if event == "ADDRESS" {
                let mut parts = args.splitn(3, ',');
                let cid = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
                let addr = parts.next().unwrap_or("").to_owned();
                let primary = parts.next() == Some("1");
                return Some(OvpnMessage::Notification(Notification::ClientAddress {
                    cid,
                    addr,
                    primary,
                }));
            }

            // CONNECT, REAUTH, ESTABLISHED, DISCONNECT all have ENV blocks.
            // Parse CID and optional KID from the args (e.g. "0,1" or "5").
            // Some events (e.g. CR_RESPONSE) have extra trailing data after
            // CID,KID — we use splitn(3) and only parse the first two.
            let mut id_parts = args.splitn(3, ',');
            let cid = id_parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let kid = id_parts.next().and_then(|s| s.parse().ok());

            // Start accumulation — don't emit anything yet.
            self.client_notif = Some(ClientNotifAccum {
                event: ClientEvent::parse(&event),
                cid,
                kid,
                env: Vec::new(),
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
                text: payload.to_owned(),
            }),
            "FATAL" => Some(Notification::Fatal {
                message: payload.to_owned(),
            }),
            "PKCS11ID-COUNT" => parse_pkcs11id_count(payload),
            "NEED-OK" => parse_need_ok(payload),
            "NEED-STR" => parse_need_str(payload),
            "RSA_SIGN" => Some(Notification::RsaSign {
                data: payload.to_owned(),
            }),
            "REMOTE" => parse_remote(payload),
            "PROXY" => parse_proxy(payload),
            "PASSWORD" => parse_password(payload),
            _ => None,
        };

        Some(OvpnMessage::Notification(notification.unwrap_or(
            Notification::Simple {
                kind: kind.to_owned(),
                payload: payload.to_owned(),
            },
        )))
    }
}

// ── Notification parsers ──────────────────────────────────────────
//
// Each returns `Option<Notification>`. `None` means "could not parse,
// fall back to Simple". This is intentional — the protocol varies
// across OpenVPN versions and we never want a parse failure to
// produce an error.

fn parse_state(payload: &str) -> Option<Notification> {
    // Wire format (OpenVPN 2.1+):
    //   timestamp,name,desc,local_ip,remote_ip[,local_port[,local_addr[,remote_port]]]
    // Field 7 (local_addr) was added later; we skip it since the
    // Notification::State struct doesn't model it.
    let mut parts = payload.splitn(9, ',');
    let timestamp = parts.next()?.parse().ok()?;
    let name = OpenVpnState::parse(parts.next()?);
    let description = parts.next()?.to_owned();
    let local_ip = parts.next()?.to_owned();
    let remote_ip = parts.next()?.to_owned();
    let local_port = parts.next().unwrap_or("").to_owned();
    let _local_addr = parts.next(); // skip local_addr
    let remote_port = parts.next().unwrap_or("").to_owned();
    Some(Notification::State {
        timestamp,
        name,
        description,
        local_ip,
        remote_ip,
        local_port,
        remote_port,
    })
}

fn parse_bytecount(payload: &str) -> Option<Notification> {
    let (a, b) = payload.split_once(',')?;
    Some(Notification::ByteCount {
        bytes_in: a.parse().ok()?,
        bytes_out: b.parse().ok()?,
    })
}

fn parse_bytecount_cli(payload: &str) -> Option<Notification> {
    let mut parts = payload.splitn(3, ',');
    let cid = parts.next()?.parse().ok()?;
    let bytes_in = parts.next()?.parse().ok()?;
    let bytes_out = parts.next()?.parse().ok()?;
    Some(Notification::ByteCountCli {
        cid,
        bytes_in,
        bytes_out,
    })
}

fn parse_log(payload: &str) -> Option<Notification> {
    let (ts_str, rest) = payload.split_once(',')?;
    let timestamp = ts_str.parse().ok()?;
    let (level_str, message) = rest.split_once(',')?;
    Some(Notification::Log {
        timestamp,
        level: LogLevel::parse(level_str),
        message: message.to_owned(),
    })
}

fn parse_echo(payload: &str) -> Option<Notification> {
    let (ts_str, param) = payload.split_once(',')?;
    let timestamp = ts_str.parse().ok()?;
    Some(Notification::Echo {
        timestamp,
        param: param.to_owned(),
    })
}

fn parse_pkcs11id_count(payload: &str) -> Option<Notification> {
    let count = payload.trim().parse().ok()?;
    Some(Notification::Pkcs11IdCount { count })
}

/// Parse `PKCS11ID-ENTRY:'idx', ID:'id', BLOB:'blob'` response line.
fn parse_pkcs11id_entry(line: &str) -> Option<OvpnMessage> {
    let rest = line.strip_prefix("PKCS11ID-ENTRY:'")?;
    let (index, rest) = rest.split_once("', ID:'")?;
    let (id, rest) = rest.split_once("', BLOB:'")?;
    let blob = rest.strip_suffix('\'')?;
    Some(OvpnMessage::Pkcs11IdEntry {
        index: index.to_owned(),
        id: id.to_owned(),
        blob: blob.to_owned(),
    })
}

/// Parse `Need 'name' ... MSG:message` from NEED-OK payload.
fn parse_need_ok(payload: &str) -> Option<Notification> {
    // Format: Need 'name' confirmation MSG:message
    let rest = payload.strip_prefix("Need '")?;
    let (name, rest) = rest.split_once('\'')?;
    let msg = rest.split_once("MSG:")?.1;
    Some(Notification::NeedOk {
        name: name.to_owned(),
        message: msg.to_owned(),
    })
}

/// Parse `Need 'name' input MSG:message` from NEED-STR payload.
fn parse_need_str(payload: &str) -> Option<Notification> {
    let rest = payload.strip_prefix("Need '")?;
    let (name, rest) = rest.split_once('\'')?;
    let msg = rest.split_once("MSG:")?.1;
    Some(Notification::NeedStr {
        name: name.to_owned(),
        message: msg.to_owned(),
    })
}

fn parse_remote(payload: &str) -> Option<Notification> {
    let mut parts = payload.splitn(3, ',');
    let host = parts.next()?.to_owned();
    let port = parts.next()?.parse().ok()?;
    let protocol = TransportProtocol::parse(parts.next()?);
    Some(Notification::Remote {
        host,
        port,
        protocol,
    })
}

fn parse_proxy(payload: &str) -> Option<Notification> {
    let mut parts = payload.splitn(4, ',');
    let proto_num = parts.next()?.parse().ok()?;
    let proto_type = TransportProtocol::parse(parts.next()?);
    let host = parts.next()?.to_owned();
    let port = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    Some(Notification::Proxy {
        proto_num,
        proto_type,
        host,
        port,
    })
}

use crate::message::PasswordNotification;

use crate::auth::AuthType;

/// Map a wire auth-type string to the typed enum.
fn parse_auth_type(s: &str) -> AuthType {
    match s {
        "Auth" => AuthType::Auth,
        "Private Key" => AuthType::PrivateKey,
        "HTTP Proxy" => AuthType::HttpProxy,
        "SOCKS Proxy" => AuthType::SocksProxy,
        other => AuthType::Custom(other.to_owned()),
    }
}

fn parse_password(payload: &str) -> Option<Notification> {
    // Verification Failed: 'type'
    if let Some(rest) = payload.strip_prefix("Verification Failed: '") {
        let auth_type = rest.strip_suffix('\'')?;
        return Some(Notification::Password(
            PasswordNotification::VerificationFailed {
                auth_type: parse_auth_type(auth_type),
            },
        ));
    }

    // Need 'type' username/password [SC:...|CRV1:...]
    // Need 'type' password
    let rest = payload.strip_prefix("Need '")?;
    let (auth_type_str, rest) = rest.split_once('\'')?;
    let rest = rest.trim_start();

    // Check for challenge-response suffixes
    if let Some(after_up) = rest.strip_prefix("username/password") {
        let after_up = after_up.trim_start();

        // Static challenge: SC:echo_flag,challenge_text
        if let Some(sc) = after_up.strip_prefix("SC:") {
            let (echo_str, challenge) = sc.split_once(',')?;
            return Some(Notification::Password(
                PasswordNotification::StaticChallenge {
                    echo: echo_str == "1",
                    challenge: challenge.to_owned(),
                },
            ));
        }

        // Dynamic challenge: CRV1:flags:state_id:username_b64:challenge
        if let Some(crv1) = after_up.strip_prefix("CRV1:") {
            let mut parts = crv1.splitn(4, ':');
            let flags = parts.next()?.to_owned();
            let state_id = parts.next()?.to_owned();
            let username_b64 = parts.next()?.to_owned();
            let challenge = parts.next()?.to_owned();
            return Some(Notification::Password(
                PasswordNotification::DynamicChallenge {
                    flags,
                    state_id,
                    username_b64,
                    challenge,
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
    use crate::auth::AuthType;
    use crate::client_event::ClientEvent;
    use crate::message::PasswordNotification;
    use crate::signal::Signal;
    use crate::status_format::StatusFormat;
    use crate::stream_mode::StreamMode;
    use bytes::BytesMut;
    use tokio_util::codec::{Decoder, Encoder};

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

    // ── Encoder tests ────────────────────────────────────────────

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
            value: r#"foo\"bar"#.to_owned(),
        });
        assert_eq!(wire, "password \"Private Key\" \"foo\\\\\\\"bar\"\n");
    }

    #[test]
    fn encode_password_simple() {
        let wire = encode_to_string(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "hunter2".to_owned(),
        });
        assert_eq!(wire, "password \"Auth\" \"hunter2\"\n");
    }

    #[test]
    fn encode_client_auth_with_config() {
        let wire = encode_to_string(OvpnCommand::ClientAuth {
            cid: 42,
            kid: 0,
            config_lines: vec![
                "push \"route 10.0.0.0 255.255.0.0\"".to_owned(),
                "push \"dhcp-option DNS 10.0.0.1\"".to_owned(),
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
        let wire = encode_to_string(OvpnCommand::ClientDeny {
            cid: 5,
            kid: 0,
            reason: "cert revoked".to_owned(),
            client_reason: Some("Your access has been revoked.".to_owned()),
        });
        assert_eq!(
            wire,
            "client-deny 5 0 \"cert revoked\" \"Your access has been revoked.\"\n"
        );
    }

    #[test]
    fn encode_rsa_sig() {
        let wire = encode_to_string(OvpnCommand::RsaSig {
            base64_lines: vec!["AAAA".to_owned(), "BBBB".to_owned()],
        });
        assert_eq!(wire, "rsa-sig\nAAAA\nBBBB\nEND\n");
    }

    #[test]
    fn encode_remote_modify() {
        let wire = encode_to_string(OvpnCommand::Remote(RemoteAction::Modify {
            host: "vpn.example.com".to_owned(),
            port: 1234,
        }));
        assert_eq!(wire, "remote MOD vpn.example.com 1234\n");
    }

    #[test]
    fn encode_proxy_http_nct() {
        let wire = encode_to_string(OvpnCommand::Proxy(ProxyAction::Http {
            host: "proxy.local".to_owned(),
            port: 8080,
            non_cleartext_only: true,
        }));
        assert_eq!(wire, "proxy HTTP proxy.local 8080 nct\n");
    }

    #[test]
    fn encode_needok() {
        use crate::need_ok::NeedOkResponse;
        let wire = encode_to_string(OvpnCommand::NeedOk {
            name: "token-insertion-request".to_owned(),
            response: NeedOkResponse::Ok,
        });
        assert_eq!(wire, "needok token-insertion-request ok\n");
    }

    #[test]
    fn encode_needstr() {
        let wire = encode_to_string(OvpnCommand::NeedStr {
            name: "name".to_owned(),
            value: "John".to_owned(),
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

    #[test]
    fn encode_client_pf() {
        let wire = encode_to_string(OvpnCommand::ClientPf {
            cid: 42,
            filter_lines: vec![
                "[CLIENTS ACCEPT]".to_owned(),
                "-accounting".to_owned(),
                "[SUBNETS DROP]".to_owned(),
                "+10.0.0.0/8".to_owned(),
                "[END]".to_owned(),
            ],
        });
        assert_eq!(
            wire,
            "client-pf 42\n\
             [CLIENTS ACCEPT]\n\
             -accounting\n\
             [SUBNETS DROP]\n\
             +10.0.0.0/8\n\
             [END]\n\
             END\n"
        );
    }

    // ── Decoder tests ────────────────────────────────────────────

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
        match &msgs[0] {
            OvpnMessage::Notification(Notification::State {
                timestamp,
                name,
                description,
                local_ip,
                remote_ip,
                ..
            }) => {
                assert_eq!(*timestamp, 1234567890);
                assert_eq!(*name, OpenVpnState::Connected);
                assert_eq!(description, "SUCCESS");
                assert_eq!(local_ip, "");
                assert_eq!(remote_ip, "10.0.0.1");
            }
            other => panic!("unexpected: {other:?}"),
        }
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
        match &msgs[0] {
            OvpnMessage::MultiLine(lines) => {
                assert_eq!(lines.len(), 3);
                assert_eq!(lines[0], "OpenVPN CLIENT LIST");
                assert_eq!(lines[2], "test,1.2.3.4:1234");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn decode_hold_query_single_value() {
        // After encoding bare `hold`, the codec expects a single value line.
        let msgs = encode_then_decode(OvpnCommand::HoldQuery, "0\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::SingleValue(s) if s == "0"));
    }

    #[test]
    fn decode_bare_state_single_value() {
        let msgs = encode_then_decode(
            OvpnCommand::State,
            "1234567890,CONNECTED,SUCCESS,,10.0.0.1,,\n",
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::SingleValue(s) if s.starts_with("1234567890")));
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
        match &msgs[1] {
            OvpnMessage::MultiLine(lines) => {
                assert_eq!(lines, &["header line", "data line"]);
            }
            other => panic!("unexpected: {other:?}"),
        }
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
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Client {
                event,
                cid,
                kid,
                env,
            }) => {
                assert_eq!(*event, ClientEvent::Connect);
                assert_eq!(*cid, 0);
                assert_eq!(*kid, Some(1));
                assert_eq!(env.len(), 2);
                assert_eq!(env[0], ("untrusted_ip".to_owned(), "1.2.3.4".to_owned()));
                assert_eq!(env[1], ("common_name".to_owned(), "TestClient".to_owned()));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn decode_client_address_single_line() {
        let msgs = decode_all(">CLIENT:ADDRESS,3,10.0.0.5,1\n");
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            OvpnMessage::Notification(Notification::ClientAddress { cid, addr, primary }) => {
                assert_eq!(*cid, 3);
                assert_eq!(addr, "10.0.0.5");
                assert!(*primary);
            }
            other => panic!("unexpected: {other:?}"),
        }
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
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Client {
                event,
                cid,
                kid,
                env,
            }) => {
                assert_eq!(*event, ClientEvent::Disconnect);
                assert_eq!(*cid, 5);
                assert_eq!(*kid, None);
                assert_eq!(env.len(), 2);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn decode_password_notification() {
        let msgs = decode_all(">PASSWORD:Need 'Auth' username/password\n");
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedAuth {
                auth_type,
            })) => {
                assert_eq!(*auth_type, AuthType::Auth);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn quote_and_escape_special_chars() {
        assert_eq!(quote_and_escape(r#"foo"bar"#), r#""foo\"bar""#);
        assert_eq!(quote_and_escape(r"a\b"), r#""a\\b""#);
        assert_eq!(quote_and_escape("simple"), r#""simple""#);
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
        match &msgs[0] {
            OvpnMessage::Notification(Notification::NeedOk { name, message }) => {
                assert_eq!(name, "token-insertion-request");
                assert_eq!(message, "Please insert your token");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn decode_hold_notification() {
        let msgs = decode_all(">HOLD:Waiting for hold release\n");
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Hold { text }) => {
                assert_eq!(text, "Waiting for hold release");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }
}
