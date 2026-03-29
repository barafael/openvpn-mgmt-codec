//! Frame decoder for the OpenVPN management protocol.

use std::collections::BTreeMap;
use std::io;

use bytes::{Buf, BytesMut};
use tokio_util::codec::Decoder;
use tracing::warn;

use crate::encoder::AccumulationLimit;
use crate::frame::Frame;

/// May arrive without a trailing newline (OpenVPN >= 2.6 sends it as an
/// interactive prompt).
const PW_PROMPT: &[u8] = b"ENTER PASSWORD:";

/// Internal accumulator for `>CLIENT:` ENV blocks.
#[derive(Debug)]
struct ClientEnvAccumulator {
    event: String,
    args: String,
    env: BTreeMap<String, String>,
}

/// A low-level decoder that splits the byte stream into [`Frame`] values.
///
/// This decoder classifies each line purely from its content — it does
/// **not** track which command was sent. Multi-line response accumulation
/// (`Line`/`End` grouping) is left to higher layers.
///
/// `>CLIENT:ENV` accumulation **is** handled here because the protocol
/// guarantees atomicity for that block.
#[derive(Debug)]
pub struct FrameDecoder {
    /// Accumulator for `>CLIENT:` ENV blocks.
    client_notification: Option<ClientEnvAccumulator>,

    /// Maximum ENV entries.
    max_client_env_entries: AccumulationLimit,

    /// Whether the initial `>INFO:` banner has been seen.
    seen_info: bool,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self {
            client_notification: None,
            max_client_env_entries: AccumulationLimit::Unlimited,
            seen_info: false,
        }
    }
}

impl FrameDecoder {
    /// Create a new frame decoder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum ENV entries for `>CLIENT:` notifications.
    pub fn with_max_client_env_entries(mut self, limit: AccumulationLimit) -> Self {
        self.max_client_env_entries = limit;
        self
    }
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

#[derive(Debug, thiserror::Error)]
#[error("{what} accumulation limit exceeded ({max})")]
struct AccumulationLimitExceeded {
    what: &'static str,
    max: usize,
}

impl Decoder for FrameDecoder {
    type Item = Frame;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            // Find the next complete line.
            let Some(newline_pos) = src.iter().position(|&b| b == b'\n') else {
                // No complete line. Check for password prompt without
                // trailing newline (OpenVPN >= 2.6).
                if src.starts_with(PW_PROMPT) {
                    let mut consume = PW_PROMPT.len();
                    if src.get(consume) == Some(&b'\r') {
                        consume += 1;
                    }
                    src.advance(consume);
                    return Ok(Some(Frame::PasswordPrompt));
                }
                if src.capacity() - src.len() < 256 {
                    src.reserve(256);
                }
                return Ok(None);
            };

            // Extract and decode the line.
            let line_bytes = src.split_to(newline_pos + 1);
            let line = match std::str::from_utf8(&line_bytes) {
                Ok(text) => text,
                Err(error) => {
                    self.client_notification = None;
                    return Err(io::Error::new(io::ErrorKind::InvalidData, error));
                }
            }
            .trim_end_matches(['\r', '\n'])
            .to_string();

            // Empty lines carry no information when the decoder is not
            // inside a CLIENT ENV accumulation. However, they *are*
            // meaningful in multi-line response blocks — the higher layer
            // decides whether to keep or discard them, so we emit them
            // as `Frame::Line("")`.
            if line.is_empty() && self.client_notification.is_none() {
                return Ok(Some(Frame::Line(line)));
            }

            // --- Phase 1: >CLIENT:ENV accumulation ---
            if let Some(ref mut accum) = self.client_notification
                && let Some(rest) = line.strip_prefix(">CLIENT:ENV,")
            {
                if rest == "END" {
                    let finished = self.client_notification.take().expect("guarded by if-let");
                    return Ok(Some(Frame::ClientEnv {
                        event: finished.event,
                        args: finished.args,
                        env: finished.env,
                    }));
                }
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
                continue;
            }

            // --- Phase 2: Self-describing lines ---

            if let Some(rest) = line.strip_prefix("SUCCESS:") {
                return Ok(Some(Frame::Success(
                    rest.strip_prefix(' ').unwrap_or(rest).to_string(),
                )));
            }

            if let Some(rest) = line.strip_prefix("ERROR:") {
                return Ok(Some(Frame::Error(
                    rest.strip_prefix(' ').unwrap_or(rest).to_string(),
                )));
            }

            if line == "ENTER PASSWORD:" {
                return Ok(Some(Frame::PasswordPrompt));
            }

            if line == "END" {
                return Ok(Some(Frame::End));
            }

            // --- Phase 3: Notifications ---
            if let Some(inner) = line.strip_prefix('>') {
                let Some((kind, payload)) = inner.split_once(':') else {
                    warn!(line = %line, "malformed notification (no colon)");
                    // Emit as a plain Line — the higher layer decides
                    // whether this is Unrecognized.
                    return Ok(Some(Frame::Line(line)));
                };

                // >INFO: banner handling.
                if kind == "INFO" {
                    if !self.seen_info {
                        self.seen_info = true;
                        return Ok(Some(Frame::Info(payload.to_string())));
                    }
                    return Ok(Some(Frame::Notification {
                        kind: kind.to_string(),
                        payload: payload.to_string(),
                    }));
                }

                // >CLIENT: — start ENV accumulation (except ADDRESS which
                // is single-line).
                if kind == "CLIENT" {
                    let (event, args) = payload
                        .split_once(',')
                        .map(|(e, a)| (e.to_string(), a.to_string()))
                        .unwrap_or_else(|| (payload.to_string(), String::new()));

                    if event == "ADDRESS" {
                        // Single-line — emit as Notification directly.
                        return Ok(Some(Frame::Notification {
                            kind: "CLIENT".to_string(),
                            payload: payload.to_string(),
                        }));
                    }

                    // Multi-line CLIENT notification — start accumulation.
                    self.client_notification = Some(ClientEnvAccumulator {
                        event,
                        args,
                        env: BTreeMap::new(),
                    });
                    continue; // Read ENV lines.
                }

                return Ok(Some(Frame::Notification {
                    kind: kind.to_string(),
                    payload: payload.to_string(),
                }));
            }

            // --- Phase 4: Unclassified line ---
            return Ok(Some(Frame::Line(line)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_one(input: &str) -> Frame {
        let mut decoder = FrameDecoder::new();
        let mut buf = BytesMut::from(input);
        decoder.decode(&mut buf).unwrap().unwrap()
    }

    #[test]
    fn success_line() {
        assert_eq!(
            decode_one("SUCCESS: pid=42\n"),
            Frame::Success("pid=42".to_string())
        );
    }

    #[test]
    fn error_line() {
        assert_eq!(
            decode_one("ERROR: unknown command\n"),
            Frame::Error("unknown command".to_string())
        );
    }

    #[test]
    fn end_line() {
        assert_eq!(decode_one("END\n"), Frame::End);
    }

    #[test]
    fn plain_line() {
        assert_eq!(
            decode_one("TITLE\tOpenVPN 2.6.8\n"),
            Frame::Line("TITLE\tOpenVPN 2.6.8".to_string())
        );
    }

    #[test]
    fn notification() {
        assert_eq!(
            decode_one(">HOLD:Waiting for hold release:0\n"),
            Frame::Notification {
                kind: "HOLD".to_string(),
                payload: "Waiting for hold release:0".to_string(),
            }
        );
    }

    #[test]
    fn info_banner() {
        let mut decoder = FrameDecoder::new();
        let mut buf = BytesMut::from(">INFO:OpenVPN Management Interface\n>INFO:second\n");

        let first = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            first,
            Frame::Info("OpenVPN Management Interface".to_string())
        );

        let second = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(
            second,
            Frame::Notification {
                kind: "INFO".to_string(),
                payload: "second".to_string(),
            }
        );
    }

    #[test]
    fn state_notification() {
        let frame = decode_one(">STATE:1711000000,CONNECTED,SUCCESS,10.8.0.6,1.2.3.4,,,,\n");
        assert!(matches!(frame, Frame::Notification { kind, .. } if kind == "STATE"));
    }

    #[test]
    fn client_env_accumulation() {
        let mut decoder = FrameDecoder::new();
        let input = "\
            >CLIENT:CONNECT,1,2\n\
            >CLIENT:ENV,common_name=alice\n\
            >CLIENT:ENV,password=secret\n\
            >CLIENT:ENV,END\n";
        let mut buf = BytesMut::from(input);

        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        match frame {
            Frame::ClientEnv { event, args, env } => {
                assert_eq!(event, "CONNECT");
                assert_eq!(args, "1,2");
                assert_eq!(env.get("common_name").unwrap(), "alice");
                assert_eq!(env.get("password").unwrap(), "secret");
            }
            other => panic!("expected ClientEnv, got {other:?}"),
        }
    }

    #[test]
    fn client_address_is_single_line() {
        let frame = decode_one(">CLIENT:ADDRESS,1,10.8.0.6,1\n");
        assert!(matches!(frame, Frame::Notification { kind, .. } if kind == "CLIENT"));
    }

    #[test]
    fn password_prompt_with_newline() {
        assert_eq!(decode_one("ENTER PASSWORD:\n"), Frame::PasswordPrompt,);
    }

    #[test]
    fn password_prompt_without_newline() {
        let mut decoder = FrameDecoder::new();
        let mut buf = BytesMut::from("ENTER PASSWORD:");
        let frame = decoder.decode(&mut buf).unwrap().unwrap();
        assert_eq!(frame, Frame::PasswordPrompt);
    }

    #[test]
    fn empty_lines_emitted_as_line() {
        let mut decoder = FrameDecoder::new();
        let mut buf = BytesMut::from("\n\n\nSUCCESS: ok\n");
        // Empty lines are emitted as Frame::Line("") — the higher layer
        // decides whether to keep or discard them.
        assert_eq!(
            decoder.decode(&mut buf).unwrap().unwrap(),
            Frame::Line(String::new())
        );
        assert_eq!(
            decoder.decode(&mut buf).unwrap().unwrap(),
            Frame::Line(String::new())
        );
        assert_eq!(
            decoder.decode(&mut buf).unwrap().unwrap(),
            Frame::Line(String::new())
        );
        assert_eq!(
            decoder.decode(&mut buf).unwrap().unwrap(),
            Frame::Success("ok".to_string())
        );
    }
}
