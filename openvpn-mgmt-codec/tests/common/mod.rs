#![allow(dead_code)]
//! Shared helpers for conformance and unit tests.

use std::time::Duration;

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::{Decoder, Encoder, Framed};

// --- Synchronous codec helpers ---

/// Decode all messages from wire bytes using a fresh codec.
pub fn decode_all(input: &str) -> Vec<OvpnMessage> {
    decode_all_with(&mut OvpnCodec::new(), input)
}

/// Decode all messages from wire bytes using a caller-provided codec.
pub fn decode_all_with(codec: &mut OvpnCodec, input: &str) -> Vec<OvpnMessage> {
    let mut buf = BytesMut::from(input);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

/// Like [`decode_all_with`] but propagates decode errors.
pub fn try_decode_all(
    codec: &mut OvpnCodec,
    input: &str,
) -> Result<Vec<OvpnMessage>, std::io::Error> {
    let mut buf = BytesMut::from(input);
    let mut msgs = Vec::new();
    loop {
        match codec.decode(&mut buf)? {
            Some(msg) => msgs.push(msg),
            None => return Ok(msgs),
        }
    }
}

/// Try to encode a command in Strict mode, returning the wire string or an error.
pub fn try_encode_strict(cmd: OvpnCommand) -> Result<String, std::io::Error> {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf)?;
    Ok(String::from_utf8(buf.to_vec()).unwrap())
}

/// Encode a command with a fresh codec and return the wire string.
pub fn encode_str(cmd: OvpnCommand) -> String {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf).unwrap();
    String::from_utf8(buf.to_vec()).unwrap()
}

/// Encode a command, then decode a simulated response. Returns all decoded messages.
pub fn encode_then_decode(cmd: OvpnCommand, response: &str) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec.encode(cmd, &mut enc_buf).unwrap();
    decode_all_with(&mut codec, response)
}

// --- Async conformance helpers ---

pub const MGMT_PASSWORD: &str = "test-password";
pub const MSG_TIMEOUT: Duration = Duration::from_secs(120);

/// Receive the next message, no timeout. Use inside an outer `timeout()`.
pub async fn recv_raw(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    framed
        .next()
        .await
        .expect("stream ended unexpectedly")
        .expect("decode error")
}

/// Receive the next message with the standard timeout.
pub async fn recv(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    timeout(MSG_TIMEOUT, recv_raw(framed))
        .await
        .expect("timed out waiting for message")
}

/// Receive the next command response, skipping real-time notifications.
pub async fn recv_response(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    loop {
        let msg = recv(framed).await;
        match &msg {
            OvpnMessage::Notification(Notification::State(..))
            | OvpnMessage::Notification(Notification::Log { .. })
            | OvpnMessage::Notification(Notification::ByteCount { .. })
            | OvpnMessage::Notification(Notification::ByteCountCli { .. }) => continue,
            _ => return msg,
        }
    }
}

/// Send a command and assert the response is `Success` containing `expected`.
pub async fn send_ok(framed: &mut Framed<TcpStream, OvpnCodec>, cmd: OvpnCommand, expected: &str) {
    framed.send(cmd).await.unwrap();
    let msg = recv_response(framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains(expected)),
        "expected Success containing {expected:?}, got {msg:?}",
    );
}

/// Connect to a management interface, authenticate, and consume the
/// INFO banner and HOLD notification. Returns the authenticated framed
/// connection.
pub async fn connect_and_auth(addr: &str) -> Framed<TcpStream, OvpnCodec> {
    let stream = TcpStream::connect(addr)
        .await
        .unwrap_or_else(|error| panic!("cannot connect to {addr}: {error}"));
    let mut framed = Framed::new(stream, OvpnCodec::new());

    let msg = recv(&mut framed).await;
    assert!(
        matches!(msg, OvpnMessage::PasswordPrompt),
        "expected password prompt, got {msg:?}",
    );

    framed
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains("password is correct")),
        "expected auth success, got {msg:?}",
    );

    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Info(_)),
        "expected >INFO banner, got {msg:?}",
    );

    let msg = recv(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Notification(Notification::Hold { .. })),
        "expected >HOLD notification, got {msg:?}",
    );

    framed
}
