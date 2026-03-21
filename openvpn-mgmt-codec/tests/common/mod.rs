//! Shared helpers for conformance tests.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;

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
            OvpnMessage::Notification(Notification::State { .. })
            | OvpnMessage::Notification(Notification::Log { .. })
            | OvpnMessage::Notification(Notification::ByteCount { .. })
            | OvpnMessage::Notification(Notification::ByteCountCli { .. }) => continue,
            _ => return msg,
        }
    }
}

/// Send a command and assert the response is `Success` containing `expected`.
pub async fn send_ok(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    cmd: OvpnCommand,
    expected: &str,
) {
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
        .unwrap_or_else(|e| panic!("cannot connect to {addr}: {e}"));
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
