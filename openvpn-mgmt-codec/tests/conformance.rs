//! Basic conformance tests against a real OpenVPN management interface.
//!
//! These tests connect to a management-only OpenVPN instance (no tunnel,
//! held mode) and verify the codec correctly handles every message type
//! that can be observed without a VPN tunnel:
//!
//! - **Connection & auth**: password prompt → management authentication
//! - **Informational commands**: `version`, `help`, `pid`
//! - **State queries**: bare `state`, `hold` query
//! - **Status formats**: `status 1` / `status 2` / `status 3`
//! - **Real-time stream toggling**: `log`, `echo`, `state`, `bytecount` on/off
//! - **Hold release**: release hold → observe `>STATE:` notification
//! - **Log history**: `log all` returns buffered log lines
//! - **Error path**: unknown command → `ERROR` response
//! - **Stateful codec**: sequential commands alternate Success/MultiLine correctly
//! - **Clean shutdown**: `exit` closes the stream
//!
//! For server-mode tests (client lifecycle, `>CLIENT:` notifications,
//! `client-auth`/`client-deny`), see `conformance_server.rs`.
//!
//! # Prerequisites
//!
//! A running OpenVPN instance with the management interface on
//! `127.0.0.1:7505`, protected by the password `test-password`.
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance -- --test-threads=1
//! docker compose down
//! ```
//!
//! `--test-threads=1` is required because OpenVPN's management interface
//! accepts only one client at a time. Tests are gated behind the
//! `conformance-tests` feature so they never run during a normal
//! `cargo test`.

#![cfg(feature = "conformance-tests")]

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::parsed_response::{parse_hold, parse_pid, parse_version};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing_test::traced_test;

const ADDR: &str = "127.0.0.1:7505";
const MGMT_PASSWORD: &str = "test-password";

/// How long to wait for a message before giving up.
const MSG_TIMEOUT: Duration = Duration::from_secs(10);

// --- Helpers ---

/// Receive the next message with a timeout so tests fail fast instead
/// of hanging forever when the management interface is unresponsive.
async fn recv(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    timeout(MSG_TIMEOUT, framed.next())
        .await
        .expect("timed out waiting for message")
        .expect("stream ended unexpectedly")
        .expect("decode error")
}

/// Receive the next command response, skipping any interleaved
/// real-time notifications (`>STATE:`, `>LOG:`, `>BYTECOUNT:`, etc.).
async fn recv_response(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    loop {
        let msg = recv(framed).await;
        if matches!(msg, OvpnMessage::Notification(_)) {
            continue;
        }
        return msg;
    }
}

/// Send a command and assert the response is `Success` containing `expected`.
async fn send_ok(framed: &mut Framed<TcpStream, OvpnCodec>, cmd: OvpnCommand, expected: &str) {
    framed.send(cmd).await.unwrap();
    let msg = recv_response(framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains(expected)),
        "expected Success containing {expected:?}, got {msg:?}",
    );
}

/// Send a command and return the MultiLine response.
async fn send_multiline(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    cmd: OvpnCommand,
) -> Vec<String> {
    framed.send(cmd).await.unwrap();
    let msg = recv_response(framed).await;
    match msg {
        OvpnMessage::MultiLine(lines) => lines,
        other => panic!("expected MultiLine, got {other:?}"),
    }
}

/// Connect to the management interface, authenticate, consume the INFO
/// banner and (if present) the HOLD notification.
///
/// Returns `(framed, in_hold)`. If another test already released hold,
/// `in_hold` is `false` — callers that need hold state should check.
async fn connect_and_auth() -> (Framed<TcpStream, OvpnCodec>, bool) {
    let stream = TcpStream::connect(ADDR)
        .await
        .expect("cannot connect — is `docker compose up -d` running?");
    let mut framed = Framed::new(stream, OvpnCodec::new());

    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(msg, OvpnMessage::PasswordPrompt),
        "expected ENTER PASSWORD prompt, got {msg:?}",
    );

    framed
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Success(s) if s.contains("password is correct")),
        "expected auth success, got {msg:?}",
    );

    let msg = recv_response(&mut framed).await;
    assert!(
        matches!(&msg, OvpnMessage::Info(s) if s.contains("Management Interface")),
        "expected >INFO banner, got {msg:?}",
    );

    // HOLD notification is sent only if the hold has not been released
    // yet. Probe with a short timeout — after a previous test releases
    // hold, new management clients do NOT see >HOLD.
    let in_hold = matches!(
        timeout(Duration::from_secs(2), framed.next()).await,
        Ok(Some(Ok(OvpnMessage::Notification(
            Notification::Hold { .. }
        ))))
    );

    (framed, in_hold)
}

// ---  ---
// Connection & Authentication
// ---  ---

#[tokio::test]
#[traced_test]
async fn connect_and_authenticate() {
    let (_framed, _in_hold) = connect_and_auth().await;
}

// ---  ---
// Informational commands
// ---  ---

#[tokio::test]
#[traced_test]
async fn version_returns_multiline_with_management_version() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::Version).await;
    let info = parse_version(&lines);
    assert!(
        info.management_version().is_some(),
        "version response should contain management version, got lines: {lines:?}"
    );
    assert!(
        info.openvpn_version_line().is_some(),
        "version response should contain OpenVPN version line, got lines: {lines:?}"
    );
}

#[tokio::test]
#[traced_test]
async fn help_returns_multiline() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::Help).await;
    assert!(lines.len() > 10, "help should list many commands");
    assert!(
        lines.iter().any(|line| line.contains("version")),
        "help should mention the version command"
    );
}

#[tokio::test]
#[traced_test]
async fn pid_returns_valid_process_id() {
    let (mut framed, _) = connect_and_auth().await;

    framed.send(OvpnCommand::Pid).await.unwrap();
    let msg = recv_response(&mut framed).await;
    let payload = match msg {
        OvpnMessage::Success(s) => s,
        other => panic!("expected Success, got {other:?}"),
    };

    let pid = parse_pid(&payload).expect("should parse as pid=N");
    assert!(pid > 0, "PID should be positive");
}

// ---  ---
// State queries
// ---  ---

#[tokio::test]
#[traced_test]
async fn state_returns_multiline_in_hold() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::State).await;
    assert!(!lines.is_empty(), "state should return at least one line");
}

#[tokio::test]
#[traced_test]
async fn hold_query_parses_correctly() {
    let (mut framed, _) = connect_and_auth().await;

    framed.send(OvpnCommand::HoldQuery).await.unwrap();
    let msg = recv_response(&mut framed).await;
    let payload = match msg {
        OvpnMessage::Success(s) => s,
        other => panic!("expected Success, got {other:?}"),
    };

    // The hold flag reflects configuration (--management-hold), not
    // whether the server is currently blocked. After a prior test calls
    // `hold release` the flag stays on, so we only verify the parse.
    let _held = parse_hold(&payload).expect("should parse as hold=N");
}

// ---  ---
// Status (no tunnel, so mostly empty)
// ---  ---

#[tokio::test]
#[traced_test]
async fn status_v1_returns_multiline() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::Status(StatusFormat::V1)).await;
    assert!(!lines.is_empty(), "status 1 should return lines");
}

#[tokio::test]
#[traced_test]
async fn status_v2_returns_multiline() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::Status(StatusFormat::V2)).await;
    assert!(!lines.is_empty(), "status 2 should return lines");
}

#[tokio::test]
#[traced_test]
async fn status_v3_returns_multiline() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::Status(StatusFormat::V3)).await;
    assert!(!lines.is_empty(), "status 3 should return lines");
}

// ---  ---
// Real-time stream toggling
// ---  ---

#[tokio::test]
#[traced_test]
async fn log_on_off_toggle() {
    let (mut framed, _) = connect_and_auth().await;

    send_ok(&mut framed, OvpnCommand::Log(StreamMode::On), "ON").await;
    send_ok(&mut framed, OvpnCommand::Log(StreamMode::Off), "OFF").await;
}

#[tokio::test]
#[traced_test]
async fn echo_on_off_toggle() {
    let (mut framed, _) = connect_and_auth().await;

    send_ok(&mut framed, OvpnCommand::Echo(StreamMode::On), "ON").await;
    send_ok(&mut framed, OvpnCommand::Echo(StreamMode::Off), "OFF").await;
}

#[tokio::test]
#[traced_test]
async fn state_stream_on_off_toggle() {
    let (mut framed, _) = connect_and_auth().await;

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "ON").await;
    send_ok(
        &mut framed,
        OvpnCommand::StateStream(StreamMode::Off),
        "OFF",
    )
    .await;
}

#[tokio::test]
#[traced_test]
async fn bytecount_toggle() {
    let (mut framed, _) = connect_and_auth().await;

    send_ok(&mut framed, OvpnCommand::ByteCount(5), "").await;
    send_ok(&mut framed, OvpnCommand::ByteCount(0), "").await;
}

// ---  ---
// Hold release & signal
// ---  ---

#[tokio::test]
#[traced_test]
async fn hold_release_triggers_state_notification() {
    let (mut framed, in_hold) = connect_and_auth().await;

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;

    if in_hold {
        send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;

        let msg = recv(&mut framed).await;
        assert!(
            matches!(&msg, OvpnMessage::Notification(Notification::State { .. })),
            "expected state notification after hold release, got {msg:?}",
        );
    } else {
        // Hold was already released by an earlier test run.
        send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::Off), "").await;
    }
}

// ---  ---
// Log stream with history
// ---  ---

#[tokio::test]
#[traced_test]
async fn log_all_returns_multiline_history() {
    let (mut framed, _) = connect_and_auth().await;

    let lines = send_multiline(&mut framed, OvpnCommand::Log(StreamMode::All)).await;
    assert!(!lines.is_empty(), "log all should return log history");
}

// ---  ---
// Error handling — unknown / invalid commands
// ---  ---

#[tokio::test]
#[traced_test]
async fn unknown_raw_command_returns_error() {
    let (mut framed, _) = connect_and_auth().await;

    framed
        .send(OvpnCommand::Raw("definitely-not-a-command".into()))
        .await
        .unwrap();
    let msg = recv_response(&mut framed).await;

    assert!(
        matches!(&msg, OvpnMessage::Error(_)),
        "unknown command should return ERROR, got {msg:?}",
    );
}

// ---  ---
// Multiple commands in sequence (stateful codec correctness)
// ---  ---

#[tokio::test]
#[traced_test]
async fn sequential_commands_maintain_codec_state() {
    let (mut framed, _) = connect_and_auth().await;

    // pid → Success
    framed.send(OvpnCommand::Pid).await.unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // version → MultiLine
    framed.send(OvpnCommand::Version).await.unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(msg, OvpnMessage::MultiLine(_)));

    // help → MultiLine
    framed.send(OvpnCommand::Help).await.unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(msg, OvpnMessage::MultiLine(_)));

    // pid again → Success (codec resets correctly)
    framed.send(OvpnCommand::Pid).await.unwrap();
    let msg = recv_response(&mut framed).await;
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

// ---  ---
// Exit / Quit
// ---  ---

#[tokio::test]
#[traced_test]
async fn exit_closes_connection() {
    let (mut framed, _) = connect_and_auth().await;

    framed.send(OvpnCommand::Exit).await.unwrap();

    let result = timeout(MSG_TIMEOUT, framed.next())
        .await
        .expect("timed out waiting for stream to close");
    assert!(
        result.is_none(),
        "stream should end after exit, got {result:?}"
    );
}
