//! Integration tests using `tokio_util::codec::Framed` over real async I/O.
//!
//! These tests verify the codec works correctly when driven through the
//! `Framed` adapter with `futures::SinkExt` / `StreamExt`, exercising the
//! full async path including buffering, backpressure, and stream termination.

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::stream::{ManagementEvent, classify};
use openvpn_mgmt_codec::*;
use tokio::io::{AsyncWriteExt, duplex};
use tokio_util::codec::Framed;

// --- Helpers ---

/// Create a Framed codec pair over a duplex stream.
/// Returns (framed_client, server_write_half).
/// The client side uses the codec; the server side is raw bytes.
fn setup() -> (
    Framed<tokio::io::DuplexStream, OvpnCodec>,
    tokio::io::DuplexStream,
) {
    let (client, server) = duplex(8192);
    (Framed::new(client, OvpnCodec::new()), server)
}

// ---  ---
// Basic Framed round-trip
// ---  ---

#[tokio::test]
async fn framed_encode_pid_and_decode_success() {
    let (mut framed, mut server) = setup();

    // Send a command through the framed sink
    framed.send(OvpnCommand::Pid).await.unwrap();

    // Server writes a response
    server.write_all(b"SUCCESS: pid=42\n").await.unwrap();

    // Read the response
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "pid=42"));
}

#[tokio::test]
async fn framed_multiline_response() {
    let (mut framed, mut server) = setup();

    framed.send(OvpnCommand::Version).await.unwrap();

    server
        .write_all(b"OpenVPN Version: 2.6.9\nManagement Version: 5\nEND\n")
        .await
        .unwrap();

    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(&msg, OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[tokio::test]
async fn framed_notification_before_command() {
    let (mut framed, mut server) = setup();

    // Server sends an unsolicited notification
    server
        .write_all(b">INFO:OpenVPN Management Interface Version 5\n")
        .await
        .unwrap();

    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Info(_)));

    // Now send a command
    framed.send(OvpnCommand::Pid).await.unwrap();
    server.write_all(b"SUCCESS: pid=99\n").await.unwrap();

    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[tokio::test]
async fn framed_classify_stream_adapter() {
    let (mut framed, mut server) = setup();

    // Send server data: a notification then a command response
    framed.send(OvpnCommand::Pid).await.unwrap();

    server
        .write_all(
            b">STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\n\
              SUCCESS: pid=42\n",
        )
        .await
        .unwrap();

    // Split and classify
    let (sink, raw_stream) = framed.split();
    let events: Vec<ManagementEvent> = raw_stream
        .map(classify)
        .take(2)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .map(|result| result.unwrap())
        .collect();

    assert_eq!(events.len(), 2);
    assert!(matches!(
        &events[0],
        ManagementEvent::Notification(Notification::State { .. })
    ));
    assert!(matches!(
        &events[1],
        ManagementEvent::Response(OvpnMessage::Success(_))
    ));

    drop(sink);
}

#[tokio::test]
async fn framed_client_notification_accumulation() {
    let (mut framed, mut server) = setup();

    server
        .write_all(
            b">CLIENT:CONNECT,1,2\n\
              >CLIENT:ENV,common_name=alice\n\
              >CLIENT:ENV,untrusted_ip=10.0.0.1\n\
              >CLIENT:ENV,END\n",
        )
        .await
        .unwrap();

    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(
        &msg,
        OvpnMessage::Notification(Notification::Client {
            event: ClientEvent::Connect,
            cid: 1,
            kid: Some(2),
            env,
        }) if env.len() == 2
    ));
}

#[tokio::test]
async fn framed_incremental_byte_delivery() {
    let (mut framed, mut server) = setup();

    // Deliver the response one byte at a time
    let response = b"SUCCESS: pid=42\n";
    for &byte in response.iter() {
        server.write_all(&[byte]).await.unwrap();
    }

    // Should still decode correctly
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "pid=42"));
}

#[tokio::test]
async fn framed_multiple_messages_in_single_write() {
    let (mut framed, mut server) = setup();

    // Server writes multiple notifications in one TCP segment
    server
        .write_all(
            b">BYTECOUNT:100,200\n\
              >BYTECOUNT:300,400\n\
              >STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\n",
        )
        .await
        .unwrap();

    let msg1 = framed.next().await.unwrap().unwrap();
    let msg2 = framed.next().await.unwrap().unwrap();
    let msg3 = framed.next().await.unwrap().unwrap();

    assert!(matches!(
        msg1,
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in: 100,
            bytes_out: 200,
        })
    ));
    assert!(matches!(
        msg2,
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in: 300,
            bytes_out: 400,
        })
    ));
    assert!(matches!(
        msg3,
        OvpnMessage::Notification(Notification::State { .. })
    ));
}

#[tokio::test]
async fn framed_stream_ends_cleanly_on_server_close() {
    let (mut framed, server) = setup();

    // Drop the server side to close the connection
    drop(server);

    // Stream should end with None (not an error)
    let result = framed.next().await;
    assert!(result.is_none());
}

#[tokio::test]
async fn framed_password_prompt_and_management_auth() {
    let (mut framed, mut server) = setup();

    // Server sends password prompt
    server.write_all(b"ENTER PASSWORD:\n").await.unwrap();

    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));

    // Client sends management password
    framed
        .send(OvpnCommand::ManagementPassword("mypass".into()))
        .await
        .unwrap();

    // Server responds
    server
        .write_all(b"SUCCESS: password is correct\n")
        .await
        .unwrap();

    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[tokio::test]
async fn framed_notification_interleaved_in_multiline() {
    let (mut framed, mut server) = setup();

    framed
        .send(OvpnCommand::Status(StatusFormat::V1))
        .await
        .unwrap();

    // Notification arrives in the middle of a multi-line response
    server
        .write_all(
            b"TITLE,OpenVPN Statistics\n\
              >BYTECOUNT:500,600\n\
              Updated,2024-03-21\n\
              END\n",
        )
        .await
        .unwrap();

    // Notification is emitted first
    let msg1 = framed.next().await.unwrap().unwrap();
    assert!(matches!(
        msg1,
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));

    // Then the complete multiline
    let msg2 = framed.next().await.unwrap().unwrap();
    assert!(matches!(&msg2, OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[tokio::test]
async fn framed_full_session_lifecycle() {
    let (mut framed, mut server) = setup();

    // 1. Banner
    server
        .write_all(b">INFO:OpenVPN Management Interface Version 5\n")
        .await
        .unwrap();
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Info(_)));

    // 2. Hold notification
    server
        .write_all(b">HOLD:Waiting for hold release:0\n")
        .await
        .unwrap();
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(
        msg,
        OvpnMessage::Notification(Notification::Hold { .. })
    ));

    // 3. Release hold
    framed.send(OvpnCommand::HoldRelease).await.unwrap();
    server
        .write_all(b"SUCCESS: hold release succeeded\n")
        .await
        .unwrap();
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // 4. Enable state notifications
    framed
        .send(OvpnCommand::StateStream(StreamMode::On))
        .await
        .unwrap();
    server
        .write_all(b"SUCCESS: real-time state notification set to ON\n")
        .await
        .unwrap();
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // 5. State transitions arrive
    server
        .write_all(
            b">STATE:1711000000,CONNECTING,,,,,,\n\
              >STATE:1711000001,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\n",
        )
        .await
        .unwrap();
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(
        &msg,
        OvpnMessage::Notification(Notification::State {
            name: OpenVpnState::Connecting,
            ..
        })
    ));
    let msg = framed.next().await.unwrap().unwrap();
    assert!(matches!(
        &msg,
        OvpnMessage::Notification(Notification::State {
            name: OpenVpnState::Connected,
            ..
        })
    ));
}
