//! Tests for `management_split`, `EventStream`, `ManagementSink`, and
//! `ManagementSession`.

use futures::StreamExt;
use openvpn_mgmt_codec::split::{ManagementSink, management_split};
use openvpn_mgmt_codec::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio_util::codec::Framed;

// --- Helpers ---

fn setup() -> (
    Framed<tokio::io::DuplexStream, OvpnCodec>,
    tokio::io::DuplexStream,
) {
    let (client, server) = duplex(8192);
    (Framed::new(client, OvpnCodec::new()), server)
}

// --- EventStream: wire-order passthrough ---

#[tokio::test]
async fn event_stream_yields_wire_order() {
    let (framed, mut server) = setup();
    let (_sink, mut events) = management_split(framed);

    server
        .write_all(b">STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,,,,,\nSUCCESS: pid=42\n")
        .await
        .unwrap();
    drop(server);

    let first = events.next().await.unwrap().unwrap();
    assert!(matches!(
        first,
        ManagementEvent::Notification(Notification::State(..))
    ));

    let second = events.next().await.unwrap().unwrap();
    assert!(matches!(
        second,
        ManagementEvent::Response(OvpnMessage::Success(_))
    ));
}

// --- EventStream: recv_response skips notifications and stashes them ---

#[tokio::test]
async fn recv_response_skips_and_stashes_notifications() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();

    server
        .write_all(b">HOLD:Waiting for hold release:0\n>STATE:1711000000,CONNECTING,,,,,,,\nSUCCESS: pid=99\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // recv_response should skip the two notifications and return SUCCESS.
    let response = events.recv_response().await.unwrap();
    assert!(matches!(response, OvpnMessage::Success(ref s) if s == "pid=99"));

    // The two skipped notifications should come out via next().
    let n1 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n1,
        ManagementEvent::Notification(Notification::Hold { .. })
    ));

    let n2 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n2,
        ManagementEvent::Notification(Notification::State(..))
    ));
}

// --- EventStream: drain_notifications ---

#[tokio::test]
async fn drain_notifications_empties_stash() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();

    server
        .write_all(b">HOLD:waiting\nSUCCESS: pid=1\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    let _ = events.recv_response().await.unwrap();

    let drained: Vec<_> = events.drain_notifications().collect();
    assert_eq!(drained.len(), 1);
    assert!(matches!(drained[0], Notification::Hold { .. }));

    // Stash should be empty now.
    assert_eq!(events.drain_notifications().count(), 0);
}

// --- EventStream: recv_success / recv_multi_line / recv_ok ---

#[tokio::test]
async fn recv_success_returns_payload() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    server.write_all(b"SUCCESS: pid=42\n").await.unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);
    let payload = events.recv_success().await.unwrap();
    assert_eq!(payload, "pid=42");
}

#[tokio::test]
async fn recv_success_on_error_returns_server_error() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    server.write_all(b"ERROR: unknown command\n").await.unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);
    let err = events.recv_success().await.unwrap_err();
    assert!(matches!(err, SessionError::ServerError(ref s) if s == "unknown command"));
}

#[tokio::test]
async fn recv_multi_line_returns_lines() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Help).await.unwrap();
    server
        .write_all(b"help text line 1\nhelp text line 2\nEND\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);
    let lines = events.recv_multi_line().await.unwrap();
    assert_eq!(lines, vec!["help text line 1", "help text line 2"]);
}

#[tokio::test]
async fn recv_ok_discards_payload() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::HoldRelease).await.unwrap();
    server
        .write_all(b"SUCCESS: hold release succeeded\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);
    events.recv_ok().await.unwrap();
}

// --- EventStream: connection closed ---

#[tokio::test]
async fn recv_response_on_closed_stream_returns_connection_closed() {
    let (framed, server) = setup();
    drop(server);

    let (_sink, mut events) = management_split(framed);
    let err = events.recv_response().await.unwrap_err();
    assert!(matches!(err, SessionError::ConnectionClosed));
}

// --- ManagementSink: typed methods encode correctly ---

#[tokio::test]
async fn sink_pid_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.pid().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    let wire = std::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(wire, "pid\n");
}

#[tokio::test]
async fn sink_hold_release_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.hold_release().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    let wire = std::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(wire, "hold release\n");
}

#[tokio::test]
async fn sink_client_auth_nt_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.client_auth_nt(42, 7).await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    let wire = std::str::from_utf8(&buf[..n]).unwrap();
    assert_eq!(wire, "client-auth-nt 42 7\n");
}

// --- ManagementSession: send + receive ---

#[tokio::test]
async fn session_pid() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server.write_all(b"SUCCESS: pid=1234\n").await.unwrap();
    });

    let pid = session.pid().await.unwrap();
    assert_eq!(pid, 1234);
}

#[tokio::test]
async fn session_version() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(b"OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu\nManagement Interface Version: 5\nEND\n")
            .await
            .unwrap();
    });

    let info = session.version().await.unwrap();
    assert_eq!(info.management_version(), Some(5));
}

#[tokio::test]
async fn session_stashes_notifications_between_commands() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(b">HOLD:Waiting for hold release:0\nSUCCESS: pid=42\n")
            .await
            .unwrap();
    });

    let pid = session.pid().await.unwrap();
    assert_eq!(pid, 42);

    let notifications: Vec<_> = session.drain_notifications().collect();
    assert_eq!(notifications.len(), 1);
    assert!(matches!(notifications[0], Notification::Hold { .. }));
}

#[tokio::test]
async fn session_into_split() {
    let (framed, mut server) = setup();
    let session = ManagementSession::new(framed);
    let (mut sink, mut events) = session.into_split();

    // Send command first (while server is still alive), then inject response.
    sink.hold_release().await.unwrap();
    server.write_all(b"SUCCESS: ok\n").await.unwrap();
    drop(server);

    let response = events.recv_response().await.unwrap();
    assert!(matches!(response, OvpnMessage::Success(_)));
}

// --- Edge cases ---

#[tokio::test]
async fn stash_preserves_notification_order() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();

    server
        .write_all(
            b">HOLD:first\n>FATAL:second\n>STATE:1711000000,CONNECTING,,,,,,,\nSUCCESS: pid=1\n",
        )
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);
    let _ = events.recv_response().await.unwrap();

    // Stashed notifications come out in FIFO order.
    let n1 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n1,
        ManagementEvent::Notification(Notification::Hold { ref text }) if text == "first"
    ));

    let n2 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n2,
        ManagementEvent::Notification(Notification::Fatal { ref message }) if message == "second"
    ));

    let n3 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n3,
        ManagementEvent::Notification(Notification::State(..))
    ));
}

#[tokio::test]
async fn multiple_recv_response_drains_stash_between() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    framed.send(OvpnCommand::HoldQuery).await.unwrap();

    server
        .write_all(b">HOLD:notif1\nSUCCESS: pid=1\n>HOLD:notif2\nSUCCESS: hold=1\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // First recv_response stashes notif1, returns pid.
    let r1 = events.recv_response().await.unwrap();
    assert!(matches!(r1, OvpnMessage::Success(ref s) if s == "pid=1"));

    // Stashed notif1 comes out first on next().
    let n1 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n1,
        ManagementEvent::Notification(Notification::Hold { ref text }) if text == "notif1"
    ));

    // Second recv_response stashes notif2, returns hold.
    let r2 = events.recv_response().await.unwrap();
    assert!(matches!(r2, OvpnMessage::Success(ref s) if s == "hold=1"));

    let n2 = events.next().await.unwrap().unwrap();
    assert!(matches!(
        n2,
        ManagementEvent::Notification(Notification::Hold { ref text }) if text == "notif2"
    ));
}

// --- recv_multi_line with interleaved notifications ---

#[tokio::test]
async fn recv_multi_line_stashes_interleaved_notifications() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Version).await.unwrap();

    // A notification arrives mid-multiline-response.
    server
        .write_all(b"OpenVPN Version: 2.6.9\n>HOLD:waiting\nManagement Version: 5\nEND\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // The notification is handled by the codec (emitted between multiline lines),
    // and recv_response will stash it.
    let response = events.recv_response().await.unwrap();

    // The codec may return the notification first (it arrives during multiline
    // accumulation and is emitted immediately by the codec). Check both cases.
    match response {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines.iter().any(|l| l.contains("2.6.9")));
            // Notification was stashed
            let notifications: Vec<_> = events.drain_notifications().collect();
            assert_eq!(notifications.len(), 1);
            assert!(matches!(notifications[0], Notification::Hold { .. }));
        }
        OvpnMessage::Notification(_) => {
            // If notification came first, the next response is the multiline.
            // (This depends on codec internals — both orderings are valid.)
            panic!("notification should have been stashed by recv_response");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// --- Session: hold_release ---

#[tokio::test]
async fn session_hold_release() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(b"SUCCESS: hold release succeeded\n")
            .await
            .unwrap();
    });

    session.hold_release().await.unwrap();
}

// --- Session: status ---

#[tokio::test]
async fn session_status() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(
                b"TITLE\tOpenVPN 2.6.8\n\
                  TIME\t2024-03-21 14:30:00\t1711031400\n\
                  HEADER\tCLIENT_LIST\tCommon Name\n\
                  GLOBAL_STATS\tMax bcast/mcast queue length\t3\n\
                  END\n",
            )
            .await
            .unwrap();
    });

    let status = session.status(StatusFormat::V3).await.unwrap();
    assert_eq!(status.title.as_deref(), Some("OpenVPN 2.6.8"));
}

// --- Session: hold_query ---

#[tokio::test]
async fn session_hold_query() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server.write_all(b"SUCCESS: hold=1\n").await.unwrap();
    });

    let held = session.hold_query().await.unwrap();
    assert!(held);
}

// --- Session: server error propagation ---

#[tokio::test]
async fn session_server_error() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(b"ERROR: command not recognized\n")
            .await
            .unwrap();
    });

    let err = session.pid().await.unwrap_err();
    assert!(matches!(err, SessionError::ServerError(ref s) if s.contains("not recognized")));
}

// --- Sink: more command encodings ---

#[tokio::test]
async fn sink_status_v3_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.status(StatusFormat::V3).await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), "status 3\n");
}

#[tokio::test]
async fn sink_signal_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.signal(Signal::SigUsr1).await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), "signal SIGUSR1\n");
}

#[tokio::test]
async fn sink_bytecount_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.bytecount(5).await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), "bytecount 5\n");
}

#[tokio::test]
async fn sink_version_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.version().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), "version\n");
}

#[tokio::test]
async fn sink_exit_encodes_command() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.exit().await.unwrap();

    let mut buf = vec![0u8; 64];
    let n = server.read(&mut buf).await.unwrap();
    assert_eq!(std::str::from_utf8(&buf[..n]).unwrap(), "exit\n");
}

// --- Sink: complex command encodings ---

#[tokio::test]
async fn sink_username_encodes_with_quoting() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.username(AuthType::Auth, "myuser").await.unwrap();

    let mut buf = vec![0u8; 128];
    let n = server.read(&mut buf).await.unwrap();
    let wire = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(wire.starts_with("username \"Auth\" \"myuser\"\n"));
}

#[tokio::test]
async fn sink_password_encodes_with_quoting() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.password(AuthType::PrivateKey, "s3cret").await.unwrap();

    let mut buf = vec![0u8; 128];
    let n = server.read(&mut buf).await.unwrap();
    let wire = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(wire.contains("\"Private Key\""));
    assert!(wire.contains("\"s3cret\""));
}

#[tokio::test]
async fn sink_client_deny_encodes_with_reason() {
    let (framed, mut server) = setup();
    let (mut sink, _events) = management_split(framed);

    sink.client_deny(
        ClientDeny::builder()
            .cid(5_u64)
            .kid(1_u64)
            .reason("bad cert")
            .build(),
    )
    .await
    .unwrap();

    let mut buf = vec![0u8; 128];
    let n = server.read(&mut buf).await.unwrap();
    let wire = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(wire.starts_with("client-deny 5 1 \"bad cert\"\n"));
}

// --- Session: load_stats ---

#[tokio::test]
async fn session_load_stats() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(b"SUCCESS: nclients=3,bytesin=100000,bytesout=50000\n")
            .await
            .unwrap();
    });

    let stats = session.load_stats().await.unwrap();
    assert_eq!(stats.nclients, 3);
    assert_eq!(stats.bytesin, 100000);
    assert_eq!(stats.bytesout, 50000);
}

// --- Session: state ---

#[tokio::test]
async fn session_state() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(
                b"1711000000,CONNECTING,,,,,,,\n1711000005,CONNECTED,SUCCESS,10.8.0.6,,,,,\nEND\n",
            )
            .await
            .unwrap();
    });

    let entries = session.state().await.unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].name, OpenVpnState::Connecting);
    assert_eq!(entries[1].name, OpenVpnState::Connected);
}

// --- Session: current_state ---

#[tokio::test]
async fn session_current_state() {
    let (framed, mut server) = setup();
    let mut session = ManagementSession::new(framed);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 64];
        let _ = server.read(&mut buf).await.unwrap();
        server
            .write_all(b"1711000005,CONNECTED,SUCCESS,10.8.0.6,,,,,\nEND\n")
            .await
            .unwrap();
    });

    let entry = session.current_state().await.unwrap();
    assert_eq!(entry.name, OpenVpnState::Connected);
    assert_eq!(entry.local_ip, "10.8.0.6");
}

// --- Session: connection closed mid-command ---

#[tokio::test]
async fn session_connection_closed_mid_command() {
    let (framed, server) = setup();
    drop(server);
    let mut session = ManagementSession::new(framed);

    let err = session.pid().await.unwrap_err();
    assert!(matches!(
        err,
        SessionError::Io(_) | SessionError::ConnectionClosed
    ));
}

// =====================================================================
// EventStream stash / poll_next interaction tests
//
// These test the core invariant: recv_response polls the transport
// directly (bypassing the stash), while next() drains the stash first.
// Getting this wrong caused an infinite loop (the original bug).
// =====================================================================

#[tokio::test]
async fn next_drains_stash_before_transport() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    framed.send(OvpnCommand::HoldQuery).await.unwrap();

    // Two notifications then two responses.
    server
        .write_all(b">HOLD:n1\n>HOLD:n2\nSUCCESS: pid=1\nSUCCESS: hold=0\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // recv_response stashes n1 and n2, returns pid.
    let r = events.recv_response().await.unwrap();
    assert!(matches!(r, OvpnMessage::Success(ref s) if s == "pid=1"));

    // next() should yield stashed n1 first (not the second SUCCESS).
    let e1 = events.next().await.unwrap().unwrap();
    assert!(
        matches!(&e1, ManagementEvent::Notification(Notification::Hold { text }) if text == "n1")
    );

    // next() should yield stashed n2.
    let e2 = events.next().await.unwrap().unwrap();
    assert!(
        matches!(&e2, ManagementEvent::Notification(Notification::Hold { text }) if text == "n2")
    );

    // Now stash is empty — next() hits the transport, gets second SUCCESS.
    let e3 = events.next().await.unwrap().unwrap();
    assert!(matches!(e3, ManagementEvent::Response(OvpnMessage::Success(ref s)) if s == "hold=0"));
}

#[tokio::test]
async fn recv_response_does_not_consume_from_stash() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    framed.send(OvpnCommand::HoldQuery).await.unwrap();

    // Notification, response, notification, response.
    server
        .write_all(b">HOLD:first\nSUCCESS: pid=1\n>HOLD:second\nSUCCESS: hold=1\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // First recv_response: stashes "first", returns pid.
    let r1 = events.recv_response().await.unwrap();
    assert!(matches!(r1, OvpnMessage::Success(ref s) if s == "pid=1"));
    assert_eq!(events.drain_notifications().count(), 1); // "first" was stashed

    // Second recv_response: stashes "second", returns hold.
    // Crucially, it must NOT re-yield "first" from the stash (which
    // was already drained above). If it did, we'd get an infinite loop.
    let r2 = events.recv_response().await.unwrap();
    assert!(matches!(r2, OvpnMessage::Success(ref s) if s == "hold=1"));
    let remaining: Vec<_> = events.drain_notifications().collect();
    assert_eq!(remaining.len(), 1);
    assert!(matches!(&remaining[0], Notification::Hold { text } if text == "second"));
}

#[tokio::test]
async fn recv_response_with_only_notifications_returns_closed() {
    let (framed, mut server) = setup();
    let (_sink, mut events) = management_split(framed);

    // Server sends only notifications, then closes.
    server
        .write_all(b">HOLD:waiting\n>FATAL:crash\n")
        .await
        .unwrap();
    drop(server);

    // recv_response should stash both notifications and return ConnectionClosed.
    let err = events.recv_response().await.unwrap_err();
    assert!(matches!(err, SessionError::ConnectionClosed));

    // The notifications were stashed before the error.
    let stashed: Vec<_> = events.drain_notifications().collect();
    assert_eq!(stashed.len(), 2);
    assert!(matches!(&stashed[0], Notification::Hold { .. }));
    assert!(matches!(&stashed[1], Notification::Fatal { .. }));
}

#[tokio::test]
async fn recv_success_on_multiline_returns_unexpected() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Help).await.unwrap();
    server.write_all(b"help line 1\nEND\n").await.unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // recv_success expects SUCCESS, but gets MultiLine.
    let err = events.recv_success().await.unwrap_err();
    assert!(matches!(
        err,
        SessionError::UnexpectedResponse(OvpnMessage::MultiLine(_))
    ));
}

#[tokio::test]
async fn recv_multi_line_on_success_returns_unexpected() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    server.write_all(b"SUCCESS: pid=42\n").await.unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // recv_multi_line expects MultiLine, but gets Success.
    let err = events.recv_multi_line().await.unwrap_err();
    assert!(matches!(
        err,
        SessionError::UnexpectedResponse(OvpnMessage::Success(_))
    ));
}

#[tokio::test]
async fn next_after_stream_end_returns_none() {
    let (framed, server) = setup();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // Stream is closed — next() returns None.
    assert!(events.next().await.is_none());
    // Calling again still returns None (idempotent).
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn alternating_recv_response_and_next() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();
    framed.send(OvpnCommand::HoldQuery).await.unwrap();
    framed.send(OvpnCommand::Pid).await.unwrap();

    server
        .write_all(b">HOLD:a\nSUCCESS: pid=1\n>HOLD:b\nSUCCESS: hold=0\n>HOLD:c\nSUCCESS: pid=2\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // Round 1: recv_response + drain
    let r1 = events.recv_response().await.unwrap();
    assert!(matches!(r1, OvpnMessage::Success(ref s) if s == "pid=1"));
    let n1 = events.next().await.unwrap().unwrap();
    assert!(
        matches!(&n1, ManagementEvent::Notification(Notification::Hold { text }) if text == "a")
    );

    // Round 2: recv_response + drain
    let r2 = events.recv_response().await.unwrap();
    assert!(matches!(r2, OvpnMessage::Success(ref s) if s == "hold=0"));
    let n2 = events.next().await.unwrap().unwrap();
    assert!(
        matches!(&n2, ManagementEvent::Notification(Notification::Hold { text }) if text == "b")
    );

    // Round 3: recv_response + drain
    let r3 = events.recv_response().await.unwrap();
    assert!(matches!(r3, OvpnMessage::Success(ref s) if s == "pid=2"));
    let n3 = events.next().await.unwrap().unwrap();
    assert!(
        matches!(&n3, ManagementEvent::Notification(Notification::Hold { text }) if text == "c")
    );

    // Stream is done.
    assert!(events.next().await.is_none());
}

#[tokio::test]
async fn drain_notifications_then_next_goes_to_transport() {
    let (mut framed, mut server) = setup();

    use futures::SinkExt;
    framed.send(OvpnCommand::Pid).await.unwrap();

    server
        .write_all(b">HOLD:stashed\nSUCCESS: pid=1\n>HOLD:from_wire\n")
        .await
        .unwrap();
    drop(server);

    let (_sink, mut events) = management_split(framed);

    // recv_response stashes the notification.
    let _ = events.recv_response().await.unwrap();

    // Drain the stash explicitly.
    let drained: Vec<_> = events.drain_notifications().collect();
    assert_eq!(drained.len(), 1);
    assert!(matches!(&drained[0], Notification::Hold { text } if text == "stashed"));

    // next() should now hit the transport (stash is empty) and get the
    // notification that arrived AFTER the response.
    let event = events.next().await.unwrap().unwrap();
    assert!(
        matches!(&event, ManagementEvent::Notification(Notification::Hold { text }) if text == "from_wire")
    );
}
