//! Server-mode conformance tests against a real OpenVPN instance with
//! `--management-client-auth` and an actual VPN client connecting.
//!
//! All server-mode checks run in a single test function using one
//! management connection. This is necessary because OpenVPN's management
//! interface accepts only one client at a time, and the server container
//! needs time to reset between sessions that we cannot reliably wait for.
//!
//! # Prerequisites
//!
//! Three Docker containers: `openvpn` (basic), `openvpn-server`
//! (server-mode with `--management-client-auth` on port 7506), and
//! `openvpn-client` (auto-connecting VPN client).
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_server
//! docker compose down
//! ```

#![cfg(feature = "conformance-tests")]

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing_test::traced_test;

const SERVER_ADDR: &str = "127.0.0.1:7506";
const MGMT_PASSWORD: &str = "test-password";

/// How long to wait for a message before giving up.
const MSG_TIMEOUT: Duration = Duration::from_secs(120);

// ── Helpers ──────────────────────────────────────────────────────────

/// Receive the next message, no timeout. Use inside an outer `timeout()`.
async fn recv_raw(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    framed
        .next()
        .await
        .expect("stream ended unexpectedly")
        .expect("decode error")
}

/// Receive the next message with the standard timeout.
async fn recv(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    timeout(MSG_TIMEOUT, recv_raw(framed))
        .await
        .expect("timed out waiting for message")
}

/// Receive the next command response, skipping real-time notifications.
async fn recv_response(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
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
async fn send_ok(
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

/// Send a status query and return the multi-line response.
async fn query_status(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    format: StatusFormat,
) -> Vec<String> {
    framed
        .send(OvpnCommand::Status(format))
        .await
        .unwrap();
    let msg = recv_response(framed).await;
    match msg {
        OvpnMessage::MultiLine(lines) => lines,
        other => panic!("expected MultiLine for status {format:?}, got {other:?}"),
    }
}

/// Drain messages until `>CLIENT:CONNECT`. Returns `(cid, kid, env)`.
async fn wait_for_client_connect(
    framed: &mut Framed<TcpStream, OvpnCodec>,
) -> (u64, u64, Vec<(String, String)>) {
    timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(framed).await;
            if let OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Connect,
                cid,
                kid: Some(kid),
                env,
            }) = msg
            {
                return (cid, kid, env);
            }
        }
    })
    .await
    .expect("timed out waiting for CLIENT:CONNECT")
}

/// Drain messages until a specific `>CLIENT:` event. Returns its `cid`.
async fn wait_for_client_event(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    expected: ClientEvent,
    timeout_msg: &str,
) -> u64 {
    timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(framed).await;
            if let OvpnMessage::Notification(Notification::Client {
                event,
                cid,
                ..
            }) = &msg
            {
                if *event == expected {
                    return *cid;
                }
            }
        }
    })
    .await
    .expect(timeout_msg)
}

// ═════════════════════════════════════════════════════════════════════
// Single comprehensive server-mode test
// ═════════════════════════════════════════════════════════════════════

/// Exercises the entire server-mode management flow in one connection:
///
/// 1. Connect, authenticate, receive INFO + HOLD
/// 2. Verify CLIENT:CONNECT ENV block has expected keys
/// 3. Approve client with `client-auth` (multi-line config push)
/// 4. Observe CLIENT:ESTABLISHED
/// 5. Query status V1/V2/V3 with real client data
/// 6. Query load-stats — nclients >= 1
/// 7. Observe bytecount notification
/// 8. Kill the client, observe CLIENT:DISCONNECT
/// 9. Wait for reconnect → defer with `client-pending-auth`
/// 10. Verify client visible in status during pending window
/// 11. Approve with `client-auth-nt` (no config push), observe ESTABLISHED
/// 12. Kill client, observe CLIENT:DISCONNECT
/// 13. Wait for reconnect → deny client (client exits after AUTH_FAILED)
/// 14. Send SIGUSR1, observe state transitions
/// 15. Exit cleanly
#[tokio::test]
#[traced_test]
async fn server_mode_lifecycle() {
    // ── Connect & authenticate ──────────────────────────────────────
    let stream = TcpStream::connect(SERVER_ADDR)
        .await
        .expect("cannot connect to openvpn-server:7506 — is `docker compose up -d` running?");
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
    eprintln!("=== authenticated, in hold mode ===");

    // ── Enable notifications & release hold ─────────────────────────
    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::ByteCount(2), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for client ===");

    // ── Wait for CLIENT:CONNECT & verify ENV keys ───────────────────
    let (cid, kid, env) = wait_for_client_connect(&mut framed).await;
    eprintln!("=== CLIENT:CONNECT cid={cid} kid={kid} env_keys={} ===", env.len());

    let keys: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
    assert!(
        keys.iter().any(|k| k.contains("common_name") || k.contains("CN")),
        "ENV should contain common_name or CN, got keys: {keys:?}",
    );
    assert!(
        keys.iter().any(|k| k.contains("untrusted_ip") || k.contains("trusted_ip")),
        "ENV should contain an IP-related key, got keys: {keys:?}",
    );

    // ── Approve with client-auth (multi-line config push) ───────────
    send_ok(
        &mut framed,
        OvpnCommand::ClientAuth {
            cid,
            kid,
            config_lines: vec![
                "push \"route 192.168.1.0 255.255.255.0\"".into(),
                "push \"dhcp-option DNS 10.8.0.1\"".into(),
            ],
        },
        "client-auth",
    )
    .await;

    // ── Wait for CLIENT:ESTABLISHED ─────────────────────────────────
    let established_cid = wait_for_client_event(
        &mut framed,
        ClientEvent::Established,
        "timed out waiting for CLIENT:ESTABLISHED",
    )
    .await;
    assert_eq!(established_cid, cid);
    eprintln!("=== CLIENT:ESTABLISHED ===");

    // ── Status with real client data ────────────────────────────────
    let v1 = query_status(&mut framed, StatusFormat::V1).await;
    assert!(
        v1.iter().any(|l| l.contains("10.8.0")),
        "status 1 should contain VPN address, got {v1:?}",
    );

    let v2 = query_status(&mut framed, StatusFormat::V2).await;
    assert!(
        v2.iter().any(|l| l.contains("CLIENT_LIST")),
        "status 2 should contain CLIENT_LIST, got {v2:?}",
    );

    let v3 = query_status(&mut framed, StatusFormat::V3).await;
    assert!(
        v3.iter().any(|l| l.contains("CLIENT_LIST")),
        "status 3 should contain CLIENT_LIST, got {v3:?}",
    );

    // ── Load-stats ──────────────────────────────────────────────────
    framed.send(OvpnCommand::LoadStats).await.unwrap();
    let msg = recv_response(&mut framed).await;
    let payload = match msg {
        OvpnMessage::Success(s) => s,
        other => panic!("expected Success for load-stats, got {other:?}"),
    };
    let stats = openvpn_mgmt_codec::parsed_response::parse_load_stats(&payload)
        .expect("load-stats payload should parse");
    assert!(
        stats.nclients >= 1,
        "should have at least 1 client, got {}",
        stats.nclients,
    );
    eprintln!("=== load-stats: {stats:?} ===");

    // ── Bytecount notification ──────────────────────────────────────
    timeout(Duration::from_secs(10), async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if matches!(
                &msg,
                OvpnMessage::Notification(Notification::ByteCountCli { .. })
                    | OvpnMessage::Notification(Notification::ByteCount { .. })
            ) {
                return;
            }
        }
    })
    .await
    .expect("expected bytecount notification within 10s");

    // ── Kill client → CLIENT:DISCONNECT ─────────────────────────────
    send_ok(
        &mut framed,
        OvpnCommand::ClientKill {
            cid,
            message: None,
        },
        "",
    )
    .await;

    let dc_cid = wait_for_client_event(
        &mut framed,
        ClientEvent::Disconnect,
        "timed out waiting for CLIENT:DISCONNECT",
    )
    .await;
    assert_eq!(dc_cid, cid);
    eprintln!("=== client killed, waiting for reconnect ===");

    // ── Client reconnects → pending-auth → approve with auth-nt ─────
    let (cid2, kid2, _) = wait_for_client_connect(&mut framed).await;
    eprintln!("=== CLIENT:CONNECT (reconnect for pending-auth) cid={cid2} kid={kid2} ===");

    send_ok(
        &mut framed,
        OvpnCommand::ClientPendingAuth {
            cid: cid2,
            kid: kid2,
            extra: "conformance-test-pending".into(),
            timeout: 30,
        },
        "client-pending-auth",
    )
    .await;
    eprintln!("=== client-pending-auth accepted ===");

    // While pending, the client should still show up in status.
    let pending_status = query_status(&mut framed, StatusFormat::V2).await;
    assert!(
        pending_status.iter().any(|l| l.contains("client")),
        "client should be visible in status during pending-auth, got {pending_status:?}",
    );

    send_ok(
        &mut framed,
        OvpnCommand::ClientAuthNt {
            cid: cid2,
            kid: kid2,
        },
        "client-auth",
    )
    .await;

    let est_cid2 = wait_for_client_event(
        &mut framed,
        ClientEvent::Established,
        "timed out waiting for CLIENT:ESTABLISHED after pending-auth",
    )
    .await;
    assert_eq!(est_cid2, cid2);
    eprintln!("=== CLIENT:ESTABLISHED after pending-auth + auth-nt ===");

    send_ok(
        &mut framed,
        OvpnCommand::ClientKill {
            cid: cid2,
            message: None,
        },
        "",
    )
    .await;

    let dc_cid2 = wait_for_client_event(
        &mut framed,
        ClientEvent::Disconnect,
        "timed out waiting for CLIENT:DISCONNECT after pending-auth cycle",
    )
    .await;
    assert_eq!(dc_cid2, cid2);
    eprintln!("=== pending-auth client killed, waiting for reconnect ===");

    // ── Client reconnects → deny (last auth test — client exits) ────
    let (cid3, kid3, _) = wait_for_client_connect(&mut framed).await;
    eprintln!("=== CLIENT:CONNECT (reconnect for deny) cid={cid3} kid={kid3} ===");

    send_ok(
        &mut framed,
        OvpnCommand::ClientDeny {
            cid: cid3,
            kid: kid3,
            reason: "conformance-test-deny".into(),
            client_reason: Some("denied by test".into()),
        },
        "client-deny",
    )
    .await;

    let dc_cid3 = wait_for_client_event(
        &mut framed,
        ClientEvent::Disconnect,
        "timed out waiting for CLIENT:DISCONNECT after deny",
    )
    .await;
    assert_eq!(dc_cid3, cid3);
    eprintln!("=== client denied (client exits, no more reconnects) ===");

    // ── Signal SIGUSR1 → state transitions ──────────────────────────
    send_ok(
        &mut framed,
        OvpnCommand::Signal(Signal::SigUsr1),
        "",
    )
    .await;

    let mut states = Vec::new();
    // Drain state notifications for 5 seconds after SIGUSR1.
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::State { name, .. }) = msg {
                states.push(name);
            }
        }
    })
    .await;
    assert!(
        !states.is_empty(),
        "should observe state transitions after SIGUSR1",
    );
    eprintln!("=== SIGUSR1 states: {states:?} ===");

    // ── Clean exit ──────────────────────────────────────────────────
    framed.send(OvpnCommand::Exit).await.unwrap();
    let result = framed.next().await;
    assert!(result.is_none(), "stream should end after exit");
    eprintln!("=== server lifecycle test complete ===");
}
