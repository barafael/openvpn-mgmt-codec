//! Server-mode conformance tests against a real OpenVPN instance with
//! `--management-client-auth` and an actual VPN client connecting.
//!
//! All server-mode checks run in a single test function using one
//! management connection. This is necessary because OpenVPN's management
//! interface accepts only one client at a time, and the server container
//! needs time to reset between sessions that we cannot reliably wait for.
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

mod common;

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use common::{MSG_TIMEOUT, connect_and_auth, recv_raw, recv_response, send_ok};
use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};
use tokio_util::codec::Framed;
use tracing_test::traced_test;

const SERVER_ADDR: &str = "127.0.0.1:7506";

// --- Helpers ---

/// Send a status query and return the multi-line response.
async fn query_status(
    framed: &mut Framed<TcpStream, OvpnCodec>,
    format: StatusFormat,
) -> Vec<String> {
    framed.send(OvpnCommand::Status(format)).await.unwrap();
    let msg = recv_response(framed).await;
    match msg {
        OvpnMessage::MultiLine(lines) => lines,
        other => panic!("expected MultiLine for status {format:?}, got {other:?}"),
    }
}

/// Drain messages until `>CLIENT:CONNECT`. Returns `(cid, kid, env)`.
async fn wait_for_client_connect(
    framed: &mut Framed<TcpStream, OvpnCodec>,
) -> (u64, u64, BTreeMap<String, String>) {
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
            if let OvpnMessage::Notification(Notification::Client { event, cid, .. }) = &msg
                && *event == expected
            {
                return *cid;
            }
        }
    })
    .await
    .expect(timeout_msg)
}

/// RAII guard that kills a child process on drop.
struct ChildGuard(std::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

// ---  ---

/// Exercises the entire server-mode management flow in one connection:
///
/// 1. Connect, authenticate, receive INFO + HOLD
/// 2. Verify CLIENT:CONNECT ENV block has expected keys
/// 3. Approve client with `client-auth` (multi-line config push)
/// 4. Observe CLIENT:ESTABLISHED
/// 5. Query status V1/V2/V3 with real client data
/// 6. Query load-stats — nclients >= 1
/// 7. Observe bytecount notification
/// 8. Interleave: rapid status queries under real tunnel traffic,
///    verify multi-line responses stay intact despite notifications
/// 9. Kill the client, observe CLIENT:DISCONNECT
/// 10. Wait for reconnect → defer with `client-pending-auth`
/// 11. Verify client visible in status during pending window
/// 12. Approve with `client-auth-nt` (no config push), observe ESTABLISHED
/// 13. Kill client, observe CLIENT:DISCONNECT
/// 14. Wait for reconnect → deny client (client exits after AUTH_FAILED)
/// 15. Send SIGUSR1, observe state transitions
/// 16. Exit cleanly
#[tokio::test]
#[traced_test]
async fn server_mode_lifecycle() {
    // --- Connect & authenticate ---
    let mut framed = connect_and_auth(SERVER_ADDR).await;
    eprintln!("=== authenticated, in hold mode ===");

    // --- Enable notifications & release hold ---
    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::ByteCount(2), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for client ===");

    // --- Wait for CLIENT:CONNECT & verify ENV keys ---
    let (cid, kid, env) = wait_for_client_connect(&mut framed).await;
    eprintln!(
        "=== CLIENT:CONNECT cid={cid} kid={kid} env_keys={} ===",
        env.len()
    );

    let keys: Vec<&str> = env.keys().map(String::as_str).collect();
    assert!(
        keys.iter()
            .any(|key| key.contains("common_name") || key.contains("CN")),
        "ENV should contain common_name or CN, got keys: {keys:?}",
    );
    assert!(
        keys.iter()
            .any(|key| key.contains("untrusted_ip") || key.contains("trusted_ip")),
        "ENV should contain an IP-related key, got keys: {keys:?}",
    );

    // --- Approve with client-auth (multi-line config push) ---
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

    // --- Wait for CLIENT:ESTABLISHED ---
    let established_cid = wait_for_client_event(
        &mut framed,
        ClientEvent::Established,
        "timed out waiting for CLIENT:ESTABLISHED",
    )
    .await;
    assert_eq!(established_cid, cid);
    eprintln!("=== CLIENT:ESTABLISHED ===");

    // --- Status with real client data ---
    let v1 = query_status(&mut framed, StatusFormat::V1).await;
    assert!(
        v1.iter().any(|line| line.contains("10.8.0")),
        "status 1 should contain VPN address, got {v1:?}",
    );

    let v2 = query_status(&mut framed, StatusFormat::V2).await;
    assert!(
        v2.iter().any(|line| line.contains("CLIENT_LIST")),
        "status 2 should contain CLIENT_LIST, got {v2:?}",
    );

    let v3 = query_status(&mut framed, StatusFormat::V3).await;
    assert!(
        v3.iter().any(|line| line.contains("CLIENT_LIST")),
        "status 3 should contain CLIENT_LIST, got {v3:?}",
    );

    // --- Load-stats ---
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

    // --- Bytecount notification ---
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

    // --- Interleaved notifications under real traffic ---
    // Exercises the codec's ability to demultiplex >BYTECOUNT:
    // notifications that arrive mid-multi-line-response.
    let (status_count, bytecount_count, state_count) = {
        let _ping = ChildGuard(
            Command::new("docker")
                .args([
                    "compose",
                    "exec",
                    "-T",
                    "openvpn-client",
                    "ping",
                    "-i",
                    "0.2",
                    "-w",
                    "6",
                    "10.8.0.1",
                ])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("failed to start ping in client container"),
        );

        send_ok(&mut framed, OvpnCommand::ByteCount(1), "").await;

        let mut status_count = 0u32;
        let mut bytecount_count = 0u32;
        let mut state_count = 0u32;

        let interleave_result = timeout(Duration::from_secs(10), async {
            for _ in 0..25 {
                framed
                    .send(OvpnCommand::Status(StatusFormat::V2))
                    .await
                    .unwrap();

                loop {
                    let msg = recv_raw(&mut framed).await;
                    match &msg {
                        OvpnMessage::MultiLine(lines) => {
                            assert!(
                                lines.iter().any(|line| {
                                    line.contains("HEADER") || line.contains("CLIENT_LIST")
                                }),
                                "status response should be intact, got {lines:?}",
                            );
                            status_count += 1;
                            break;
                        }
                        OvpnMessage::Notification(Notification::ByteCount { .. })
                        | OvpnMessage::Notification(Notification::ByteCountCli { .. }) => {
                            bytecount_count += 1;
                        }
                        OvpnMessage::Notification(Notification::State(..)) => {
                            state_count += 1;
                        }
                        OvpnMessage::Notification(_) => {}
                        other => panic!("unexpected message during interleave test: {other:?}"),
                    }
                }
                sleep(Duration::from_millis(200)).await;
            }
        })
        .await;
        assert!(
            interleave_result.is_ok(),
            "interleave test timed out after {status_count} status, {bytecount_count} bytecount",
        );

        (status_count, bytecount_count, state_count)
    };
    // _ping dropped here — tunnel traffic stops before client-kill

    assert_eq!(
        status_count, 25,
        "should have received all 25 status responses"
    );
    assert!(
        bytecount_count > 0,
        "should have seen bytecount notifications interleaved with status queries",
    );
    eprintln!(
        "=== interleave test: {status_count} status, {bytecount_count} bytecount, {state_count} state ===",
    );

    // --- Kill client → CLIENT:DISCONNECT ---
    send_ok(
        &mut framed,
        OvpnCommand::ClientKill { cid, message: None },
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

    // --- Client reconnects → pending-auth → approve with auth-nt ---
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
        pending_status.iter().any(|line| line.contains("client")),
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

    // --- Client reconnects → deny (last auth test — client exits) ---
    let (cid3, kid3, _) = wait_for_client_connect(&mut framed).await;
    eprintln!("=== CLIENT:CONNECT (reconnect for deny) cid={cid3} kid={kid3} ===");

    send_ok(
        &mut framed,
        OvpnCommand::ClientDeny(ClientDeny {
            cid: cid3,
            kid: kid3,
            reason: "conformance-test-deny".into(),
            client_reason: Some("denied by test".into()),
        }),
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

    // --- Signal SIGUSR1 → state transitions ---
    send_ok(&mut framed, OvpnCommand::Signal(Signal::SigUsr1), "").await;

    let mut states = Vec::new();
    // Drain state notifications for 5 seconds after SIGUSR1.
    timeout(Duration::from_secs(5), async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::State(StateEntry { name, .. })) = msg {
                states.push(name);
            }
        }
    })
    .await
    .ok();
    assert!(
        !states.is_empty(),
        "should observe state transitions after SIGUSR1",
    );
    eprintln!("=== SIGUSR1 states: {states:?} ===");

    // --- Clean exit ---
    framed.send(OvpnCommand::Exit).await.unwrap();
    let result = framed.next().await;
    assert!(result.is_none(), "stream should end after exit");
    eprintln!("=== server lifecycle test complete ===");
}
