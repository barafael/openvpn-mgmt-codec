//! Conformance tests for `>REMOTE:` and `>PROXY:` management notifications.
//!
//! These notifications are sent by OpenVPN when `--management-query-remote`
//! and `--management-query-proxy` are enabled. The management client must
//! respond before the connection can proceed.
//!
//! # Prerequisites
//!
//! The `openvpn-client-remote` Docker container (port 7507) with its own
//! management interface and `--management-query-remote --management-query-proxy`.
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_remote
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

const CLIENT_REMOTE_ADDR: &str = "127.0.0.1:7507";
const MGMT_PASSWORD: &str = "test-password";
const MSG_TIMEOUT: Duration = Duration::from_secs(120);

// ── Helpers ──────────────────────────────────────────────────────────

async fn recv_raw(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    framed
        .next()
        .await
        .expect("stream ended unexpectedly")
        .expect("decode error")
}

async fn recv(framed: &mut Framed<TcpStream, OvpnCodec>) -> OvpnMessage {
    timeout(MSG_TIMEOUT, recv_raw(framed))
        .await
        .expect("timed out waiting for message")
}

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

/// Connect to the client-remote management interface and authenticate.
async fn connect_client_mgmt() -> Framed<TcpStream, OvpnCodec> {
    let stream = TcpStream::connect(CLIENT_REMOTE_ADDR)
        .await
        .expect("cannot connect to client-remote:7507 — is `docker compose up -d` running?");
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

// ═════════════════════════════════════════════════════════════════════

/// After hold release, a client with `--management-query-remote` sends
/// `>REMOTE:host,port,protocol` and waits for a response before connecting.
/// With `--management-query-proxy`, it also sends `>PROXY:`.
///
/// This test:
/// 1. Connects to the client's management interface, authenticates
/// 2. Enables state notifications, releases hold
/// 3. Observes `>REMOTE:openvpn-server,1194,udp`
/// 4. Responds with `Remote(Accept)`
/// 5. Observes `>PROXY:` notification
/// 6. Responds with `Proxy(None)` (direct connection)
/// 7. Verifies the client proceeds to connect (state transitions)
#[tokio::test]
#[traced_test]
async fn remote_and_proxy_accept() {
    let mut framed = connect_client_mgmt().await;
    eprintln!("=== authenticated to client-remote management ===");

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for >REMOTE: ===");

    // After hold release, OpenVPN queries the management interface for
    // the remote server address before connecting.
    let remote = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Remote { host, port, protocol }) = msg {
                return (host, port, protocol);
            }
        }
    })
    .await
    .expect("timed out waiting for >REMOTE: notification");

    eprintln!("=== >REMOTE: host={} port={} protocol={:?} ===", remote.0, remote.1, remote.2);
    assert_eq!(remote.1, 1194, "remote port should be 1194");
    assert!(
        matches!(remote.2, TransportProtocol::Udp),
        "remote protocol should be UDP, got {:?}",
        remote.2,
    );

    // Accept the remote entry as-is.
    send_ok(&mut framed, OvpnCommand::Remote(RemoteAction::Accept), "").await;
    eprintln!("=== Remote(Accept) sent ===");

    // Next, OpenVPN queries for proxy settings.
    let proxy = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Proxy { index, proxy_type, host }) = msg
            {
                return (index, proxy_type, host);
            }
        }
    })
    .await
    .expect("timed out waiting for >PROXY: notification");

    eprintln!(
        "=== >PROXY: index={} type={} host={} ===",
        proxy.0, proxy.1, proxy.2,
    );

    // Connect directly, no proxy.
    send_ok(&mut framed, OvpnCommand::Proxy(ProxyAction::None), "").await;
    eprintln!("=== Proxy(None) sent ===");

    // The client should now proceed to connect. Watch for state transitions
    // indicating the connection is progressing (CONNECTING, WAIT, AUTH, etc.).
    let mut states = Vec::new();
    let _ = timeout(Duration::from_secs(30), async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::State { name, .. }) = msg {
                let done = matches!(
                    name,
                    OpenVpnState::Connected | OpenVpnState::Auth | OpenVpnState::GetConfig
                );
                states.push(name);
                if done {
                    return;
                }
            }
        }
    })
    .await;

    assert!(
        !states.is_empty(),
        "should observe state transitions after REMOTE+PROXY accept",
    );
    eprintln!("=== states after accept: {states:?} ===");

    // Clean exit.
    framed.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== remote/proxy conformance test complete ===");
}
