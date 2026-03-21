//! Conformance tests for `>REMOTE:` management notifications.
//!
//! Sent by OpenVPN when `--management-query-remote` is enabled.
//! The management client must respond before the connection proceeds.
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

mod common;

use std::time::Duration;

use common::{MSG_TIMEOUT, connect_and_auth, recv_raw, send_ok};
use futures::SinkExt;
use openvpn_mgmt_codec::*;
use tokio::time::timeout;
use tracing_test::traced_test;

const CLIENT_REMOTE_ADDR: &str = "127.0.0.1:7507";

/// After hold release, a client with `--management-query-remote` sends
/// `>REMOTE:host,port,protocol` and waits for a response before connecting.
///
/// Note: `--management-query-proxy` is also enabled but OpenVPN 2.6.16
/// does not send `>PROXY:` for UDP connections.
#[tokio::test]
#[traced_test]
async fn remote_accept() {
    let mut framed = connect_and_auth(CLIENT_REMOTE_ADDR).await;
    eprintln!("=== authenticated to client-remote management ===");

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for >REMOTE: ===");

    let remote = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Remote {
                host,
                port,
                protocol,
            }) = msg
            {
                return (host, port, protocol);
            }
        }
    })
    .await
    .expect("timed out waiting for >REMOTE: notification");

    eprintln!(
        "=== >REMOTE: host={} port={} protocol={:?} ===",
        remote.0, remote.1, remote.2
    );
    assert_eq!(remote.1, 1194, "remote port should be 1194");
    assert!(
        matches!(remote.2, TransportProtocol::Udp),
        "remote protocol should be UDP, got {:?}",
        remote.2,
    );

    send_ok(&mut framed, OvpnCommand::Remote(RemoteAction::Accept), "").await;
    eprintln!("=== Remote(Accept) sent ===");

    // RESOLVE and WAIT confirm the client acted on our response.
    let mut states = Vec::new();
    timeout(Duration::from_secs(5), async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::State { name, .. }) = msg {
                states.push(name);
            }
        }
    })
    .await
    .ok();

    assert!(
        !states.is_empty(),
        "should observe state transitions after Remote(Accept)",
    );
    eprintln!("=== states after accept: {states:?} ===");

    framed.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== remote conformance test complete ===");
}
