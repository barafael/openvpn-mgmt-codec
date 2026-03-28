//! Conformance tests for `>REMOTE:` management notifications.
//!
//! Sent by OpenVPN when `--management-query-remote` is enabled.
//! The management client must respond before the connection proceeds.
//!
//! These tests share a single management socket (OpenVPN allows one mgmt
//! client at a time). Run with `--test-threads=1` to avoid contention.
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

/// Respond to `>REMOTE:` with `Modify` to override the host and port.
///
/// The client should proceed to resolve/connect using the overridden values.
/// Since we redirect to the same server, the connection should still proceed.
#[tokio::test]
#[traced_test]
async fn remote_modify() {
    let mut framed = connect_and_auth(CLIENT_REMOTE_ADDR).await;
    eprintln!("=== authenticated to client-remote management ===");

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for >REMOTE: ===");

    let (host, _port, _protocol) = timeout(MSG_TIMEOUT, async {
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

    // Override with the same host but explicit port — connection should proceed.
    send_ok(
        &mut framed,
        OvpnCommand::Remote(RemoteAction::Modify {
            host: host.clone(),
            port: 1194,
        }),
        "",
    )
    .await;
    eprintln!("=== Remote(Modify {{ host={host}, port=1194 }}) sent ===");

    // Expect state transitions after the modified remote is used.
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
        "should observe state transitions after Remote(Modify)",
    );
    eprintln!("=== states after modify: {states:?} ===");

    framed.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== remote_modify conformance test complete ===");
}

/// Respond to `>REMOTE:` with `Skip` to skip the current entry.
///
/// With only one `--remote` configured, skipping should cause the client
/// to cycle back and re-query, or fail. Either way the codec must handle
/// it without panicking.
#[tokio::test]
#[traced_test]
async fn remote_skip() {
    let mut framed = connect_and_auth(CLIENT_REMOTE_ADDR).await;
    eprintln!("=== authenticated to client-remote management ===");

    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== hold released, waiting for >REMOTE: ===");

    // Wait for the first >REMOTE: notification.
    timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if matches!(msg, OvpnMessage::Notification(Notification::Remote { .. })) {
                return;
            }
        }
    })
    .await
    .expect("timed out waiting for >REMOTE: notification");

    // Skip the entry — OpenVPN should cycle to the next remote (or re-query).
    send_ok(&mut framed, OvpnCommand::Remote(RemoteAction::Skip), "").await;
    eprintln!("=== Remote(Skip) sent ===");

    // Collect whatever happens next — another >REMOTE:, state changes,
    // or the connection closing (OpenVPN may terminate after skip when
    // only one --remote entry is configured).
    let mut saw_remote_or_state = false;
    timeout(Duration::from_secs(5), async {
        use futures::StreamExt;
        while let Some(Ok(msg)) = framed.next().await {
            match msg {
                OvpnMessage::Notification(Notification::Remote { .. })
                | OvpnMessage::Notification(Notification::State { .. }) => {
                    saw_remote_or_state = true;
                }
                _ => {}
            }
        }
    })
    .await
    .ok();

    // After skip with a single --remote entry, OpenVPN may either re-query
    // (producing another >REMOTE: or state transition) or close the
    // connection. Both outcomes are valid codec behaviour.
    eprintln!("=== remote_skip: saw_remote_or_state={saw_remote_or_state} ===");

    let _ = framed.send(OvpnCommand::Exit).await;
}
