//! Conformance tests for `>PASSWORD:` management notifications.
//!
//! Sent by OpenVPN when `--management-query-passwords` is enabled and
//! the client needs credentials. The server has `management-client-auth`,
//! so this test must also approve the client on the server side.
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_password
//! docker compose down
//! ```

#![cfg(feature = "conformance-tests")]

mod common;

use std::time::Duration;

use common::{connect_and_auth, recv_raw, send_ok, MGMT_PASSWORD, MSG_TIMEOUT};
use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::*;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::codec::Framed;
use tracing_test::traced_test;

const SERVER_ADDR: &str = "127.0.0.1:7506";
const CLIENT_PASSWORD_ADDR: &str = "127.0.0.1:7508";

/// The server has `management-client-auth`, so a background task
/// auto-approves the client on port 7506 while the main task handles
/// the password flow on port 7508.
#[tokio::test]
#[traced_test]
async fn password_need_auth() {
    // ── Set up server: connect (with retry), release hold, auto-approve ──
    let server_stream = timeout(Duration::from_secs(30), async {
        loop {
            match TcpStream::connect(SERVER_ADDR).await {
                Ok(stream) => return stream,
                Err(_) => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    })
    .await
    .expect("server management not reachable within 30s");
    let mut server = Framed::new(server_stream, OvpnCodec::new());

    // Auth to server management (same sequence as connect_and_auth but
    // on an already-connected stream from the retry loop).
    let msg = common::recv(&mut server).await;
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));
    server
        .send(OvpnCommand::ManagementPassword(MGMT_PASSWORD.into()))
        .await
        .unwrap();
    let msg = common::recv(&mut server).await;
    assert!(matches!(&msg, OvpnMessage::Success(s) if s.contains("password")));
    let msg = common::recv(&mut server).await;
    assert!(matches!(&msg, OvpnMessage::Info(_)));
    let msg = common::recv(&mut server).await;
    assert!(matches!(&msg, OvpnMessage::Notification(Notification::Hold { .. })));

    send_ok(&mut server, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== server hold released ===");

    // Auto-approve any CLIENT:CONNECT on the server.
    tokio::spawn(async move {
        loop {
            let msg = match timeout(Duration::from_secs(10), server.next()).await {
                Ok(Some(Ok(msg))) => msg,
                _ => return,
            };
            if let OvpnMessage::Notification(Notification::Client {
                event: ClientEvent::Connect,
                cid,
                kid: Some(kid),
                ..
            }) = msg
            {
                eprintln!("=== server: auto-approving CLIENT:CONNECT cid={cid} kid={kid} ===");
                server
                    .send(OvpnCommand::ClientAuthNt { cid, kid })
                    .await
                    .ok();
            }
        }
    });

    // ── Set up client: connect, release hold, wait for >PASSWORD: ───
    let mut framed = connect_and_auth(CLIENT_PASSWORD_ADDR).await;
    send_ok(&mut framed, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;
    eprintln!("=== client hold released, waiting for >PASSWORD: ===");

    let pw_notification = timeout(MSG_TIMEOUT, async {
        loop {
            let msg = recv_raw(&mut framed).await;
            if let OvpnMessage::Notification(Notification::Password(ref pw)) = msg {
                return pw.clone();
            }
        }
    })
    .await
    .expect("timed out waiting for >PASSWORD: notification");

    eprintln!("=== >PASSWORD: {pw_notification:?} ===");
    assert!(
        matches!(
            &pw_notification,
            PasswordNotification::NeedAuth { auth_type } if *auth_type == AuthType::Auth
        ),
        "expected NeedAuth with AuthType::Auth, got {pw_notification:?}",
    );

    framed
        .send(OvpnCommand::Username {
            auth_type: AuthType::Auth,
            value: Redacted::new("testuser"),
        })
        .await
        .unwrap();
    framed
        .send(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: Redacted::new("testpass"),
        })
        .await
        .unwrap();
    eprintln!("=== credentials supplied ===");

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
        "should observe state transitions after supplying credentials",
    );
    eprintln!("=== states after credentials: {states:?} ===");

    framed.send(OvpnCommand::Exit).await.unwrap();
    eprintln!("=== password conformance test complete ===");
}
