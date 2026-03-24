//! Wire-format conformance tests: verify that the codec's encoder
//! produces output that a real OpenVPN management interface accepts.
//!
//! These tests encode typed `OvpnCommand` values via the codec and send
//! the resulting wire bytes to OpenVPN. The goal is to catch spec
//! non-compliance in the encoder — e.g., incorrect quoting, escaping,
//! or field ordering that the codec's own parser wouldn't notice.
//!
//! # What this catches that unit tests don't
//!
//! The proptest `command_encode_parse_roundtrip` verifies that the
//! encoder and parser agree with *each other*. But both could be wrong
//! in the same way. These tests use OpenVPN's own `parse_line()` lexer
//! as the oracle:
//! - <https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c>
//! - <https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt>
//!
//! # Running
//!
//! ```sh
//! docker compose up -d --wait
//! cargo test -p openvpn-mgmt-codec --features conformance-tests \
//!     --test conformance_wire_format -- --test-threads=1
//! docker compose down
//! ```
//!
//! `--test-threads=1` because the management interface is single-client.

#![cfg(feature = "conformance-tests")]

mod common;

use common::{connect_and_auth, recv_response, send_ok};
use futures::SinkExt;
use openvpn_mgmt_codec::*;
use tracing_test::traced_test;

const BASIC_ADDR: &str = "127.0.0.1:7505";

// --- Helpers ---

/// Send a command and assert the response is NOT an ERROR containing
/// a parse/syntax complaint. Contextual errors like "command not
/// allowed" are fine — they prove the wire format was parsed correctly.
///
/// Returns the response for further assertions if needed.
async fn send_and_check_accepted(
    framed: &mut tokio_util::codec::Framed<tokio::net::TcpStream, OvpnCodec>,
    cmd: OvpnCommand,
    label: &str,
) -> OvpnMessage {
    framed.send(cmd).await.unwrap();
    let msg = recv_response(framed).await;
    // A syntax/parse error from OpenVPN means our wire format is wrong.
    // Contextual errors ("not in server mode") are acceptable — they
    // prove the command was parsed and dispatched, just not applicable.
    if let OvpnMessage::Error(ref e) = msg {
        assert!(
            !e.contains("unknown command") && !e.contains("parse") && !e.contains("Usage"),
            "{label}: encoder output rejected by OpenVPN: {e:?}",
        );
    }
    msg
}

// --- Tests ---

/// Commands that always produce SUCCESS or MultiLine on the basic
/// management-only instance. These are the simplest to validate.
#[tokio::test]
#[traced_test]
async fn basic_commands_accepted() {
    let mut framed = connect_and_auth(BASIC_ADDR).await;

    // Release hold first so state transitions work.
    send_ok(&mut framed, OvpnCommand::HoldRelease, "hold release").await;

    let cases: Vec<(OvpnCommand, &str)> = vec![
        (OvpnCommand::Version, "version"),
        (OvpnCommand::Help, "help"),
        (OvpnCommand::Pid, "pid"),
        (OvpnCommand::Net, "net"),
        (OvpnCommand::LoadStats, "load-stats"),
        (OvpnCommand::Status(StatusFormat::V1), "status 1"),
        (OvpnCommand::Status(StatusFormat::V2), "status 2"),
        (OvpnCommand::Status(StatusFormat::V3), "status 3"),
        (OvpnCommand::State, "state"),
        (OvpnCommand::StateStream(StreamMode::On), "state on"),
        (OvpnCommand::StateStream(StreamMode::Off), "state off"),
        (OvpnCommand::Log(StreamMode::On), "log on"),
        (OvpnCommand::Log(StreamMode::Off), "log off"),
        (OvpnCommand::Echo(StreamMode::On), "echo on"),
        (OvpnCommand::Echo(StreamMode::Off), "echo off"),
        (OvpnCommand::ByteCount(5), "bytecount 5"),
        (OvpnCommand::ByteCount(0), "bytecount 0"),
        (OvpnCommand::Verb(None), "verb"),
        (OvpnCommand::Verb(Some(4)), "verb 4"),
        (OvpnCommand::Mute(None), "mute"),
        (OvpnCommand::Mute(Some(10)), "mute 10"),
        (
            OvpnCommand::AuthRetry(AuthRetryMode::Interact),
            "auth-retry interact",
        ),
        (
            OvpnCommand::AuthRetry(AuthRetryMode::None),
            "auth-retry none",
        ),
        (OvpnCommand::ForgetPasswords, "forget-passwords"),
        (OvpnCommand::HoldOn, "hold on"),
        (OvpnCommand::HoldQuery, "hold"),
    ];

    for (cmd, label) in cases {
        let msg = send_and_check_accepted(&mut framed, cmd, label).await;
        assert!(
            matches!(&msg, OvpnMessage::Success(_) | OvpnMessage::MultiLine(_)),
            "{label}: expected Success or MultiLine, got {msg:?}",
        );
    }

    framed.send(OvpnCommand::Exit).await.unwrap();
}

/// Password commands with quoted, spaced auth types against a real
/// OpenVPN instance that is prompting for credentials.
///
/// This is the test that would have caught the original spec
/// non-compliance: the encoder produces `password "Auth" "testpass"`
/// and OpenVPN's `parse_line()` validates it with `streq()`.
///
/// Uses the `openvpn-client-password` container (port 7508) which has
/// `--management-query-passwords`, and the `openvpn-server` container
/// (port 7506) which auto-approves clients.
#[tokio::test]
#[traced_test]
async fn password_wire_format_accepted_by_openvpn() {
    use std::time::Duration;
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    use tokio_util::codec::Framed;

    const SERVER_ADDR: &str = "127.0.0.1:7506";
    const CLIENT_PASSWORD_ADDR: &str = "127.0.0.1:7508";

    // --- Set up server: connect, release hold, auto-approve ---
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

    let msg = common::recv(&mut server).await;
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));
    server
        .send(OvpnCommand::ManagementPassword(
            common::MGMT_PASSWORD.into(),
        ))
        .await
        .unwrap();
    let _auth_ok = common::recv(&mut server).await;
    let _info = common::recv(&mut server).await;
    let _hold = common::recv(&mut server).await;
    send_ok(&mut server, OvpnCommand::HoldRelease, "hold release").await;

    // Auto-approve CLIENT:CONNECT.
    tokio::spawn(async move {
        use futures::StreamExt;
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
                if server
                    .send(OvpnCommand::ClientAuthNt { cid, kid })
                    .await
                    .is_err()
                {
                    return;
                }
            }
        }
    });

    // --- Set up client: wait for >PASSWORD:Need 'Auth' ---
    let mut client = connect_and_auth(CLIENT_PASSWORD_ADDR).await;
    send_ok(&mut client, OvpnCommand::StateStream(StreamMode::On), "").await;
    send_ok(&mut client, OvpnCommand::HoldRelease, "hold release").await;

    let pw_notification = timeout(Duration::from_secs(30), async {
        loop {
            let msg = common::recv_raw(&mut client).await;
            if let OvpnMessage::Notification(Notification::Password(ref pw)) = msg {
                return pw.clone();
            }
        }
    })
    .await
    .expect("timed out waiting for >PASSWORD: notification");

    assert!(
        matches!(
            &pw_notification,
            PasswordNotification::NeedAuth { auth_type } if *auth_type == AuthType::Auth
        ),
        "expected NeedAuth/Auth, got {pw_notification:?}",
    );

    // --- The actual wire format test ---
    // Send username and password via the codec encoder. OpenVPN's
    // parse_line() will parse the quoted auth type and streq() will
    // validate it. If our quoting is wrong, OpenVPN responds with
    // ERROR.
    client
        .send(OvpnCommand::Username {
            auth_type: AuthType::Auth,
            value: Redacted::new("testuser"),
        })
        .await
        .unwrap();
    client
        .send(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: Redacted::new("testpass"),
        })
        .await
        .unwrap();

    // If the wire format was accepted, we should see state transitions
    // (AUTH, GET_CONFIG, etc.) rather than an ERROR response.
    let mut saw_state = false;
    timeout(Duration::from_secs(5), async {
        loop {
            let msg = common::recv_raw(&mut client).await;
            match msg {
                OvpnMessage::Error(e) => {
                    panic!("password wire format rejected by OpenVPN: {e}");
                }
                OvpnMessage::Notification(Notification::State { .. }) => {
                    saw_state = true;
                }
                _ => {}
            }
        }
    })
    .await
    .ok();

    assert!(
        saw_state,
        "should observe state transitions after credentials"
    );
    client.send(OvpnCommand::Exit).await.unwrap();
}
