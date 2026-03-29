//! Stateful sequence tests for the OvpnCodec.
//!
//! These tests exercise the codec across multi-command sequences where
//! internal state (expected response kind, accumulation buffers) must
//! be correctly maintained between encode/decode cycles.

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

// --- Helpers ---

fn codec() -> OvpnCodec {
    OvpnCodec::new()
}

/// Encode a command, then feed response bytes and collect all decoded messages.
fn roundtrip(codec: &mut OvpnCodec, cmd: OvpnCommand, response: &str) -> Vec<OvpnMessage> {
    let mut enc_buf = BytesMut::new();
    codec.encode(cmd, &mut enc_buf).unwrap();
    let mut dec_buf = BytesMut::from(response);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut dec_buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

/// Feed raw bytes into the decoder without encoding a command first.
fn decode_raw(codec: &mut OvpnCodec, data: &str) -> Vec<OvpnMessage> {
    let mut buf = BytesMut::from(data);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

// ---  ---
// Multi-command sequences
// ---  ---

#[test]
fn pid_then_version_sequence() {
    let mut c = codec();

    // 1. pid → SUCCESS
    let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=1234\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("1234")));

    // 2. version → multi-line
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Version,
        "OpenVPN Version: OpenVPN 2.6.9\nManagement Interface Version: 5\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[test]
fn status_then_signal_then_status() {
    let mut c = codec();

    // 1. status v1 → multi-line
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Status(StatusFormat::V1),
        "TITLE,OpenVPN Statistics\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(_)));

    // 2. signal → SUCCESS
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Signal(Signal::SigUsr1),
        "SUCCESS: signal SIGUSR1 thrown\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    // 3. status v3 → multi-line again
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Status(StatusFormat::V3),
        "TITLE\ttab\tcol3\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 1));
}

#[test]
fn hold_query_then_hold_release_then_state_stream() {
    let mut c = codec();

    // hold → SUCCESS
    let msgs = roundtrip(&mut c, OvpnCommand::HoldQuery, "SUCCESS: hold=0\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("hold=0")));

    // hold release → SUCCESS
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::HoldRelease,
        "SUCCESS: hold release succeeded\n",
    );
    assert_eq!(msgs.len(), 1);

    // state all → multi-line
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::StateStream(StreamMode::All),
        "1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 1));
}

#[test]
fn notifications_between_commands_do_not_corrupt_state() {
    let mut c = codec();

    // 1. Send pid command
    let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=42\n");
    assert_eq!(msgs.len(), 1);

    // 2. Unsolicited notifications arrive between commands
    let msgs = decode_raw(
        &mut c,
        ">STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\n\
         >BYTECOUNT:1024,2048\n",
    );
    assert_eq!(msgs.len(), 2);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::State(..))
    ));
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));

    // 3. Next command still works correctly
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Version,
        "OpenVPN Version: 2.6.9\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 1));
}

#[test]
fn notification_interleaved_in_multiline_preserves_sequence() {
    let mut c = codec();

    // status v1 with a STATE notification arriving mid-response
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Status(StatusFormat::V1),
        "TITLE,OpenVPN Statistics\n\
         >STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\n\
         Updated,2024-03-21 12:00:00\n\
         END\n",
    );
    // Should get: notification first (emitted immediately), then multiline
    assert_eq!(msgs.len(), 2);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::State(..))
    ));
    assert!(matches!(&msgs[1], OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[test]
fn client_notification_between_two_commands() {
    let mut c = codec();

    // 1. pid
    let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=100\n");
    assert_eq!(msgs.len(), 1);

    // 2. CLIENT notification arrives unsolicited
    let msgs = decode_raw(
        &mut c,
        ">CLIENT:CONNECT,1,2\n\
         >CLIENT:ENV,common_name=alice\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Client {
            event: ClientEvent::Connect,
            cid: 1,
            kid: Some(2),
            ..
        })
    ));

    // 3. Next command still works
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Signal(Signal::SigHup),
        "SUCCESS: signal SIGHUP thrown\n",
    );
    assert_eq!(msgs.len(), 1);
}

#[test]
fn multiple_multiline_commands_in_sequence() {
    let mut c = codec();

    // help → multiline
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Help,
        "Management Interface Commands:\nhelp : show help\nstatus : show status\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 3));

    // status → multiline
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Status(StatusFormat::V2),
        "HEADER\tCLIENT_LIST\ndata row\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 2));

    // state (bare) → multiline
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::State,
        "1711000000,CONNECTED,SUCCESS,10.0.0.2,,,,,\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
}

#[test]
fn auth_sequence_password_then_username_then_auth_retry() {
    let mut c = codec();

    // Simulate: password prompt arrives, we authenticate
    let msgs = decode_raw(&mut c, ">PASSWORD:Need 'Auth' username/password\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedAuth {
            auth_type: AuthType::Auth,
        }))
    ));

    // username
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Username {
            auth_type: AuthType::Auth,
            value: "admin".into(),
        },
        "SUCCESS: username entered\n",
    );
    assert_eq!(msgs.len(), 1);

    // password
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "secret".into(),
        },
        "SUCCESS: password entered\n",
    );
    assert_eq!(msgs.len(), 1);

    // auth-retry
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::AuthRetry(AuthRetryMode::Interact),
        "SUCCESS: auth-retry set to interact\n",
    );
    assert_eq!(msgs.len(), 1);
}

#[test]
fn client_auth_then_client_deny_sequence() {
    let mut c = codec();

    // CLIENT:CONNECT arrives
    let msgs = decode_raw(
        &mut c,
        ">CLIENT:CONNECT,10,0\n\
         >CLIENT:ENV,common_name=bob\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);

    // Approve
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::ClientAuthNt { cid: 10, kid: 0 },
        "SUCCESS: client-auth-nt succeeded\n",
    );
    assert_eq!(msgs.len(), 1);

    // Another CLIENT:CONNECT
    let msgs = decode_raw(
        &mut c,
        ">CLIENT:CONNECT,11,0\n\
         >CLIENT:ENV,common_name=eve\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);

    // Deny
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::ClientDeny(ClientDeny {
            cid: 11,
            kid: 0,
            reason: "unauthorized".to_string(),
            client_reason: Some("access denied".to_string()),
        }),
        "SUCCESS: client-deny succeeded\n",
    );
    assert_eq!(msgs.len(), 1);
}

#[test]
fn error_response_does_not_corrupt_subsequent_commands() {
    let mut c = codec();

    // Command returns ERROR
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Signal(Signal::SigUsr2),
        "ERROR: signal not supported\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Error(_)));

    // Next command still works
    let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=99\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
}

#[test]
fn management_password_then_banner_then_commands() {
    let mut c = codec();

    // Management interface sends password prompt
    let msgs = decode_raw(&mut c, "ENTER PASSWORD:\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::PasswordPrompt));

    // Send management password
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::ManagementPassword("s3cret".into()),
        "SUCCESS: password is correct\n",
    );
    assert_eq!(msgs.len(), 1);

    // INFO banner
    let msgs = decode_raw(
        &mut c,
        ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Info(_)));

    // Normal commands work
    let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=42\n");
    assert_eq!(msgs.len(), 1);
}

#[test]
fn raw_multiline_command_then_normal_command() {
    let mut c = codec();

    // Raw multiline
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::RawMultiLine("some-custom-cmd".to_string()),
        "line1\nline2\nEND\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 2));

    // Normal command after
    let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=5\n");
    assert_eq!(msgs.len(), 1);
}

#[test]
fn stream_mode_on_off_produces_success() {
    let mut c = codec();

    // state on → SUCCESS
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::StateStream(StreamMode::On),
        "SUCCESS: real-time state notification set to ON\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    // state off → SUCCESS
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::StateStream(StreamMode::Off),
        "SUCCESS: real-time state notification set to OFF\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
}

#[test]
fn stream_mode_all_produces_multiline() {
    let mut c = codec();

    let msgs = roundtrip(
        &mut c,
        OvpnCommand::StateStream(StreamMode::All),
        "1711000000,CONNECTING,,,,,,\n\
         1711000001,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\n\
         END\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[test]
fn log_stream_recent_produces_multiline() {
    let mut c = codec();

    let msgs = roundtrip(
        &mut c,
        OvpnCommand::Log(StreamMode::Recent(5)),
        "1711000000,I,initialization complete\n\
         1711000001,D,debug info\n\
         END\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[test]
fn bytecount_enable_then_notifications_then_disable() {
    let mut c = codec();

    // Enable
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::ByteCount(5),
        "SUCCESS: bytecount interval changed\n",
    );
    assert_eq!(msgs.len(), 1);

    // Notifications arrive
    let msgs = decode_raw(
        &mut c,
        ">BYTECOUNT:100,200\n\
         >BYTECOUNT:300,400\n",
    );
    assert_eq!(msgs.len(), 2);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in: 100,
            bytes_out: 200
        })
    ));

    // Disable
    let msgs = roundtrip(
        &mut c,
        OvpnCommand::ByteCount(0),
        "SUCCESS: bytecount interval changed\n",
    );
    assert_eq!(msgs.len(), 1);
}

#[test]
fn exit_expects_no_response() {
    let mut c = codec();

    // Exit command — encode sets expected to NoResponse
    let mut enc_buf = BytesMut::new();
    c.encode(OvpnCommand::Exit, &mut enc_buf).unwrap();

    // Any subsequent line should be Unrecognized (NoResponse → no framing)
    let mut dec_buf = BytesMut::from("some trailing data\n");
    let msg = c.decode(&mut dec_buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Unrecognized { .. }));
}

#[test]
fn ten_sequential_pid_commands() {
    let mut c = codec();

    for i in 0..10 {
        let msgs = roundtrip(
            &mut c,
            OvpnCommand::Pid,
            &format!("SUCCESS: pid={}\n", 100 + i),
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
    }
}

#[test]
fn alternating_multiline_and_singleline_commands() {
    let mut c = codec();

    for _ in 0..5 {
        // Multi-line
        let msgs = roundtrip(
            &mut c,
            OvpnCommand::Status(StatusFormat::V1),
            "row1\nrow2\nEND\n",
        );
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::MultiLine(_)));

        // Single-line
        let msgs = roundtrip(&mut c, OvpnCommand::Pid, "SUCCESS: pid=42\n");
        assert_eq!(msgs.len(), 1);
        assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
    }
}
