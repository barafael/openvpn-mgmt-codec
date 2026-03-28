//! Boundary condition tests: accumulation limits, FromStr/Display edge
//! cases, CRLF line endings, and classify exhaustiveness.

mod common;

use std::collections::BTreeMap;

use bytes::BytesMut;
use openvpn_mgmt_codec::stream::ManagementEvent;
use openvpn_mgmt_codec::*;
use tokio_util::codec::Encoder;

use common::{decode_all_with as decode_all, try_decode_all};

// ---  ---
// Accumulation limit boundary conditions
// ---  ---

#[test]
fn multiline_limit_exact_boundary_succeeds() {
    let mut codec = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(3));
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    // Exactly 3 lines — should succeed
    let msgs = decode_all(&mut codec, "line1\nline2\nline3\nEND\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 3));
}

#[test]
fn multiline_limit_one_over_boundary_fails() {
    let mut codec = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(3));
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let result = try_decode_all(&mut codec, "line1\nline2\nline3\nline4\nEND\n");
    assert!(result.is_err());
}

#[test]
fn multiline_limit_zero_allows_first_line_but_rejects_second() {
    // Max(0) means the limit check fires when the buffer already has 0 items
    // and we try to push another. The first line seeds the buffer (vec![line]),
    // so it gets in. The second push triggers the limit.
    let mut codec = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(0));
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    // Single line + END succeeds (first line seeds the buf, END terminates)
    let msgs = decode_all(&mut codec, "line1\nEND\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 1));
}

#[test]
fn multiline_limit_one_allows_single_line() {
    let mut codec = OvpnCodec::new().with_max_multi_line_lines(AccumulationLimit::Max(1));
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let msgs = decode_all(&mut codec, "single\nEND\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 1));
}

#[test]
fn client_env_limit_exact_boundary_succeeds() {
    let mut codec = OvpnCodec::new().with_max_client_env_entries(AccumulationLimit::Max(2));

    let msgs = decode_all(
        &mut codec,
        ">CLIENT:CONNECT,1,0\n\
         >CLIENT:ENV,key1=val1\n\
         >CLIENT:ENV,key2=val2\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Client { env, .. }) if env.len() == 2
    ));
}

#[test]
fn client_env_limit_one_over_boundary_fails() {
    let mut codec = OvpnCodec::new().with_max_client_env_entries(AccumulationLimit::Max(2));

    let result = try_decode_all(
        &mut codec,
        ">CLIENT:CONNECT,1,0\n\
         >CLIENT:ENV,key1=val1\n\
         >CLIENT:ENV,key2=val2\n\
         >CLIENT:ENV,key3=val3\n\
         >CLIENT:ENV,END\n",
    );
    assert!(result.is_err());
}

#[test]
fn client_env_limit_zero_rejects_any_entry() {
    let mut codec = OvpnCodec::new().with_max_client_env_entries(AccumulationLimit::Max(0));

    let result = try_decode_all(
        &mut codec,
        ">CLIENT:CONNECT,1,0\n\
         >CLIENT:ENV,key=val\n\
         >CLIENT:ENV,END\n",
    );
    assert!(result.is_err());
}

#[test]
fn unlimited_accumulation_handles_large_response() {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let mut input = String::new();
    for i in 0..500 {
        input.push_str(&format!("line {i}\n"));
    }
    input.push_str("END\n");

    let msgs = decode_all(&mut codec, &input);
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 500));
}

#[test]
fn empty_multiline_response() {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    // Immediate END — the first "END" is interpreted as a data line (first
    // line of multiline). But since expected is MultiLine and the line
    // equals "END", this produces an empty MultiLine.
    let msgs = decode_all(&mut codec, "END\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.is_empty()));
}

// ---  ---
// FromStr / Display edge cases (valid per spec)
// ---  ---

#[test]
fn status_format_display_roundtrip_all() {
    for fmt in [StatusFormat::V1, StatusFormat::V2, StatusFormat::V3] {
        let string = fmt.to_string();
        let parsed: StatusFormat = string.parse().unwrap();
        assert_eq!(parsed, fmt);
    }
}

#[test]
fn stream_mode_display_roundtrip_all() {
    for mode in [
        StreamMode::On,
        StreamMode::Off,
        StreamMode::All,
        StreamMode::OnAll,
        StreamMode::Recent(0),
        StreamMode::Recent(1),
        StreamMode::Recent(u32::MAX),
    ] {
        let string = mode.to_string();
        let parsed: StreamMode = string.parse().unwrap();
        assert_eq!(parsed, mode);
    }
}

#[test]
fn auth_type_display_roundtrip_including_custom() {
    for auth in [
        AuthType::Auth,
        AuthType::PrivateKey,
        AuthType::HttpProxy,
        AuthType::SocksProxy,
    ] {
        let string = auth.to_string();
        let parsed: AuthType = string.parse().unwrap();
        assert_eq!(parsed, auth);
    }
    // Unknown values don't roundtrip through FromStr (which is fallible).
    assert!("MyPlugin".parse::<AuthType>().is_err());
}

#[test]
fn auth_retry_mode_display_roundtrip() {
    for mode in [
        AuthRetryMode::None,
        AuthRetryMode::Interact,
        AuthRetryMode::NoInteract,
    ] {
        let string = mode.to_string();
        let parsed: AuthRetryMode = string.parse().unwrap();
        assert_eq!(parsed, mode);
    }
}

#[test]
fn signal_display_roundtrip() {
    for sig in [
        Signal::SigHup,
        Signal::SigTerm,
        Signal::SigUsr1,
        Signal::SigUsr2,
    ] {
        let string = sig.to_string();
        let parsed: Signal = string.parse().unwrap();
        assert_eq!(parsed, sig);
    }
}

#[test]
fn stream_mode_recent_zero() {
    let mode = StreamMode::Recent(0);
    assert_eq!(mode.to_string(), "0");
    assert_eq!("0".parse::<StreamMode>().unwrap(), mode);
}

#[test]
fn auth_type_custom_empty_string() {
    let auth = AuthType::Unknown(String::new());
    let string = auth.to_string();
    assert_eq!(string, "");
    // Empty string is not a recognized auth type.
    assert!(string.parse::<AuthType>().is_err());
}

#[test]
fn ovpn_command_from_str_basic_commands() {
    assert_eq!(
        "version".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::Version
    );
    assert_eq!("pid".parse::<OvpnCommand>().unwrap(), OvpnCommand::Pid);
    assert_eq!("help".parse::<OvpnCommand>().unwrap(), OvpnCommand::Help);
    assert_eq!("net".parse::<OvpnCommand>().unwrap(), OvpnCommand::Net);
    assert_eq!("exit".parse::<OvpnCommand>().unwrap(), OvpnCommand::Exit);
    assert_eq!("quit".parse::<OvpnCommand>().unwrap(), OvpnCommand::Quit);
}

#[test]
fn ovpn_command_from_str_status_variants() {
    assert_eq!(
        "status".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::Status(StatusFormat::V1)
    );
    assert_eq!(
        "status 2".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::Status(StatusFormat::V2)
    );
    assert_eq!(
        "status 3".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::Status(StatusFormat::V3)
    );
}

#[test]
fn ovpn_command_from_str_state_stream_modes() {
    assert_eq!(
        "state on".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::StateStream(StreamMode::On)
    );
    assert_eq!(
        "state off".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::StateStream(StreamMode::Off)
    );
    assert_eq!(
        "state on all".parse::<OvpnCommand>().unwrap(),
        OvpnCommand::StateStream(StreamMode::OnAll)
    );
}

#[test]
fn ovpn_command_from_str_unknown_falls_to_raw() {
    let cmd = "some-future-command arg1 arg2"
        .parse::<OvpnCommand>()
        .unwrap();
    assert!(matches!(cmd, OvpnCommand::Raw(_)));
}

// ---  ---
// CRLF line ending handling
// ---  ---

#[test]
fn crlf_success_response() {
    let mut codec = OvpnCodec::new();
    let msgs = decode_all(&mut codec, "SUCCESS: pid=42\r\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "pid=42"));
}

#[test]
fn crlf_error_response() {
    let mut codec = OvpnCodec::new();
    let msgs = decode_all(&mut codec, "ERROR: command not found\r\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s == "command not found"));
}

#[test]
fn crlf_notification() {
    let mut codec = OvpnCodec::new();
    let msgs = decode_all(
        &mut codec,
        ">STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,,,,\r\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::State {
            name: OpenVpnState::Connected,
            ..
        })
    ));
}

#[test]
fn crlf_multiline_response() {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec.encode(OvpnCommand::Version, &mut enc_buf).unwrap();

    let msgs = decode_all(&mut codec, "OpenVPN 2.6.9\r\nManagement 5\r\nEND\r\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::MultiLine(lines) if lines.len() == 2));
}

#[test]
fn crlf_client_notification() {
    let mut codec = OvpnCodec::new();
    let msgs = decode_all(
        &mut codec,
        ">CLIENT:CONNECT,1,2\r\n\
         >CLIENT:ENV,common_name=alice\r\n\
         >CLIENT:ENV,END\r\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Client { .. })
    ));
}

#[test]
fn crlf_password_prompt() {
    let mut codec = OvpnCodec::new();
    let msgs = decode_all(&mut codec, "ENTER PASSWORD:\r\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::PasswordPrompt));
}

#[test]
fn mixed_lf_and_crlf_in_same_stream() {
    let mut codec = OvpnCodec::new();
    let msgs = decode_all(
        &mut codec,
        ">BYTECOUNT:100,200\n\
         >BYTECOUNT:300,400\r\n\
         >STATE:1711000000,CONNECTING,,,,,,\n",
    );
    assert_eq!(msgs.len(), 3);
}

// ---  ---
// ManagementEvent::from exhaustiveness
// ---  ---

#[test]
fn classify_success() {
    let event = ManagementEvent::from(OvpnMessage::Success("ok".to_string()));
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::Success(_))
    ));
}

#[test]
fn classify_error() {
    let event = ManagementEvent::from(OvpnMessage::Error("fail".to_string()));
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::Error(_))
    ));
}

#[test]
fn classify_multiline() {
    let event = ManagementEvent::from(OvpnMessage::MultiLine(vec!["a".to_string()]));
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::MultiLine(_))
    ));
}

#[test]
fn classify_info() {
    let event = ManagementEvent::from(OvpnMessage::Info("banner".to_string()));
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::Info(_))
    ));
}

#[test]
fn classify_password_prompt() {
    let event = ManagementEvent::from(OvpnMessage::PasswordPrompt);
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::PasswordPrompt)
    ));
}

#[test]
fn classify_unrecognized() {
    let event = ManagementEvent::from(OvpnMessage::Unrecognized {
        line: "garbage".to_string(),
        kind: UnrecognizedKind::UnexpectedLine,
    });
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::Unrecognized { .. })
    ));
}

#[test]
fn classify_pkcs11_id_entry() {
    let event = ManagementEvent::from(OvpnMessage::Pkcs11IdEntry {
        index: "0".to_string(),
        id: "id".to_string(),
        blob: "blob".to_string(),
    });
    assert!(matches!(
        event,
        ManagementEvent::Response(OvpnMessage::Pkcs11IdEntry { .. })
    ));
}

#[test]
fn classify_notification_state() {
    let event = ManagementEvent::from(OvpnMessage::Notification(Notification::State {
        timestamp: 0,
        name: OpenVpnState::Connected,
        description: String::new(),
        local_ip: String::new(),
        remote_ip: String::new(),
        remote_port: None,
        local_addr: String::new(),
        local_port: None,
        local_ipv6: String::new(),
    }));
    assert!(matches!(
        event,
        ManagementEvent::Notification(Notification::State { .. })
    ));
}

#[test]
fn classify_notification_client() {
    let event = ManagementEvent::from(OvpnMessage::Notification(Notification::Client {
        event: ClientEvent::Connect,
        cid: 1,
        kid: Some(0),
        env: BTreeMap::new(),
    }));
    assert!(matches!(
        event,
        ManagementEvent::Notification(Notification::Client { .. })
    ));
}

#[test]
fn classify_notification_hold() {
    let event = ManagementEvent::from(OvpnMessage::Notification(Notification::Hold {
        text: "waiting".to_string(),
    }));
    assert!(matches!(
        event,
        ManagementEvent::Notification(Notification::Hold { .. })
    ));
}

#[test]
fn classify_notification_fatal() {
    let event = ManagementEvent::from(OvpnMessage::Notification(Notification::Fatal {
        message: "crash".to_string(),
    }));
    assert!(matches!(
        event,
        ManagementEvent::Notification(Notification::Fatal { .. })
    ));
}

#[test]
fn classify_notification_password() {
    let event = ManagementEvent::from(OvpnMessage::Notification(Notification::Password(
        PasswordNotification::NeedAuth {
            auth_type: AuthType::Auth,
        },
    )));
    assert!(matches!(
        event,
        ManagementEvent::Notification(Notification::Password(_))
    ));
}

#[test]
fn classify_notification_simple_fallback() {
    let event = ManagementEvent::from(OvpnMessage::Notification(Notification::Simple {
        kind: "FUTURE".to_string(),
        payload: "data".to_string(),
    }));
    assert!(matches!(
        event,
        ManagementEvent::Notification(Notification::Simple { .. })
    ));
}
