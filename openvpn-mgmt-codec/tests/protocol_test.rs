//! Protocol-level test data derived from the OpenVPN management interface spec.
//!
//! These tests exercise realistic server output across the full protocol
//! surface: connection lifecycle, status formats, multi-line CLIENT
//! notifications with real env-var sets, interleaved notifications, edge
//! cases, and challenge/response sequences.
//!
//! Long protocol payloads live in `tests/fixtures/*.txt` and are pulled in
//! via `include_str!` so the test logic stays readable.

use bytes::BytesMut;
use openvpn_mgmt_codec::ClientEvent;
use openvpn_mgmt_codec::OpenVpnState;
use openvpn_mgmt_codec::PasswordNotification;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

// ── Helpers ──────────────────────────────────────────────────────────

fn encode_to_string(cmd: OvpnCommand) -> String {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf).unwrap();
    String::from_utf8(buf.to_vec()).unwrap()
}

fn decode_all(input: &str) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::from(input);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

fn encode_then_decode(cmd: OvpnCommand, response: &str) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec.encode(cmd, &mut enc_buf).unwrap();
    let mut dec_buf = BytesMut::from(response);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut dec_buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

// ═══════════════════════════════════════════════════════════════════════
// Connection lifecycle
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn connection_banner() {
    let msgs =
        decode_all(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Info(s) if s.contains("Version 5")
    ));
}

#[test]
fn full_state_transition_sequence() {
    let input = include_str!("fixtures/state_transitions.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 7);

    match &msgs[0] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            ..
        }) => {
            assert_eq!(*timestamp, 1711000000);
            assert_eq!(*name, OpenVpnState::Connecting);
            assert_eq!(description, "");
        }
        other => panic!("expected STATE notification, got: {other:?}"),
    }
    match &msgs[6] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            remote_port,
            ..
        }) => {
            assert_eq!(*timestamp, 1711000006);
            assert_eq!(*name, OpenVpnState::Connected);
            assert_eq!(description, "SUCCESS");
            assert_eq!(local_ip, "10.8.0.6");
            assert_eq!(remote_ip, "198.51.100.1");
            assert_eq!(remote_port, "1194");
        }
        other => panic!("expected STATE notification, got: {other:?}"),
    }
}

#[test]
fn reconnecting_and_exiting_states() {
    let input = "\
        >STATE:1711000010,RECONNECTING,SIGUSR1,,,,,\n\
        >STATE:1711000011,CONNECTING,,,,,,\n\
        >STATE:1711000050,EXITING,SIGTERM,,,,,\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 3);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            ..
        }) => {
            assert_eq!(*timestamp, 1711000010);
            assert_eq!(*name, OpenVpnState::Reconnecting);
            assert_eq!(description, "SIGUSR1");
        }
        other => panic!("unexpected: {other:?}"),
    }
    match &msgs[2] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            ..
        }) => {
            assert_eq!(*timestamp, 1711000050);
            assert_eq!(*name, OpenVpnState::Exiting);
            assert_eq!(description, "SIGTERM");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Status output formats (V1, V2, V3)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn status_v1_server_with_clients() {
    let response = include_str!("fixtures/status_v1_server.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines[0], "OpenVPN CLIENT LIST");
            assert!(lines.iter().any(|l| l.contains("client1")));
            assert!(lines.iter().any(|l| l.contains("client2")));
            assert!(lines.iter().any(|l| l.contains("ROUTING TABLE")));
            assert!(lines.iter().any(|l| l.contains("GLOBAL STATS")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v2_with_headers() {
    let response = include_str!("fixtures/status_v2.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V2), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines[0].starts_with("HEADER,CLIENT_LIST"));
            assert!(lines.iter().any(|l| l.starts_with("CLIENT_LIST,client1")));
            assert!(lines.iter().any(|l| l.starts_with("ROUTING_TABLE,")));
            assert!(lines.iter().any(|l| l.starts_with("GLOBAL_STATS,")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v3_tab_delimited() {
    let response = include_str!("fixtures/status_v3.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V3), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines[0].starts_with("TITLE\t"));
            assert!(lines[1].starts_with("TIME\t"));
            for line in lines {
                assert!(
                    line.contains('\t'),
                    "V3 line should be tab-delimited: {line}"
                );
            }
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v1_client_mode() {
    let response = include_str!("fixtures/status_v1_client.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines[0], "OpenVPN STATISTICS");
            assert!(lines.iter().any(|l| l.starts_with("TUN/TAP read bytes")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Version and help output
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn version_response() {
    let response = include_str!("fixtures/version.txt");
    let msgs = encode_then_decode(OvpnCommand::Version, response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
            assert!(lines[0].contains("OpenVPN Version:"));
            assert!(lines[1].contains("Management Interface Version: 5"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn help_response() {
    let response = include_str!("fixtures/help.txt");
    let msgs = encode_then_decode(OvpnCommand::Help, response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines.len() > 20, "help output should list many commands");
            assert!(lines[0].contains("Management Interface"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Bytecount notifications
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn bytecount_client_mode() {
    let msgs = decode_all(">BYTECOUNT:256789,128456\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*bytes_in, 256789);
            assert_eq!(*bytes_out, 128456);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bytecount_cli_server_mode() {
    let msgs = decode_all(">BYTECOUNT_CLI:3,1548576,984320\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*cid, 3);
            assert_eq!(*bytes_in, 1548576);
            assert_eq!(*bytes_out, 984320);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bytecount_enable_disable_roundtrip() {
    assert_eq!(encode_to_string(OvpnCommand::ByteCount(5)), "bytecount 5\n");
    assert_eq!(encode_to_string(OvpnCommand::ByteCount(0)), "bytecount 0\n");
}

// ═══════════════════════════════════════════════════════════════════════
// Log notifications
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn log_notifications_all_flags() {
    let input = include_str!("fixtures/log_all_flags.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 5);

    let levels: Vec<LogLevel> = msgs
        .iter()
        .map(|m| match m {
            OvpnMessage::Notification(Notification::Log { level, .. }) => level.clone(),
            other => panic!("unexpected: {other:?}"),
        })
        .collect();
    assert_eq!(
        levels,
        vec![
            LogLevel::Info,
            LogLevel::Debug,
            LogLevel::Warning,
            LogLevel::NonFatal,
            LogLevel::Fatal,
        ]
    );
}

#[test]
fn log_history_dump() {
    let response = "\
1711000000,I,OpenVPN 2.6.8 started\n\
1711000001,I,Initialization Sequence Completed\n\
END\n";
    let msgs = encode_then_decode(OvpnCommand::Log(StreamMode::All), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn log_recent_n() {
    let response = "\
1711000005,I,recent line 1\n\
1711000006,I,recent line 2\n\
1711000007,I,recent line 3\n\
END\n";
    let msgs = encode_then_decode(OvpnCommand::Log(StreamMode::Recent(3)), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 3);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// State history and streaming
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn state_history_on_all() {
    let response = include_str!("fixtures/state_history.txt");
    let msgs = encode_then_decode(OvpnCommand::StateStream(StreamMode::OnAll), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 4);
            assert!(lines.last().unwrap().contains("CONNECTED"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn state_stream_on_off() {
    let msgs = encode_then_decode(
        OvpnCommand::StateStream(StreamMode::On),
        "SUCCESS: real-time state notification set to ON\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("ON")));

    let msgs = encode_then_decode(
        OvpnCommand::StateStream(StreamMode::Off),
        "SUCCESS: real-time state notification set to OFF\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("OFF")));
}

// ═══════════════════════════════════════════════════════════════════════
// CLIENT notifications — full env-var sets from the spec
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn client_connect_full_env() {
    let input = include_str!("fixtures/client_connect_full_env.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            assert_eq!(*event, ClientEvent::Connect);
            assert_eq!(*cid, 0);
            assert_eq!(*kid, Some(1));
            assert_eq!(env.len(), 19);
            assert_eq!(env[0], ("untrusted_ip".into(), "203.0.113.50".into()));
            assert_eq!(env[2], ("common_name".into(), "client1.example.com".into()));
            assert_eq!(env[3], ("username".into(), "jdoe".into()));
            let ciphers = env.iter().find(|(k, _)| k == "IV_CIPHERS").unwrap();
            assert_eq!(ciphers.1, "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn client_reauth() {
    let input = include_str!("fixtures/client_reauth.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            assert_eq!(*event, ClientEvent::Reauth);
            assert_eq!(*cid, 0);
            assert_eq!(*kid, Some(2));
            assert_eq!(env.len(), 3);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn client_established() {
    let input = include_str!("fixtures/client_established.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            assert_eq!(*event, ClientEvent::Established);
            assert_eq!(*cid, 0);
            assert_eq!(*kid, None);
            assert_eq!(env.len(), 3);
            let pool_ip = env
                .iter()
                .find(|(k, _)| k == "ifconfig_pool_remote_ip")
                .unwrap();
            assert_eq!(pool_ip.1, "10.8.0.6");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn client_disconnect_with_stats() {
    let input = include_str!("fixtures/client_disconnect.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            assert_eq!(*event, ClientEvent::Disconnect);
            assert_eq!(*cid, 5);
            assert_eq!(*kid, None);
            assert_eq!(env.len(), 5);
            let duration = env.iter().find(|(k, _)| k == "time_duration").unwrap();
            assert_eq!(duration.1, "18432");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn client_address_notification() {
    let msgs = decode_all(">CLIENT:ADDRESS,7,10.8.0.14,1\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ClientAddress { cid, addr, primary }) => {
            assert_eq!(*cid, 7);
            assert_eq!(addr, "10.8.0.14");
            assert!(*primary);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn multiple_client_events_sequential() {
    let input = include_str!("fixtures/client_connect_sequential.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 2);
    match (&msgs[0], &msgs[1]) {
        (
            OvpnMessage::Notification(Notification::Client {
                cid: cid0,
                env: env0,
                ..
            }),
            OvpnMessage::Notification(Notification::Client {
                cid: cid1,
                env: env1,
                ..
            }),
        ) => {
            assert_eq!(*cid0, 0);
            assert_eq!(env0[0].1, "alice");
            assert_eq!(*cid1, 1);
            assert_eq!(env1[0].1, "bob");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Password / auth prompts
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn password_need_auth() {
    let msgs = decode_all(">PASSWORD:Need 'Auth' username/password\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedAuth {
            auth_type,
        })) => {
            assert_eq!(*auth_type, AuthType::Auth);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_need_private_key() {
    let msgs = decode_all(">PASSWORD:Need 'Private Key' password\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedPassword {
            auth_type,
        })) => {
            assert_eq!(*auth_type, AuthType::PrivateKey);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_verification_failed() {
    let msgs = decode_all(">PASSWORD:Verification Failed: 'Auth'\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::VerificationFailed { auth_type },
        )) => {
            assert_eq!(*auth_type, AuthType::Auth);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_verification_failed_private_key() {
    let msgs = decode_all(">PASSWORD:Verification Failed: 'Private Key'\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::VerificationFailed { auth_type },
        )) => {
            assert_eq!(*auth_type, AuthType::PrivateKey);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn challenge_response_dynamic_crv1() {
    let msgs = decode_all(
        ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:bXlzdGF0ZQ==:dXNlcg==:Enter PIN']\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::DynamicChallenge {
                flags,
                state_id,
                username_b64,
                challenge,
            },
        )) => {
            assert_eq!(flags, "R,E");
            assert_eq!(state_id, "bXlzdGF0ZQ==");
            assert_eq!(username_b64, "dXNlcg==");
            assert_eq!(challenge, "Enter PIN");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn challenge_response_static_scrv1() {
    let msgs =
        decode_all(">PASSWORD:Need 'Auth' username/password SC:1,Please enter your OTP token\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::StaticChallenge {
                echo, challenge, ..
            },
        )) => {
            assert!(*echo);
            assert_eq!(challenge, "Please enter your OTP token");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// HOLD notifications
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn hold_waiting() {
    let msgs = decode_all(">HOLD:Waiting for hold release:10\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Hold { text }) => {
            assert!(text.contains("Waiting for hold release"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// ECHO notifications
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn echo_notification() {
    let msgs = decode_all(">ECHO:1711000000,my-custom-directive value123\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Echo { timestamp, param }) => {
            assert_eq!(*timestamp, 1711000000);
            assert!(param.contains("my-custom-directive"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn echo_history_dump() {
    let response = "\
1711000000,echo-param-1\n\
1711000001,echo-param-2\n\
END\n";
    let msgs = encode_then_decode(OvpnCommand::Echo(StreamMode::All), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// FATAL / NEED-OK / NEED-STR / RSA_SIGN / REMOTE / PROXY notifications
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn fatal_notification() {
    let msgs = decode_all(
        ">FATAL:Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Fatal { message }) => {
            assert!(message.contains("TUN/TAP"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn need_ok_notification() {
    let msgs = decode_all(
        ">NEED-OK:Need 'token-insertion-request' confirmation MSG:Please insert your hardware token\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::NeedOk { name, message }) => {
            assert_eq!(name, "token-insertion-request");
            assert!(message.contains("hardware token"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn need_str_notification() {
    let msgs = decode_all(">NEED-STR:Need 'profile-name' input MSG:Enter your profile name\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::NeedStr { name, message }) => {
            assert_eq!(name, "profile-name");
            assert_eq!(message, "Enter your profile name");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn rsa_sign_notification() {
    let msgs = decode_all(">RSA_SIGN:dGhlIGRhdGEgdG8gc2lnbg==\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::RsaSign { data }) => {
            assert_eq!(data, "dGhlIGRhdGEgdG8gc2lnbg==");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn remote_notification() {
    let msgs = decode_all(">REMOTE:vpn.example.com,1194,udp\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Remote {
            host,
            port,
            protocol,
        }) => {
            assert_eq!(host, "vpn.example.com");
            assert_eq!(*port, 1194);
            assert_eq!(*protocol, TransportProtocol::Udp);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn proxy_notification() {
    let msgs = decode_all(">PROXY:1,udp,vpn.example.com\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Proxy {
            index,
            proxy_type,
            host,
        }) => {
            assert_eq!(*index, 1);
            assert_eq!(proxy_type, "udp");
            assert_eq!(host, "vpn.example.com");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Encoder roundtrips for all command variants
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn encode_all_simple_commands() {
    assert_eq!(encode_to_string(OvpnCommand::State), "state\n");
    assert_eq!(encode_to_string(OvpnCommand::Version), "version\n");
    assert_eq!(encode_to_string(OvpnCommand::Pid), "pid\n");
    assert_eq!(encode_to_string(OvpnCommand::Help), "help\n");
    assert_eq!(encode_to_string(OvpnCommand::Net), "net\n");
    assert_eq!(encode_to_string(OvpnCommand::Exit), "exit\n");
    assert_eq!(encode_to_string(OvpnCommand::Quit), "quit\n");
    assert_eq!(
        encode_to_string(OvpnCommand::ForgetPasswords),
        "forget-passwords\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::Pkcs11IdCount),
        "pkcs11-id-count\n"
    );
}

#[test]
fn encode_verb_get_and_set() {
    assert_eq!(encode_to_string(OvpnCommand::Verb(None)), "verb\n");
    assert_eq!(encode_to_string(OvpnCommand::Verb(Some(0))), "verb 0\n");
    assert_eq!(encode_to_string(OvpnCommand::Verb(Some(4))), "verb 4\n");
    assert_eq!(encode_to_string(OvpnCommand::Verb(Some(15))), "verb 15\n");
}

#[test]
fn encode_mute_get_and_set() {
    assert_eq!(encode_to_string(OvpnCommand::Mute(None)), "mute\n");
    assert_eq!(encode_to_string(OvpnCommand::Mute(Some(0))), "mute 0\n");
    assert_eq!(encode_to_string(OvpnCommand::Mute(Some(40))), "mute 40\n");
}

#[test]
fn encode_all_signals() {
    assert_eq!(
        encode_to_string(OvpnCommand::Signal(Signal::SigHup)),
        "signal SIGHUP\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::Signal(Signal::SigTerm)),
        "signal SIGTERM\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::Signal(Signal::SigUsr1)),
        "signal SIGUSR1\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::Signal(Signal::SigUsr2)),
        "signal SIGUSR2\n"
    );
}

#[test]
fn encode_all_hold_variants() {
    assert_eq!(encode_to_string(OvpnCommand::HoldQuery), "hold\n");
    assert_eq!(encode_to_string(OvpnCommand::HoldOn), "hold on\n");
    assert_eq!(encode_to_string(OvpnCommand::HoldOff), "hold off\n");
    assert_eq!(encode_to_string(OvpnCommand::HoldRelease), "hold release\n");
}

#[test]
fn encode_all_stream_modes() {
    for (mode, expected) in [
        (StreamMode::On, "on"),
        (StreamMode::Off, "off"),
        (StreamMode::All, "all"),
        (StreamMode::OnAll, "on all"),
        (StreamMode::Recent(20), "20"),
    ] {
        assert_eq!(
            encode_to_string(OvpnCommand::Log(mode.clone())),
            format!("log {expected}\n")
        );
    }
}

#[test]
fn encode_kill_by_common_name() {
    assert_eq!(
        encode_to_string(OvpnCommand::Kill(KillTarget::CommonName(
            "Test-Client".into()
        ))),
        "kill Test-Client\n"
    );
}

#[test]
fn encode_kill_by_address() {
    assert_eq!(
        encode_to_string(OvpnCommand::Kill(KillTarget::Address {
            protocol: "tcp".into(),
            ip: "203.0.113.10".into(),
            port: 52841,
        })),
        "kill tcp:203.0.113.10:52841\n"
    );
}

#[test]
fn encode_auth_retry_modes() {
    assert_eq!(
        encode_to_string(OvpnCommand::AuthRetry(AuthRetryMode::None)),
        "auth-retry none\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::AuthRetry(AuthRetryMode::Interact)),
        "auth-retry interact\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::AuthRetry(AuthRetryMode::NoInteract)),
        "auth-retry nointeract\n"
    );
}

#[test]
fn encode_username() {
    let wire = encode_to_string(OvpnCommand::Username {
        auth_type: AuthType::Auth,
        value: "jdoe".into(),
    });
    assert_eq!(wire, "username \"Auth\" \"jdoe\"\n");
}

#[test]
fn encode_username_with_special_chars() {
    let wire = encode_to_string(OvpnCommand::Username {
        auth_type: AuthType::Auth,
        value: "user \"name\\here".into(),
    });
    assert_eq!(wire, "username \"Auth\" \"user \\\"name\\\\here\"\n");
}

#[test]
fn encode_pkcs11_id_get() {
    assert_eq!(
        encode_to_string(OvpnCommand::Pkcs11IdGet(0)),
        "pkcs11-id-get 0\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::Pkcs11IdGet(3)),
        "pkcs11-id-get 3\n"
    );
}

#[test]
fn encode_client_auth_nt() {
    assert_eq!(
        encode_to_string(OvpnCommand::ClientAuthNt { cid: 0, kid: 1 }),
        "client-auth-nt 0 1\n"
    );
}

#[test]
fn encode_client_deny_no_client_reason() {
    let wire = encode_to_string(OvpnCommand::ClientDeny {
        cid: 3,
        kid: 0,
        reason: "policy violation".into(),
        client_reason: None,
    });
    assert_eq!(wire, "client-deny 3 0 \"policy violation\"\n");
}

#[test]
fn encode_client_kill() {
    assert_eq!(
        encode_to_string(OvpnCommand::ClientKill {
            cid: 42,
            message: None
        }),
        "client-kill 42\n"
    );
}

#[test]
fn encode_remote_accept_and_skip() {
    assert_eq!(
        encode_to_string(OvpnCommand::Remote(RemoteAction::Accept)),
        "remote ACCEPT\n"
    );
    assert_eq!(
        encode_to_string(OvpnCommand::Remote(RemoteAction::Skip)),
        "remote SKIP\n"
    );
}

#[test]
fn encode_proxy_socks() {
    assert_eq!(
        encode_to_string(OvpnCommand::Proxy(ProxyAction::Socks {
            host: "socks.local".into(),
            port: 1080,
        })),
        "proxy SOCKS socks.local 1080\n"
    );
}

#[test]
fn encode_proxy_none() {
    assert_eq!(
        encode_to_string(OvpnCommand::Proxy(ProxyAction::None)),
        "proxy NONE\n"
    );
}

#[test]
fn encode_proxy_http_without_nct() {
    assert_eq!(
        encode_to_string(OvpnCommand::Proxy(ProxyAction::Http {
            host: "proxy.corp".into(),
            port: 3128,
            non_cleartext_only: false,
        })),
        "proxy HTTP proxy.corp 3128\n"
    );
}

#[test]
fn encode_raw_command() {
    assert_eq!(
        encode_to_string(OvpnCommand::Raw("custom-command arg1 arg2".into())),
        "custom-command arg1 arg2\n"
    );
}

#[test]
fn encode_needstr_with_spaces() {
    let wire = encode_to_string(OvpnCommand::NeedStr {
        name: "profile".into(),
        value: "My VPN Profile".into(),
    });
    assert_eq!(wire, "needstr profile \"My VPN Profile\"\n");
}

#[test]
fn encode_needok_cancel() {
    let wire = encode_to_string(OvpnCommand::NeedOk {
        name: "token-insertion-request".into(),
        response: NeedOkResponse::Cancel,
    });
    assert_eq!(wire, "needok token-insertion-request cancel\n");
}

// ═══════════════════════════════════════════════════════════════════════
// SUCCESS / ERROR responses for various commands
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn success_responses() {
    let msgs = encode_then_decode(OvpnCommand::Pid, "SUCCESS: pid=28456\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "pid=28456"));

    let msgs = encode_then_decode(
        OvpnCommand::Signal(Signal::SigUsr2),
        "SUCCESS: signal SIGUSR2 thrown\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("SIGUSR2")));

    let msgs = encode_then_decode(
        OvpnCommand::ByteCount(5),
        "SUCCESS: bytecount interval changed\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    let msgs = encode_then_decode(
        OvpnCommand::ForgetPasswords,
        "SUCCESS: Passwords were forgotten\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("forgotten")));

    let msgs = encode_then_decode(
        OvpnCommand::HoldRelease,
        "SUCCESS: hold release succeeded\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    let msgs = encode_then_decode(
        OvpnCommand::ClientAuthNt { cid: 0, kid: 1 },
        "SUCCESS: client-auth-nt command succeeded\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    let msgs = encode_then_decode(
        OvpnCommand::ClientDeny {
            cid: 0,
            kid: 1,
            reason: "denied".into(),
            client_reason: None,
        },
        "SUCCESS: client-deny command succeeded\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    let msgs = encode_then_decode(
        OvpnCommand::ClientKill {
            cid: 5,
            message: None,
        },
        "SUCCESS: client-kill command succeeded\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    let msgs = encode_then_decode(
        OvpnCommand::Kill(KillTarget::CommonName("test".into())),
        "SUCCESS: common name 'test' found, 1 client(s) killed\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("killed")));
}

#[test]
fn error_responses() {
    let msgs = encode_then_decode(
        OvpnCommand::Raw("bogus".into()),
        "ERROR: unknown command, enter 'help' for more options\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("unknown command")));

    let msgs = encode_then_decode(
        OvpnCommand::Kill(KillTarget::CommonName("nonexistent".into())),
        "ERROR: common name 'nonexistent' not found\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("not found")));

    let msgs = encode_then_decode(
        OvpnCommand::ClientDeny {
            cid: 999,
            kid: 0,
            reason: "denied".into(),
            client_reason: None,
        },
        "ERROR: client-deny command failed\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(_)));

    let msgs = encode_then_decode(
        OvpnCommand::AuthRetry(AuthRetryMode::Interact),
        "ERROR: auth-retry can only be changed when connected to a management interface client\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(_)));
}

// ═══════════════════════════════════════════════════════════════════════
// Edge cases and interleaving
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn crlf_line_endings() {
    let msgs = decode_all(
        ">INFO:OpenVPN Management Interface Version 5\r\n\
                           SUCCESS: pid=1234\r\n",
    );
    assert_eq!(msgs.len(), 2);
    assert!(matches!(&msgs[0], OvpnMessage::Info(s) if s.contains("Version 5")));
    assert!(matches!(&msgs[1], OvpnMessage::Success(s) if s == "pid=1234"));
}

/// A real-time `>STATE:` notification injected mid-status response. The spec
/// only guarantees atomicity for `>CLIENT:` notifications — other real-time
/// messages can arrive during multi-line command responses. The codec must
/// emit them immediately without breaking the accumulation.
#[test]
fn notification_interleaved_in_multiline_status() {
    let response = include_str!("fixtures/status_interleaved.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), response);
    assert_eq!(msgs.len(), 2);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::Connected
    ));
    match &msgs[1] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 4);
            assert!(!lines.iter().any(|l| l.contains(">STATE:")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bytecount_interleaved_in_version_response() {
    let msgs = encode_then_decode(
        OvpnCommand::Version,
        "OpenVPN Version: OpenVPN 2.6.8\n\
         >BYTECOUNT:500000,300000\n\
         Management Interface Version: 5\n\
         END\n",
    );
    assert_eq!(msgs.len(), 2);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::ByteCount { bytes_in, bytes_out })
            if *bytes_in == 500000 && *bytes_out == 300000
    ));
    match &msgs[1] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn multiple_notifications_before_any_command() {
    let input = "\
>INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n\
>HOLD:Waiting for hold release:0\n\
>STATE:1711000000,CONNECTING,,,,,,\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 3);
    assert!(matches!(&msgs[0], OvpnMessage::Info(_)));
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::Hold { text })
            if text.contains("Waiting for hold release")
    ));
    assert!(matches!(
        &msgs[2],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::Connecting
    ));
}

#[test]
fn env_value_containing_equals() {
    let input = "\
>CLIENT:CONNECT,0,1\n\
>CLIENT:ENV,tls_digest_sha256_0=aa:bb:cc=dd\n\
>CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env[0].0, "tls_digest_sha256_0");
            assert_eq!(env[0].1, "aa:bb:cc=dd");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn env_key_with_no_value() {
    let input = "\
>CLIENT:CONNECT,0,1\n\
>CLIENT:ENV,empty_key\n\
>CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env[0].0, "empty_key");
            assert_eq!(env[0].1, "");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn empty_success_and_error() {
    let msgs = decode_all("SUCCESS:\nERROR:\n");
    assert_eq!(msgs.len(), 2);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.is_empty()));
    assert!(matches!(&msgs[1], OvpnMessage::Error(s) if s.is_empty()));
}

#[test]
fn hold_query_returns_one() {
    let msgs = encode_then_decode(OvpnCommand::HoldQuery, "SUCCESS: hold=1\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "hold=1"));
}

#[test]
fn pkcs11_id_get_parsed() {
    let msgs = encode_then_decode(
        OvpnCommand::Pkcs11IdGet(0),
        ">PKCS11ID-ENTRY:'0', ID:'MY_ID', BLOB:'MY_BLOB'\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Pkcs11IdEntry { index, id, blob } => {
            assert_eq!(index, "0");
            assert_eq!(id, "MY_ID");
            assert_eq!(blob, "MY_BLOB");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn pkcs11_id_get_malformed_falls_back() {
    // If the format doesn't match, fall back to Unrecognized
    let msgs = encode_then_decode(OvpnCommand::Pkcs11IdGet(0), "some unexpected response\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Unrecognized { .. }));
}

#[test]
fn pkcs11_id_count_success() {
    let msgs = encode_then_decode(OvpnCommand::Pkcs11IdCount, "SUCCESS: 2\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "2"));
}

// ═══════════════════════════════════════════════════════════════════════
// Realistic multi-command session simulation
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn full_session_sequence() {
    let mut codec = OvpnCodec::new();

    // 1. Banner arrives.
    let mut buf = BytesMut::from(
        ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Info(_)));

    // HOLD notification arrives.
    buf.extend_from_slice(b">HOLD:Waiting for hold release:0\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        msg,
        OvpnMessage::Notification(Notification::Hold { .. })
    ));

    // 2. Send hold release command.
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::HoldRelease, &mut enc_buf)
        .unwrap();
    assert_eq!(&enc_buf[..], b"hold release\n");

    // Receive SUCCESS for hold release.
    buf.extend_from_slice(b"SUCCESS: hold release succeeded\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // 3. State transitions arrive as real-time notifications.
    buf.extend_from_slice(b">STATE:1711000000,CONNECTING,,,,,,\n");
    buf.extend_from_slice(b">STATE:1711000006,CONNECTED,SUCCESS,10.8.0.6,198.51.100.1,1194,,\n");
    let msg1 = codec.decode(&mut buf).unwrap().unwrap();
    let msg2 = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        msg1,
        OvpnMessage::Notification(Notification::State { .. })
    ));
    assert!(matches!(
        msg2,
        OvpnMessage::Notification(Notification::State { .. })
    ));

    // 4. Send status query.
    enc_buf.clear();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    // 5. Receive status multi-line response.
    buf.extend_from_slice(
        b"OpenVPN CLIENT LIST\n\
          Updated,2024-03-21 14:30:00\n\
          END\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match msg {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0], "OpenVPN CLIENT LIST");
        }
        other => panic!("unexpected: {other:?}"),
    }

    assert!(buf.is_empty());
}

#[test]
fn server_mode_client_auth_session() {
    let mut codec = OvpnCodec::new();

    // 1. CLIENT:CONNECT with env.
    let mut buf = BytesMut::from(
        ">CLIENT:CONNECT,0,1\n\
         >CLIENT:ENV,untrusted_ip=203.0.113.50\n\
         >CLIENT:ENV,common_name=alice\n\
         >CLIENT:ENV,END\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match &msg {
        OvpnMessage::Notification(Notification::Client { event, .. }) => {
            assert_eq!(*event, ClientEvent::Connect);
        }
        other => panic!("unexpected: {other:?}"),
    }

    // 2. Authorize the client with config push.
    let mut enc_buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::ClientAuth {
                cid: 0,
                kid: 1,
                config_lines: vec![
                    "push \"route 10.0.0.0 255.255.0.0\"".into(),
                    "push \"dhcp-option DNS 10.0.0.1\"".into(),
                ],
            },
            &mut enc_buf,
        )
        .unwrap();

    buf.extend_from_slice(b"SUCCESS: client-auth command succeeded\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // 3. CLIENT:ESTABLISHED notification.
    buf.extend_from_slice(
        b">CLIENT:ESTABLISHED,0\n\
          >CLIENT:ENV,common_name=alice\n\
          >CLIENT:ENV,ifconfig_pool_remote_ip=10.8.0.6\n\
          >CLIENT:ENV,END\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match &msg {
        OvpnMessage::Notification(Notification::Client { event, .. }) => {
            assert_eq!(*event, ClientEvent::Established);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Incremental / partial decode (data arriving in chunks)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn partial_line_buffering() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();

    buf.extend_from_slice(b">INFO:OpenVPN Manage");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b"ment Interface Version 5\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Info(_)));
}

#[test]
fn partial_client_env_block() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();

    buf.extend_from_slice(b">CLIENT:CONNECT,0,1\n");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b">CLIENT:ENV,common_name=alice\n");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b">CLIENT:ENV,END\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match msg {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env.len(), 1);
            assert_eq!(env[0].1, "alice");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// New commands (Phase 2)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn encode_load_stats() {
    assert_eq!(encode_to_string(OvpnCommand::LoadStats), "load-stats\n");
}

#[test]
fn load_stats_success_response() {
    let msgs = encode_then_decode(
        OvpnCommand::LoadStats,
        "SUCCESS: nclients=3,bytesin=1234567,bytesout=7654321\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("nclients=3")));
}

#[test]
fn encode_client_pending_auth() {
    let wire = encode_to_string(OvpnCommand::ClientPendingAuth {
        cid: 0,
        kid: 1,
        extra: "my-auth-session-id".into(),
        timeout: 120,
    });
    assert_eq!(wire, "client-pending-auth 0 1 my-auth-session-id 120\n");
}

#[test]
fn encode_cr_response() {
    let wire = encode_to_string(OvpnCommand::CrResponse {
        response: "SGFsbG8gV2VsdCE=".into(),
    });
    assert_eq!(wire, "cr-response SGFsbG8gV2VsdCE=\n");
}

#[test]
fn encode_certificate() {
    let wire = encode_to_string(OvpnCommand::Certificate {
        pem_lines: vec![
            "-----BEGIN CERTIFICATE-----".into(),
            "MIIBojCCAUmgAwIBAgIUZ...".into(),
            "-----END CERTIFICATE-----".into(),
        ],
    });
    assert_eq!(
        wire,
        "certificate\n\
         -----BEGIN CERTIFICATE-----\n\
         MIIBojCCAUmgAwIBAgIUZ...\n\
         -----END CERTIFICATE-----\n\
         END\n"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Challenge-response auth commands (Phase 4)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn encode_challenge_response_crv1() {
    let wire = encode_to_string(OvpnCommand::ChallengeResponse {
        state_id: "bXlzdGF0ZQ==".into(),
        response: "123456".into(),
    });
    assert_eq!(wire, "password \"Auth\" \"CRV1::bXlzdGF0ZQ==::123456\"\n");
}

#[test]
fn encode_static_challenge_response_scrv1() {
    let wire = encode_to_string(OvpnCommand::StaticChallengeResponse {
        password_b64: "cGFzc3dvcmQ=".into(),
        response_b64: "MTIzNDU2".into(),
    });
    assert_eq!(wire, "password \"Auth\" \"SCRV1:cGFzc3dvcmQ=:MTIzNDU2\"\n");
}

#[test]
fn challenge_response_with_special_chars_in_state_id() {
    let wire = encode_to_string(OvpnCommand::ChallengeResponse {
        state_id: "abc+def/ghi=".into(),
        response: "mypin".into(),
    });
    // Base64 chars like +/= should pass through unmodified
    assert!(wire.contains("CRV1::abc+def/ghi=::mypin"));
}

// ═══════════════════════════════════════════════════════════════════════
// Management password authentication (Phase 5)
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn decode_password_prompt() {
    let msgs = decode_all("ENTER PASSWORD:\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::PasswordPrompt));
}

#[test]
fn encode_management_password() {
    let wire = encode_to_string(OvpnCommand::ManagementPassword("s3cret".into()));
    assert_eq!(wire, "s3cret\n");
}

#[test]
fn management_password_handshake() {
    let mut codec = OvpnCodec::new();

    // Server sends password prompt.
    let mut buf = BytesMut::from("ENTER PASSWORD:\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));

    // Client sends password.
    let mut enc_buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::ManagementPassword("s3cret".into()),
            &mut enc_buf,
        )
        .unwrap();
    assert_eq!(&enc_buf[..], b"s3cret\n");

    // Server responds with success, then sends banner.
    buf.extend_from_slice(b"SUCCESS: password is correct\n");
    buf.extend_from_slice(b">INFO:OpenVPN Management Interface Version 5\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(ref s) if s.contains("password is correct")));
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Info(_)));
}

#[test]
fn management_password_wrong() {
    let mut codec = OvpnCodec::new();

    let mut buf = BytesMut::from("ENTER PASSWORD:\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::PasswordPrompt));

    let mut enc_buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::ManagementPassword("wrong".into()),
            &mut enc_buf,
        )
        .unwrap();

    buf.extend_from_slice(b"ERROR: bad password\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Error(ref s) if s.contains("bad password")));
}

#[test]
fn partial_multiline_response() {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let mut buf = BytesMut::new();

    buf.extend_from_slice(b"OpenVPN CLIENT LIST\nUpdated,2024-03-21\n");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b"END\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match msg {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Real-world test data sourced from internet (OpenVPN ecosystem)
// Sources: openvpn/openvpn manage.c, management-notes.txt,
//   jkroepke/openvpn-auth-oauth2, kumina/openvpn_exporter,
//   Jamie-/openvpn-api, mysteriumnetwork/go-openvpn,
//   tonyseek/openvpn-status, OpenVPN community docs
// ═══════════════════════════════════════════════════════════════════════

// ── Status format variants from real deployments ─────────────────

#[test]
fn status_v1_server_empty_no_clients() {
    let response = include_str!("fixtures/status_v1_server_empty.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines[0], "OpenVPN CLIENT LIST");
            assert!(lines.iter().any(|l| l.contains("ROUTING TABLE")));
            assert!(
                lines
                    .iter()
                    .any(|l| l.contains("Max bcast/mcast queue length,0"))
            );
            // No client lines between the header row and ROUTING TABLE
            let client_header_idx = lines
                .iter()
                .position(|l| l.starts_with("Common Name,"))
                .unwrap();
            let routing_idx = lines.iter().position(|l| l == "ROUTING TABLE").unwrap();
            assert_eq!(
                client_header_idx + 1,
                routing_idx,
                "no clients between header and routing table"
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v1_server_many_clients() {
    let response = include_str!("fixtures/status_v1_server_many_clients.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            // Three clients, three routing entries
            let client_count = lines
                .iter()
                .filter(|l| l.contains("@example.com") || l.contains("@corp.local"))
                .count();
            assert!(
                client_count >= 3,
                "should find at least 3 client references"
            );
            assert!(lines.iter().any(|l| l.contains("foo@example.com")));
            assert!(lines.iter().any(|l| l.contains("bar@example.com")));
            assert!(lines.iter().any(|l| l.contains("admin@corp.local")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v2_full_with_title_time_dco() {
    let response = include_str!("fixtures/status_v2_full.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V2), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            // V2 full format includes TITLE and TIME rows
            assert!(lines[0].starts_with("TITLE,OpenVPN 2.6.9"));
            assert!(lines[1].starts_with("TIME,"));
            // Multiple clients
            let client_lines: Vec<_> = lines
                .iter()
                .filter(|l| l.starts_with("CLIENT_LIST,"))
                .collect();
            assert_eq!(client_lines.len(), 2);
            // IPv6 virtual address present for first client
            assert!(client_lines[0].contains("2002:232:324:12::8"));
            // DCO stats
            assert!(lines.iter().any(|l| l.contains("dco_enabled")));
            // IPv6 routing entry
            assert!(lines.iter().any(|l| l.starts_with("ROUTING_TABLE,2002:")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v2_old_format_fewer_columns() {
    let response = include_str!("fixtures/status_v2_old.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V2), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines[0].starts_with("TITLE,OpenVPN 2.3.2"));
            // Old format: no Virtual IPv6 Address, Client ID, Peer ID, Data Channel Cipher
            let header = lines
                .iter()
                .find(|l| l.starts_with("HEADER,CLIENT_LIST"))
                .unwrap();
            assert!(!header.contains("Virtual IPv6 Address"));
            assert!(!header.contains("Data Channel Cipher"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn status_v1_client_full_with_compression_stats() {
    let response = include_str!("fixtures/status_v1_client_full.txt");
    let msgs = encode_then_decode(OvpnCommand::Status(StatusFormat::V1), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines[0], "OpenVPN STATISTICS");
            // Should include compression stats
            assert!(lines.iter().any(|l| l.starts_with("pre-compress bytes")));
            assert!(lines.iter().any(|l| l.starts_with("post-compress bytes")));
            assert!(lines.iter().any(|l| l.starts_with("pre-decompress bytes")));
            assert!(lines.iter().any(|l| l.starts_with("post-decompress bytes")));
            assert!(lines.iter().any(|l| l.starts_with("Auth read bytes")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Version output from different OpenVPN versions ───────────────

#[test]
fn version_response_2_6_9() {
    let response = include_str!("fixtures/version_2_6_9.txt");
    let msgs = encode_then_decode(OvpnCommand::Version, response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines[0].contains("2.6.9"));
            assert!(lines[0].contains("[DCO]"));
            assert!(lines[1].contains("Management Interface Version: 5"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn version_response_old_2_3() {
    let response = include_str!("fixtures/version_old.txt");
    let msgs = encode_then_decode(OvpnCommand::Version, response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines[0].contains("2.3.2"));
            // Old format: "Management Version:" not "Management Interface Version:"
            assert!(lines[1].contains("Management Version: 1"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Help output from OpenVPN 2.6.9 (full command list) ───────────

#[test]
fn help_response_2_6_9_with_newer_commands() {
    let response = include_str!("fixtures/help_2_6_9.txt");
    let msgs = encode_then_decode(OvpnCommand::Help, response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert!(lines.len() > 30, "2.6.9 help should be extensive");
            // New commands not in older versions
            assert!(lines.iter().any(|l| l.contains("cr-response")));
            assert!(lines.iter().any(|l| l.contains("client-pending-auth")));
            assert!(lines.iter().any(|l| l.contains("pk-sig")));
            assert!(lines.iter().any(|l| l.contains("certificate")));
            assert!(lines.iter().any(|l| l.contains("load-stats")));
            assert!(lines.iter().any(|l| l.contains("remote-entry-count")));
            assert!(lines.iter().any(|l| l.contains("env-filter")));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── State notifications: all 13 state names from manage.h ────────

#[test]
fn state_all_known_names() {
    // All state names defined in manage.h's openvpn_state enum
    let states: Vec<(&str, OpenVpnState)> = vec![
        ("INITIAL", OpenVpnState::Custom("INITIAL".into())),
        ("CONNECTING", OpenVpnState::Connecting),
        ("WAIT", OpenVpnState::Wait),
        ("AUTH", OpenVpnState::Auth),
        ("GET_CONFIG", OpenVpnState::GetConfig),
        ("ASSIGN_IP", OpenVpnState::AssignIp),
        ("ADD_ROUTES", OpenVpnState::AddRoutes),
        ("CONNECTED", OpenVpnState::Connected),
        ("RECONNECTING", OpenVpnState::Reconnecting),
        ("EXITING", OpenVpnState::Exiting),
        ("RESOLVE", OpenVpnState::Resolve),
        ("TCP_CONNECT", OpenVpnState::TcpConnect),
        ("AUTH_PENDING", OpenVpnState::AuthPending),
    ];
    for (i, (state_str, expected)) in states.iter().enumerate() {
        let input = format!(">STATE:{},{state_str},,,,,,\n", 1700000000 + i as u64);
        let msgs = decode_all(&input);
        assert_eq!(msgs.len(), 1, "failed for state: {state_str}");
        match &msgs[0] {
            OvpnMessage::Notification(Notification::State { name, .. }) => {
                assert_eq!(name, expected);
            }
            other => panic!("unexpected for {state_str}: {other:?}"),
        }
    }
}

#[test]
fn state_connected_with_all_fields_populated() {
    // 9 comma-separated fields: timestamp,name,desc,local_ip,remote_ip,remote_port,local_addr,local_port,local_ipv6
    let msgs = decode_all(">STATE:1608159538,CONNECTED,SUCCESS,10.10.10.1,1.2.3.4,1194,\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            remote_port,
            ..
        }) => {
            assert_eq!(*timestamp, 1608159538);
            assert_eq!(*name, OpenVpnState::Connected);
            assert_eq!(description, "SUCCESS");
            assert_eq!(local_ip, "10.10.10.1");
            assert_eq!(remote_ip, "1.2.3.4");
            assert_eq!(remote_port, "1194");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn state_reconnecting_various_reasons() {
    // From real-world: tls-error, connection-reset, dco-connect-error, SIGUSR1
    let reasons = [
        "tls-error",
        "connection-reset",
        "dco-connect-error",
        "SIGUSR1",
        "ping-restart",
        "server-poll-timeout",
    ];
    for reason in &reasons {
        let input = format!(">STATE:1711000010,RECONNECTING,{reason},,,,,\n");
        let msgs = decode_all(&input);
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            OvpnMessage::Notification(Notification::State {
                name, description, ..
            }) => {
                assert_eq!(*name, OpenVpnState::Reconnecting);
                assert_eq!(description, *reason);
            }
            other => panic!("unexpected for {reason}: {other:?}"),
        }
    }
}

#[test]
fn state_ipv6_connection() {
    let input = include_str!("fixtures/state_ipv6.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 5);
    // Last state should be CONNECTED with server.example.com as remote
    match &msgs[4] {
        OvpnMessage::Notification(Notification::State {
            name,
            local_ip,
            remote_ip,
            ..
        }) => {
            assert_eq!(*name, OpenVpnState::Connected);
            assert_eq!(local_ip, "192.168.20.4");
            assert_eq!(remote_ip, "server.example.com");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Full connection lifecycle from real capture ──────────────────

#[test]
fn full_connection_lifecycle_from_capture() {
    let input = include_str!("fixtures/full_connection_lifecycle.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 9);

    // Banner
    assert!(matches!(&msgs[0], OvpnMessage::Info(s) if s.contains("Version 5")));
    // HOLD
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::Hold { .. })
    ));
    // CONNECTING
    assert!(matches!(
        &msgs[2],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::Connecting
    ));
    // WAIT
    assert!(matches!(
        &msgs[3],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::Wait
    ));
    // AUTH
    assert!(matches!(
        &msgs[4],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::Auth
    ));
    // GET_CONFIG
    assert!(matches!(
        &msgs[5],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::GetConfig
    ));
    // ASSIGN_IP
    assert!(matches!(
        &msgs[6],
        OvpnMessage::Notification(Notification::State { local_ip, .. }) if local_ip == "10.10.10.1"
    ));
    // ADD_ROUTES
    assert!(matches!(
        &msgs[7],
        OvpnMessage::Notification(Notification::State { name, .. }) if *name == OpenVpnState::AddRoutes
    ));
    // CONNECTED with full address info
    match &msgs[8] {
        OvpnMessage::Notification(Notification::State {
            name,
            local_ip,
            remote_ip,
            remote_port,
            ..
        }) => {
            assert_eq!(*name, OpenVpnState::Connected);
            assert_eq!(local_ip, "10.10.10.1");
            assert_eq!(remote_ip, "1.2.3.4");
            assert_eq!(remote_port, "1194");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Password/auth: all auth types from manage.c ──────────────────

#[test]
fn password_need_http_proxy() {
    let msgs = decode_all(">PASSWORD:Need 'HTTP Proxy' username/password\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedAuth {
            auth_type,
        })) => {
            assert_eq!(*auth_type, AuthType::HttpProxy);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_need_socks_proxy() {
    let msgs = decode_all(">PASSWORD:Need 'SOCKS Proxy' username/password\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedAuth {
            auth_type,
        })) => {
            assert_eq!(*auth_type, AuthType::SocksProxy);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_verification_failed_http_proxy() {
    let msgs = decode_all(">PASSWORD:Verification Failed: 'HTTP Proxy'\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::VerificationFailed { auth_type },
        )) => {
            assert_eq!(*auth_type, AuthType::HttpProxy);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_verification_failed_socks_proxy() {
    let msgs = decode_all(">PASSWORD:Verification Failed: 'SOCKS Proxy'\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::VerificationFailed { auth_type },
        )) => {
            assert_eq!(*auth_type, AuthType::SocksProxy);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn static_challenge_no_echo() {
    let msgs = decode_all(">PASSWORD:Need 'Auth' username/password SC:0,Enter your OTP code\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::StaticChallenge {
                echo, challenge, ..
            },
        )) => {
            assert!(!*echo);
            assert_eq!(challenge, "Enter your OTP code");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn password_custom_auth_type() {
    // Custom auth types that aren't in the standard set
    let msgs = decode_all(">PASSWORD:Need 'Management' password\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(PasswordNotification::NeedPassword {
            auth_type,
        })) => {
            assert_eq!(*auth_type, AuthType::Custom("Management".into()));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── CLIENT notifications: rich TLS env from real servers ─────────

#[test]
fn client_connect_tls_rich_env() {
    let input = include_str!("fixtures/client_connect_tls_rich.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            assert_eq!(*event, ClientEvent::Connect);
            assert_eq!(*cid, 1);
            assert_eq!(*kid, Some(2));
            // Should have 22 env vars (rich TLS set)
            assert_eq!(env.len(), 22);
            // X509 fields
            assert!(
                env.iter()
                    .any(|(k, v)| k == "X509_0_CN" && v == "client_two")
            );
            assert!(env.iter().any(|(k, v)| k == "X509_0_C" && v == "DE"));
            // TLS digest
            assert!(env.iter().any(|(k, _)| k == "tls_digest_0"));
            assert!(env.iter().any(|(k, _)| k == "tls_digest_sha256_0"));
            // SSO capabilities
            let sso = env.iter().find(|(k, _)| k == "IV_SSO").unwrap();
            assert_eq!(sso.1, "webauth,openurl,crtext");
            // Hex serial
            assert!(
                env.iter()
                    .any(|(k, v)| k == "tls_serial_hex_0" && v == "37:83")
            );
            // CA cert info (chain depth 1)
            assert!(env.iter().any(|(k, _)| k == "tls_serial_1"));
            assert!(env.iter().any(|(k, _)| k == "tls_digest_1"));
            // n_clients
            assert!(env.iter().any(|(k, v)| k == "n_clients" && v == "0"));
            // Empty values for username/password
            assert!(env.iter().any(|(k, v)| k == "username" && v.is_empty()));
            assert!(env.iter().any(|(k, v)| k == "password" && v.is_empty()));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn client_cr_response_event() {
    let input = include_str!("fixtures/client_cr_response.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            assert_eq!(*event, ClientEvent::Custom("CR_RESPONSE".into()));
            // CR_RESPONSE header: "1,2,SGFsbG8gV2VsdCE=" — the parser uses
            // splitn(3) so CID=1, KID=2, and the base64 tail is ignored.
            assert_eq!(*cid, 1);
            assert_eq!(*kid, Some(2));
            assert_eq!(env.len(), 3);
            assert!(env.iter().any(|(k, v)| k == "common_name" && v == "test"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Log notifications from real servers ──────────────────────────

#[test]
fn log_history_real_server_output() {
    let response = include_str!("fixtures/log_history_real.txt");
    let msgs = encode_then_decode(OvpnCommand::Log(StreamMode::All), response);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 6);
            assert!(lines[0].contains("OpenVPN 2.6.8"));
            assert!(lines[1].contains("MANAGEMENT: CMD"));
            assert!(lines[2].contains("Initialization Sequence Completed"));
            assert!(lines[3].contains("TLS Error"));
            assert!(lines[4].contains("WARNING"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn log_with_management_cmd_echo() {
    let msgs = decode_all(">LOG:1711000001,D,MANAGEMENT: CMD 'state on'\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Log {
            timestamp,
            level,
            message,
        }) => {
            assert_eq!(*timestamp, 1711000001);
            assert_eq!(*level, LogLevel::Debug);
            assert_eq!(message, "MANAGEMENT: CMD 'state on'");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── BYTECOUNT edge cases ────────────────────────────────────────

#[test]
fn bytecount_zero_values() {
    let msgs = decode_all(">BYTECOUNT:0,0\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*bytes_in, 0);
            assert_eq!(*bytes_out, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bytecount_large_values() {
    // Real-world: servers can transfer hundreds of GB
    let msgs = decode_all(">BYTECOUNT:129822996000,126946564000\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*bytes_in, 129822996000);
            assert_eq!(*bytes_out, 126946564000);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn bytecount_cli_multiple_clients() {
    let input = "\
        >BYTECOUNT_CLI:0,1234567,7654321\n\
        >BYTECOUNT_CLI:1,8888888,9999999\n\
        >BYTECOUNT_CLI:3,0,0\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 3);
    match &msgs[2] {
        OvpnMessage::Notification(Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*cid, 3);
            assert_eq!(*bytes_in, 0);
            assert_eq!(*bytes_out, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── SUCCESS/ERROR messages from manage.c source code ────────────

#[test]
fn success_load_stats_real_format() {
    // Exact format from manage.c: nclients=%d,bytesin=%s,bytesout=%s
    let msgs = encode_then_decode(
        OvpnCommand::LoadStats,
        "SUCCESS: nclients=0,bytesin=0,bytesout=0\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "nclients=0,bytesin=0,bytesout=0"));
}

#[test]
fn success_kill_by_address_real_format() {
    let msgs = encode_then_decode(
        OvpnCommand::Kill(KillTarget::Address {
            protocol: "tcp".into(),
            ip: "1.2.3.4".into(),
            port: 4000,
        }),
        "SUCCESS: 1 client(s) at address tcp:1.2.3.4:4000 killed\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("1.2.3.4:4000")));
}

#[test]
fn success_verb_level_changed() {
    let msgs = encode_then_decode(OvpnCommand::Verb(Some(4)), "SUCCESS: verb level changed\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("verb level")));
}

#[test]
fn success_verb_query() {
    let msgs = encode_then_decode(OvpnCommand::Verb(None), "SUCCESS: verb=4\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "verb=4"));
}

#[test]
fn success_mute_level_changed() {
    let msgs = encode_then_decode(OvpnCommand::Mute(Some(40)), "SUCCESS: mute level changed\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
}

#[test]
fn success_mute_query() {
    let msgs = encode_then_decode(OvpnCommand::Mute(None), "SUCCESS: mute=40\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "mute=40"));
}

#[test]
fn success_auth_retry_changed() {
    let msgs = encode_then_decode(
        OvpnCommand::AuthRetry(AuthRetryMode::Interact),
        "SUCCESS: auth-retry parameter changed\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
}

#[test]
fn success_hold_on_off() {
    let msgs = encode_then_decode(OvpnCommand::HoldOn, "SUCCESS: hold on command succeeded\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));

    let msgs = encode_then_decode(
        OvpnCommand::HoldOff,
        "SUCCESS: hold off command succeeded\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(_)));
}

#[test]
fn success_password_is_correct() {
    // Management interface password auth
    let msgs = decode_all("SUCCESS: password is correct\n");
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "password is correct"));
}

#[test]
fn success_forget_passwords_real() {
    let msgs = encode_then_decode(
        OvpnCommand::ForgetPasswords,
        "SUCCESS: forget-passwords command succeeded\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("forget-passwords")));
}

// Error messages from manage.c
#[test]
fn error_signal_ignored() {
    let msgs = encode_then_decode(
        OvpnCommand::Signal(Signal::SigUsr1),
        "ERROR: signal 'SIGUSR1' is currently ignored\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("currently ignored")));
}

#[test]
fn error_signal_unknown() {
    let msgs = encode_then_decode(
        OvpnCommand::Raw("signal BADNAME".into()),
        "ERROR: signal 'BADNAME' is not a known signal type\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("not a known signal type")));
}

#[test]
fn error_verb_out_of_range() {
    let msgs = encode_then_decode(
        OvpnCommand::Verb(Some(15)),
        "ERROR: verb level is out of range\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("out of range")));
}

#[test]
fn error_client_pending_auth_too_long() {
    let msgs = encode_then_decode(
        OvpnCommand::ClientPendingAuth {
            cid: 0,
            kid: 1,
            extra: "x".repeat(2048),
            timeout: 300,
        },
        "ERROR: client-pending-auth command failed. Extra parameter might be too long\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("too long")));
}

#[test]
fn error_command_not_allowed() {
    let msgs = encode_then_decode(
        OvpnCommand::Raw("client-auth 0 1".into()),
        "ERROR: command not allowed\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s == "command not allowed"));
}

#[test]
fn error_command_not_available() {
    let msgs = encode_then_decode(
        OvpnCommand::Raw("client-pf 1".into()),
        "ERROR: The client-pf command is not currently available\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("not currently available")));
}

#[test]
fn error_unknown_command_full() {
    let msgs = encode_then_decode(
        OvpnCommand::Raw("foobar".into()),
        "ERROR: unknown command [foobar], enter 'help' for more options\n",
    );
    assert!(matches!(&msgs[0], OvpnMessage::Error(s) if s.contains("[foobar]")));
}

// ── FATAL notifications from real servers ─────────────────────────

#[test]
fn fatal_tun_tap_device() {
    let msgs = decode_all(
        ">FATAL:Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)\n",
    );
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Fatal { message })
            if message.contains("TUN/TAP") && message.contains("errno=2")
    ));
}

#[test]
fn fatal_all_adapters_in_use() {
    let msgs = decode_all(">FATAL:All TAP-Windows adapters on this system are currently in use.\n");
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Fatal { message })
            if message.contains("TAP-Windows")
    ));
}

#[test]
fn fatal_connection_timeout() {
    let msgs = decode_all(">FATAL:Connection to server timed out\n");
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Fatal { message })
            if message.contains("timed out")
    ));
}

// ── ECHO notifications ──────────────────────────────────────────

#[test]
fn echo_forget_passwords() {
    let msgs = decode_all(">ECHO:1101519562,forget-passwords\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Echo { timestamp, param }) => {
            assert_eq!(*timestamp, 1101519562);
            assert_eq!(param, "forget-passwords");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── REMOTE notification with different protocols ─────────────────

#[test]
fn remote_notification_tcp() {
    let msgs = decode_all(">REMOTE:vpn.example.com,443,tcp-client\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Remote {
            host,
            port,
            protocol,
        }) => {
            assert_eq!(host, "vpn.example.com");
            assert_eq!(*port, 443);
            assert_eq!(*protocol, TransportProtocol::Custom("tcp-client".into()));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── PROXY notification variants ─────────────────────────────────

#[test]
fn proxy_notification_tcp() {
    let msgs = decode_all(">PROXY:1,TCP,vpn.example.com\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Proxy {
            index,
            proxy_type,
            host,
        }) => {
            assert_eq!(*index, 1);
            assert_eq!(proxy_type, "TCP");
            assert_eq!(host, "vpn.example.com");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Unrecognized / forward-compat notification types ────────────

#[test]
fn unrecognized_notification_falls_back_to_simple() {
    // Future notification types the codec doesn't know about yet
    let unknown_types = [
        ">NOTIFY:info,remote-exit,EXIT\n",
        ">UPDOWN:UP,tun0,1500,1500,10.8.0.2,10.8.0.1,init\n",
        ">INFOMSG:WEB_AUTH::https://auth.example.com/login?session=abc123\n",
        ">PK_SIGN:dGhlIGRhdGEgdG8gc2lnbg==\n",
        ">PK_SIGN:dGhlIGRhdGEgdG8gc2lnbg==,RSA_PKCS1_PSS_PADDING\n",
        ">NEED-CERTIFICATE:macosx-keychain:subject:o=OpenVPN-TEST\n",
    ];
    for input in &unknown_types {
        let msgs = decode_all(input);
        assert_eq!(msgs.len(), 1, "failed for: {input}");
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
                assert!(!kind.is_empty(), "kind should not be empty for: {input}");
                assert!(
                    !payload.is_empty(),
                    "payload should not be empty for: {input}"
                );
            }
            other => panic!("expected Simple fallback for {input}, got: {other:?}"),
        }
    }
}

#[test]
fn pk_sign_notification_with_algorithm() {
    let msgs = decode_all(">PK_SIGN:dGhlIGRhdGEgdG8gc2lnbg==,ECDSA\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "PK_SIGN");
            assert!(payload.contains("ECDSA"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn infomsg_web_auth() {
    let msgs = decode_all(">INFOMSG:WEB_AUTH::https://auth.example.com/login\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "INFOMSG");
            assert!(payload.contains("WEB_AUTH"));
            assert!(payload.contains("https://auth.example.com"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn infomsg_cr_text() {
    let msgs = decode_all(">INFOMSG:CR_TEXT:R,E:Please enter your TOTP code\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "INFOMSG");
            assert!(payload.contains("CR_TEXT"));
            assert!(payload.contains("TOTP code"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Encoder tests for commands found in newer protocol versions ──

#[test]
fn encode_remote_modify() {
    let wire = encode_to_string(OvpnCommand::Remote(RemoteAction::Modify {
        host: "vpn.otherexample.com".into(),
        port: 1234,
    }));
    assert_eq!(wire, "remote MOD vpn.otherexample.com 1234\n");
}

#[test]
fn encode_proxy_http_with_nct() {
    let wire = encode_to_string(OvpnCommand::Proxy(ProxyAction::Http {
        host: "proxy.intranet".into(),
        port: 8080,
        non_cleartext_only: true,
    }));
    assert_eq!(wire, "proxy HTTP proxy.intranet 8080 nct\n");
}

#[test]
fn encode_proxy_socks_ipv6() {
    let wire = encode_to_string(OvpnCommand::Proxy(ProxyAction::Socks {
        host: "fe00::1".into(),
        port: 1080,
    }));
    assert_eq!(wire, "proxy SOCKS fe00::1 1080\n");
}

#[test]
fn encode_password_http_proxy() {
    let wire = encode_to_string(OvpnCommand::Password {
        auth_type: AuthType::HttpProxy,
        value: "proxypass".into(),
    });
    assert_eq!(wire, "password \"HTTP Proxy\" \"proxypass\"\n");
}

#[test]
fn encode_password_socks_proxy() {
    let wire = encode_to_string(OvpnCommand::Password {
        auth_type: AuthType::SocksProxy,
        value: "sockspass".into(),
    });
    assert_eq!(wire, "password \"SOCKS Proxy\" \"sockspass\"\n");
}

#[test]
fn encode_username_http_proxy() {
    let wire = encode_to_string(OvpnCommand::Username {
        auth_type: AuthType::HttpProxy,
        value: "proxyuser".into(),
    });
    assert_eq!(wire, "username \"HTTP Proxy\" \"proxyuser\"\n");
}

#[test]
fn encode_client_auth_empty_config_real() {
    // Real-world: authorize without pushing config (equivalent to client-auth-nt)
    let wire = encode_to_string(OvpnCommand::ClientAuth {
        cid: 5,
        kid: 0,
        config_lines: vec![],
    });
    assert_eq!(wire, "client-auth 5 0\nEND\n");
}

#[test]
fn encode_client_auth_with_multiple_push_directives() {
    // Real-world server pushing routes and DNS
    let wire = encode_to_string(OvpnCommand::ClientAuth {
        cid: 0,
        kid: 1,
        config_lines: vec![
            "push \"route 192.168.1.0 255.255.255.0\"".into(),
            "push \"route 10.0.0.0 255.0.0.0\"".into(),
            "push \"ifconfig 10.8.0.6 10.8.0.5\"".into(),
            "push \"dhcp-option DNS 10.0.0.1\"".into(),
            "push \"dhcp-option DNS 10.0.0.2\"".into(),
        ],
    });
    assert!(wire.starts_with("client-auth 0 1\n"));
    assert!(wire.ends_with("END\n"));
    assert!(wire.contains("push \"route 192.168.1.0 255.255.255.0\""));
    assert!(wire.contains("push \"dhcp-option DNS 10.0.0.2\""));
}

#[test]
fn encode_rsa_sig_real_base64() {
    let wire = encode_to_string(OvpnCommand::RsaSig {
        base64_lines: vec![
            "MIIBojCCAUmgAwIBAgIUZjh4yttr3sEvyIgnQC9CF1gHYP0wDQYJKoZIhvcNAQ".into(),
            "ELBQAwGTEXMBUGA1UEAwwOT3BlblZQTi1URVNUMB4XDTI0MDEwMTAwMDAwMFoX".into(),
        ],
    });
    assert!(wire.starts_with("rsa-sig\n"));
    assert!(wire.ends_with("END\n"));
    assert!(wire.contains("MIIBojCCA"));
}

// ── HOLD edge cases ─────────────────────────────────────────────

#[test]
fn hold_waiting_with_seconds() {
    let msgs = decode_all(">HOLD:Waiting for hold release:10\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Hold { text }) => {
            assert_eq!(text, "Waiting for hold release:10");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn hold_query_returns_zero() {
    let msgs = encode_then_decode(OvpnCommand::HoldQuery, "SUCCESS: hold=0\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s == "hold=0"));
}

// ── Complex session simulations from real usage patterns ─────────

#[test]
fn server_mode_deny_then_accept_session() {
    let mut codec = OvpnCodec::new();

    // Banner + HOLD
    let mut buf = BytesMut::from(
        ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n\
         >HOLD:Waiting for hold release:0\n",
    );
    let _info = codec.decode(&mut buf).unwrap().unwrap();
    let _hold = codec.decode(&mut buf).unwrap().unwrap();

    // Release hold
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::HoldRelease, &mut enc_buf)
        .unwrap();
    buf.extend_from_slice(b"SUCCESS: hold release succeeded\n");
    let _success = codec.decode(&mut buf).unwrap().unwrap();

    // Client 0 connects — deny it
    buf.extend_from_slice(
        b">CLIENT:CONNECT,0,1\n\
          >CLIENT:ENV,untrusted_ip=192.168.1.100\n\
          >CLIENT:ENV,common_name=evil_client\n\
          >CLIENT:ENV,END\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        &msg,
        OvpnMessage::Notification(Notification::Client { event, .. }) if *event == ClientEvent::Connect
    ));

    enc_buf.clear();
    codec
        .encode(
            OvpnCommand::ClientDeny {
                cid: 0,
                kid: 1,
                reason: "certificate revoked".into(),
                client_reason: Some("Your access has been revoked".into()),
            },
            &mut enc_buf,
        )
        .unwrap();
    buf.extend_from_slice(b"SUCCESS: client-deny command succeeded\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // Client 1 connects — accept with config push
    buf.extend_from_slice(
        b">CLIENT:CONNECT,1,1\n\
          >CLIENT:ENV,untrusted_ip=10.0.0.50\n\
          >CLIENT:ENV,common_name=good_client\n\
          >CLIENT:ENV,END\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(
        &msg,
        OvpnMessage::Notification(Notification::Client { event, .. }) if *event == ClientEvent::Connect
    ));

    enc_buf.clear();
    codec
        .encode(
            OvpnCommand::ClientAuth {
                cid: 1,
                kid: 1,
                config_lines: vec!["push \"route 10.0.0.0 255.255.0.0\"".into()],
            },
            &mut enc_buf,
        )
        .unwrap();
    buf.extend_from_slice(b"SUCCESS: client-auth command succeeded\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // Client 1 established
    buf.extend_from_slice(
        b">CLIENT:ESTABLISHED,1\n\
          >CLIENT:ENV,common_name=good_client\n\
          >CLIENT:ENV,ifconfig_pool_remote_ip=10.8.0.10\n\
          >CLIENT:ENV,END\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match &msg {
        OvpnMessage::Notification(Notification::Client { event, env, .. }) => {
            assert_eq!(*event, ClientEvent::Established);
            assert!(
                env.iter()
                    .any(|(k, v)| k == "ifconfig_pool_remote_ip" && v == "10.8.0.10")
            );
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn client_mode_auth_with_challenge_session() {
    let mut codec = OvpnCodec::new();

    // Banner
    let mut buf = BytesMut::from(
        ">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n",
    );
    let _info = codec.decode(&mut buf).unwrap().unwrap();

    // HOLD
    buf.extend_from_slice(b">HOLD:Waiting for hold release:0\n");
    let _hold = codec.decode(&mut buf).unwrap().unwrap();

    // Release hold
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::HoldRelease, &mut enc_buf)
        .unwrap();
    buf.extend_from_slice(b"SUCCESS: hold release succeeded\n");
    let _success = codec.decode(&mut buf).unwrap().unwrap();

    // State transitions
    buf.extend_from_slice(
        b">STATE:1711000000,CONNECTING,,,,,,\n\
          >STATE:1711000001,WAIT,,,,,,\n\
          >STATE:1711000002,AUTH,,,,,,\n",
    );
    for _ in 0..3 {
        let msg = codec.decode(&mut buf).unwrap().unwrap();
        assert!(matches!(
            msg,
            OvpnMessage::Notification(Notification::State { .. })
        ));
    }

    // Password prompt with static challenge
    buf.extend_from_slice(
        b">PASSWORD:Need 'Auth' username/password SC:1,Please enter your OTP token\n",
    );
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match &msg {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::StaticChallenge {
                echo, challenge, ..
            },
        )) => {
            assert!(*echo);
            assert_eq!(challenge, "Please enter your OTP token");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // Send username
    enc_buf.clear();
    codec
        .encode(
            OvpnCommand::Username {
                auth_type: AuthType::Auth,
                value: "testuser".into(),
            },
            &mut enc_buf,
        )
        .unwrap();
    buf.extend_from_slice(b"SUCCESS: 'Auth' username entered, but not yet verified\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // Send SCRV1 password response
    enc_buf.clear();
    codec
        .encode(
            OvpnCommand::StaticChallengeResponse {
                password_b64: "cGFzc3dvcmQ=".into(),
                response_b64: "MTIzNDU2".into(),
            },
            &mut enc_buf,
        )
        .unwrap();
    buf.extend_from_slice(b"SUCCESS: 'Auth' password entered, but not yet verified\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(_)));

    // Connected
    buf.extend_from_slice(b">STATE:1711000010,CONNECTED,SUCCESS,10.8.0.6,198.51.100.1,1194,,\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match &msg {
        OvpnMessage::Notification(Notification::State { name, local_ip, .. }) => {
            assert_eq!(*name, OpenVpnState::Connected);
            assert_eq!(local_ip, "10.8.0.6");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn notification_storm_between_commands() {
    // Real-world scenario: many notifications arrive between commands
    let mut codec = OvpnCodec::new();

    let mut buf = BytesMut::from(
        ">INFO:OpenVPN Management Interface Version 5\n\
         >HOLD:Waiting for hold release:0\n\
         >STATE:1711000000,CONNECTING,,,,,,\n\
         >LOG:1711000000,I,Initialization sequence starting\n\
         >STATE:1711000001,WAIT,,,,,,\n\
         >STATE:1711000002,AUTH,,,,,,\n\
         >LOG:1711000002,D,MANAGEMENT: CMD 'state on'\n\
         >STATE:1711000003,GET_CONFIG,,,,,,\n\
         >STATE:1711000005,CONNECTED,SUCCESS,10.8.0.6,1.2.3.4,1194,,\n\
         >BYTECOUNT:0,0\n",
    );

    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }

    assert_eq!(msgs.len(), 10);
    assert!(matches!(&msgs[0], OvpnMessage::Info(_)));
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::Hold { .. })
    ));
    assert!(matches!(
        &msgs[9],
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));
}

// ── Edge cases: CRLF in various positions ────────────────────────

#[test]
fn crlf_in_multiline_response() {
    let msgs = encode_then_decode(
        OvpnCommand::Status(StatusFormat::V1),
        "OpenVPN CLIENT LIST\r\nUpdated,2024-01-01\r\nEND\r\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0], "OpenVPN CLIENT LIST");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn crlf_in_client_notification() {
    let input = ">CLIENT:CONNECT,0,1\r\n\
                  >CLIENT:ENV,common_name=test\r\n\
                  >CLIENT:ENV,END\r\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env[0].1, "test");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Incremental delivery edge cases ─────────────────────────────

#[test]
fn partial_state_notification_split_at_comma() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();

    buf.extend_from_slice(b">STATE:1711000000,CONN");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b"ECTED,SUCCESS,10.8.0.6,1.2.3.4,1194,,\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match msg {
        OvpnMessage::Notification(Notification::State { name, local_ip, .. }) => {
            assert_eq!(name, OpenVpnState::Connected);
            assert_eq!(local_ip, "10.8.0.6");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn partial_multiline_client_env_split() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();

    // Header arrives
    buf.extend_from_slice(b">CLIENT:CONNECT,0,1\n");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    // First env arrives in two chunks
    buf.extend_from_slice(b">CLIENT:ENV,untrusted_ip=");
    assert!(codec.decode(&mut buf).unwrap().is_none());
    buf.extend_from_slice(b"203.0.113.50\n");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    // Second env
    buf.extend_from_slice(b">CLIENT:ENV,common_name=alice\n");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    // Terminator
    buf.extend_from_slice(b">CLIENT:ENV,END\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    match msg {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env.len(), 2);
            assert_eq!(env[0], ("untrusted_ip".into(), "203.0.113.50".into()));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn partial_success_split_mid_word() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();

    buf.extend_from_slice(b"SUCCESS");
    assert!(codec.decode(&mut buf).unwrap().is_none());

    buf.extend_from_slice(b": pid=99999\n");
    let msg = codec.decode(&mut buf).unwrap().unwrap();
    assert!(matches!(msg, OvpnMessage::Success(s) if s == "pid=99999"));
}

// ── Multiple interleaved notifications during multiline ─────────

#[test]
fn multiple_notifications_interleaved_in_status() {
    let msgs = encode_then_decode(
        OvpnCommand::Status(StatusFormat::V1),
        "OpenVPN CLIENT LIST\n\
         >STATE:1711000000,CONNECTED,SUCCESS,10.8.0.6,1.2.3.4,1194,,\n\
         >BYTECOUNT:500000,300000\n\
         Updated,2024-03-21\n\
         >LOG:1711000000,I,test message\n\
         END\n",
    );
    // 3 interleaved notifications + 1 multiline response
    assert_eq!(msgs.len(), 4);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::State { .. })
    ));
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));
    assert!(matches!(
        &msgs[2],
        OvpnMessage::Notification(Notification::Log { .. })
    ));
    match &msgs[3] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 2);
            assert_eq!(lines[0], "OpenVPN CLIENT LIST");
            assert_eq!(lines[1], "Updated,2024-03-21");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ── Encoding edge cases ─────────────────────────────────────────

#[test]
fn encode_password_with_unicode() {
    let wire = encode_to_string(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "p\u{00e4}ssw\u{00f6}rd".into(), // pässwörd
    });
    assert_eq!(wire, "password \"Auth\" \"p\u{00e4}ssw\u{00f6}rd\"\n");
}

#[test]
fn encode_password_with_backslash_and_quote_combo() {
    // The nightmare string: \" (backslash then quote)
    let wire = encode_to_string(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "pass\\\"word".into(),
    });
    assert_eq!(wire, "password \"Auth\" \"pass\\\\\\\"word\"\n");
}

#[test]
fn encode_needstr_with_quotes() {
    let wire = encode_to_string(OvpnCommand::NeedStr {
        name: "profile".into(),
        value: "My \"Special\" Profile".into(),
    });
    assert_eq!(wire, "needstr profile \"My \\\"Special\\\" Profile\"\n");
}

#[test]
fn encode_client_deny_with_both_reasons() {
    let wire = encode_to_string(OvpnCommand::ClientDeny {
        cid: 5,
        kid: 0,
        reason: "cert revoked".into(),
        client_reason: Some("Your access has been revoked.".into()),
    });
    assert_eq!(
        wire,
        "client-deny 5 0 \"cert revoked\" \"Your access has been revoked.\"\n"
    );
}

#[test]
fn encode_client_pending_auth_web_auth() {
    // Real-world: WEB_AUTH SSO flow
    let wire = encode_to_string(OvpnCommand::ClientPendingAuth {
        cid: 1,
        kid: 2,
        extra: "WEB_AUTH::https://auth.example.com/login".into(),
        timeout: 300,
    });
    assert_eq!(
        wire,
        "client-pending-auth 1 2 WEB_AUTH::https://auth.example.com/login 300\n"
    );
}

#[test]
fn encode_certificate_real_pem() {
    let wire = encode_to_string(OvpnCommand::Certificate {
        pem_lines: vec![
            "-----BEGIN CERTIFICATE-----".into(),
            "MIIBojCCAUmgAwIBAgIUZjh4yttr3sEvyIgnQC9CF1gHYP0wDQYJKoZIhvcNAQ".into(),
            "ELBQAwGTEXMBUGA1UEAwwOT3BlblZQTi1URVNUMB4XDTI0MDEwMTAwMDAwMFoX".into(),
            "DTI1MDEwMTAwMDAwMFowGTEXMBUGA1UEAwwOT3BlblZQTi1URVNUMIGfMA0GCSqG".into(),
            "-----END CERTIFICATE-----".into(),
        ],
    });
    assert!(wire.starts_with("certificate\n"));
    assert!(wire.contains("-----BEGIN CERTIFICATE-----"));
    assert!(wire.contains("-----END CERTIFICATE-----"));
    assert!(wire.ends_with("END\n"));
}

// ── PKCS#11 response variations ─────────────────────────────────

#[test]
fn pkcs11_id_count_from_notification() {
    let msgs = decode_all(">PKCS11ID-COUNT:5\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Pkcs11IdCount { count }) => {
            assert_eq!(*count, 5);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn pkcs11_id_count_zero() {
    let msgs = decode_all(">PKCS11ID-COUNT:0\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Pkcs11IdCount { count }) => {
            assert_eq!(*count, 0);
        }
        other => panic!("unexpected: {other:?}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Decoder graceful degradation on malformed notifications
// ═══════════════════════════════════════════════════════════════════════
//
// Every `parse_*` function returns `Option<Notification>`.  When the
// wire payload is truncated, garbled, or from a future OpenVPN version,
// the decoder must fall back to `Notification::Simple` — never panic,
// never return `Err`.

#[test]
fn malformed_notification_no_colon_produces_unrecognized() {
    // A `>` line with no colon at all is truly malformed.
    let msgs = decode_all(">GARBAGE\n");
    assert_eq!(msgs.len(), 1);
    assert!(
        matches!(&msgs[0], OvpnMessage::Unrecognized { .. }),
        "expected Unrecognized for >GARBAGE, got: {:?}",
        msgs[0]
    );
}

#[test]
fn malformed_state_falls_back_to_simple() {
    // >STATE: with a non-numeric timestamp
    let msgs = decode_all(">STATE:not-a-timestamp,CONNECTED,ok,10.0.0.1,1.2.3.4\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "STATE");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_state_too_few_fields_falls_back_to_simple() {
    // >STATE: with only two fields (needs at least 5)
    let msgs = decode_all(">STATE:1234,CONNECTED\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "STATE");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_bytecount_falls_back_to_simple() {
    // No comma separator
    let msgs = decode_all(">BYTECOUNT:not_a_number\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "BYTECOUNT");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_bytecount_cli_falls_back_to_simple() {
    // Only two fields instead of three
    let msgs = decode_all(">BYTECOUNT_CLI:1,100\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "BYTECOUNT_CLI");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_log_falls_back_to_simple() {
    // No comma at all — can't split timestamp from rest
    let msgs = decode_all(">LOG:no-commas-here\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "LOG");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_echo_falls_back_to_simple() {
    let msgs = decode_all(">ECHO:no-comma\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "ECHO");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_pkcs11id_count_falls_back_to_simple() {
    let msgs = decode_all(">PKCS11ID-COUNT:abc\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "PKCS11ID-COUNT");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_need_ok_falls_back_to_simple() {
    // Missing the "Need '" prefix
    let msgs = decode_all(">NEED-OK:Something unexpected\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "NEED-OK");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_need_str_falls_back_to_simple() {
    let msgs = decode_all(">NEED-STR:Bad format no quotes\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "NEED-STR");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_remote_falls_back_to_simple() {
    // Non-numeric port
    let msgs = decode_all(">REMOTE:host.example.com,notaport,udp\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "REMOTE");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_proxy_falls_back_to_simple() {
    // Only one field — not enough
    let msgs = decode_all(">PROXY:1\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "PROXY");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn malformed_password_verification_falls_back_to_simple() {
    // Verification Failed but missing closing quote
    let msgs = decode_all(">PASSWORD:Verification Failed: 'Auth\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "PASSWORD");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn unrecognized_password_subformat_falls_back_to_simple() {
    // Neither "Verification Failed", "Need ... username/password", nor "Need ... password"
    let cases = [
        // Missing "Need '" prefix entirely
        ">PASSWORD:Something completely different\n",
        // Valid "Need 'Type'" prefix, but the rest is neither
        // "username/password" nor "password" — exercises the final None
        // fallback at the end of parse_password.
        ">PASSWORD:Need 'Auth' credentials\n",
    ];
    for input in &cases {
        let msgs = decode_all(input);
        assert_eq!(msgs.len(), 1, "failed for: {input}");
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
                assert_eq!(kind, "PASSWORD");
            }
            other => panic!("expected Simple fallback for {input}, got: {other:?}"),
        }
    }
}

// ── CLIENT notification edge cases ──────────────────────────────────

#[test]
fn client_notification_no_comma_in_payload() {
    // >CLIENT:CONNECT with no comma after the event name — no CID.
    // The decoder should still handle this gracefully.
    let msgs = decode_all(">CLIENT:CONNECT\n>CLIENT:ENV,END\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { event, cid, .. }) => {
            assert_eq!(*event, ClientEvent::Connect);
            assert_eq!(*cid, 0, "missing CID should default to 0");
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

#[test]
fn client_notification_interleaved_in_multiline_response() {
    // A >CLIENT: notification arrives while the codec is accumulating a
    // multi-line `status` response. The CLIENT block should be emitted
    // as a separate message, and the status response should complete
    // intact.
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V1), &mut enc_buf)
        .unwrap();

    let mut buf = BytesMut::from(
        "TITLE,OpenVPN Statistics\n\
         >CLIENT:CONNECT,0,1\n\
         >CLIENT:ENV,untrusted_ip=10.0.0.1\n\
         >CLIENT:ENV,END\n\
         TIME,2024-01-01 00:00:00\n\
         END\n",
    );

    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }

    assert_eq!(
        msgs.len(),
        2,
        "expected CLIENT notification + MultiLine response"
    );
    assert!(
        matches!(
            &msgs[0],
            OvpnMessage::Notification(Notification::Client { .. })
        ),
        "first message should be Client notification, got: {:?}",
        msgs[0]
    );
    assert!(
        matches!(&msgs[1], OvpnMessage::MultiLine(_)),
        "second message should be MultiLine, got: {:?}",
        msgs[1]
    );
    // The multiline response should contain the lines that were NOT part
    // of the CLIENT block.
    if let OvpnMessage::MultiLine(lines) = &msgs[1] {
        assert!(lines.iter().any(|l| l.contains("TITLE")));
        assert!(lines.iter().any(|l| l.contains("TIME")));
    }
}
