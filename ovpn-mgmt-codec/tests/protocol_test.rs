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
use ovpn_mgmt_codec::*;
use ovpn_mgmt_codec::PasswordNotification;
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
    let msgs = decode_all(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n");
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
            assert_eq!(name, "CONNECTING");
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
            local_port,
            ..
        }) => {
            assert_eq!(*timestamp, 1711000006);
            assert_eq!(name, "CONNECTED");
            assert_eq!(description, "SUCCESS");
            assert_eq!(local_ip, "10.8.0.6");
            assert_eq!(remote_ip, "198.51.100.1");
            assert_eq!(local_port, "1194");
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
            assert_eq!(name, "RECONNECTING");
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
            assert_eq!(name, "EXITING");
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
        OvpnMessage::Notification(Notification::ByteCount { bytes_in, bytes_out }) => {
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
    assert_eq!(
        encode_to_string(OvpnCommand::ByteCount(0)),
        "bytecount 0\n"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Log notifications
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn log_notifications_all_flags() {
    let input = include_str!("fixtures/log_all_flags.txt");
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 5);

    let flags: Vec<&str> = msgs
        .iter()
        .map(|m| match m {
            OvpnMessage::Notification(Notification::Log { flags, .. }) => flags.as_str(),
            other => panic!("unexpected: {other:?}"),
        })
        .collect();
    assert_eq!(flags, vec!["I", "D", "W", "N", "F"]);
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
            header_args,
            env,
        }) => {
            assert_eq!(event, "CONNECT");
            assert_eq!(header_args, "0,1");
            assert_eq!(env.len(), 19);
            assert_eq!(env[0], ("untrusted_ip".into(), "203.0.113.50".into()));
            assert_eq!(
                env[2],
                ("common_name".into(), "client1.example.com".into())
            );
            assert_eq!(env[3], ("username".into(), "jdoe".into()));
            let ciphers = env.iter().find(|(k, _)| k == "IV_CIPHERS").unwrap();
            assert_eq!(
                ciphers.1,
                "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
            );
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
            header_args,
            env,
        }) => {
            assert_eq!(event, "REAUTH");
            assert_eq!(header_args, "0,2");
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
            header_args,
            env,
        }) => {
            assert_eq!(event, "ESTABLISHED");
            assert_eq!(header_args, "0");
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
            header_args,
            env,
        }) => {
            assert_eq!(event, "DISCONNECT");
            assert_eq!(header_args, "5");
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
            assert_eq!(cid, "7");
            assert_eq!(addr, "10.8.0.14");
            assert_eq!(primary, "1");
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
                header_args: args0,
                env: env0,
                ..
            }),
            OvpnMessage::Notification(Notification::Client {
                header_args: args1,
                env: env1,
                ..
            }),
        ) => {
            assert_eq!(args0, "0,1");
            assert_eq!(env0[0].1, "alice");
            assert_eq!(args1, "1,1");
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
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::NeedAuth { auth_type },
        )) => {
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
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::NeedPassword { auth_type },
        )) => {
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
    let msgs =
        decode_all(">PASSWORD:Need 'Auth' username/password CRV1:R,E:bXlzdGF0ZQ==:dXNlcg==:Enter PIN\n");
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
            PasswordNotification::StaticChallenge { echo, challenge },
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
    let msgs = decode_all(">FATAL:Cannot open TUN/TAP dev /dev/net/tun: No such file or directory (errno=2)\n");
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
            assert_eq!(port, "1194");
            assert_eq!(protocol, "udp");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[test]
fn proxy_notification() {
    let msgs = decode_all(">PROXY:1,udp,vpn.example.com,1194\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Proxy {
            proto_num,
            proto_type,
            host,
            port,
        }) => {
            assert_eq!(proto_num, "1");
            assert_eq!(proto_type, "udp");
            assert_eq!(host, "vpn.example.com");
            assert_eq!(port, "1194");
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
    assert_eq!(
        encode_to_string(OvpnCommand::HoldRelease),
        "hold release\n"
    );
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
            ip: "203.0.113.10".into(),
            port: 52841,
        })),
        "kill 203.0.113.10:52841\n"
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
        encode_to_string(OvpnCommand::ClientKill { cid: 42 }),
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
        OvpnCommand::ClientKill { cid: 5 },
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
    let msgs = decode_all(">INFO:OpenVPN Management Interface Version 5\r\n\
                           SUCCESS: pid=1234\r\n");
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
        OvpnMessage::Notification(Notification::State { name, .. }) if name == "CONNECTED"
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
        OvpnMessage::Notification(Notification::State { name, .. }) if name == "CONNECTING"
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
    let msgs = encode_then_decode(OvpnCommand::HoldQuery, "1\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::SingleValue(s) if s == "1"));
}

#[test]
fn pkcs11_id_get_parsed() {
    let msgs = encode_then_decode(
        OvpnCommand::Pkcs11IdGet(0),
        "PKCS11ID-ENTRY:'0', ID:'MY_ID', BLOB:'MY_BLOB'\n",
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
    // If the format doesn't match, fall back to SingleValue
    let msgs = encode_then_decode(
        OvpnCommand::Pkcs11IdGet(0),
        "some unexpected response\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::SingleValue(s) if s == "some unexpected response"));
}

#[test]
fn pkcs11_id_count_success() {
    let msgs = encode_then_decode(
        OvpnCommand::Pkcs11IdCount,
        "SUCCESS: 2\n",
    );
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
            assert_eq!(event, "CONNECT");
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
            assert_eq!(event, "ESTABLISHED");
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
        timeout: 120,
        extra: "my-auth-session-id".into(),
    });
    assert_eq!(wire, "client-pending-auth 0 1 120 my-auth-session-id\n");
}

#[test]
fn encode_client_deny_v2_full() {
    let wire = encode_to_string(OvpnCommand::ClientDenyV2 {
        cid: 5,
        kid: 0,
        reason: "cert revoked".into(),
        client_reason: Some("Access denied".into()),
        redirect_url: Some("https://example.com/reauth".into()),
    });
    assert_eq!(
        wire,
        "client-deny-v2 5 0 \"cert revoked\" \"Access denied\" \"https://example.com/reauth\"\n"
    );
}

#[test]
fn encode_client_deny_v2_no_optionals() {
    let wire = encode_to_string(OvpnCommand::ClientDenyV2 {
        cid: 3,
        kid: 0,
        reason: "policy".into(),
        client_reason: None,
        redirect_url: None,
    });
    assert_eq!(wire, "client-deny-v2 3 0 \"policy\"\n");
}

#[test]
fn encode_cr_response() {
    let wire = encode_to_string(OvpnCommand::CrResponse {
        cid: 0,
        kid: 1,
        response: "123456".into(),
    });
    assert_eq!(wire, "cr-response 0 1 123456\n");
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

#[test]
fn encode_bypass_message() {
    let wire = encode_to_string(OvpnCommand::BypassMessage("dns 1.2.3.4".into()));
    assert_eq!(wire, "bypass-message \"dns 1.2.3.4\"\n");
}

#[test]
fn encode_bypass_message_with_special_chars() {
    let wire = encode_to_string(OvpnCommand::BypassMessage("msg with \"quotes\"".into()));
    assert_eq!(wire, "bypass-message \"msg with \\\"quotes\\\"\"\n");
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
    assert_eq!(
        wire,
        "password \"Auth\" \"CRV1::bXlzdGF0ZQ==::123456\"\n"
    );
}

#[test]
fn encode_static_challenge_response_scrv1() {
    let wire = encode_to_string(OvpnCommand::StaticChallengeResponse {
        password_b64: "cGFzc3dvcmQ=".into(),
        response_b64: "MTIzNDU2".into(),
    });
    assert_eq!(
        wire,
        "password \"Auth\" \"SCRV1:cGFzc3dvcmQ=:MTIzNDU2\"\n"
    );
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
        .encode(OvpnCommand::ManagementPassword("s3cret".into()), &mut enc_buf)
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
        .encode(OvpnCommand::ManagementPassword("wrong".into()), &mut enc_buf)
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
