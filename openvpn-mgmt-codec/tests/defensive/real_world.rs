//! Real-world edge cases drawn from OpenVPN bug trackers, CVEs, and
//! client library issue reports.
//!
//! Each test is annotated with its source.  Unlike the injection tests
//! in `main.rs`, these should all **pass** — they verify the codec
//! handles messy real-world data gracefully rather than panicking or
//! producing garbage.

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

// ── Helpers ──────────────────────────────────────────────────────────

fn decode_all(input: &str) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::from(input);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

fn encode(cmd: OvpnCommand) -> String {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf).unwrap();
    String::from_utf8(buf.to_vec()).unwrap()
}

// ═════════════════════════════════════════════════════════════════════
// Variable-length >STATE: fields with trailing empty commas
// Source: real forum logs, OpenVPN 2.4+
//         >STATE:1676768325,WAIT,,,,,,
// See also: https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h
//           (state field definitions evolved across versions)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn state_all_fields_empty_trailing_commas() {
    // Minimal state line — only timestamp and state name, rest empty.
    let msgs = decode_all(">STATE:1676768325,WAIT,,,,,,\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            ..
        }) => {
            assert_eq!(*timestamp, 1676768325);
            assert_eq!(*name, OpenVpnState::Wait);
            assert_eq!(description, "");
            assert_eq!(local_ip, "");
            assert_eq!(remote_ip, "");
            assert_eq!(local_port, "");
            assert_eq!(remote_port, "");
        }
        other => panic!("expected State notification, got: {other:?}"),
    }
}

#[test]
fn state_only_four_fields_old_openvpn() {
    // Very old OpenVPN versions may send fewer fields.
    // parse_state uses splitn(9) — missing fields become "".
    let msgs = decode_all(">STATE:1384405371,CONNECTED,SUCCESS,10.200.0.36\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            ..
        }) => {
            assert_eq!(*timestamp, 1384405371);
            assert_eq!(*name, OpenVpnState::Connected);
            assert_eq!(description, "SUCCESS");
            assert_eq!(local_ip, "10.200.0.36");
            // remote_ip is the 5th field — missing here.
            // parse_state requires 5 fields, so this falls back to Simple.
        }
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "STATE");
        }
        other => panic!("expected State or Simple notification, got: {other:?}"),
    }
}

#[test]
fn state_reconnecting_with_reason() {
    // Source: https://github.com/mysteriumnetwork/go-openvpn test captures
    let msgs = decode_all(">STATE:1676768323,RECONNECTING,dco-connect-error,,,,,\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State {
            name, description, ..
        }) => {
            assert_eq!(*name, OpenVpnState::Reconnecting);
            assert_eq!(description, "dco-connect-error");
        }
        other => panic!("expected State notification, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// String timestamp instead of u64 — parse_state must not panic
// Source: https://github.com/tonyseek/openvpn-status/issues/24
//         Timestamp format changed between OpenVPN versions.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn state_string_timestamp_degrades_to_simple() {
    // Older or alternative builds might emit a string timestamp.
    // parse_state expects u64 — .parse().ok()? returns None → Simple.
    let msgs = decode_all(">STATE:2022-07-20 16:43:45,CONNECTED,SUCCESS,10.0.0.1,1.2.3.4,,,\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "STATE");
            assert!(payload.contains("2022-07-20"));
        }
        other => panic!("expected Simple fallback for string timestamp, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// UNDEF as Common Name in CLIENT ENV
// Source: https://community.openvpn.net/openvpn/ticket/160
//         https://github.com/jkroepke/openvpn-auth-oauth2/issues/139
// ═════════════════════════════════════════════════════════════════════

#[test]
fn client_env_undef_common_name() {
    let input = "\
        >CLIENT:CONNECT,0,1\n\
        >CLIENT:ENV,common_name=UNDEF\n\
        >CLIENT:ENV,untrusted_ip=10.0.0.1\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env[0], ("common_name".into(), "UNDEF".into()));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

#[test]
fn client_env_missing_common_name_entirely() {
    // Source: https://community.openvpn.net/openvpn/ticket/160
    //         https://forums.openvpn.net/viewtopic.php?t=12801
    // In some disconnect scenarios, common_name is absent.
    let input = "\
        >CLIENT:DISCONNECT,5\n\
        >CLIENT:ENV,bytes_received=12345\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert!(!env.iter().any(|(k, _)| k == "common_name"));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// ENV values containing '=' signs
// Source: inherent protocol design, X.509 DNs contain '='
// ═════════════════════════════════════════════════════════════════════

#[test]
fn client_env_value_with_multiple_equals() {
    let input = "\
        >CLIENT:CONNECT,0,1\n\
        >CLIENT:ENV,tls_id_0=CN=user,OU=vpn,O=corp\n\
        >CLIENT:ENV,X509_0_CN=admin=root\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            // split_once('=') should preserve everything after first '='.
            assert_eq!(env[0], ("tls_id_0".into(), "CN=user,OU=vpn,O=corp".into()));
            assert_eq!(env[1], ("X509_0_CN".into(), "admin=root".into()));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

#[test]
fn client_env_key_with_no_equals() {
    // Source: defensive — the spec does not define this case, but
    // real servers have been observed emitting bare keys without '='.
    // Key should be the whole string, value should be empty.
    let input = "\
        >CLIENT:CONNECT,0,1\n\
        >CLIENT:ENV,bare_key\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env[0], ("bare_key".into(), "".into()));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// Trailing \n\0 in control messages
// Source: https://github.com/OpenVPN/openvpn/issues/645
//         Real 2FA clients (OpenVPN Connect v3.5.1) append \n\0.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn decoder_handles_null_byte_in_notification() {
    // A server relaying a client's CR_RESPONSE might include trailing \0.
    // The decoder should not panic — the null just becomes part of the
    // parsed string (it's valid UTF-8).
    let msgs = decode_all(">INFO:CR_RESPONSE,c2E=\0\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Info(s) if s.contains("CR_RESPONSE")));
}

#[test]
fn decoder_handles_null_byte_in_success() {
    let msgs = decode_all("SUCCESS: pid=1234\0\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("pid=1234")));
}

// ═════════════════════════════════════════════════════════════════════
// CRLF in base64 static challenge response
// Source: https://github.com/OpenVPN/openvpn-gui/issues/317
//         Windows CryptBinaryToString inserts \r\n every 76 chars
//         by default, breaking the line-oriented protocol.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn static_challenge_response_crlf_in_base64_stripped() {
    // Simulate a base64 encoder that inserts CRLF mid-string.
    let wire = encode(OvpnCommand::StaticChallengeResponse {
        password_b64: "dGVzdHBhc3N3\r\nb3Jk".into(),
        response_b64: "MTIzNDU2\r\n".into(),
    });

    // CRLF must be stripped — output must be a single line.
    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "CRLF in base64 was not stripped — got {line_count} lines\nwire: {wire:?}"
    );

    // The base64 content should be intact minus the CRLF.
    assert!(
        wire.contains("dGVzdHBhc3N3b3Jk"),
        "base64 content was corrupted"
    );
    assert!(wire.contains("MTIzNDU2"), "response base64 was corrupted");
}

#[test]
fn challenge_response_crlf_in_state_id_stripped() {
    let wire = encode(OvpnCommand::ChallengeResponse {
        state_id: "abc\r\ndef".into(),
        response: "myresponse".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(line_count, 1, "CRLF in state_id produced multiple lines");
    assert!(wire.contains("abcdef"), "state_id CRLF not stripped");
}

// ═════════════════════════════════════════════════════════════════════
// Double-escaping prevention
// Source: https://github.com/OpenVPN/openvpn-gui/issues/351
//         GUI escaped password THEN base64-encoded it, corrupting
//         the payload.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn static_challenge_no_double_escape_of_base64() {
    // Base64 strings contain only [A-Za-z0-9+/=].  quote_and_escape
    // should not add extra backslashes to these characters.
    let wire = encode(OvpnCommand::StaticChallengeResponse {
        password_b64: "dGVzdHBhcw==".into(),
        response_b64: "MTIzNDU2".into(),
    });

    // The wire should contain the base64 verbatim inside quotes.
    assert!(
        wire.contains("SCRV1:dGVzdHBhcw==:MTIzNDU2"),
        "base64 was corrupted by double-escaping\nwire: {wire:?}"
    );
}

// ═════════════════════════════════════════════════════════════════════
// Unknown / future notification types degrade to Simple
// Source: protocol evolution — new notification types added regularly
//         e.g. >INFOMSG:, >PK_SIGN:, >NOTIFY:, >UPDOWN:
// ═════════════════════════════════════════════════════════════════════

#[test]
fn unknown_notification_type_degrades_to_simple() {
    let msgs = decode_all(">UPDOWN:UP,tun0,1500,1500,10.8.0.2,10.8.0.1,init\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "UPDOWN");
            assert!(payload.contains("tun0"));
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn infomsg_web_auth_degrades_to_simple() {
    let msgs = decode_all(">INFOMSG:WEB_AUTH::https://auth.example.com/verify?session=abc123\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "INFOMSG");
            assert!(payload.contains("WEB_AUTH"));
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

#[test]
fn pk_sign_with_algorithm_degrades_to_simple() {
    // >PK_SIGN is newer than >RSA_SIGN, not yet modeled.
    let msgs = decode_all(">PK_SIGN:AABBCCDD==,RSA_PKCS1_PSS_PADDING,SHA256\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, .. }) => {
            assert_eq!(kind, "PK_SIGN");
        }
        other => panic!("expected Simple fallback, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// Malformed notification (no colon after >)
// Source: defensive — could come from a buggy or hostile server
// ═════════════════════════════════════════════════════════════════════

#[test]
fn notification_with_no_colon_becomes_unrecognized() {
    let msgs = decode_all(">GARBAGE_NO_COLON\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Unrecognized {
            kind: UnrecognizedKind::MalformedNotification,
            ..
        }
    ));
}

// ═════════════════════════════════════════════════════════════════════
// CLIENT notification with unexpected event type
// Source: protocol evolution — new event types added (CR_RESPONSE etc.)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn client_unknown_event_type_still_accumulates_env() {
    let input = "\
        >CLIENT:FUTURE_EVENT,7,2\n\
        >CLIENT:ENV,foo=bar\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event,
            cid,
            kid,
            env,
        }) => {
            // Unknown event type should parse into Custom variant.
            assert_eq!(*event, ClientEvent::Custom("FUTURE_EVENT".into()));
            assert_eq!(*cid, 7);
            assert_eq!(*kid, Some(2));
            assert_eq!(env.len(), 1);
            assert_eq!(env[0], ("foo".into(), "bar".into()));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// Empty lines from server
// Source: defensive — TCP connection drops and reconnects can produce
//         empty lines; also observed in https://github.com/OpenVPN/openvpn/pull/46
//         where man_read buffer corruption produced spurious empty lines.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn empty_line_becomes_unrecognized() {
    // An empty line is not SUCCESS/ERROR/notification — should not panic.
    let msgs = decode_all("\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Unrecognized {
            kind: UnrecognizedKind::UnexpectedLine,
            ..
        }
    ));
}

#[test]
fn blank_line_between_notifications_handled() {
    let msgs = decode_all(
        ">INFO:OpenVPN Management Interface Version 5\n\
         \n\
         >STATE:1234567890,CONNECTING,,,,,,\n",
    );
    assert_eq!(msgs.len(), 3);
    assert!(matches!(&msgs[0], OvpnMessage::Info(_)));
    assert!(matches!(&msgs[1], OvpnMessage::Unrecognized { .. }));
    assert!(matches!(
        &msgs[2],
        OvpnMessage::Notification(Notification::State { .. })
    ));
}

// ═════════════════════════════════════════════════════════════════════
// Partial / incomplete data (connection dropped mid-line)
// Source: inherent to TCP stream framing — tokio-util codec contract
//         requires returning Ok(None) when insufficient data is
//         available.
// ═════════════════════════════════════════════════════════════════════

#[test]
fn incomplete_line_returns_none_not_error() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::from(">STATE:1234567890,CONNEC");
    // No newline yet — decoder should return None (need more data).
    let result = codec.decode(&mut buf).unwrap();
    assert!(result.is_none(), "expected None for incomplete line");
    // Buffer should be preserved.
    assert_eq!(buf.len(), 24);
}

#[test]
fn incomplete_client_env_block_buffers_correctly() {
    let mut codec = OvpnCodec::new();

    // Feed the CLIENT header.
    let mut buf = BytesMut::from(">CLIENT:CONNECT,0,1\n>CLIENT:ENV,key=val\n");
    let msg = codec.decode(&mut buf).unwrap();
    // No message yet — accumulating ENV lines.
    assert!(msg.is_none(), "expected None while accumulating CLIENT ENV");

    // Feed the terminator.
    buf.extend_from_slice(b">CLIENT:ENV,END\n");
    let msg = codec.decode(&mut buf).unwrap();
    assert!(msg.is_some(), "expected Client message after ENV,END");
    match msg.unwrap() {
        OvpnMessage::Notification(Notification::Client { env, .. }) => {
            assert_eq!(env.len(), 1);
            assert_eq!(env[0], ("key".into(), "val".into()));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// Invalid UTF-8 from server (binary garbage)
// Source: https://nvd.nist.gov/vuln/detail/CVE-2024-5594
//         Unsanitized control chars in PUSH_REPLY (fixed in 2.6.11).
// ═════════════════════════════════════════════════════════════════════

#[test]
fn invalid_utf8_returns_error_not_panic() {
    let mut codec = OvpnCodec::new();
    // 0xFF is never valid in UTF-8.
    let mut buf = BytesMut::from(&b">STATE:\xff\n"[..]);
    let result = codec.decode(&mut buf);
    assert!(result.is_err(), "expected error for invalid UTF-8, got Ok");
}

// ═════════════════════════════════════════════════════════════════════
// BYTECOUNT with huge values (>2^32)
// Source: long-running VPN sessions can accumulate terabytes
// ═════════════════════════════════════════════════════════════════════

#[test]
fn bytecount_large_u64_values() {
    let msgs = decode_all(">BYTECOUNT:9999999999999,8888888888888\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*bytes_in, 9_999_999_999_999);
            assert_eq!(*bytes_out, 8_888_888_888_888);
        }
        other => panic!("expected ByteCount notification, got: {other:?}"),
    }
}

// ═════════════════════════════════════════════════════════════════════
// PASSWORD notification edge cases
// Source: https://github.com/NordSecurity/gopenvpn (Auth-Token variant)
//         https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c
//         (Verification Failed format for all auth types)
// ═════════════════════════════════════════════════════════════════════

#[test]
fn password_auth_token_degrades_to_simple() {
    // Source: https://github.com/NordSecurity/gopenvpn
    // Auth-Token is not a standard subtype; falls back to Simple.
    let msgs = decode_all(">PASSWORD:Auth-Token:tok_abc123\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "PASSWORD");
            assert!(payload.contains("Auth-Token"));
        }
        other => panic!("expected Simple fallback for Auth-Token, got: {other:?}"),
    }
}

#[test]
fn password_verification_failed_custom_type() {
    let msgs = decode_all(">PASSWORD:Verification Failed: 'HTTP Proxy'\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::VerificationFailed { auth_type },
        )) => {
            assert_eq!(*auth_type, AuthType::HttpProxy);
        }
        other => panic!("expected VerificationFailed, got: {other:?}"),
    }
}
