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

use super::common::{decode_all, encode_str as encode};

// --- Helpers ---

fn try_encode_strict(cmd: OvpnCommand) -> Result<String, std::io::Error> {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf)?;
    Ok(String::from_utf8(buf.to_vec()).unwrap())
}

// ---  ---
// Variable-length >STATE: fields with trailing empty commas
// Source: real forum logs, OpenVPN 2.4+
//         >STATE:1676768325,WAIT,,,,,,
// See also: https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h
//           (state field definitions evolved across versions)
// ---  ---

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
            assert_eq!(*local_port, None);
            assert_eq!(*remote_port, None);
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
    // Source: OpenVPN manage.c state output — the description field carries
    //         the reconnect reason (e.g. "dco-connect-error", "tls-error").
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

// ---  ---
// String timestamp instead of u64 — parse_state must not panic
// Source: https://github.com/tonyseek/openvpn-status/issues/24
//         Timestamp format changed between OpenVPN versions.
// ---  ---

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

// ---  ---
// UNDEF as Common Name in CLIENT ENV
// Source: https://community.openvpn.net/openvpn/ticket/160
//         https://github.com/jkroepke/openvpn-auth-oauth2/issues/139
// ---  ---

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
            assert_eq!(env["common_name"], "UNDEF");
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
            assert!(!env.contains_key("common_name"));
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ---  ---
// ENV values containing '=' signs
// Source: inherent protocol design, X.509 DNs contain '='
// ---  ---

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
            assert_eq!(env["tls_id_0"], "CN=user,OU=vpn,O=corp");
            assert_eq!(env["X509_0_CN"], "admin=root");
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
            assert_eq!(env["bare_key"], "");
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ---  ---
// Trailing \n\0 in control messages
// Source: https://github.com/OpenVPN/openvpn/issues/645
//         Real 2FA clients (OpenVPN Connect v3.5.1) append \n\0.
// ---  ---

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

// ---  ---
// CRLF in base64 static challenge response
// Source: https://github.com/OpenVPN/openvpn-gui/issues/317
//         Windows CryptBinaryToString inserts \r\n every 76 chars
//         by default, breaking the line-oriented protocol.
// ---  ---

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

// ---  ---
// Double-escaping prevention
// Source: https://github.com/OpenVPN/openvpn-gui/issues/351
//         GUI escaped password THEN base64-encoded it, corrupting
//         the payload.
// ---  ---

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

// ---  ---
// Unknown / future notification types degrade to Simple
// Source: protocol evolution — new notification types added regularly
//         e.g. >INFOMSG:, >NOTIFY:, >UPDOWN:
// ---  ---

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
fn infomsg_web_auth_is_first_class() {
    // >INFOMSG: is a first-class notification type.
    let msgs = decode_all(">INFOMSG:WEB_AUTH::https://auth.example.com/verify?session=abc123\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::InfoMsg { extra }) => {
            assert!(extra.contains("WEB_AUTH"));
        }
        other => panic!("expected InfoMsg, got: {other:?}"),
    }
}

#[test]
fn pk_sign_with_algorithm_parsed() {
    // >PK_SIGN:base64_data,algorithm — now properly parsed.
    let msgs = decode_all(">PK_SIGN:AABBCCDD==,RSA_PKCS1_PSS_PADDING\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::PkSign {
            data,
            algorithm: Some(algo),
        }) if data == "AABBCCDD==" && algo == "RSA_PKCS1_PSS_PADDING"
    ));
}

#[test]
fn pk_sign_without_algorithm_parsed() {
    // >PK_SIGN:base64_data — no algorithm (management client version ≤ 2).
    let msgs = decode_all(">PK_SIGN:AABBCCDD==\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::PkSign {
            data,
            algorithm: None,
        }) if data == "AABBCCDD=="
    ));
}

#[test]
fn pk_sign_empty_payload_degrades_to_simple() {
    let msgs = decode_all(">PK_SIGN:\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Simple { kind, .. }) if kind == "PK_SIGN"
    ));
}

// ---  ---
// >INFO: routing: first is OvpnMessage::Info, subsequent are Notification::Info
// ---  ---

#[test]
fn first_info_is_banner_subsequent_are_notifications() {
    let msgs = decode_all(
        ">INFO:OpenVPN Management Interface Version 5\n\
         >INFO:WEB_AUTH::https://auth.example.com\n",
    );
    assert_eq!(msgs.len(), 2);
    assert!(matches!(&msgs[0], OvpnMessage::Info(s) if s.contains("Management")));
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::Info { message })
        if message.contains("WEB_AUTH")
    ));
}

// ---  ---
// Malformed notification (no colon after >)
// Source: defensive — could come from a buggy or hostile server
// ---  ---

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

// ---  ---
// CLIENT notification with unexpected event type
// Source: protocol evolution — new event types added (CR_RESPONSE etc.)
// ---  ---

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
            // Unknown event type should parse into Unknown variant.
            assert_eq!(*event, ClientEvent::Unknown("FUTURE_EVENT".into()));
            assert_eq!(*cid, 7);
            assert_eq!(*kid, Some(2));
            assert_eq!(env.len(), 1);
            assert_eq!(env["foo"], "bar");
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ---  ---
// Empty lines from server
// Source: defensive — TCP connection drops and reconnects can produce
//         empty lines; also observed in https://github.com/OpenVPN/openvpn/pull/46
//         where man_read buffer corruption produced spurious empty lines.
// ---  ---

#[test]
fn empty_line_is_silently_skipped() {
    // Empty lines carry no information and are silently discarded.
    // This absorbs spurious newlines from TCP reconnects, buffer
    // corruption, and the password prompt's missing line terminator
    // (OpenVPN ≥ 2.6).
    let msgs = decode_all("\n");
    assert_eq!(msgs.len(), 0);
}

#[test]
fn blank_line_between_notifications_skipped() {
    // Empty lines between real messages are skipped — only the
    // meaningful messages are emitted.
    let msgs = decode_all(
        ">INFO:OpenVPN Management Interface Version 5\n\
         \n\
         >STATE:1234567890,CONNECTING,,,,,,\n",
    );
    assert_eq!(msgs.len(), 2);
    assert!(matches!(&msgs[0], OvpnMessage::Info(_)));
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::State { .. })
    ));
}

// ---  ---
// Partial / incomplete data (connection dropped mid-line)
// Source: inherent to TCP stream framing — tokio-util codec contract
//         requires returning Ok(None) when insufficient data is
//         available.
// ---  ---

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
            assert_eq!(env["key"], "val");
        }
        other => panic!("expected Client notification, got: {other:?}"),
    }
}

// ---  ---
// Invalid UTF-8 from server (binary garbage)
// Source: https://nvd.nist.gov/vuln/detail/CVE-2024-5594
//         Unsanitized control chars in PUSH_REPLY (fixed in 2.6.11).
// ---  ---

#[test]
fn invalid_utf8_returns_error_not_panic() {
    let mut codec = OvpnCodec::new();
    // 0xFF is never valid in UTF-8.
    let mut buf = BytesMut::from(&b">STATE:\xff\n"[..]);
    let result = codec.decode(&mut buf);
    assert!(result.is_err(), "expected error for invalid UTF-8, got Ok");
}

// ---  ---
// BYTECOUNT with huge values (>2^32)
// Source: long-running VPN sessions can accumulate terabytes
// ---  ---

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

// ---  ---
// PASSWORD notification edge cases
// Source: https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c
//         management_auth_token() emits >PASSWORD:Auth-Token:{token}
//         management_up_down() / man_password_verify() emit Verification Failed
// ---  ---

#[test]
fn password_auth_token_parsed() {
    // Source: manage.c management_auth_token()
    // Wire: >PASSWORD:Auth-Token:{token}
    let msgs = decode_all(">PASSWORD:Auth-Token:tok_abc123\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(PasswordNotification::AuthToken {
            token,
        })) => {
            assert_eq!(token.expose(), "tok_abc123");
        }
        other => panic!("expected AuthToken, got: {other:?}"),
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

// ---  ---
// Very long lines — stress test for buffer handling
// Source: defensive — long-running VPN servers with many clients can
//         produce STATUS responses with very long lines, and X.509
//         Distinguished Names can be hundreds of bytes.
// ---  ---

#[test]
fn decoder_handles_very_long_notification_line() {
    // 100 KB description field — well beyond typical, but must not
    // panic, allocate pathologically, or corrupt adjacent messages.
    let long_desc = "A".repeat(100_000);
    let wire = format!(
        ">STATE:1700000000,CONNECTED,{long_desc},10.8.0.1,1.2.3.4,1194,,\n\
         >BYTECOUNT:100,200\n"
    );
    let msgs = decode_all(&wire);
    assert_eq!(msgs.len(), 2);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State { description, .. }) => {
            assert_eq!(description.len(), 100_000);
        }
        other => panic!("expected State notification, got: {other:?}"),
    }
    // The subsequent message must still decode correctly.
    assert!(matches!(
        &msgs[1],
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));
}

#[test]
fn encoder_handles_very_long_password() {
    let long_pass = "p".repeat(100_000);
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: long_pass.clone().into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.contains(&long_pass));
}

// ---  ---
// >CLIENT:CR_RESPONSE — challenge-response notification (OpenVPN 2.6+)
//
// Wire format (from manage.c `management_notify_client_cr_response`):
//   >CLIENT:CR_RESPONSE,{CID},{KID},{base64_response}
//   >CLIENT:ENV,untrusted_ip={ip}
//   >CLIENT:ENV,untrusted_port={port}
//   >CLIENT:ENV,common_name={cn}
//   >CLIENT:ENV,username={user}
//   >CLIENT:ENV,IV_SSO={caps}
//   ...
//   >CLIENT:ENV,END
//
// - CID: client ID (unsigned long), assigned sequentially from 0
// - KID: key ID (unsigned int), the TLS session key index (0, 1, 2…)
// - base64_response: the client's base64-encoded answer to a
//   CR_TEXT challenge (e.g. a TOTP code)
//
// The header carries the response on the same line as CID/KID,
// unlike CONNECT/REAUTH/DISCONNECT which have only CID,KID.
// The codec parser uses splitn(3, ',') so the base64 tail after
// KID is ignored — it is part of the header, not an ENV var.
//
// Introduced in OpenVPN 2.6 alongside:
//   - Server-side --client-crresponse script hook
//   - OPENVPN_PLUGIN_CLIENT_CRRESPONSE plugin type
//   - >INFOMSG:CR_TEXT: notification for challenge delivery
//
// Sources:
//   - https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c
//     (management_notify_client_cr_response)
//   - https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt
//   - https://patchwork.openvpn.net/project/openvpn2/patch/20210518122635.2235658-1-arne@rfc2549.org/
//     (v3 patch by Arne Schwabe, May 2021)
//   - https://github.com/jkroepke/openvpn-auth-oauth2
//     (real-world CR_RESPONSE consumer)
// ---  ---

#[test]
fn client_cr_response_with_full_env() {
    // Realistic CR_RESPONSE from a TOTP-enabled OpenVPN 2.6 server.
    // The base64 payload "MTIzNDU2" decodes to "123456" (a typical
    // 6-digit TOTP code). The ENV block includes SSO capability
    // flags and a username from the locked auth context.
    let input = "\
        >CLIENT:CR_RESPONSE,42,0,MTIzNDU2\n\
        >CLIENT:ENV,untrusted_ip=203.0.113.50\n\
        >CLIENT:ENV,untrusted_port=52841\n\
        >CLIENT:ENV,common_name=client1.example.com\n\
        >CLIENT:ENV,username=jdoe\n\
        >CLIENT:ENV,IV_SSO=webauth,openurl,crtext\n\
        >CLIENT:ENV,IV_VER=2.6.8\n\
        >CLIENT:ENV,IV_PLAT=linux\n\
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
            assert_eq!(*event, ClientEvent::CrResponse("MTIzNDU2".to_string()));
            assert_eq!(*cid, 42);
            assert_eq!(*kid, Some(0));
            assert_eq!(env.len(), 7);
            assert_eq!(env["untrusted_ip"], "203.0.113.50");
            assert_eq!(env["username"], "jdoe");
            assert_eq!(
                env.get("IV_SSO").map(String::as_str),
                Some("webauth,openurl,crtext"),
                "expected IV_SSO with crtext capability"
            );
        }
        other => panic!("expected Client CR_RESPONSE notification, got: {other:?}"),
    }
}

// ---  ---
// STATUS v2/v3 interleaving with notifications
// Source: inherent to the protocol — OpenVPN emits real-time
//         notifications at any time, even mid-STATUS response.
//         The existing status_interleaved.txt covers v1; these
//         tests verify the same property for v2 and v3 formats.
// ---  ---

#[test]
fn status_v2_interleaved_with_notification() {
    let response = "\
        HEADER,CLIENT_LIST,Common Name,Real Address\n\
        >BYTECOUNT:99999,88888\n\
        CLIENT_LIST,client1,203.0.113.10:52841\n\
        GLOBAL_STATS,Max bcast/mcast queue length,3\n\
        END\n";
    let mut codec = OvpnCodec::new();
    let mut enc = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V2), &mut enc)
        .unwrap();
    let mut buf = BytesMut::from(response);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    assert_eq!(
        msgs.len(),
        2,
        "expected notification + multiline, got {msgs:?}"
    );
    // Notification arrives first (interleaved).
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::ByteCount {
            bytes_in: 99999,
            bytes_out: 88888,
        })
    ));
    // Multi-line block is reassembled without the notification line.
    match &msgs[1] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 3);
            assert!(lines[0].starts_with("HEADER,CLIENT_LIST"));
            assert!(lines[1].starts_with("CLIENT_LIST,client1"));
            assert!(lines[2].starts_with("GLOBAL_STATS"));
        }
        other => panic!("expected MultiLine, got: {other:?}"),
    }
}

#[test]
fn status_v3_interleaved_with_notification() {
    let response = "\
        TITLE\tOpenVPN 2.6.8\n\
        >STATE:1700000000,CONNECTED,SUCCESS,10.8.0.1,,,,\n\
        TIME\t2024-03-21 14:30:00\t1711031400\n\
        GLOBAL_STATS\tMax bcast/mcast queue length\t3\n\
        END\n";
    let mut codec = OvpnCodec::new();
    let mut enc = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V3), &mut enc)
        .unwrap();
    let mut buf = BytesMut::from(response);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    assert_eq!(
        msgs.len(),
        2,
        "expected notification + multiline, got {msgs:?}"
    );
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::State { .. })
    ));
    match &msgs[1] {
        OvpnMessage::MultiLine(lines) => {
            assert_eq!(lines.len(), 3);
            assert!(lines[0].starts_with("TITLE\t"));
            assert!(lines[1].starts_with("TIME\t"));
            assert!(lines[2].starts_with("GLOBAL_STATS\t"));
        }
        other => panic!("expected MultiLine, got: {other:?}"),
    }
}

// ---  ---
// >PKCS11ID-ENTRY with realistic PKCS#11 data
// Source: OpenVPN management-notes.txt, section on pkcs11-id-get.
//         Real PKCS#11 tokens use hex-encoded serial numbers as IDs
//         and DER-encoded certificate blobs in base64.
// ---  ---

#[test]
fn pkcs11id_entry_with_realistic_token_data() {
    // Realistic PKCS#11 entry: a hardware token with a hex serial
    // number and a base64-encoded certificate blob.
    let msgs = decode_all(
        ">PKCS11ID-ENTRY:'0', ID:'pkcs11:model=SoftHSM%20v2;\
         manufacturer=SoftHSM%20project;serial=a1b2c3d4e5f6;\
         token=My%20Token;id=%01%02%03;object=my-cert;type=cert', \
         BLOB:'MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAU'\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Pkcs11IdEntry { index, id, blob } => {
            assert_eq!(index, "0");
            assert!(
                id.starts_with("pkcs11:model=SoftHSM"),
                "expected PKCS#11 URI, got: {id}"
            );
            assert!(id.contains("serial=a1b2c3d4e5f6"));
            assert!(
                blob.starts_with("MIICpDCCAYwC"),
                "expected base64 DER certificate, got: {blob}"
            );
        }
        other => panic!("expected Pkcs11IdEntry, got: {other:?}"),
    }
}

// ---  ---
// >BYTECOUNT_CLI — per-client byte count in server mode
// Source: OpenVPN management-notes.txt, bytecount command.
//         Server mode emits >BYTECOUNT_CLI:{cid},{bytes_in},{bytes_out}
//         for each client at the configured interval.
// ---  ---

#[test]
fn bytecount_cli_realistic_server_data() {
    // Simulate a server reporting per-client byte counts for three
    // clients, including a freshly connected client (CID 5, zero bytes)
    // and a long-running client with >2^32 byte counts.
    let input = "\
        >BYTECOUNT_CLI:0,52834567,9812345\n\
        >BYTECOUNT_CLI:3,5368709120,1073741824\n\
        >BYTECOUNT_CLI:5,0,0\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 3);

    // First client: moderate traffic.
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*cid, 0);
            assert_eq!(*bytes_in, 52_834_567);
            assert_eq!(*bytes_out, 9_812_345);
        }
        other => panic!("expected ByteCountCli, got: {other:?}"),
    }

    // Second client: >2^32 bytes (5 GB in, 1 GB out).
    match &msgs[1] {
        OvpnMessage::Notification(Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*cid, 3);
            assert_eq!(*bytes_in, 5_368_709_120);
            assert_eq!(*bytes_out, 1_073_741_824);
        }
        other => panic!("expected ByteCountCli, got: {other:?}"),
    }

    // Third client: freshly connected, zero traffic.
    match &msgs[2] {
        OvpnMessage::Notification(Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        }) => {
            assert_eq!(*cid, 5);
            assert_eq!(*bytes_in, 0);
            assert_eq!(*bytes_out, 0);
        }
        other => panic!("expected ByteCountCli, got: {other:?}"),
    }
}

// ---  ---
// EncoderMode::Strict — CRLF in base64 and state_id rejected
// ---  ---

#[test]
fn strict_static_challenge_response_crlf_in_base64_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::StaticChallengeResponse {
            password_b64: "dGVzdHBhc3N3\r\nb3Jk".into(),
            response_b64: "MTIzNDU2\r\n".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_challenge_response_crlf_in_state_id_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ChallengeResponse {
            state_id: "abc\r\ndef".into(),
            response: "myresponse".into(),
        })
        .is_err()
    );
}
