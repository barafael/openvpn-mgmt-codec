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

use super::common::{decode_all, encode_str as encode, try_encode_strict};

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
        OvpnMessage::Notification(Notification::State(StateEntry {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            local_port,
            remote_port,
            ..
        })) => {
            assert_eq!(*timestamp, UtcTimestamp(1676768325));
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
        OvpnMessage::Notification(Notification::State(StateEntry {
            timestamp,
            name,
            description,
            local_ip,
            ..
        })) => {
            assert_eq!(*timestamp, UtcTimestamp(1384405371));
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
        OvpnMessage::Notification(Notification::State(StateEntry {
            name, description, ..
        })) => {
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
//         https://community.openvpn.net/openvpn/ticket/1434
//         https://github.com/jkroepke/openvpn-auth-oauth2/issues/139
//
// Ticket #160: OpenVPN clears common_name internally before calling
//   disconnect scripts — the TLS session may already be torn down,
//   so set_common_name() has nothing to read.
// Ticket #1434: Same symptom via a different code path — the
//   client-disconnect script env lacks common_name entirely.
// Also observed in forum reports:
//   https://forums.openvpn.net/viewtopic.php?t=12801
//   https://forum.netgate.com/topic/175246/openvpn-common-name-undef
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
    //         https://community.openvpn.net/openvpn/ticket/1434
    //         https://forums.openvpn.net/viewtopic.php?t=12801
    // In some disconnect scenarios, common_name is absent because
    // the TLS session is already torn down when the script runs.
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
//         by default (unless CRYPT_STRING_NOCRLF is set), breaking
//         the line-oriented management protocol because \n is the
//         message delimiter.
//         Fix: set CRYPT_STRING_NOCRLF in CryptBinaryToString flags.
// ---  ---

#[test]
fn static_challenge_response_newline_in_password_safe() {
    // Newlines in plaintext are safely absorbed by base64 encoding.
    let wire = encode(OvpnCommand::StaticChallengeResponse {
        password: "test\r\npassword".into(),
        response: "123456\r\n".into(),
    });

    // Output must be a single line — newlines are encoded away.
    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "newline in password produced {line_count} wire lines\nwire: {wire:?}"
    );
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
//         the payload.  When static-challenge is in use the input
//         is already base64, so escaping the password inside the
//         base64 breaks it.  The fix: skip management-interface
//         escaping for base64-encoded payloads.
// ---  ---

#[test]
fn static_challenge_base64_output_is_clean() {
    // Verify the encoder produces valid base64 in the SCRV1 payload.
    let wire = encode(OvpnCommand::StaticChallengeResponse {
        password: "testpass".into(),
        response: "123456".into(),
    });

    // The wire should contain well-formed SCRV1 with base64 content.
    assert!(
        wire.contains("SCRV1:dGVzdHBhc3M=:MTIzNDU2"),
        "base64 encoding was incorrect\nwire: {wire:?}"
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
    // >PK_SIGN:base64_data,algorithm — present when management client
    // version > 2.  Supported padding algorithms (from management-notes.txt):
    //   RSA_PKCS1_PADDING, RSA_NO_PADDING, ECDSA,
    //   RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=max
    //
    // Source: https://community.openvpn.net/openvpn/ticket/764
    //         (external-key sometimes requests signatures for too-long data)
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
//
// PR #46: a recursive issue in man_read where the input buffer enters
//         an inconsistent state while processing commands, causing
//         OpenVPN to process the same command multiple times and then
//         fail to read remaining commands — emitting spurious blank lines.
//
// CVE-2025-2704 can also cause abrupt server crashes mid-output when
// TLS-crypt-v2 state is corrupted, which may manifest as a truncated
// TCP stream with trailing blank fragments.
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
        OvpnMessage::Notification(Notification::State(..))
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
// Source: https://nvd.nist.gov/vuln/detail/CVE-2024-5594 (CVSS 9.1)
//         OpenVPN before 2.6.11 did not sanitize PUSH_REPLY messages,
//         allowing a malicious server to inject non-printable/control
//         characters that end up in client logs, cause high CPU load,
//         or feed garbage to third-party plugins.  Fixed in 2.6.11.
//
// Also patched in the same release:
//   CVE-2024-28882 — multiple exit notifications extend session
//   CVE-2024-4877 — Windows-specific GUI elevation
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
        OvpnMessage::Notification(Notification::State(StateEntry { description, .. })) => {
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
        OvpnMessage::Notification(Notification::State(..))
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
fn strict_static_challenge_response_encodes_cleanly() {
    // In strict mode, plaintext is base64-encoded internally — always succeeds
    // since base64 output contains no unsafe characters.
    assert!(
        try_encode_strict(OvpnCommand::StaticChallengeResponse {
            password: "test\r\npassword".into(),
            response: "123456\r\n".into(),
        })
        .is_ok()
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

// =========================================================================
// Gap-filling tests from CVEs, bug trackers, and protocol edge cases
// discovered via internet research (2024–2026).
// =========================================================================

// ---  ---
// Multi-byte UTF-8 in common names through encoder paths
// Source: https://community.openvpn.net/openvpn/ticket/67
//         (Unicode symbols in CN replaced by underscores before 2.3)
//         https://community.openvpn.net/openvpn/ticket/194
//         (Management Interface does not allow UTF-8 passwords)
//
// Since OpenVPN 2.3 with --no-name-remapping, CN can contain any
// printable character including multi-byte UTF-8.  The encoder must
// pass these through without corruption.
// ---  ---

#[test]
fn kill_common_name_with_multibyte_utf8() {
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName(
        "Ñoño García".into(),
    )));
    assert_eq!(wire.lines().count(), 1);
    assert!(
        wire.contains("Ñoño García"),
        "multi-byte UTF-8 CN was corrupted\nwire: {wire:?}"
    );
}

#[test]
fn kill_common_name_with_cjk_characters() {
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName("田中太郎".into())));
    assert_eq!(wire.lines().count(), 1);
    assert!(
        wire.contains("田中太郎"),
        "CJK CN was corrupted\nwire: {wire:?}"
    );
}

#[test]
fn client_deny_reason_with_multibyte_utf8() {
    let wire = encode(OvpnCommand::ClientDeny(ClientDeny {
        cid: 1,
        kid: 0,
        reason: "Accès refusé".into(),
        client_reason: Some("Доступ запрещён".into()),
    }));
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.contains("Accès refusé"));
    assert!(wire.contains("Доступ запрещён"));
}

#[test]
fn password_with_multibyte_utf8() {
    // Ticket #194: UTF-8 passwords weren't supported on the management
    // interface until later versions.  The encoder must preserve them.
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "пароль密码Ñ".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(
        wire.contains("пароль密码Ñ"),
        "UTF-8 password was corrupted\nwire: {wire:?}"
    );
}

// ---  ---
// Common name with spaces — quoting required since 2.5
// Source: https://sourceforge.net/p/openvpn/mailman/message/32963023/
//         (compat-names and spaces in Common Names)
//         https://github.com/opnsense/core/issues/2245
//         (status table broken by spaces in CN)
//
// With --compat-names removed in 2.5, spaces are no longer
// remapped to underscores.  `kill "Firstname Lastname"` must
// be properly quoted on the wire.
// ---  ---

#[test]
fn kill_common_name_with_spaces() {
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName(
        "Firstname Lastname".into(),
    )));
    assert_eq!(wire.lines().count(), 1);
    assert!(
        wire.contains("Firstname Lastname"),
        "CN with spaces was corrupted\nwire: {wire:?}"
    );
}

#[test]
fn kill_common_name_that_looks_like_command_argument() {
    // A CN that looks like a command flag should not confuse the parser.
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName(
        "--signal SIGTERM".into(),
    )));
    assert_eq!(wire.lines().count(), 1);
    assert!(
        wire.contains("--signal SIGTERM"),
        "flag-like CN was corrupted or stripped\nwire: {wire:?}"
    );
}

// ---  ---
// CVE-2021-31605: Numeric field injection (openvpn-monitor)
// Source: https://seclists.org/fulldisclosure/2021/Sep/47
//         https://www.compass-security.com/en/news/detail/vulnerabilities-in-openvpn-monitor
//
// openvpn-monitor 1.1.3 passed HTTP POST params (ip, port,
// client_id) unsanitized to the management socket.  An attacker
// could inject "\nsignal SIGTERM" after a numeric value.
//
// This tests the same pattern via the codec: a client_pending_auth
// extra field carrying an injection payload embedded after what
// looks like numeric data.
// ---  ---

#[test]
fn client_pending_auth_numeric_field_injection() {
    // Simulates the CVE-2021-31605 pattern: a "numeric" value
    // followed by a newline and an injected command.
    let wire = encode(OvpnCommand::ClientPendingAuth {
        cid: 5,
        kid: 0,
        extra: "WEB_AUTH::https://auth.example.com\nsignal SIGTERM".into(),
        timeout: 30,
    });
    assert_eq!(
        wire.lines().count(),
        1,
        "numeric field injection via client-pending-auth extra\nwire: {wire:?}"
    );
}

// ---  ---
// CRV1 dynamic challenge — challenge_text containing colons
// Source: https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt
//         "state_id may not contain colon characters, but
//          challenge_text may"
//
// The decoder uses splitn(4, ':') on the CRV1 payload, so the
// fourth segment (challenge_text) captures everything including
// embedded colons.
// ---  ---

#[test]
fn dynamic_challenge_with_colons_in_challenge_text() {
    // challenge_text = "Enter code from device: Model X: PIN"
    // This has two extra colons that must NOT be treated as CRV1 delimiters.
    let input = ">PASSWORD:Verification Failed: 'Auth' \
                 ['CRV1:R,E:c3RhdGVfaWQ=:dXNlcg==:Enter code from device: Model X: PIN']\n";
    let msgs = decode_all(input);
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
            assert_eq!(state_id, "c3RhdGVfaWQ=");
            assert_eq!(username_b64, "dXNlcg==");
            assert_eq!(
                challenge, "Enter code from device: Model X: PIN",
                "colons in challenge_text were incorrectly split"
            );
        }
        other => panic!("expected DynamicChallenge, got: {other:?}"),
    }
}

#[test]
fn dynamic_challenge_with_empty_flags() {
    // Flags can be empty (no echo, no response-required).
    let input = ">PASSWORD:Verification Failed: 'Auth' \
                 ['CRV1::c3RhdGU=:dXNlcg==:Simple challenge']\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::DynamicChallenge { flags, .. },
        )) => {
            assert_eq!(flags, "");
        }
        other => panic!("expected DynamicChallenge, got: {other:?}"),
    }
}

// ---  ---
// >CLIENT:DISCONNECT with empty ENV block
// Source: https://community.openvpn.net/openvpn/ticket/1434
//         client-disconnect script env lacks common_name entirely
//         when TLS session is already torn down.
//
// Unlike the UNDEF CN tests above (which have *some* env vars),
// this tests a completely minimal disconnect: only the END marker.
// ---  ---

#[test]
fn client_disconnect_with_completely_empty_env() {
    let input = "\
        >CLIENT:DISCONNECT,99\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event, cid, env, ..
        }) => {
            assert_eq!(*event, ClientEvent::Disconnect);
            assert_eq!(*cid, 99);
            assert!(
                env.is_empty(),
                "expected empty ENV block for bare disconnect, got: {env:?}"
            );
        }
        other => panic!("expected Client DISCONNECT, got: {other:?}"),
    }
}

// ---  ---
// >CLIENT:REAUTH — distinct from CONNECT for client-deny behavior
// Source: https://community.openvpn.net/openvpn/ticket/1447
//         (Cannot reauthenticate clients using auth-token with
//          management-client-auth)
//
// A client-deny issued for REAUTH invalidates the renegotiated key
// but the existing TLS session continues for --tran-window seconds.
// A client-deny issued for CONNECT terminates the session immediately.
// The codec must distinguish these event types.
// ---  ---

#[test]
fn client_reauth_parsed_distinctly_from_connect() {
    let input = "\
        >CLIENT:REAUTH,10,2\n\
        >CLIENT:ENV,common_name=client1\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event, cid, kid, ..
        }) => {
            assert_eq!(*event, ClientEvent::Reauth);
            assert_eq!(*cid, 10);
            assert_eq!(*kid, Some(2));
        }
        other => panic!("expected Client REAUTH, got: {other:?}"),
    }
}

// ---  ---
// Password with literal backslash sequences
// Source: https://community.openvpn.net/openvpn/ticket/958
//         (Special characters in passwords)
//
// Passwords containing `"`, `\`, and literal `\n` (two characters,
// not a newline) must be properly escaped per the OpenVPN config-file
// lexer rules: `\\` → `\`, `\"` → `"`.
// ---  ---

#[test]
fn password_with_backslash_and_quotes() {
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: r#"p@ss"w\ord"#.into(),
    });
    assert_eq!(wire.lines().count(), 1);
    // The backslash and quote must be escaped on the wire.
    assert!(
        wire.contains(r#"p@ss\"w\\ord"#),
        "backslash/quote escaping failed\nwire: {wire:?}"
    );
}

#[test]
fn password_with_literal_backslash_n_sequence() {
    // Literal `\n` (two chars: backslash + n) — must be escaped as `\\n`,
    // NOT treated as a newline.
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: r"before\nafter".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(
        wire.contains(r"before\\nafter"),
        "literal backslash-n was not escaped\nwire: {wire:?}"
    );
}

// ---  ---
// >PK_SIGN with large base64 payload and PSS padding params
// Source: https://community.openvpn.net/openvpn/ticket/764
//         (--management-external-key sometimes requests signatures
//          for too long data)
//
// RSA-PSS algorithm field includes comma-separated params:
//   RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=max
// The decoder must not split on these commas — the algorithm field
// is everything after the first comma in the >PK_SIGN: payload.
// ---  ---

#[test]
fn pk_sign_with_pss_padding_and_hash_params() {
    let msgs = decode_all(">PK_SIGN:AABBCCDD==,RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=max\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::PkSign {
            data, algorithm, ..
        }) => {
            assert_eq!(data, "AABBCCDD==");
            assert_eq!(
                algorithm.as_deref(),
                Some("RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=max"),
                "PSS padding params were truncated at internal comma"
            );
        }
        other => panic!("expected PkSign, got: {other:?}"),
    }
}

#[test]
fn pk_sign_with_ecdsa_algorithm() {
    let msgs = decode_all(">PK_SIGN:EEFF0011==,ECDSA\n");
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::PkSign {
            data,
            algorithm: Some(algo),
        }) if data == "EEFF0011==" && algo == "ECDSA"
    ));
}

#[test]
fn pk_sign_with_large_base64_payload() {
    // Ticket #764: external-key can request signatures for large data.
    // Simulate an 8 KB base64 payload.
    let large_b64 = "A".repeat(8192);
    let wire = format!(">PK_SIGN:{large_b64},RSA_PKCS1_PADDING\n");
    let msgs = decode_all(&wire);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::PkSign { data, .. }) => {
            assert_eq!(data.len(), 8192);
        }
        other => panic!("expected PkSign, got: {other:?}"),
    }
}

// ---  ---
// >NEED-OK notification with quoted prompt
// Source: https://openvpn.net/community-docs/management-interface.html
//         "The needok command is used to confirm a >NEED-OK
//          real-time notification, normally used by OpenVPN to
//          block while waiting for a specific user action."
//
// The prompt name is single-quoted in the wire format:
//   >NEED-OK:Need 'token-insertion-request' confirmation MSG:Please insert your Smartcard
// ---  ---

#[test]
fn need_ok_with_smartcard_prompt() {
    let msgs = decode_all(
        ">NEED-OK:Need 'token-insertion-request' confirmation MSG:Please insert your Smartcard\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::NeedOk { name, message }) => {
            assert_eq!(name, "token-insertion-request");
            assert_eq!(message, "Please insert your Smartcard");
        }
        other => panic!("expected NeedOk, got: {other:?}"),
    }
}

#[test]
fn need_ok_with_colon_in_message() {
    // MSG text may contain colons — split_once("MSG:") ensures only the
    // first MSG: is used as delimiter.
    let msgs = decode_all(
        ">NEED-OK:Need 'action' confirmation MSG:Step 1: insert token. Step 2: press OK.\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::NeedOk { message, .. }) => {
            assert_eq!(
                message, "Step 1: insert token. Step 2: press OK.",
                "colons in NEED-OK message were incorrectly split"
            );
        }
        other => panic!("expected NeedOk, got: {other:?}"),
    }
}

// ---  ---
// Truncated TCP stream mid-multiline-block
// Source: CVE-2025-2704 (https://nvd.nist.gov/vuln/detail/CVE-2025-2704)
//         OpenVPN 2.6.1–2.6.13 with TLS-crypt-v2 can crash via ASSERT
//         when receiving a mix of authenticated + malformed packets.
//         The server exits abruptly, which from the management client's
//         perspective looks like a TCP close mid-response.
//
// The decoder must not panic or corrupt state when the stream ends
// in the middle of a multi-line block (before the terminating END).
// ---  ---

#[test]
fn truncated_multiline_block_returns_none() {
    let mut codec = OvpnCodec::new();
    let mut enc = BytesMut::new();
    codec
        .encode(OvpnCommand::Status(StatusFormat::V2), &mut enc)
        .unwrap();

    // Feed a partial status response — no END terminator.
    let mut buf = BytesMut::from(
        "HEADER,CLIENT_LIST,Common Name,Real Address\n\
         CLIENT_LIST,client1,203.0.113.10:52841\n",
    );
    // Should return None — still accumulating the block.
    let result = codec.decode(&mut buf).unwrap();
    assert!(
        result.is_none(),
        "expected None for truncated multiline block"
    );
}

// ---  ---
// `version n` silent acceptance for management client version < 4
// Source: https://github.com/OpenVPN/openvpn/commit/d5814ecd2323ec7c2e6dad2cbf3884c031d9a5a3
//         (Document management client versions)
//         https://mail-archive.com/openvpn-devel@lists.sourceforge.net/msg35782.html
//         (Fixup version command on management interface)
//
// For version 1–3, `version n` produces NO response from the server.
// Only version >= 4 returns "SUCCESS: Management client version set
// to N".  The codec must not hang waiting for a response that will
// never come.
// ---  ---

#[test]
fn set_version_3_expects_no_response() {
    let mut codec = OvpnCodec::new();
    let mut enc = BytesMut::new();
    codec.encode(OvpnCommand::SetVersion(3), &mut enc).unwrap();

    // The next thing on the wire is an unrelated notification — not a
    // SUCCESS response.  The codec must emit the notification without
    // blocking on a response that was never sent.
    let mut buf = BytesMut::from(">BYTECOUNT:100,200\n");
    let msg = codec.decode(&mut buf).unwrap();
    assert!(
        msg.is_some(),
        "codec blocked waiting for version 3 response"
    );
    assert!(matches!(
        msg.unwrap(),
        OvpnMessage::Notification(Notification::ByteCount { .. })
    ));
}

#[test]
fn set_version_4_expects_success_response() {
    let mut codec = OvpnCodec::new();
    let mut enc = BytesMut::new();
    codec.encode(OvpnCommand::SetVersion(4), &mut enc).unwrap();

    let mut buf = BytesMut::from("SUCCESS: Management client version set to 4\n");
    let msg = codec.decode(&mut buf).unwrap();
    assert!(msg.is_some());
    assert!(matches!(msg.unwrap(), OvpnMessage::Success(_)));
}

// ---  ---
// >HOLD notification — blocking state machine
// Source: https://forums.openvpn.net/viewtopic.php?t=32748
//         (Client hangs at "Need hold release from management interface")
//         https://deepwiki.com/OpenVPN/openvpn/8-management-interface
//         (HOLD/RELEASE state machine)
//
// >HOLD: blocks the OpenVPN daemon until `hold release` is issued.
// If the management client never responds, the server hangs.
// ---  ---

#[test]
fn hold_notification_with_counter() {
    let msgs = decode_all(">HOLD:Waiting for hold release:0\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Hold { text }) => {
            assert_eq!(text, "Waiting for hold release:0");
        }
        other => panic!("expected Hold, got: {other:?}"),
    }
}

#[test]
fn hold_notification_with_nonzero_counter() {
    // Counter > 0 means this is a restart hold, not the initial one.
    let msgs = decode_all(">HOLD:Waiting for hold release:5\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Hold { text }) => {
            assert_eq!(text, "Waiting for hold release:5");
        }
        other => panic!("expected Hold, got: {other:?}"),
    }
}

// ---  ---
// >CLIENT:ESTABLISHED — no KID field
// Source: management-notes.txt
//         ESTABLISHED and DISCONNECT have only CID (no KID).
//         ENV block may include bytes_received/bytes_sent.
// ---  ---

#[test]
fn client_established_has_no_kid() {
    let input = "\
        >CLIENT:ESTABLISHED,7\n\
        >CLIENT:ENV,common_name=user1\n\
        >CLIENT:ENV,END\n";
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Client {
            event, cid, kid, ..
        }) => {
            assert_eq!(*event, ClientEvent::Established);
            assert_eq!(*cid, 7);
            assert_eq!(*kid, None, "ESTABLISHED should not have KID");
        }
        other => panic!("expected Client ESTABLISHED, got: {other:?}"),
    }
}

// ---  ---
// >CLIENT:ADDRESS — single-line notification (no ENV block)
// Source: manage.c — management_learn_addr()
//         ADDRESS,{CID},{IP},{PRIMARY}
// ---  ---

#[test]
fn client_address_ipv6() {
    let msgs = decode_all(">CLIENT:ADDRESS,3,fd00::1,1\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::ClientAddress { cid, addr, primary }) => {
            assert_eq!(*cid, 3);
            assert_eq!(addr, "fd00::1");
            assert!(*primary);
        }
        other => panic!("expected ClientAddress, got: {other:?}"),
    }
}

// ---  ---
// Static challenge (SC:) — flag bits
// Source: management-notes.txt
//         SC:{flag},{challenge_text}
//         flag bit 0 = ECHO, bit 1 = RESPONSE_CONCAT (FORMAT)
//
// Flag value 0: no echo, base64 SCRV1 format.
// Flag value 1: echo, base64 SCRV1 format.
// Flag value 3: echo + response concatenated with password as plain text.
// ---  ---

#[test]
fn static_challenge_flag_3_echo_and_concat() {
    let msgs = decode_all(">PASSWORD:Need 'Auth' username/password SC:3,Enter backup code\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::StaticChallenge {
                echo,
                response_concat,
                challenge,
            },
        )) => {
            assert!(*echo, "bit 0 should be set for flag=3");
            assert!(*response_concat, "bit 1 should be set for flag=3");
            assert_eq!(challenge, "Enter backup code");
        }
        other => panic!("expected StaticChallenge, got: {other:?}"),
    }
}

#[test]
fn static_challenge_with_colon_in_challenge_text() {
    // Challenge text can contain commas and colons.
    let msgs = decode_all(
        ">PASSWORD:Need 'Auth' username/password SC:1,Enter PIN for device: YubiKey 5\n",
    );
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Password(
            PasswordNotification::StaticChallenge { challenge, .. },
        )) => {
            // split_once(',') ensures only the first comma is the delimiter.
            assert_eq!(challenge, "Enter PIN for device: YubiKey 5");
        }
        other => panic!("expected StaticChallenge, got: {other:?}"),
    }
}

// ---  ---
// Management password prompt — 3-attempt limit
// Source: manage.c man_check_password()
//         After 3 failed attempts, the server closes the connection.
//
// The password prompt is "ENTER PASSWORD:" followed by a newline.
// ---  ---

#[test]
fn management_password_prompt_parsed() {
    let msgs = decode_all("ENTER PASSWORD:\n");
    assert_eq!(msgs.len(), 1);
    assert!(
        matches!(&msgs[0], OvpnMessage::PasswordPrompt),
        "expected PasswordPrompt, got: {:?}",
        msgs[0]
    );
}

// ---  ---
// >NOTIFY: notification — simple fallback
// Source: manage.c — man_output_standalone()
//         >NOTIFY:info,remote-exit,EXIT
// ---  ---

#[test]
fn notify_notification_degrades_to_simple() {
    let msgs = decode_all(">NOTIFY:info,remote-exit,EXIT\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Simple { kind, payload }) => {
            assert_eq!(kind, "NOTIFY");
            assert_eq!(payload, "info,remote-exit,EXIT");
        }
        other => panic!("expected Simple for NOTIFY, got: {other:?}"),
    }
}

// ---  ---
// >FATAL: with various real-world messages
// Source: manage.c — fatal notifications from TAP driver, timeout, etc.
// ---  ---

#[test]
fn fatal_tap_driver_error() {
    let msgs = decode_all(">FATAL:There are no TAP-Windows adapters on this system.\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::Fatal { message }) => {
            assert!(message.contains("TAP-Windows"));
        }
        other => panic!("expected Fatal, got: {other:?}"),
    }
}

// ---  ---
// >REMOTE: notification with hostname (not just IP)
// Source: NordSecurity/gopenvpn — STATE with hostname as remote IP
// ---  ---

#[test]
fn state_with_hostname_as_remote() {
    let msgs = decode_all(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.1,vpn.example.com,1194,,\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State(StateEntry {
            remote_ip,
            remote_port,
            ..
        })) => {
            assert_eq!(remote_ip, "vpn.example.com");
            assert_eq!(*remote_port, Some(1194));
        }
        other => panic!("expected State, got: {other:?}"),
    }
}

// ---  ---
// >STATE: with IPv6 local address (field 9)
// Source: manage.h — tun_local_ipv6 field added in later versions
// ---  ---

#[test]
fn state_with_ipv6_local_address() {
    let msgs =
        decode_all(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.1,1.2.3.4,1194,,1194,fd00::1\n");
    assert_eq!(msgs.len(), 1);
    match &msgs[0] {
        OvpnMessage::Notification(Notification::State(StateEntry { local_ipv6, .. })) => {
            assert_eq!(local_ipv6, "fd00::1");
        }
        other => panic!("expected State, got: {other:?}"),
    }
}
