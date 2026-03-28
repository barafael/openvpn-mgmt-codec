//! Adversarial roundtrip tests.
//!
//! These tests encode commands with tricky or edge-case inputs, then
//! decode the wire output to verify that the result is a valid, single
//! message — not a split/corrupted command.
//!
//! Injection-specific tests (newline, null byte, bare CR, END injection,
//! strict-mode rejection) live in `tests/defensive/` — this file covers
//! encoding edge cases that are *not* injection vectors: escaping,
//! unicode, empty strings, long payloads, and self-decode behaviour.

mod common;

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

use common::encode_str;

// --- Helpers ---

/// Encode a command, simulate the server echoing SUCCESS for it, and
/// verify decode produces exactly one message.
fn encode_decode_single_success(cmd: OvpnCommand) -> OvpnMessage {
    let msgs = common::encode_then_decode(cmd, "SUCCESS: ok\n");
    assert_eq!(msgs.len(), 1, "expected 1 message, got {}", msgs.len());
    msgs.into_iter().next().unwrap()
}

// ---  ---
// Escaping edge cases
// ---  ---

#[test]
fn password_with_backslashes_and_quotes() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: r#"p@ss\"word"#.into(),
    });
    assert_eq!(wire.lines().count(), 1, "must be single line: {wire:?}");
    assert!(wire.starts_with("password "));
}

#[test]
fn password_with_only_special_chars() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: r#"\"\\\"\\\\""#.into(),
    });
    assert_eq!(wire.lines().count(), 1);
}

#[test]
fn password_with_unicode() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "пароль密码パスワード".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.contains("пароль"));
}

#[test]
fn password_empty_string() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    // Should still have quoted empty string
    assert!(wire.contains("\"\""));
}

#[test]
fn password_with_spaces() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "my complex password with spaces".into(),
    });
    assert_eq!(wire.lines().count(), 1);
}

#[test]
fn custom_auth_type_with_spaces() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Unknown("My Custom Auth".to_string()),
        value: "pass".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    // The auth type must be properly quoted
    assert!(wire.contains("My Custom Auth"));
}

#[test]
fn client_deny_without_client_reason() {
    let wire = encode_str(OvpnCommand::ClientDeny(ClientDeny {
        cid: 1,
        kid: 0,
        reason: "simple reason".to_string(),
        client_reason: None,
    }));
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.starts_with("client-deny 1 0 "));
}

// ---  ---
// Roundtrip integrity: encode → server SUCCESS → decode
// ---  ---

#[test]
fn roundtrip_needstr_with_special_chars() {
    let msg = encode_decode_single_success(OvpnCommand::NeedStr {
        name: "prompt".to_string(),
        value: "value with \"quotes\" and \\backslashes\\".to_string(),
    });
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[test]
fn roundtrip_proxy_http_with_nct() {
    let msg = encode_decode_single_success(OvpnCommand::Proxy(ProxyAction::Http {
        host: "proxy.example.com".to_string(),
        port: 8080,
        non_cleartext_only: true,
    }));
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[test]
fn roundtrip_remote_mod() {
    let msg = encode_decode_single_success(OvpnCommand::Remote(RemoteAction::Modify {
        host: "newhost.example.com".to_string(),
        port: 443,
    }));
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[test]
fn roundtrip_client_pending_auth() {
    let msg = encode_decode_single_success(OvpnCommand::ClientPendingAuth {
        cid: 42,
        kid: 1,
        extra: "WEB_AUTH::http://auth.example.com/callback".to_string(),
        timeout: 300,
    });
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[test]
fn roundtrip_cr_response() {
    let msg = encode_decode_single_success(OvpnCommand::CrResponse {
        response: "base64encodedresponse==".into(),
    });
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

// ---  ---
// Self-decode: encode then decode own wire output
// ---  ---

#[test]
fn self_decode_simple_commands_produce_success_or_unrecognized() {
    // Simple commands produce bare text lines. Without server response
    // framing, the decoder will see them as unrecognized (expected:
    // SuccessOrError). This tests that the codec doesn't panic.
    for cmd in [
        OvpnCommand::Pid,
        OvpnCommand::ForgetPasswords,
        OvpnCommand::HoldQuery,
        OvpnCommand::Pkcs11IdCount,
        OvpnCommand::LoadStats,
    ] {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(cmd, &mut buf).unwrap();
        let mut msgs = Vec::new();
        while let Some(msg) = codec.decode(&mut buf).unwrap() {
            msgs.push(msg);
        }
        assert_eq!(msgs.len(), 1);
    }
}

#[test]
fn self_decode_multiline_command_body_becomes_multiline_response() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::ClientAuth {
                cid: 1,
                kid: 0,
                config_lines: vec!["push \"route 10.0.0.0 255.0.0.0\"".to_string()],
            },
            &mut buf,
        )
        .unwrap();
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    // We get messages without panicking — that's the key assertion.
    assert!(!msgs.is_empty());
}

// ---  ---
// Very long inputs
// ---  ---

#[test]
fn very_long_password_encodes_successfully() {
    let long_pw = "x".repeat(100_000);
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: Redacted::new(long_pw),
    });
    assert_eq!(wire.lines().count(), 1);
}

#[test]
fn very_long_config_lines_encode_successfully() {
    let lines: Vec<String> = (0..1000)
        .map(|idx| format!("push \"route 10.{}.0.0 255.255.0.0\"", idx % 256))
        .collect();
    let wire = encode_str(OvpnCommand::ClientAuth {
        cid: 1,
        kid: 0,
        config_lines: lines,
    });
    // 1 header + 1000 config + 1 END = 1002
    assert_eq!(wire.lines().count(), 1002);
}
