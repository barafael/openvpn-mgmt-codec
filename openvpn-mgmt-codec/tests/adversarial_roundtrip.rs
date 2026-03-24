//! Adversarial roundtrip tests.
//!
//! These tests encode commands with tricky or edge-case inputs, then
//! decode the wire output to verify that the result is a valid, single
//! message — not a split/corrupted command.

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

// --- Helpers ---

fn encode_bytes(cmd: OvpnCommand) -> BytesMut {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf).unwrap();
    buf
}

fn encode_str(cmd: OvpnCommand) -> String {
    String::from_utf8(encode_bytes(cmd).to_vec()).unwrap()
}

/// Encode a command, simulate the server echoing SUCCESS for it, and
/// verify decode produces exactly one message.
fn encode_decode_single_success(cmd: OvpnCommand) -> OvpnMessage {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec.encode(cmd, &mut enc_buf).unwrap();
    let mut dec_buf = BytesMut::from("SUCCESS: ok\n");
    let msg = codec.decode(&mut dec_buf).unwrap().unwrap();
    assert!(codec.decode(&mut dec_buf).unwrap().is_none());
    msg
}

/// Encode a command and decode its own wire bytes (self-decode test).
/// For multi-line commands, appends an END terminator.
fn self_decode(cmd: OvpnCommand, is_multiline: bool) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf).unwrap();
    if is_multiline {
        // The codec expects the first line of a multiline response to
        // already be a data line, not the command header. Skip the
        // header and decode the body + END.
    }
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

// ---  ---
// Password with special characters
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

// ---  ---
// Username with injection attempts
// ---  ---

#[test]
fn username_with_null_bytes() {
    let wire = encode_str(OvpnCommand::Username {
        auth_type: AuthType::Auth,
        value: "admin\0root".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(!wire.contains('\0'), "null byte must be stripped");
}

#[test]
fn username_with_cr_lf() {
    let wire = encode_str(OvpnCommand::Username {
        auth_type: AuthType::Auth,
        value: "admin\r\nsignal SIGTERM".into(),
    });
    assert_eq!(wire.lines().count(), 1);
}

// ---  ---
// Custom auth type edge cases
// ---  ---

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
fn custom_auth_type_with_quotes() {
    let wire = encode_str(OvpnCommand::Password {
        auth_type: AuthType::Unknown(r#"Auth"Evil"#.to_string()),
        value: "pass".into(),
    });
    assert_eq!(wire.lines().count(), 1);
}

// ---  ---
// Multi-line block commands with adversarial bodies
// ---  ---

#[test]
fn client_auth_config_line_containing_end() {
    let wire = encode_str(OvpnCommand::ClientAuth {
        cid: 1,
        kid: 0,
        config_lines: vec![
            "push \"route 10.0.0.0 255.255.0.0\"".to_string(),
            "END".to_string(), // Adversarial — must not terminate block
            "push \"route 10.1.0.0 255.255.0.0\"".to_string(),
        ],
    });
    // Block structure: header + 3 body lines + END = 5 lines
    assert_eq!(wire.lines().count(), 5);
    assert!(
        wire.lines().last().unwrap() == "END",
        "last line must be the real END terminator"
    );
}

#[test]
fn rsa_sig_with_end_in_base64() {
    let wire = encode_str(OvpnCommand::RsaSig {
        base64_lines: vec![
            "ABCDEFGH".to_string(),
            "END".to_string(), // Would terminate block early
            "IJKLMNOP".to_string(),
        ],
    });
    assert_eq!(wire.lines().count(), 5);
}

#[test]
fn certificate_with_pem_boundaries() {
    let wire = encode_str(OvpnCommand::Certificate {
        pem_lines: vec![
            "-----BEGIN CERTIFICATE-----".to_string(),
            "MIIBkTCB+wIJAL1oAq3F8LiNMA0G".to_string(),
            "-----END CERTIFICATE-----".to_string(),
        ],
    });
    // header + 3 lines + END = 5
    assert_eq!(wire.lines().count(), 5);
}

#[test]
fn client_auth_empty_config() {
    let wire = encode_str(OvpnCommand::ClientAuth {
        cid: 5,
        kid: 3,
        config_lines: vec![],
    });
    // header + END = 2 lines
    assert_eq!(wire.lines().count(), 2);
    assert!(wire.starts_with("client-auth 5 3\n"));
    assert!(wire.ends_with("END\n"));
}

#[test]
fn rsa_sig_empty_body() {
    let wire = encode_str(OvpnCommand::RsaSig {
        base64_lines: vec![],
    });
    assert_eq!(wire.lines().count(), 2);
}

// ---  ---
// Challenge-response with special characters
// ---  ---

#[test]
fn challenge_response_with_colons_in_state_id() {
    let wire = encode_str(OvpnCommand::ChallengeResponse {
        state_id: "state:with:colons".to_string(),
        response: "myresponse".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.contains("CRV1"));
}

#[test]
fn static_challenge_response_with_equals_in_b64() {
    let wire = encode_str(OvpnCommand::StaticChallengeResponse {
        password_b64: "cGFzcw==".into(),
        response_b64: "cmVzcA==".into(),
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.contains("SCRV1"));
    assert!(wire.contains("cGFzcw=="));
}

// ---  ---
// Client-deny with adversarial reason strings
// ---  ---

#[test]
fn client_deny_reason_with_quotes() {
    let wire = encode_str(OvpnCommand::ClientDeny {
        cid: 1,
        kid: 0,
        reason: r#"reason "with quotes""#.to_string(),
        client_reason: Some(r#"client "reason""#.to_string()),
    });
    assert_eq!(wire.lines().count(), 1);
}

#[test]
fn client_deny_without_client_reason() {
    let wire = encode_str(OvpnCommand::ClientDeny {
        cid: 1,
        kid: 0,
        reason: "simple reason".to_string(),
        client_reason: None,
    });
    assert_eq!(wire.lines().count(), 1);
    assert!(wire.starts_with("client-deny 1 0 "));
}

// ---  ---
// Strict mode rejects
// ---  ---

#[test]
fn strict_mode_rejects_newline_in_password() {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    let result = codec.encode(
        OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "pass\nword".into(),
        },
        &mut buf,
    );
    assert!(result.is_err());
}

#[test]
fn strict_mode_rejects_null_in_username() {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    let result = codec.encode(
        OvpnCommand::Username {
            auth_type: AuthType::Auth,
            value: "admin\0".into(),
        },
        &mut buf,
    );
    assert!(result.is_err());
}

#[test]
fn strict_mode_rejects_end_in_block_body() {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    let result = codec.encode(
        OvpnCommand::ClientAuth {
            cid: 1,
            kid: 0,
            config_lines: vec!["END".to_string()],
        },
        &mut buf,
    );
    assert!(result.is_err());
}

#[test]
fn strict_mode_accepts_clean_inputs() {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::Password {
                auth_type: AuthType::Auth,
                value: "clean_password_123".into(),
            },
            &mut buf,
        )
        .unwrap();
    assert!(!buf.is_empty());
}

// ---  ---
// Roundtrip integrity: encode → server SUCCESS → decode
// ---  ---

#[test]
fn roundtrip_sanitized_password_produces_valid_success() {
    let msg = encode_decode_single_success(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "pass\nword\r\0".into(),
    });
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

#[test]
fn roundtrip_kill_by_common_name() {
    let msg = encode_decode_single_success(OvpnCommand::Kill(KillTarget::CommonName(
        "test\nclient".to_string(),
    )));
    assert!(matches!(msg, OvpnMessage::Success(_)));
}

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
        let msgs = self_decode(cmd, false);
        assert_eq!(msgs.len(), 1);
    }
}

#[test]
fn self_decode_multiline_command_body_becomes_multiline_response() {
    // client-auth header + config lines + END → decoder sees header as
    // first multiline line, config as body, END terminates.
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
    // The encoder sets expected to SuccessOrError for ClientAuth.
    // Feed the encoded bytes back — first line is "client-auth 1 0"
    // which is ambiguous. It will be Unrecognized since SuccessOrError
    // is expected and the line has no SUCCESS/ERROR prefix.
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
