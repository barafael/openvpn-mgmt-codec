//! Defensive tests beyond the OpenVPN management interface spec.
//!
//! The [protocol spec][spec] was designed for a trusted, local management
//! client and is silent on what happens when string values contain
//! newlines, when multi-line block bodies contain a bare `END` line, or
//! when `AuthType::Unknown` carries metacharacters.
//!
//! These tests cover both encoder modes:
//! - **Sanitize** (default): asserts safe stripping/escaping behavior.
//! - **Strict**: asserts that the encoder rejects unsafe inputs with errors.
//!
//! [spec]: https://openvpn.net/community-docs/management-interface.html

mod real_world;

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use tokio_util::codec::{Decoder, Encoder};

// --- Helpers ---

/// Encode a command in the default (Sanitize) mode and return the wire bytes.
fn encode(cmd: OvpnCommand) -> String {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf).unwrap();
    String::from_utf8(buf.to_vec()).unwrap()
}

/// Try to encode a command in Strict mode.
fn try_encode_strict(cmd: OvpnCommand) -> Result<String, std::io::Error> {
    let mut codec = OvpnCodec::new().with_encoder_mode(EncoderMode::Strict);
    let mut buf = BytesMut::new();
    codec.encode(cmd, &mut buf)?;
    Ok(String::from_utf8(buf.to_vec()).unwrap())
}

// ---  ---
// 1. Newline injection via quote_and_escape
// ---  ---
//
// quote_and_escape only escapes `\` and `"`.  A newline byte passes
// through verbatim, splitting one command into two on the wire.

#[test]
fn password_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "hunter2\nsignal SIGTERM".into(),
    });

    // Safe behaviour: the encoded output must be exactly ONE line.
    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "password with embedded newline produced {line_count} wire lines — \
         command injection!\nwire: {wire:?}"
    );
}

#[test]
fn username_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Username {
        auth_type: AuthType::Auth,
        value: "admin\nkill all".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "username with embedded newline produced {line_count} wire lines — \
         command injection!\nwire: {wire:?}"
    );
}

#[test]
fn client_deny_reason_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::ClientDeny {
        cid: 1,
        kid: 0,
        reason: "banned\nsignal SIGTERM".into(),
        client_reason: None,
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "client-deny reason with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn client_deny_client_reason_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::ClientDeny {
        cid: 1,
        kid: 0,
        reason: "policy".into(),
        client_reason: Some("sorry\nexit".into()),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "client-deny client_reason with embedded newline produced \
         {line_count} wire lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn needstr_value_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::NeedStr {
        name: "token".into(),
        value: "abc\nexit".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "needstr value with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn challenge_response_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::ChallengeResponse {
        state_id: "state123".into(),
        response: "resp\nexit".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "challenge-response with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn static_challenge_response_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::StaticChallengeResponse {
        password_b64: "cGFzcw==\nexit".into(),
        response_b64: "cmVzcA==".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "static-challenge-response with embedded newline produced \
         {line_count} wire lines — command injection!\nwire: {wire:?}"
    );
}

// ---  ---
// 2. Newline injection in unescaped string fields
// ---  ---
//
// These fields are interpolated into the wire format with no escaping
// at all — not even quote_and_escape.

#[test]
fn kill_common_name_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName(
        "victim\nsignal SIGTERM".into(),
    )));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "kill CN with embedded newline produced {line_count} wire lines — \
         command injection!\nwire: {wire:?}"
    );
}

#[test]
fn remote_mod_host_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Remote(RemoteAction::Modify {
        host: "evil.com\nsignal SIGTERM".into(),
        port: 1194,
    }));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "remote MOD host with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn proxy_http_host_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Proxy(ProxyAction::Http {
        host: "proxy.evil\nsignal SIGTERM".into(),
        port: 8080,
        non_cleartext_only: false,
    }));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "proxy HTTP host with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn proxy_socks_host_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Proxy(ProxyAction::Socks {
        host: "proxy.evil\nsignal SIGTERM".into(),
        port: 1080,
    }));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "proxy SOCKS host with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn needok_name_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::NeedOk {
        name: "prompt\nexit".into(),
        response: NeedOkResponse::Ok,
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "needok name with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn needstr_name_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::NeedStr {
        name: "prompt\nexit".into(),
        value: "safe".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "needstr name with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn cr_response_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::CrResponse {
        response: "resp\nexit".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "cr-response with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn client_pending_auth_extra_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::ClientPendingAuth {
        cid: 0,
        kid: 0,
        extra: "data\nexit".into(),
        timeout: 30,
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "client-pending-auth extra with embedded newline produced \
         {line_count} wire lines — command injection!\nwire: {wire:?}"
    );
}

// ---  ---
// 3. END injection in multi-line blocks
// ---  ---
//
// write_block writes body lines verbatim.  A line that is exactly
// "END" terminates the block early; remaining lines become standalone
// commands on the wire.

#[test]
fn client_auth_end_in_config_lines_must_not_split_block() {
    let wire = encode(OvpnCommand::ClientAuth {
        cid: 0,
        kid: 1,
        config_lines: vec![
            "push \"route 10.0.0.0 255.0.0.0\"".into(),
            "END".into(),
            "signal SIGTERM".into(),
        ],
    });

    // Count "END" occurrences — a safe encoder must have exactly ONE
    // terminal END, not an early one that splits the block.
    let end_count = wire.lines().filter(|line| *line == "END").count();
    assert_eq!(
        end_count, 1,
        "client-auth config_lines containing 'END' produced {end_count} \
         END markers — block split / command injection!\nwire: {wire:?}"
    );
}

#[test]
fn rsa_sig_end_in_base64_must_not_split_block() {
    let wire = encode(OvpnCommand::RsaSig {
        base64_lines: vec!["AAAA".into(), "END".into(), "signal SIGTERM".into()],
    });

    let end_count = wire.lines().filter(|line| *line == "END").count();
    assert_eq!(
        end_count, 1,
        "rsa-sig base64_lines containing 'END' produced {end_count} \
         END markers — block split / command injection!\nwire: {wire:?}"
    );
}

#[test]
fn certificate_end_in_pem_must_not_split_block() {
    let wire = encode(OvpnCommand::Certificate {
        pem_lines: vec![
            "-----BEGIN CERTIFICATE-----".into(),
            "END".into(),
            "signal SIGTERM".into(),
            "-----END CERTIFICATE-----".into(),
        ],
    });

    let end_count = wire.lines().filter(|line| *line == "END").count();
    assert_eq!(
        end_count, 1,
        "certificate pem_lines containing 'END' produced {end_count} \
         END markers — block split / command injection!\nwire: {wire:?}"
    );
}

#[test]
fn client_auth_newline_in_config_line_must_not_inject() {
    let wire = encode(OvpnCommand::ClientAuth {
        cid: 0,
        kid: 1,
        config_lines: vec!["push \"route 10.0.0.0 255.0.0.0\"\nsignal SIGTERM".into()],
    });

    // header + 1 body line + END = 3 lines.
    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 3,
        "client-auth config line with embedded newline produced \
         {line_count} wire lines (expected 3) — command injection!\nwire: {wire:?}"
    );
}

// ---  ---
// 4. auth_type quote breakout via AuthType::Unknown
// ---  ---
//
// auth_type is manually wrapped in `"..."` without escaping.
// An Unknown type containing `"` breaks out of the quoting.

#[test]
fn custom_auth_type_with_quote_must_not_break_framing() {
    let wire = encode(OvpnCommand::Username {
        auth_type: AuthType::Unknown("Auth\" injected".into()),
        value: "admin".into(),
    });

    // A safe encoder produces exactly one well-formed line.  Count the
    // unescaped quote characters — they should come in matched pairs
    // (one pair for auth_type, one pair for the escaped value).
    let line = wire.trim_end();
    assert!(
        !line.contains("Auth\" injected"),
        "auth_type quote was not escaped — breaks wire framing!\nwire: {wire:?}"
    );
}

#[test]
fn custom_auth_type_with_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Unknown("Auth\nsignal SIGTERM".into()),
        value: "pass".into(),
    });

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "Unknown auth_type with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

// ---  ---
// 5. Round-trip proof: injected command is actually parsed
// ---  ---
//
// These tests go one step further: encode a malicious payload, then
// feed the wire bytes back through the decoder.  If the decoder sees
// more than one message, a second command was successfully injected.

#[test]
fn password_injection_roundtrip_must_produce_single_message() {
    // Encode a password that embeds a fake SUCCESS line.
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::Password {
                auth_type: AuthType::Auth,
                value: "hunter2\nSUCCESS: injected".into(),
            },
            &mut buf,
        )
        .unwrap();

    // Now pretend the server echoed our bytes back (pathological, but
    // demonstrates the framing break).  Decode what we just encoded.
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }

    assert!(
        msgs.len() <= 1,
        "password injection produced {} decoded messages — the embedded \
         newline was treated as a line break!\nmessages: {msgs:#?}",
        msgs.len()
    );
}

#[test]
fn kill_injection_roundtrip_must_produce_single_message() {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::new();
    codec
        .encode(
            OvpnCommand::Kill(KillTarget::CommonName("victim\nSUCCESS: pwned".into())),
            &mut buf,
        )
        .unwrap();

    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }

    assert!(
        msgs.len() <= 1,
        "kill CN injection produced {} decoded messages — the embedded \
         newline was treated as a line break!\nmessages: {msgs:#?}",
        msgs.len()
    );
}

#[test]
fn client_auth_end_injection_roundtrip() {
    // Encode client-auth with an "END" body line followed by a payload
    // that looks like a successful command response.
    let mut codec = OvpnCodec::new();
    let mut enc = BytesMut::new();
    codec
        .encode(
            OvpnCommand::ClientAuth {
                cid: 0,
                kid: 1,
                config_lines: vec![
                    "push \"route 10.0.0.0 255.0.0.0\"".into(),
                    "END".into(),
                    "SUCCESS: injected".into(),
                ],
            },
            &mut enc,
        )
        .unwrap();

    // Verify the wire bytes: the body "END" must have been escaped so
    // the only bare END is the block terminator.
    let wire = String::from_utf8(enc.to_vec()).unwrap();
    let bare_end_count = wire.lines().filter(|line| *line == "END").count();
    assert_eq!(
        bare_end_count, 1,
        "encoded client-auth has {bare_end_count} bare END lines (expected \
         exactly 1 terminator)\nwire: {wire:?}"
    );

    // Now simulate the server response for this multi-line command and
    // verify the decoder does not see a spurious SUCCESS message.
    let mut dec = BytesMut::from("SUCCESS: client-auth command succeeded\n");
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut dec).unwrap() {
        msgs.push(msg);
    }

    assert_eq!(
        msgs.len(),
        1,
        "expected exactly 1 decoded SUCCESS message, got {}\nmessages: {msgs:#?}",
        msgs.len()
    );
    assert!(
        matches!(&msgs[0], OvpnMessage::Success(s) if s.contains("client-auth")),
        "expected SUCCESS response, got: {:?}",
        msgs[0]
    );
}

// ---  ---
// 6. Missed encoder fields (second-pass findings)
// ---  ---
//
// Found by auditing every `format!` interpolation in the encoder
// that was not covered by sections 1–4.  Kill(Address { ip }) and
// ManagementPassword were the two remaining paths that passed user
// strings to write_line without sanitize_line or quote_and_escape.

#[test]
fn kill_address_ip_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Kill(KillTarget::Address {
        protocol: TransportProtocol::Tcp,
        ip: "10.0.0.1\nsignal SIGTERM".to_string(),
        port: 1194,
    }));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "kill address ip with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

#[test]
fn management_password_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::ManagementPassword(
        "s3cret\nsignal SIGTERM".into(),
    ));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "management password with embedded newline produced {line_count} \
         wire lines — command injection!\nwire: {wire:?}"
    );
}

// ---  ---
// 7. Null byte injection
// ---  ---
//
// Null bytes are valid UTF-8 but are C string terminators.  OpenVPN's
// management interface is C code — a \0 in a password could truncate
// the value at the C layer, effectively shortening it:
//   password "Auth" "realpass\0ignored"  →  C sees "realpass"
//
// This is a well-known C interop attack vector.  Real-world precedent:
//   - https://github.com/OpenVPN/openvpn/issues/645
//     Clients appending \n\0 to 2FA responses.
//   - https://nvd.nist.gov/vuln/detail/CVE-2024-5594
//     Unsanitized control characters in PUSH_REPLY.
//   - https://community.openvpn.net/openvpn/ticket/908
//     Stray LF in passwords causing management client hangs.

#[test]
fn password_null_byte_must_be_stripped() {
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "real\0fake".into(),
    });

    assert!(
        !wire.contains('\0'),
        "password with null byte passed through to wire — C truncation \
         attack!\nwire bytes: {:?}",
        wire.as_bytes()
    );
}

#[test]
fn username_null_byte_must_be_stripped() {
    let wire = encode(OvpnCommand::Username {
        auth_type: AuthType::Auth,
        value: "admin\0root".into(),
    });

    assert!(
        !wire.contains('\0'),
        "username with null byte passed through to wire — C truncation \
         attack!\nwire bytes: {:?}",
        wire.as_bytes()
    );
}

#[test]
fn kill_common_name_null_byte_must_be_stripped() {
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName(
        "victim\0extra".into(),
    )));

    assert!(
        !wire.contains('\0'),
        "kill CN with null byte passed through to wire — C truncation \
         attack!\nwire bytes: {:?}",
        wire.as_bytes()
    );
}

#[test]
fn client_deny_reason_null_byte_must_be_stripped() {
    let wire = encode(OvpnCommand::ClientDeny {
        cid: 1,
        kid: 0,
        reason: "banned\0not really".into(),
        client_reason: None,
    });

    assert!(
        !wire.contains('\0'),
        "client-deny reason with null byte passed through to wire — \
         C truncation attack!\nwire bytes: {:?}",
        wire.as_bytes()
    );
}

#[test]
fn management_password_null_byte_must_be_stripped() {
    let wire = encode(OvpnCommand::ManagementPassword("pass\0word".into()));

    assert!(
        !wire.contains('\0'),
        "management password with null byte passed through to wire — \
         C truncation attack!\nwire bytes: {:?}",
        wire.as_bytes()
    );
}

#[test]
fn block_body_null_byte_must_be_stripped() {
    let wire = encode(OvpnCommand::ClientAuth {
        cid: 0,
        kid: 1,
        config_lines: vec!["push \"route 10.0.0.0\0 255.0.0.0\"".into()],
    });

    assert!(
        !wire.contains('\0'),
        "client-auth config line with null byte passed through to wire — \
         C truncation attack!\nwire bytes: {:?}",
        wire.as_bytes()
    );
}

// ---  ---
// 7b. Bare carriage-return (\r) injection
// ---  ---
//
// A bare \r (without \n) can cause display corruption on terminals
// that interpret CR as "move cursor to column 0", overwriting the
// visible command prefix.  It can also confuse line-based parsers
// that treat \r as a line separator.  The encoder must strip bare
// \r, just like \n and \0.

#[test]
fn password_bare_cr_must_be_stripped() {
    let wire = encode(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "hunter2\rsignal SIGTERM".into(),
    });

    assert!(
        !wire.contains('\r'),
        "password with bare \\r passed through to wire\nwire: {wire:?}"
    );
    // The value should be concatenated without the \r.
    assert!(
        wire.contains("hunter2signal SIGTERM"),
        "bare \\r was not stripped from password value\nwire: {wire:?}"
    );
}

#[test]
fn kill_common_name_bare_cr_must_be_stripped() {
    let wire = encode(OvpnCommand::Kill(KillTarget::CommonName(
        "victim\rsignal SIGTERM".into(),
    )));

    assert!(
        !wire.contains('\r'),
        "kill CN with bare \\r passed through to wire\nwire: {wire:?}"
    );
}

#[test]
fn strict_password_bare_cr_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "hunter2\rsignal SIGTERM".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_kill_common_name_bare_cr_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Kill(KillTarget::CommonName(
            "victim\rsignal SIGTERM".into(),
        )))
        .is_err()
    );
}

// ---  ---
// 8. Raw command newline injection
// ---  ---
//
// Raw is an escape hatch, but it should still not allow injecting
// multiple wire lines.  A user who builds `Raw("status\nkill all")`
// likely expects a single command, not two.
//
// Prior art: https://nvd.nist.gov/vuln/detail/CVE-2024-54780
// pfSense passed unsanitized user input (containing \n) to the
// OpenVPN management interface, allowing arbitrary command injection.

#[test]
fn raw_newline_must_not_inject_command() {
    let wire = encode(OvpnCommand::Raw("status\nkill all".into()));

    let line_count = wire.lines().count();
    assert_eq!(
        line_count, 1,
        "Raw command with embedded newline produced {line_count} wire \
         lines — command injection!\nwire: {wire:?}"
    );
}

// ---  ---
// 9. EncoderMode::Strict — reject unsafe inputs
// ---  ---
//
// In Strict mode, encode() returns Err for the same inputs that
// Sanitize mode silently strips. These tests mirror the Sanitize-mode
// tests above to ensure both modes are exercised.

#[test]
fn strict_password_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "hunter2\nsignal SIGTERM".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_username_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Username {
            auth_type: AuthType::Auth,
            value: "admin\nkill all".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_client_deny_reason_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ClientDeny {
            cid: 1,
            kid: 0,
            reason: "banned\nsignal SIGTERM".into(),
            client_reason: None,
        })
        .is_err()
    );
}

#[test]
fn strict_client_deny_client_reason_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ClientDeny {
            cid: 1,
            kid: 0,
            reason: "policy".into(),
            client_reason: Some("sorry\nexit".into()),
        })
        .is_err()
    );
}

#[test]
fn strict_needstr_value_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::NeedStr {
            name: "token".into(),
            value: "abc\nexit".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_challenge_response_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ChallengeResponse {
            state_id: "state123".into(),
            response: "resp\nexit".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_static_challenge_response_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::StaticChallengeResponse {
            password_b64: "cGFzcw==\nexit".into(),
            response_b64: "cmVzcA==".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_kill_common_name_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Kill(KillTarget::CommonName(
            "victim\nsignal SIGTERM".into(),
        )))
        .is_err()
    );
}

#[test]
fn strict_kill_address_ip_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Kill(KillTarget::Address {
            protocol: TransportProtocol::Tcp,
            ip: "10.0.0.1\nsignal SIGTERM".to_string(),
            port: 1194,
        }))
        .is_err()
    );
}

#[test]
fn strict_remote_mod_host_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Remote(RemoteAction::Modify {
            host: "evil.com\nsignal SIGTERM".into(),
            port: 1194,
        }))
        .is_err()
    );
}

#[test]
fn strict_proxy_http_host_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Proxy(ProxyAction::Http {
            host: "proxy.evil\nsignal SIGTERM".into(),
            port: 8080,
            non_cleartext_only: false,
        }))
        .is_err()
    );
}

#[test]
fn strict_proxy_socks_host_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Proxy(ProxyAction::Socks {
            host: "proxy.evil\nsignal SIGTERM".into(),
            port: 1080,
        }))
        .is_err()
    );
}

#[test]
fn strict_needok_name_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::NeedOk {
            name: "prompt\nexit".into(),
            response: NeedOkResponse::Ok,
        })
        .is_err()
    );
}

#[test]
fn strict_needstr_name_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::NeedStr {
            name: "prompt\nexit".into(),
            value: "safe".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_cr_response_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::CrResponse {
            response: "resp\nexit".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_client_pending_auth_extra_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ClientPendingAuth {
            cid: 0,
            kid: 0,
            extra: "data\nexit".into(),
            timeout: 30,
        })
        .is_err()
    );
}

#[test]
fn strict_management_password_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ManagementPassword(
            "s3cret\nsignal SIGTERM".into(),
        ))
        .is_err()
    );
}

#[test]
fn strict_raw_newline_rejected() {
    assert!(try_encode_strict(OvpnCommand::Raw("status\nkill all".into())).is_err());
}

#[test]
fn strict_password_null_byte_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Password {
            auth_type: AuthType::Auth,
            value: "real\0fake".into(),
        })
        .is_err()
    );
}

#[test]
fn strict_client_auth_end_in_config_lines_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ClientAuth {
            cid: 0,
            kid: 1,
            config_lines: vec![
                "push \"route 10.0.0.0 255.0.0.0\"".into(),
                "END".into(),
                "signal SIGTERM".into(),
            ],
        })
        .is_err()
    );
}

#[test]
fn strict_rsa_sig_end_in_base64_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::RsaSig {
            base64_lines: vec!["AAAA".into(), "END".into(), "signal SIGTERM".into()],
        })
        .is_err()
    );
}

#[test]
fn strict_certificate_end_in_pem_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Certificate {
            pem_lines: vec![
                "-----BEGIN CERTIFICATE-----".into(),
                "END".into(),
                "signal SIGTERM".into(),
                "-----END CERTIFICATE-----".into(),
            ],
        })
        .is_err()
    );
}

#[test]
fn strict_client_auth_newline_in_config_line_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::ClientAuth {
            cid: 0,
            kid: 1,
            config_lines: vec!["push \"route 10.0.0.0 255.0.0.0\"\nsignal SIGTERM".into()],
        })
        .is_err()
    );
}

#[test]
fn strict_custom_auth_type_with_newline_rejected() {
    assert!(
        try_encode_strict(OvpnCommand::Password {
            auth_type: AuthType::Unknown("Auth\nsignal SIGTERM".into()),
            value: "pass".into(),
        })
        .is_err()
    );
}

// --- Strict mode: clean inputs pass through ---

#[test]
fn strict_clean_password_accepted() {
    let result = try_encode_strict(OvpnCommand::Password {
        auth_type: AuthType::Auth,
        value: "hunter2".into(),
    });
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "password \"Auth\" \"hunter2\"\n");
}

#[test]
fn strict_clean_client_auth_accepted() {
    let result = try_encode_strict(OvpnCommand::ClientAuth {
        cid: 0,
        kid: 1,
        config_lines: vec!["push \"route 10.0.0.0 255.0.0.0\"".into()],
    });
    assert!(result.is_ok());
    let wire = result.unwrap();
    assert_eq!(wire.lines().count(), 3); // header + 1 body + END
}
