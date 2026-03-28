//! Notification parser edge case tests.
//!
//! These test the decoder's notification parsers with malformed, truncated,
//! or unusual payloads to verify graceful degradation to `Notification::Simple`.

mod common;

use openvpn_mgmt_codec::*;

use common::decode_all;

// --- Helpers ---

fn decode_single(input: &str) -> OvpnMessage {
    let msgs = decode_all(input);
    assert_eq!(msgs.len(), 1, "expected 1 message, got {}", msgs.len());
    msgs.into_iter().next().unwrap()
}

fn expect_notification(input: &str) -> Notification {
    match decode_single(input) {
        OvpnMessage::Notification(notification) => notification,
        other => panic!("expected Notification, got {other:?}"),
    }
}

fn expect_simple(input: &str) -> (String, String) {
    match expect_notification(input) {
        Notification::Simple { kind, payload } => (kind, payload),
        other => panic!("expected Simple fallback, got {other:?}"),
    }
}

// ---  ---
// STATE notification edge cases
// ---  ---

#[test]
fn state_minimal_fields() {
    // Only timestamp, state name, desc, local_ip, remote_ip are required
    // (the parser needs 5 fields via .next()?)
    let notification =
        expect_notification(">STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4\n");
    assert!(matches!(
        notification,
        Notification::State {
            timestamp: 1711000000,
            name: OpenVpnState::Connected,
            ..
        }
    ));
}

#[test]
fn state_empty_optional_fields() {
    let notification = expect_notification(">STATE:1711000000,CONNECTING,,,,,,\n");
    assert!(matches!(
        notification,
        Notification::State {
            name: OpenVpnState::Connecting,
            ..
        }
    ));
}

#[test]
fn state_non_numeric_timestamp_falls_back_to_simple() {
    let (kind, _) = expect_simple(">STATE:not_a_number,CONNECTED,SUCCESS,,,,,\n");
    assert_eq!(kind, "STATE");
}

#[test]
fn state_empty_payload_falls_back_to_simple() {
    let (kind, payload) = expect_simple(">STATE:\n");
    assert_eq!(kind, "STATE");
    assert_eq!(payload, "");
}

#[test]
fn state_too_few_fields_falls_back_to_simple() {
    // Only 2 fields — need at least 5
    let (kind, _) = expect_simple(">STATE:1711000000,CONNECTED\n");
    assert_eq!(kind, "STATE");
}

#[test]
fn state_with_all_nine_fields() {
    let notification = expect_notification(
        ">STATE:1711000000,CONNECTED,SUCCESS,10.0.0.2,1.2.3.4,1194,192.168.1.5,51234,fd00::1\n",
    );
    if let Notification::State {
        local_ipv6,
        remote_port,
        ..
    } = notification
    {
        assert_eq!(local_ipv6, "fd00::1");
        assert_eq!(remote_port, Some(1194));
    } else {
        panic!("expected State");
    }
}

#[test]
fn state_unknown_state_name() {
    let notification = expect_notification(">STATE:1711000000,FUTURE_STATE,desc,,,,,\n");
    if let Notification::State { name, .. } = notification {
        assert!(matches!(name, OpenVpnState::Unknown(s) if s == "FUTURE_STATE"));
    } else {
        panic!("expected State");
    }
}

// ---  ---
// BYTECOUNT edge cases
// ---  ---

#[test]
fn bytecount_zero_values() {
    let notification = expect_notification(">BYTECOUNT:0,0\n");
    assert!(matches!(
        notification,
        Notification::ByteCount {
            bytes_in: 0,
            bytes_out: 0
        }
    ));
}

#[test]
fn bytecount_large_values() {
    let notification =
        expect_notification(">BYTECOUNT:18446744073709551615,18446744073709551615\n");
    assert!(matches!(
        notification,
        Notification::ByteCount {
            bytes_in: u64::MAX,
            bytes_out: u64::MAX,
        }
    ));
}

#[test]
fn bytecount_non_numeric_falls_back_to_simple() {
    let (kind, _) = expect_simple(">BYTECOUNT:abc,def\n");
    assert_eq!(kind, "BYTECOUNT");
}

#[test]
fn bytecount_missing_second_field_falls_back_to_simple() {
    let (kind, _) = expect_simple(">BYTECOUNT:100\n");
    assert_eq!(kind, "BYTECOUNT");
}

#[test]
fn bytecount_empty_falls_back_to_simple() {
    let (kind, _) = expect_simple(">BYTECOUNT:\n");
    assert_eq!(kind, "BYTECOUNT");
}

#[test]
fn bytecount_negative_falls_back_to_simple() {
    let (kind, _) = expect_simple(">BYTECOUNT:-1,100\n");
    assert_eq!(kind, "BYTECOUNT");
}

#[test]
fn bytecount_cli_valid() {
    let notification = expect_notification(">BYTECOUNT_CLI:42,1024,2048\n");
    assert!(matches!(
        notification,
        Notification::ByteCountCli {
            cid: 42,
            bytes_in: 1024,
            bytes_out: 2048,
        }
    ));
}

#[test]
fn bytecount_cli_missing_field_falls_back() {
    let (kind, _) = expect_simple(">BYTECOUNT_CLI:42,1024\n");
    assert_eq!(kind, "BYTECOUNT_CLI");
}

// ---  ---
// LOG edge cases
// ---  ---

#[test]
fn log_with_commas_in_message() {
    let notification = expect_notification(">LOG:1711000000,I,message with, commas, inside\n");
    if let Notification::Log { level, message, .. } = notification {
        assert_eq!(level, LogLevel::Info);
        assert_eq!(message, "message with, commas, inside");
    } else {
        panic!("expected Log");
    }
}

#[test]
fn log_unknown_level() {
    let notification = expect_notification(">LOG:1711000000,X,some message\n");
    if let Notification::Log { level, .. } = notification {
        assert!(matches!(level, LogLevel::Unknown(s) if s == "X"));
    } else {
        panic!("expected Log");
    }
}

#[test]
fn log_empty_message() {
    let notification = expect_notification(">LOG:1711000000,I,\n");
    if let Notification::Log { message, .. } = notification {
        assert_eq!(message, "");
    } else {
        panic!("expected Log");
    }
}

#[test]
fn log_non_numeric_timestamp_falls_back() {
    let (kind, _) = expect_simple(">LOG:bad,I,message\n");
    assert_eq!(kind, "LOG");
}

#[test]
fn log_missing_fields_falls_back() {
    let (kind, _) = expect_simple(">LOG:1711000000\n");
    assert_eq!(kind, "LOG");
}

// ---  ---
// ECHO edge cases
// ---  ---

#[test]
fn echo_with_commas() {
    let notification = expect_notification(">ECHO:1711000000,key=value,extra,data\n");
    if let Notification::Echo { param, .. } = notification {
        assert_eq!(param, "key=value,extra,data");
    } else {
        panic!("expected Echo");
    }
}

#[test]
fn echo_empty_param() {
    let notification = expect_notification(">ECHO:1711000000,\n");
    if let Notification::Echo { param, .. } = notification {
        assert_eq!(param, "");
    } else {
        panic!("expected Echo");
    }
}

// ---  ---
// PASSWORD notification edge cases
// ---  ---

#[test]
fn password_need_auth_all_known_types() {
    for (wire, expected) in [
        ("Auth", AuthType::Auth),
        ("Private Key", AuthType::PrivateKey),
        ("HTTP Proxy", AuthType::HttpProxy),
        ("SOCKS Proxy", AuthType::SocksProxy),
    ] {
        let notification =
            expect_notification(&format!(">PASSWORD:Need '{wire}' username/password\n"));
        assert!(matches!(
            &notification,
            Notification::Password(PasswordNotification::NeedAuth { auth_type })
            if *auth_type == expected
        ));
    }
}

#[test]
fn password_need_password_private_key() {
    let notification = expect_notification(">PASSWORD:Need 'Private Key' password\n");
    assert!(matches!(
        notification,
        Notification::Password(PasswordNotification::NeedPassword {
            auth_type: AuthType::PrivateKey,
        })
    ));
}

#[test]
fn password_custom_auth_type() {
    let notification = expect_notification(">PASSWORD:Need 'MyPlugin' username/password\n");
    assert!(matches!(
        &notification,
        Notification::Password(PasswordNotification::NeedAuth { auth_type })
        if *auth_type == AuthType::Unknown("MyPlugin".to_string())
    ));
}

#[test]
fn password_verification_failed() {
    let notification = expect_notification(">PASSWORD:Verification Failed: 'Auth'\n");
    assert!(matches!(
        notification,
        Notification::Password(PasswordNotification::VerificationFailed {
            auth_type: AuthType::Auth,
        })
    ));
}

#[test]
fn password_auth_token() {
    let notification = expect_notification(">PASSWORD:Auth-Token:abc123xyz\n");
    if let Notification::Password(PasswordNotification::AuthToken { token }) = notification {
        assert_eq!(token.expose(), "abc123xyz");
    } else {
        panic!("expected AuthToken, got {notification:?}");
    }
}

#[test]
fn password_auth_token_empty() {
    let notification = expect_notification(">PASSWORD:Auth-Token:\n");
    if let Notification::Password(PasswordNotification::AuthToken { token }) = notification {
        assert_eq!(token.expose(), "");
    } else {
        panic!("expected AuthToken");
    }
}

#[test]
fn password_static_challenge_echo_and_concat_flags() {
    // flag=0: echo=false, response_concat=false
    let notification =
        expect_notification(">PASSWORD:Need 'Auth' username/password SC:0,Enter PIN\n");
    if let Notification::Password(PasswordNotification::StaticChallenge {
        echo,
        response_concat,
        challenge,
    }) = notification
    {
        assert!(!echo);
        assert!(!response_concat);
        assert_eq!(challenge, "Enter PIN");
    } else {
        panic!("expected StaticChallenge");
    }

    // flag=1: echo=true, response_concat=false
    let notification =
        expect_notification(">PASSWORD:Need 'Auth' username/password SC:1,Enter OTP\n");
    if let Notification::Password(PasswordNotification::StaticChallenge {
        echo,
        response_concat,
        ..
    }) = notification
    {
        assert!(echo);
        assert!(!response_concat);
    } else {
        panic!("expected StaticChallenge");
    }

    // flag=2: echo=false, response_concat=true
    let notification =
        expect_notification(">PASSWORD:Need 'Auth' username/password SC:2,Challenge\n");
    if let Notification::Password(PasswordNotification::StaticChallenge {
        echo,
        response_concat,
        ..
    }) = notification
    {
        assert!(!echo);
        assert!(response_concat);
    } else {
        panic!("expected StaticChallenge");
    }

    // flag=3: echo=true, response_concat=true
    let notification = expect_notification(">PASSWORD:Need 'Auth' username/password SC:3,Both\n");
    if let Notification::Password(PasswordNotification::StaticChallenge {
        echo,
        response_concat,
        ..
    }) = notification
    {
        assert!(echo);
        assert!(response_concat);
    } else {
        panic!("expected StaticChallenge");
    }
}

#[test]
fn password_dynamic_challenge_crv1() {
    let notification = expect_notification(
        ">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:sid123:dXNlcg==:Enter OTP']\n",
    );
    if let Notification::Password(PasswordNotification::DynamicChallenge {
        flags,
        state_id,
        username_b64,
        challenge,
    }) = notification
    {
        assert_eq!(flags, "R,E");
        assert_eq!(state_id, "sid123");
        assert_eq!(username_b64, "dXNlcg==");
        assert_eq!(challenge, "Enter OTP");
    } else {
        panic!("expected DynamicChallenge, got {notification:?}");
    }
}

#[test]
fn password_unrecognized_format_falls_back_to_simple() {
    let (kind, _) = expect_simple(">PASSWORD:Something Entirely New\n");
    assert_eq!(kind, "PASSWORD");
}

#[test]
fn password_need_with_unknown_suffix_falls_back() {
    // "Need 'Auth' something_else" — neither "username/password" nor "password"
    let (kind, _) = expect_simple(">PASSWORD:Need 'Auth' certificate\n");
    assert_eq!(kind, "PASSWORD");
}

// ---  ---
// REMOTE / PROXY edge cases
// ---  ---

#[test]
fn remote_valid() {
    let notification = expect_notification(">REMOTE:vpn.example.com,1194,udp\n");
    assert!(matches!(
        notification,
        Notification::Remote { port: 1194, .. }
    ));
}

#[test]
fn remote_non_numeric_port_falls_back() {
    let (kind, _) = expect_simple(">REMOTE:host,abc,udp\n");
    assert_eq!(kind, "REMOTE");
}

#[test]
fn remote_missing_protocol_falls_back() {
    let (kind, _) = expect_simple(">REMOTE:host,1194\n");
    assert_eq!(kind, "REMOTE");
}

#[test]
fn proxy_valid() {
    let notification = expect_notification(">PROXY:1,TCP,proxy.local\n");
    assert!(matches!(notification, Notification::Proxy { index: 1, .. }));
}

#[test]
fn proxy_non_numeric_index_falls_back() {
    let (kind, _) = expect_simple(">PROXY:abc,TCP,proxy.local\n");
    assert_eq!(kind, "PROXY");
}

// ---  ---
// NEED-OK / NEED-STR edge cases
// ---  ---

#[test]
fn need_ok_valid() {
    let notification = expect_notification(
        ">NEED-OK:Need 'token-insertion-request' confirmation MSG:Insert token\n",
    );
    assert!(matches!(
        notification,
        Notification::NeedOk { ref name, ref message }
        if name == "token-insertion-request" && message == "Insert token"
    ));
}

#[test]
fn need_ok_missing_msg_falls_back() {
    let (kind, _) = expect_simple(">NEED-OK:Need 'foo' confirmation without MSG\n");
    assert_eq!(kind, "NEED-OK");
}

#[test]
fn need_ok_no_quote_falls_back() {
    let (kind, _) = expect_simple(">NEED-OK:malformed payload\n");
    assert_eq!(kind, "NEED-OK");
}

#[test]
fn need_str_valid() {
    let notification = expect_notification(">NEED-STR:Need 'username' input MSG:Enter username\n");
    assert!(matches!(
        notification,
        Notification::NeedStr { ref name, ref message }
        if name == "username" && message == "Enter username"
    ));
}

// ---  ---
// PKCS11 edge cases
// ---  ---

#[test]
fn pkcs11_id_count_valid() {
    let notification = expect_notification(">PKCS11ID-COUNT:3\n");
    assert!(matches!(
        notification,
        Notification::Pkcs11IdCount { count: 3 }
    ));
}

#[test]
fn pkcs11_id_count_zero() {
    let notification = expect_notification(">PKCS11ID-COUNT:0\n");
    assert!(matches!(
        notification,
        Notification::Pkcs11IdCount { count: 0 }
    ));
}

#[test]
fn pkcs11_id_count_non_numeric_falls_back() {
    let (kind, _) = expect_simple(">PKCS11ID-COUNT:abc\n");
    assert_eq!(kind, "PKCS11ID-COUNT");
}

#[test]
fn pkcs11_id_entry_valid() {
    let msg = decode_single(">PKCS11ID-ENTRY:'0', ID:'pkcs11:token=MyToken', BLOB:'AQID'\n");
    assert!(matches!(
        msg,
        OvpnMessage::Pkcs11IdEntry {
            ref index,
            ref id,
            ref blob,
        } if index == "0" && id == "pkcs11:token=MyToken" && blob == "AQID"
    ));
}

#[test]
fn pkcs11_id_entry_malformed_falls_back() {
    let msg = decode_single(">PKCS11ID-ENTRY:malformed data\n");
    assert!(matches!(
        msg,
        OvpnMessage::Notification(Notification::Simple { ref kind, .. })
        if kind == "PKCS11ID-ENTRY"
    ));
}

// ---  ---
// Miscellaneous notification edge cases
// ---  ---

#[test]
fn hold_preserves_full_text() {
    let notification = expect_notification(">HOLD:Waiting for hold release:5\n");
    assert!(matches!(
        notification,
        Notification::Hold { ref text } if text == "Waiting for hold release:5"
    ));
}

#[test]
fn fatal_preserves_message() {
    let notification = expect_notification(">FATAL:cannot allocate TUN/TAP dev\n");
    assert!(matches!(
        notification,
        Notification::Fatal { ref message } if message == "cannot allocate TUN/TAP dev"
    ));
}

#[test]
fn rsa_sign_preserves_data() {
    let notification = expect_notification(">RSA_SIGN:AQID/base64data==\n");
    assert!(matches!(
        notification,
        Notification::RsaSign { ref data } if data == "AQID/base64data=="
    ));
}

#[test]
fn unknown_notification_type_becomes_simple() {
    let (kind, payload) = expect_simple(">FUTURE_TYPE:some data here\n");
    assert_eq!(kind, "FUTURE_TYPE");
    assert_eq!(payload, "some data here");
}

#[test]
fn info_banner_is_separate_variant() {
    let msg = decode_single(">INFO:OpenVPN Management Interface Version 5\n");
    assert!(matches!(msg, OvpnMessage::Info(s) if s.contains("Version 5")));
}

#[test]
fn notification_with_empty_payload() {
    let notification = expect_notification(">HOLD:\n");
    assert!(matches!(notification, Notification::Hold { ref text } if text.is_empty()));
}

#[test]
fn notification_with_no_colon_is_unrecognized() {
    let msg = decode_single(">MALFORMED_NO_COLON\n");
    assert!(matches!(msg, OvpnMessage::Unrecognized { .. }));
}

#[test]
fn client_address_notification() {
    let notification = expect_notification(">CLIENT:ADDRESS,42,10.8.0.6,1\n");
    assert!(matches!(
        notification,
        Notification::ClientAddress {
            cid: 42,
            addr: ref a,
            primary: true,
        } if a == "10.8.0.6"
    ));
}

#[test]
fn client_address_not_primary() {
    let notification = expect_notification(">CLIENT:ADDRESS,42,10.8.0.6,0\n");
    assert!(matches!(
        notification,
        Notification::ClientAddress { primary: false, .. }
    ));
}

#[test]
fn client_disconnect_no_kid() {
    let msgs = decode_all(
        ">CLIENT:DISCONNECT,5\n\
         >CLIENT:ENV,duration=3600\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        &msgs[0],
        OvpnMessage::Notification(Notification::Client {
            event: ClientEvent::Disconnect,
            cid: 5,
            kid: None,
            ..
        })
    ));
}

#[test]
fn client_cr_response_event() {
    let msgs = decode_all(
        ">CLIENT:CR_RESPONSE,10,2,base64data\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);
    if let OvpnMessage::Notification(Notification::Client { event, .. }) = &msgs[0] {
        assert!(matches!(event, ClientEvent::CrResponse(s) if s == "base64data"));
    } else {
        panic!("expected Client notification");
    }
}

#[test]
fn client_env_with_equals_in_value() {
    let msgs = decode_all(
        ">CLIENT:CONNECT,1,0\n\
         >CLIENT:ENV,untrusted_ip=10.0.0.1\n\
         >CLIENT:ENV,password=foo=bar=baz\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);
    if let OvpnMessage::Notification(Notification::Client { env, .. }) = &msgs[0] {
        assert_eq!(env.get("password").map(String::as_str), Some("foo=bar=baz"));
    } else {
        panic!("expected Client");
    }
}

#[test]
fn client_env_key_without_value() {
    let msgs = decode_all(
        ">CLIENT:CONNECT,1,0\n\
         >CLIENT:ENV,key_only\n\
         >CLIENT:ENV,END\n",
    );
    assert_eq!(msgs.len(), 1);
    if let OvpnMessage::Notification(Notification::Client { env, .. }) = &msgs[0] {
        assert_eq!(env.get("key_only").map(String::as_str), Some(""));
    } else {
        panic!("expected Client");
    }
}
