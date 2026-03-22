//! Property-based tests for the OvpnCodec.
//!
//! Tests cover: roundtrip encoding/decoding, robustness against arbitrary
//! input, encoder well-formedness, injection resistance, codec state
//! independence, interleaving safety, partial-input equivalence, and
//! structural integrity of multi-line messages.

use bytes::BytesMut;
use openvpn_mgmt_codec::*;
use proptest::prelude::*;
use tokio_util::codec::{Decoder, Encoder};

// --- String strategies ---
//
// Wire-format constraints dictate which characters are safe in each
// position. All strategies exclude \n, \r, \0 (line-oriented protocol).

/// Safe for comma/colon/quote-delimited fields.
/// Excludes: , : ' " > \ and control characters.
fn safe_field() -> BoxedStrategy<String> {
    "[a-zA-Z0-9 _.;!?@#$%^&*+=~|-]{0,80}".boxed()
}

/// Safe for the *last* field in a delimited format — allows commas and colons.
fn safe_text() -> BoxedStrategy<String> {
    "[a-zA-Z0-9 _.,;:!?@#$%^&*+=~|-]{0,80}".boxed()
}

/// ENV key: alphanumeric + underscore, at least one char, not "END".
fn safe_env_key() -> BoxedStrategy<String> {
    "[a-zA-Z_][a-zA-Z0-9_]{0,30}"
        .prop_filter("must not be END", |s| s != "END")
        .boxed()
}

// --- Type strategies ---
//
// Custom variants use a "CUSTOM_" prefix to guarantee they never
// collide with known-variant parse strings.

fn arb_auth_type() -> BoxedStrategy<AuthType> {
    prop_oneof![
        Just(AuthType::Auth),
        Just(AuthType::PrivateKey),
        Just(AuthType::HttpProxy),
        Just(AuthType::SocksProxy),
        "CUSTOM_[a-zA-Z]{1,20}".prop_map(AuthType::Unknown),
    ]
    .boxed()
}

fn arb_client_event() -> BoxedStrategy<ClientEvent> {
    prop_oneof![
        Just(ClientEvent::Connect),
        Just(ClientEvent::Reauth),
        Just(ClientEvent::Established),
        Just(ClientEvent::Disconnect),
        "CUSTOM_[A-Z]{1,10}".prop_map(ClientEvent::Unknown),
    ]
    .boxed()
}

fn arb_log_level() -> BoxedStrategy<LogLevel> {
    prop_oneof![
        Just(LogLevel::Info),
        Just(LogLevel::Debug),
        Just(LogLevel::Warning),
        Just(LogLevel::NonFatal),
        Just(LogLevel::Fatal),
        "CUSTOM_[A-Z]{1,10}".prop_map(LogLevel::Unknown),
    ]
    .boxed()
}

fn arb_openvpn_state() -> BoxedStrategy<OpenVpnState> {
    prop_oneof![
        Just(OpenVpnState::Connecting),
        Just(OpenVpnState::Wait),
        Just(OpenVpnState::Auth),
        Just(OpenVpnState::GetConfig),
        Just(OpenVpnState::AssignIp),
        Just(OpenVpnState::AddRoutes),
        Just(OpenVpnState::Connected),
        Just(OpenVpnState::Reconnecting),
        Just(OpenVpnState::Exiting),
        Just(OpenVpnState::TcpConnect),
        Just(OpenVpnState::Resolve),
        "CUSTOM_[A-Z]{1,10}".prop_map(OpenVpnState::Unknown),
    ]
    .boxed()
}

fn arb_transport_protocol() -> BoxedStrategy<TransportProtocol> {
    prop_oneof![
        Just(TransportProtocol::Udp),
        Just(TransportProtocol::Tcp),
        "CUSTOM_[a-zA-Z]{1,10}".prop_map(TransportProtocol::Unknown),
    ]
    .boxed()
}

fn arb_password_notification() -> BoxedStrategy<PasswordNotification> {
    prop_oneof![
        arb_auth_type().prop_map(|at| PasswordNotification::NeedAuth { auth_type: at }),
        arb_auth_type().prop_map(|at| PasswordNotification::NeedPassword { auth_type: at }),
        arb_auth_type().prop_map(|at| PasswordNotification::VerificationFailed { auth_type: at }),
        (any::<bool>(), any::<bool>(), safe_text()).prop_map(
            |(echo, response_concat, challenge)| {
                PasswordNotification::StaticChallenge {
                    echo,
                    response_concat,
                    challenge,
                }
            },
        ),
        (safe_field(), safe_field(), safe_field(), safe_text()).prop_map(
            |(flags, state_id, username_b64, challenge)| {
                PasswordNotification::DynamicChallenge {
                    flags,
                    state_id,
                    username_b64,
                    challenge,
                }
            },
        ),
        safe_text().prop_map(|token| PasswordNotification::AuthToken {
            token: Redacted::new(token)
        }),
    ]
    .boxed()
}

// --- Wire serialization ---
//
// These functions produce the exact byte sequence the OpenVPN server
// would emit for each message type. The decoder should reconstruct
// the original message from these bytes.

fn notification_to_wire(notif: &Notification) -> String {
    match notif {
        Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            remote_port,
            local_addr,
            local_port,
            local_ipv6,
        } => {
            let rport = remote_port.map(|p| p.to_string()).unwrap_or_default();
            let lport = local_port.map(|p| p.to_string()).unwrap_or_default();
            format!(
                ">STATE:{timestamp},{name},{description},{local_ip},\
                     {remote_ip},{rport},{local_addr},{lport},{local_ipv6}\n"
            )
        }
        Notification::ByteCount {
            bytes_in,
            bytes_out,
        } => format!(">BYTECOUNT:{bytes_in},{bytes_out}\n"),
        Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        } => format!(">BYTECOUNT_CLI:{cid},{bytes_in},{bytes_out}\n"),
        Notification::Log {
            timestamp,
            level,
            message,
        } => format!(">LOG:{timestamp},{level},{message}\n"),
        Notification::Echo { timestamp, param } => format!(">ECHO:{timestamp},{param}\n"),
        Notification::Hold { text } => format!(">HOLD:{text}\n"),
        Notification::Fatal { message } => format!(">FATAL:{message}\n"),
        Notification::Pkcs11IdCount { count } => format!(">PKCS11ID-COUNT:{count}\n"),
        Notification::NeedOk { name, message } => {
            format!(">NEED-OK:Need '{name}' confirmation MSG:{message}\n")
        }
        Notification::NeedStr { name, message } => {
            format!(">NEED-STR:Need '{name}' input MSG:{message}\n")
        }
        Notification::RsaSign { data } => format!(">RSA_SIGN:{data}\n"),
        Notification::Remote {
            host,
            port,
            protocol,
        } => format!(">REMOTE:{host},{port},{protocol}\n"),
        Notification::Proxy {
            index,
            proxy_type,
            host,
        } => format!(">PROXY:{index},{proxy_type},{host}\n"),
        Notification::Password(pw) => match pw {
            PasswordNotification::NeedAuth { auth_type } => {
                format!(">PASSWORD:Need '{auth_type}' username/password\n")
            }
            PasswordNotification::NeedPassword { auth_type } => {
                format!(">PASSWORD:Need '{auth_type}' password\n")
            }
            PasswordNotification::VerificationFailed { auth_type } => {
                format!(">PASSWORD:Verification Failed: '{auth_type}'\n")
            }
            PasswordNotification::StaticChallenge {
                echo,
                response_concat,
                challenge,
            } => {
                let flag = (*echo as u32) | ((*response_concat as u32) << 1);
                format!(">PASSWORD:Need 'Auth' username/password SC:{flag},{challenge}\n")
            }
            PasswordNotification::DynamicChallenge {
                flags,
                state_id,
                username_b64,
                challenge,
            } => format!(
                ">PASSWORD:Verification Failed: 'Auth' \
                 ['CRV1:{flags}:{state_id}:{username_b64}:{challenge}']\n"
            ),
            PasswordNotification::AuthToken { token } => {
                format!(">PASSWORD:Auth-Token:{}\n", token.expose())
            }
        },
        Notification::Client {
            event,
            cid,
            kid,
            env,
        } => {
            let mut wire = match kid {
                Some(k) => format!(">CLIENT:{event},{cid},{k}\n"),
                None => format!(">CLIENT:{event},{cid}\n"),
            };
            for (key, val) in env {
                wire.push_str(&format!(">CLIENT:ENV,{key}={val}\n"));
            }
            wire.push_str(">CLIENT:ENV,END\n");
            wire
        }
        Notification::ClientAddress { cid, addr, primary } => {
            let flag = if *primary { "1" } else { "0" };
            format!(">CLIENT:ADDRESS,{cid},{addr},{flag}\n")
        }
        Notification::PkSign { data, algorithm } => match algorithm {
            Some(algo) => format!(">PK_SIGN:{data},{algo}\n"),
            None => format!(">PK_SIGN:{data}\n"),
        },
        Notification::Info { message } => format!(">INFO:{message}\n"),
        Notification::Simple { kind, payload } => format!(">{kind}:{payload}\n"),
    }
}

// --- Decode helpers ---

/// Decode all messages from wire bytes using a fresh codec.
fn decode_all(wire: &str) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut buf = BytesMut::from(wire);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

/// Decode after encoding a command to set the codec's expected-response state.
fn decode_with_command(cmd: OvpnCommand, wire: &str) -> Vec<OvpnMessage> {
    let mut codec = OvpnCodec::new();
    let mut enc_buf = BytesMut::new();
    codec.encode(cmd, &mut enc_buf).unwrap();
    let mut buf = BytesMut::from(wire);
    let mut msgs = Vec::new();
    while let Some(msg) = codec.decode(&mut buf).unwrap() {
        msgs.push(msg);
    }
    msgs
}

// --- Roundtrip tests ---

proptest! {
    // --- Self-describing messages (no codec state needed) ---

    #[test]
    fn roundtrip_success(text in safe_text()) {
        let wire = format!("SUCCESS: {text}\n");
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Success(text));
    }

    #[test]
    fn roundtrip_error(text in safe_text()) {
        let wire = format!("ERROR: {text}\n");
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Error(text));
    }

    #[test]
    fn roundtrip_info(text in safe_text()) {
        let wire = format!(">INFO:{text}\n");
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Info(text));
    }

    // --- State-dependent messages ---

    #[test]
    fn roundtrip_multiline(
        lines in prop::collection::vec(
            safe_field().prop_filter("not END", |s| s != "END"),
            0..10,
        )
    ) {
        let mut wire = String::new();
        for line in &lines {
            wire.push_str(line);
            wire.push('\n');
        }
        wire.push_str("END\n");
        // Status expects a multi-line response.
        let msgs = decode_with_command(
            OvpnCommand::Status(StatusFormat::V1),
            &wire,
        );
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::MultiLine(lines));
    }

    #[test]
    fn roundtrip_pkcs11id_entry(
        index in safe_field(),
        id in safe_field(),
        blob in safe_field(),
    ) {
        let wire = format!(
            ">PKCS11ID-ENTRY:'{index}', ID:'{id}', BLOB:'{blob}'\n"
        );
        // >PKCS11ID-ENTRY: is a self-describing notification (has > prefix).
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(
            &msgs[0],
            &OvpnMessage::Pkcs11IdEntry {
                index,
                id,
                blob,
            }
        );
    }

    // --- Notification roundtrips ---

    #[test]
    fn roundtrip_notif_state(
        timestamp in any::<u64>(),
        name in arb_openvpn_state(),
        description in safe_field(),
        local_ip in safe_field(),
        remote_ip in safe_field(),
        remote_port in proptest::option::of(any::<u16>()),
        local_addr in safe_field(),
        local_port in proptest::option::of(any::<u16>()),
        local_ipv6 in safe_field(),
    ) {
        let notif = Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            remote_port,
            local_addr,
            local_port,
            local_ipv6,
        };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_bytecount(
        bytes_in in any::<u64>(),
        bytes_out in any::<u64>(),
    ) {
        let notif = Notification::ByteCount { bytes_in, bytes_out };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_bytecount_cli(
        cid in any::<u64>(),
        bytes_in in any::<u64>(),
        bytes_out in any::<u64>(),
    ) {
        let notif = Notification::ByteCountCli { cid, bytes_in, bytes_out };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_log(
        timestamp in any::<u64>(),
        level in arb_log_level(),
        message in safe_text(),
    ) {
        let notif = Notification::Log { timestamp, level, message };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_echo(
        timestamp in any::<u64>(),
        param in safe_text(),
    ) {
        let notif = Notification::Echo { timestamp, param };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_hold(text in safe_text()) {
        let notif = Notification::Hold { text };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_fatal(message in safe_text()) {
        let notif = Notification::Fatal { message };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_pkcs11id_count(count in any::<u32>()) {
        let notif = Notification::Pkcs11IdCount { count };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_need_ok(
        name in safe_field(),
        message in safe_text(),
    ) {
        let notif = Notification::NeedOk { name, message };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_need_str(
        name in safe_field(),
        message in safe_text(),
    ) {
        let notif = Notification::NeedStr { name, message };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_rsa_sign(data in safe_text()) {
        let notif = Notification::RsaSign { data };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_remote(
        host in safe_field(),
        port in any::<u16>(),
        protocol in arb_transport_protocol(),
    ) {
        let notif = Notification::Remote { host, port, protocol };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_proxy(
        index in any::<u32>(),
        proxy_type in arb_transport_protocol(),
        host in safe_field(),
    ) {
        let notif = Notification::Proxy { index, proxy_type, host };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_password(pw in arb_password_notification()) {
        let notif = Notification::Password(pw);
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_client(
        event in arb_client_event(),
        cid in any::<u64>(),
        kid in prop::option::of(any::<u64>()),
        env in prop::collection::vec(
            (safe_env_key(), safe_text()),
            0..10,
        ),
    ) {
        let notif = Notification::Client { event, cid, kid, env };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_client_address(
        cid in any::<u64>(),
        addr in safe_field(),
        primary in any::<bool>(),
    ) {
        let notif = Notification::ClientAddress { cid, addr, primary };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }

    #[test]
    fn roundtrip_notif_simple(
        kind in "CUSTOM_[A-Z]{1,10}",
        payload in safe_text(),
    ) {
        let notif = Notification::Simple { kind, payload };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);
        prop_assert_eq!(msgs.len(), 1);
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
    }
}

// --- PasswordPrompt (no proptest needed — deterministic) ---

#[test]
fn roundtrip_password_prompt() {
    let msgs = decode_all("ENTER PASSWORD:\n");
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0], OvpnMessage::PasswordPrompt);
}

// ---  ---
// Additional property tests
// ---  ---

// --- Adversarial string strategy ---
//
// Generates strings designed to break the line-oriented protocol:
// embedded newlines, null bytes, protocol keywords, block terminators.

fn adversarial_string() -> BoxedStrategy<String> {
    prop_oneof![
        Just("\n".to_string()),
        Just("\r\n".to_string()),
        Just("\0".to_string()),
        Just("END".to_string()),
        Just(">INFO:injected\n".to_string()),
        Just("SUCCESS: injected\n".to_string()),
        Just("ERROR: injected\n".to_string()),
        Just("ENTER PASSWORD:\n".to_string()),
        Just("\nsignal SIGTERM\n".to_string()),
        Just("line1\r\nline2\r\n".to_string()),
        Just("\\\"\\\\".to_string()),
        safe_text(),
        safe_field().prop_map(|s| format!("{s}\n{s}")),
        safe_field().prop_map(|s| format!("{s}\0{s}")),
        safe_field().prop_map(|s| format!("{s}\rEND\n{s}")),
    ]
    .boxed()
}

// --- Command sub-type strategies ---

fn arb_status_format() -> BoxedStrategy<StatusFormat> {
    prop_oneof![
        Just(StatusFormat::V1),
        Just(StatusFormat::V2),
        Just(StatusFormat::V3),
    ]
    .boxed()
}

fn arb_stream_mode() -> BoxedStrategy<StreamMode> {
    prop_oneof![
        Just(StreamMode::On),
        Just(StreamMode::Off),
        Just(StreamMode::All),
        Just(StreamMode::OnAll),
        any::<u32>().prop_map(StreamMode::Recent),
    ]
    .boxed()
}

fn arb_signal() -> BoxedStrategy<Signal> {
    prop_oneof![
        Just(Signal::SigHup),
        Just(Signal::SigTerm),
        Just(Signal::SigUsr1),
        Just(Signal::SigUsr2),
    ]
    .boxed()
}

fn arb_auth_retry_mode() -> BoxedStrategy<AuthRetryMode> {
    prop_oneof![
        Just(AuthRetryMode::None),
        Just(AuthRetryMode::Interact),
        Just(AuthRetryMode::NoInteract),
    ]
    .boxed()
}

fn arb_need_ok_response() -> BoxedStrategy<NeedOkResponse> {
    prop_oneof![Just(NeedOkResponse::Ok), Just(NeedOkResponse::Cancel),].boxed()
}

// --- OvpnCommand strategies ---

/// Build a strategy for every `OvpnCommand` variant, parameterized by
/// the string strategy used for text fields. Using `safe_text()` gives
/// well-formed commands; using `adversarial_string()` exercises the
/// encoder's sanitization defenses.
fn arb_ovpn_command_with(s: BoxedStrategy<String>) -> BoxedStrategy<OvpnCommand> {
    let kill = prop_oneof![
        s.clone().prop_map(KillTarget::CommonName),
        (arb_transport_protocol(), s.clone(), any::<u16>())
            .prop_map(|(protocol, ip, port)| KillTarget::Address { protocol, ip, port }),
    ];
    let remote = prop_oneof![
        Just(RemoteAction::Accept),
        Just(RemoteAction::Skip),
        (s.clone(), any::<u16>()).prop_map(|(host, port)| RemoteAction::Modify { host, port }),
    ];
    let proxy = prop_oneof![
        Just(ProxyAction::None),
        (s.clone(), any::<u16>(), any::<bool>()).prop_map(|(host, port, nct)| ProxyAction::Http {
            host,
            port,
            non_cleartext_only: nct,
        }),
        (s.clone(), any::<u16>()).prop_map(|(host, port)| ProxyAction::Socks { host, port }),
    ];

    proptest::strategy::Union::new(vec![
        // --- Parameterless ---
        Just(OvpnCommand::State).boxed(),
        Just(OvpnCommand::Version).boxed(),
        Just(OvpnCommand::Pid).boxed(),
        Just(OvpnCommand::Help).boxed(),
        Just(OvpnCommand::Net).boxed(),
        Just(OvpnCommand::HoldQuery).boxed(),
        Just(OvpnCommand::HoldOn).boxed(),
        Just(OvpnCommand::HoldOff).boxed(),
        Just(OvpnCommand::HoldRelease).boxed(),
        Just(OvpnCommand::Pkcs11IdCount).boxed(),
        Just(OvpnCommand::LoadStats).boxed(),
        Just(OvpnCommand::ForgetPasswords).boxed(),
        Just(OvpnCommand::Exit).boxed(),
        Just(OvpnCommand::Quit).boxed(),
        // --- Simple parameterized ---
        arb_status_format().prop_map(OvpnCommand::Status).boxed(),
        arb_stream_mode().prop_map(OvpnCommand::StateStream).boxed(),
        arb_stream_mode().prop_map(OvpnCommand::Log).boxed(),
        arb_stream_mode().prop_map(OvpnCommand::Echo).boxed(),
        any::<u32>().prop_map(OvpnCommand::ByteCount).boxed(),
        arb_signal().prop_map(OvpnCommand::Signal).boxed(),
        prop::option::of(0..16u8)
            .prop_map(OvpnCommand::Verb)
            .boxed(),
        prop::option::of(any::<u32>())
            .prop_map(OvpnCommand::Mute)
            .boxed(),
        any::<u32>().prop_map(OvpnCommand::Pkcs11IdGet).boxed(),
        arb_auth_retry_mode()
            .prop_map(OvpnCommand::AuthRetry)
            .boxed(),
        kill.prop_map(OvpnCommand::Kill).boxed(),
        remote.prop_map(OvpnCommand::Remote).boxed(),
        proxy.prop_map(OvpnCommand::Proxy).boxed(),
        // --- String commands ---
        (arb_auth_type(), s.clone())
            .prop_map(|(at, v)| OvpnCommand::Username {
                auth_type: at,
                value: Redacted::new(v),
            })
            .boxed(),
        (arb_auth_type(), s.clone())
            .prop_map(|(at, v)| OvpnCommand::Password {
                auth_type: at,
                value: Redacted::new(v),
            })
            .boxed(),
        (s.clone(), s.clone())
            .prop_map(|(si, r)| OvpnCommand::ChallengeResponse {
                state_id: si,
                response: Redacted::new(r),
            })
            .boxed(),
        (s.clone(), s.clone())
            .prop_map(|(p, r)| OvpnCommand::StaticChallengeResponse {
                password_b64: Redacted::new(p),
                response_b64: Redacted::new(r),
            })
            .boxed(),
        (s.clone(), arb_need_ok_response())
            .prop_map(|(n, r)| OvpnCommand::NeedOk {
                name: n,
                response: r,
            })
            .boxed(),
        (s.clone(), s.clone())
            .prop_map(|(n, v)| OvpnCommand::NeedStr { name: n, value: v })
            .boxed(),
        s.clone()
            .prop_map(|s| OvpnCommand::ManagementPassword(Redacted::new(s)))
            .boxed(),
        s.clone().prop_map(OvpnCommand::Raw).boxed(),
        s.clone()
            .prop_map(|r| OvpnCommand::CrResponse {
                response: Redacted::new(r),
            })
            .boxed(),
        (any::<u64>(), any::<u64>(), s.clone(), any::<u32>())
            .prop_map(|(c, k, e, t)| OvpnCommand::ClientPendingAuth {
                cid: c,
                kid: k,
                extra: e,
                timeout: t,
            })
            .boxed(),
        // --- Complex with Option strings ---
        (
            any::<u64>(),
            any::<u64>(),
            s.clone(),
            prop::option::of(s.clone()),
        )
            .prop_map(|(c, k, r, cr)| OvpnCommand::ClientDeny {
                cid: c,
                kid: k,
                reason: r,
                client_reason: cr,
            })
            .boxed(),
        // --- Multi-line commands ---
        prop::collection::vec(s.clone(), 0..5)
            .prop_map(|lines| OvpnCommand::RsaSig {
                base64_lines: lines,
            })
            .boxed(),
        (
            any::<u64>(),
            any::<u64>(),
            prop::collection::vec(s.clone(), 0..5),
        )
            .prop_map(|(c, k, lines)| OvpnCommand::ClientAuth {
                cid: c,
                kid: k,
                config_lines: lines,
            })
            .boxed(),
        prop::collection::vec(s.clone(), 0..5)
            .prop_map(|lines| OvpnCommand::Certificate { pem_lines: lines })
            .boxed(),
        // --- Client management (numeric only) ---
        (any::<u64>(), any::<u64>())
            .prop_map(|(c, k)| OvpnCommand::ClientAuthNt { cid: c, kid: k })
            .boxed(),
        (any::<u64>(), prop::option::of(s.clone()))
            .prop_map(|(c, m)| OvpnCommand::ClientKill { cid: c, message: m })
            .boxed(),
    ])
    .boxed()
}

fn arb_ovpn_command() -> BoxedStrategy<OvpnCommand> {
    arb_ovpn_command_with(safe_text())
}

fn arb_ovpn_command_adversarial() -> BoxedStrategy<OvpnCommand> {
    arb_ovpn_command_with(adversarial_string())
}

// --- Composite notification & wire strategies ---

/// Any single-line notification (excludes `Client`, which is multi-line).
fn arb_single_line_notification() -> BoxedStrategy<Notification> {
    prop_oneof![
        (
            any::<u64>(),
            arb_openvpn_state(),
            safe_field(),
            safe_field(),
            safe_field(),
            proptest::option::of(any::<u16>()),
            safe_field(),
            proptest::option::of(any::<u16>()),
            safe_field(),
        )
            .prop_map(|(ts, name, desc, lip, rip, rport, laddr, lport, lipv6)| {
                Notification::State {
                    timestamp: ts,
                    name,
                    description: desc,
                    local_ip: lip,
                    remote_ip: rip,
                    remote_port: rport,
                    local_addr: laddr,
                    local_port: lport,
                    local_ipv6: lipv6,
                }
            }),
        (any::<u64>(), any::<u64>()).prop_map(|(bi, bo)| Notification::ByteCount {
            bytes_in: bi,
            bytes_out: bo,
        }),
        (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(c, bi, bo)| {
            Notification::ByteCountCli {
                cid: c,
                bytes_in: bi,
                bytes_out: bo,
            }
        }),
        (any::<u64>(), arb_log_level(), safe_text()).prop_map(|(ts, level, msg)| {
            Notification::Log {
                timestamp: ts,
                level,
                message: msg,
            }
        }),
        (any::<u64>(), safe_text()).prop_map(|(ts, param)| Notification::Echo {
            timestamp: ts,
            param
        }),
        safe_text().prop_map(|t| Notification::Hold { text: t }),
        safe_text().prop_map(|m| Notification::Fatal { message: m }),
        any::<u32>().prop_map(|c| Notification::Pkcs11IdCount { count: c }),
        (safe_field(), safe_text()).prop_map(|(n, m)| Notification::NeedOk {
            name: n,
            message: m
        }),
        (safe_field(), safe_text()).prop_map(|(n, m)| Notification::NeedStr {
            name: n,
            message: m
        }),
        safe_text().prop_map(|d| Notification::RsaSign { data: d }),
        (safe_field(), any::<u16>(), arb_transport_protocol()).prop_map(|(h, p, pr)| {
            Notification::Remote {
                host: h,
                port: p,
                protocol: pr,
            }
        }),
        (any::<u32>(), arb_transport_protocol(), safe_field()).prop_map(|(idx, pt, h)| {
            Notification::Proxy {
                index: idx,
                proxy_type: pt,
                host: h,
            }
        }),
        arb_password_notification().prop_map(Notification::Password),
        (any::<u64>(), safe_field(), any::<bool>()).prop_map(|(c, a, p)| {
            Notification::ClientAddress {
                cid: c,
                addr: a,
                primary: p,
            }
        }),
        ("CUSTOM_[A-Z]{1,10}", safe_text()).prop_map(|(k, p)| Notification::Simple {
            kind: k,
            payload: p
        }),
    ]
    .boxed()
}

/// A self-describing wire message: one whose decoding does not depend
/// on the codec's `expected` response-kind state.
fn arb_self_describing_wire() -> BoxedStrategy<String> {
    prop_oneof![
        safe_text().prop_map(|t| format!("SUCCESS: {t}\n")),
        safe_text().prop_map(|t| format!("ERROR: {t}\n")),
        safe_text().prop_map(|t| format!(">INFO:{t}\n")),
        Just("ENTER PASSWORD:\n".to_string()),
        arb_single_line_notification().prop_map(|n| notification_to_wire(&n)),
    ]
    .boxed()
}

// --- Property tests ---

proptest! {
    // --- 1. Robustness: no panics on arbitrary input ---
    //
    // The decoder must never panic on arbitrary byte input. Any byte
    // sequence — including invalid UTF-8, truncated messages, and
    // random noise — should produce Ok(Some/None) or Err, never an
    // unwind.

    #[test]
    fn decoder_never_panics_on_arbitrary_input(
        data in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::from(data.as_slice());
        for _ in 0..data.len() + 1 {
            match codec.decode(&mut buf) {
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        // Reaching here without panicking satisfies the property.
    }

    // --- 2. Encoder well-formedness ---
    //
    // Encoded commands must always produce valid UTF-8 bytes ending
    // with \n, containing no \r or \0 bytes — even when string fields
    // contain adversarial payloads (embedded newlines, nulls, quotes,
    // protocol keywords, etc.). This is the encoder's core safety
    // contract.

    #[test]
    fn encoded_output_is_well_formed(cmd in arb_ovpn_command_adversarial()) {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(cmd, &mut buf).unwrap();
        let wire = std::str::from_utf8(&buf)
            .expect("encoded output must be valid UTF-8");
        prop_assert!(wire.ends_with('\n'), "must end with newline");
        prop_assert!(!wire.contains('\r'), "must not contain \\r");
        prop_assert!(!wire.contains('\0'), "must not contain \\0");
    }

    // --- 3 + 5. Line count / injection resistance ---
    //
    // Encoding any single OvpnCommand must produce exactly the expected
    // number of newline-terminated lines: 1 for single-line commands,
    // N+2 for multi-line blocks (header + N body lines + END).
    //
    // This IS the injection resistance property: adversarial string
    // payloads containing \n, \r, END, >, SUCCESS:, ERROR: etc. must
    // never inflate the line count, because that would cause a single
    // command to be misinterpreted as multiple commands by the server.

    #[test]
    fn encoded_line_count_matches_structure(cmd in arb_ovpn_command_adversarial()) {
        let expected_lines = match &cmd {
            OvpnCommand::RsaSig { base64_lines } => base64_lines.len() + 2,
            OvpnCommand::ClientAuth { config_lines, .. } => config_lines.len() + 2,
            OvpnCommand::Certificate { pem_lines } => pem_lines.len() + 2,
            _ => 1,
        };
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        codec.encode(cmd, &mut buf).unwrap();
        let wire = std::str::from_utf8(&buf).unwrap();
        let actual_lines = wire.matches('\n').count();
        prop_assert_eq!(
            actual_lines, expected_lines,
            "line count mismatch in: {:?}", wire,
        );
    }

    // --- 4. Encoding determinism ---
    //
    // Encoding the same command twice with independent codec instances
    // must produce byte-identical wire output. The encoder is a pure
    // function of the command value.

    #[test]
    fn encoding_is_deterministic(cmd in arb_ovpn_command()) {
        let encode = |c: OvpnCommand| -> Vec<u8> {
            let mut codec = OvpnCodec::new();
            let mut buf = BytesMut::new();
            codec.encode(c, &mut buf).unwrap();
            buf.to_vec()
        };
        let a = encode(cmd.clone());
        let b = encode(cmd);
        prop_assert_eq!(a, b);
    }

    // --- 6. Self-describing message state independence ---
    //
    // Self-describing messages (SUCCESS, ERROR, notifications,
    // ENTER PASSWORD) must decode identically regardless of what
    // command was last encoded. The codec's expected-response-kind
    // state must not affect these unambiguous message types.

    #[test]
    fn self_describing_messages_ignore_codec_state(
        cmd_a in arb_ovpn_command(),
        cmd_b in arb_ovpn_command(),
        wire in arb_self_describing_wire(),
    ) {
        let decode_after = |cmd: OvpnCommand, w: &str| -> Vec<OvpnMessage> {
            let mut codec = OvpnCodec::new();
            let mut enc = BytesMut::new();
            codec.encode(cmd, &mut enc).unwrap();
            let mut dec = BytesMut::from(w);
            let mut msgs = Vec::new();
            while let Some(msg) = codec.decode(&mut dec).unwrap() {
                msgs.push(msg);
            }
            msgs
        };
        let a = decode_after(cmd_a, &wire);
        let b = decode_after(cmd_b, &wire);
        prop_assert_eq!(a, b);
    }

    // --- 7. Interleaving safety ---
    //
    // A single-line notification arriving mid-way through a multi-line
    // response block must be emitted immediately as a separate message,
    // and the surrounding multi-line block must still be accumulated
    // correctly with all its lines intact and in order.

    #[test]
    fn notification_interleaved_in_multiline_is_safe(
        lines in prop::collection::vec(
            safe_field().prop_filter("not END", |s| s != "END"),
            1..10,
        ),
        notif in arb_single_line_notification(),
        inject_idx in 0..10usize,
    ) {
        let inject_pos = inject_idx % lines.len();
        let notif_wire = notification_to_wire(&notif);

        // Build wire: lines[..pos], notification, lines[pos..], END
        let mut wire = String::new();
        for l in &lines[..inject_pos] {
            wire.push_str(l);
            wire.push('\n');
        }
        wire.push_str(&notif_wire);
        for l in &lines[inject_pos..] {
            wire.push_str(l);
            wire.push('\n');
        }
        wire.push_str("END\n");

        let msgs = decode_with_command(
            OvpnCommand::Status(StatusFormat::V1),
            &wire,
        );

        prop_assert_eq!(
            msgs.len(), 2,
            "expected 2 messages (notification + multiline), got {}",
            msgs.len(),
        );
        prop_assert_eq!(&msgs[0], &OvpnMessage::Notification(notif));
        prop_assert_eq!(&msgs[1], &OvpnMessage::MultiLine(lines));
    }

    // --- 8a. Partial-input equivalence (single-line) ---
    //
    // Feeding the wire bytes of a valid message one byte at a time
    // must produce the same decoded messages as feeding all bytes at
    // once. The decoder must correctly handle arbitrary split points
    // in the input stream.

    #[test]
    fn byte_at_a_time_matches_bulk_decode(
        wire in arb_self_describing_wire(),
    ) {
        let bulk = decode_all(&wire);

        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        let mut incremental = Vec::new();
        for &b in wire.as_bytes() {
            buf.extend_from_slice(&[b]);
            while let Some(msg) = codec.decode(&mut buf).unwrap() {
                incremental.push(msg);
            }
        }

        prop_assert_eq!(bulk, incremental);
    }

    // --- 8b. Partial-input equivalence (multi-line CLIENT) ---
    //
    // The partial-input property also holds for multi-line CLIENT
    // notification blocks: feeding the wire bytes one byte at a time
    // produces the same decoded notification as feeding all at once.

    #[test]
    fn byte_at_a_time_client_notification(
        event in arb_client_event(),
        cid in any::<u64>(),
        kid in prop::option::of(any::<u64>()),
        env in prop::collection::vec(
            (safe_env_key(), safe_text()),
            0..10,
        ),
    ) {
        let notif = Notification::Client { event, cid, kid, env };
        let wire = notification_to_wire(&notif);

        let bulk = decode_all(&wire);

        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::new();
        let mut incremental = Vec::new();
        for &b in wire.as_bytes() {
            buf.extend_from_slice(&[b]);
            while let Some(msg) = codec.decode(&mut buf).unwrap() {
                incremental.push(msg);
            }
        }

        prop_assert_eq!(bulk, incremental);
    }

    // --- 9. CLIENT notification atomicity ---
    //
    // A CLIENT notification block with N env pairs must always decode
    // to exactly one Notification::Client message containing exactly
    // N env entries — never partial, never duplicated.

    #[test]
    fn client_notification_has_exact_env_count(
        event in arb_client_event(),
        cid in any::<u64>(),
        kid in prop::option::of(any::<u64>()),
        env in prop::collection::vec(
            (safe_env_key(), safe_text()),
            0..20,
        ),
    ) {
        let n = env.len();
        let notif = Notification::Client { event, cid, kid, env };
        let wire = notification_to_wire(&notif);
        let msgs = decode_all(&wire);

        prop_assert_eq!(msgs.len(), 1, "expected 1 message, got {}", msgs.len());
        match &msgs[0] {
            OvpnMessage::Notification(Notification::Client {
                env: decoded_env, ..
            }) => {
                prop_assert_eq!(decoded_env.len(), n);
            }
            other => prop_assert!(false, "expected Client notification, got {:?}", other),
        }
    }

    // --- 10. Multi-line block integrity ---
    //
    // A multi-line response block with N lines (none being "END" or
    // starting with ">") must always decode to a MultiLine message
    // containing exactly N entries, preserving content and order.

    #[test]
    fn multiline_block_has_exact_line_count(
        lines in prop::collection::vec(
            safe_field().prop_filter("not END", |s| s != "END"),
            0..50,
        ),
    ) {
        let n = lines.len();
        let mut wire = String::new();
        for line in &lines {
            wire.push_str(line);
            wire.push('\n');
        }
        wire.push_str("END\n");

        let msgs = decode_with_command(
            OvpnCommand::Status(StatusFormat::V1),
            &wire,
        );

        prop_assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            OvpnMessage::MultiLine(decoded) => {
                prop_assert_eq!(decoded.len(), n);
                prop_assert_eq!(decoded, &lines);
            }
            other => prop_assert!(false, "expected MultiLine, got {:?}", other),
        }
    }

    // --- 11. Monotonic progress ---
    //
    // The decoder must always make progress: each decode() call that
    // returns Ok(Some(_)) must consume at least one byte from the
    // buffer. The total number of messages decoded cannot exceed the
    // number of input bytes (since every message requires at least
    // one \n byte). The decoder must never loop infinitely.

    #[test]
    fn decoder_always_makes_progress(
        data in prop::collection::vec(any::<u8>(), 0..4096)
    ) {
        let mut codec = OvpnCodec::new();
        let mut buf = BytesMut::from(data.as_slice());
        let mut iterations = 0usize;
        let max = data.len() + 1;

        loop {
            let before = buf.len();
            match codec.decode(&mut buf) {
                Ok(Some(_)) => {
                    prop_assert!(
                        buf.len() < before,
                        "decode returned Some but buffer did not shrink \
                         (before={before}, after={})",
                        buf.len(),
                    );
                }
                Ok(None) | Err(_) => break,
            }
            iterations += 1;
            prop_assert!(
                iterations <= max,
                "decoder exceeded {max} iterations",
            );
        }
    }
}
