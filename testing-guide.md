# Testing Guide

Comprehensive testing instructions for the codec and UI, organized by
feature area. Each section lists what to test, which codec types are
exercised, and how to verify both offline (unit/integration) and online
(conformance against real OpenVPN).

## Prerequisites

```bash
# Offline tests (no Docker needed)
cargo test --workspace

# Conformance tests (Docker required)
docker compose up -d --build --wait
cargo test -p openvpn-mgmt-codec --features conformance-tests
docker compose down
```

### Docker containers

Defined in [docker-compose.yml](docker-compose.yml). Each container is
built from configs in the [conformance/](conformance/) directory.

| Container                 | Port | Dockerfile                                                                   | Config                                                   | Purpose                                    |
| ------------------------- | ---- | ---------------------------------------------------------------------------- | -------------------------------------------------------- | ------------------------------------------ |
| `openvpn`                 | 7505 | [Dockerfile](conformance/Dockerfile)                                         | [test-mgmt.ovpn](conformance/test-mgmt.ovpn)             | Basic management-only, no tunnel           |
| `openvpn-server`          | 7506 | [Dockerfile.server](conformance/Dockerfile.server) (target: server)          | [server.ovpn](conformance/server.ovpn)                   | Server with management-client-auth         |
| `openvpn-client`          | —    | [Dockerfile.server](conformance/Dockerfile.server) (target: client)          | [client.ovpn](conformance/client.ovpn)                   | Auto-connecting VPN client                 |
| `openvpn-client-remote`   | 7507 | [Dockerfile.server](conformance/Dockerfile.server) (target: client-remote)   | [client-remote.ovpn](conformance/client-remote.ovpn)     | Client with `--management-query-remote`    |
| `openvpn-client-password` | 7508 | [Dockerfile.server](conformance/Dockerfile.server) (target: client-password) | [client-password.ovpn](conformance/client-password.ovpn) | Client with `--management-query-passwords` |

---

## 1. Connection lifecycle

### What to test

| Operation              | Command                                                                                                                  | Response            | Notification                                                      |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------- | ----------------------------------------------------------------- |
| Connect + authenticate | [`ManagementPassword`](openvpn-mgmt-codec/src/command.rs#L392)                                                           | `SUCCESS:`          | —                                                                 |
| Release hold           | [`HoldRelease`](openvpn-mgmt-codec/src/command.rs#L162)                                                                  | `SUCCESS:`          | [`>HOLD:`](openvpn-mgmt-codec/src/message.rs#L175) before release |
| Query hold flag        | [`HoldQuery`](openvpn-mgmt-codec/src/command.rs#L149) → [`parse_hold()`](openvpn-mgmt-codec/src/parsed_response.rs#L153) | `SUCCESS: hold=0/1` | —                                                                 |
| View state changes     | [`StateStream(On)`](openvpn-mgmt-codec/src/command.rs#L88)                                                              | `SUCCESS:`          | [`Notification::State`](openvpn-mgmt-codec/src/message.rs#L117)   |
| Disconnect             | [`Signal(SigTerm)`](openvpn-mgmt-codec/src/command.rs#L140)                                                              | `SUCCESS:`          | `>STATE:...EXITING`                                               |
| Reconnect              | [`Signal(SigUsr1)`](openvpn-mgmt-codec/src/command.rs#L140)                                                              | `SUCCESS:`          | `>STATE:...RECONNECTING`                                          |

### Codec test coverage

- **Offline:**
  - [stateful_sequences.rs](openvpn-mgmt-codec/tests/stateful_sequences.rs) — [pid_then_version_sequence](openvpn-mgmt-codec/tests/stateful_sequences.rs#L44), [hold_query_then_hold_release_then_state_stream](openvpn-mgmt-codec/tests/stateful_sequences.rs#L95), [management_password_then_banner_then_commands](openvpn-mgmt-codec/tests/stateful_sequences.rs#L352)
  - [framed_integration.rs](openvpn-mgmt-codec/tests/framed_integration.rs) — async Framed transport
  - [codec.rs](openvpn-mgmt-codec/src/codec.rs) — [decode_hold_notification](openvpn-mgmt-codec/src/codec.rs#L1758), [decode_password_prompt_no_newline_with_cr](openvpn-mgmt-codec/src/codec.rs#L1701), [decode_password_prompt_no_newline_without_cr](openvpn-mgmt-codec/src/codec.rs#L1711)
- **Conformance:** [conformance.rs](openvpn-mgmt-codec/tests/conformance.rs) (18 tests against port 7505)

### UI test checklist

> **Minimal WSL setup** (no Docker):
>
> ```bash
> echo 'test-password' > /tmp/mgmt-pw.txt
> sudo openvpn --dev null --management 0.0.0.0 7505 /tmp/mgmt-pw.txt --management-hold --verb 4
> ```
>
> Enter the password in the UI connection form and connect. With `--dev null`
> OpenVPN reaches `ASSIGN_IP` and stays there — no real tunnel, so full state
> transitions (CONNECTED, RECONNECTING, EXITING) require the Docker setup.

- [ ] Connect to `localhost:7505` with password `test-password`
- [ ] Verify `[INFO]` banner appears in Log tab (bottom, oldest entry)
- [ ] Verify `[WARN] Hold: Waiting for hold release` appears (only on first
      connection after OpenVPN starts — once hold is released, subsequent
      connections skip it)
- [ ] Send `hold release` — verify state transitions begin
- [ ] Verify state display updates (with `--dev null`: stays at `ASSIGN_IP`;
      with Docker: CONNECTING → CONNECTED)
- [ ] Send `signal SIGTERM` — verify clean disconnect (Docker setup)
- [ ] Reconnect scenario: send `signal SIGUSR1`, verify RECONNECTING state
      (Docker setup)

---

## 2. Monitoring dashboard

### What to test

| Operation            | Command                                                  | Response/Notification                                                                   | Parsed type                                                    |
| -------------------- | -------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| Live bandwidth       | [`ByteCount(5)`](openvpn-mgmt-codec/src/command.rs#L135) | [`Notification::ByteCount`](openvpn-mgmt-codec/src/message.rs#L139)                     | `bytes_in: u64`, `bytes_out: u64`                              |
| Per-client bandwidth | (server mode)                                            | [`Notification::ByteCountCli`](openvpn-mgmt-codec/src/message.rs#L147)                  | `cid: u64`, `bytes_in`, `bytes_out`                            |
| Log viewer           | [`Log(On)`](openvpn-mgmt-codec/src/command.rs#L126)      | [`Notification::Log`](openvpn-mgmt-codec/src/message.rs#L157)                           | [`LogLevel`](openvpn-mgmt-codec/src/log_level.rs#L10)          |
| Echo messages        | [`Echo(On)`](openvpn-mgmt-codec/src/command.rs#L130)     | [`Notification::Echo`](openvpn-mgmt-codec/src/message.rs#L167)                          | `timestamp`, `param`                                           |
| Current state        | [`State`](openvpn-mgmt-codec/src/command.rs#L84) query  | `MultiLine` → [`parse_state_history()`](openvpn-mgmt-codec/src/parsed_response.rs#L287) | [`StateEntry`](openvpn-mgmt-codec/src/parsed_response.rs#L199) |

### Codec test coverage

- **Offline:**
  - [protocol_test.rs](openvpn-mgmt-codec/tests/protocol_test.rs) — [bytecount_client_mode](openvpn-mgmt-codec/tests/protocol_test.rs#L249), [bytecount_cli_server_mode](openvpn-mgmt-codec/tests/protocol_test.rs#L265), [log_notifications_all_flags](openvpn-mgmt-codec/tests/protocol_test.rs#L293), [echo_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L649), [state_history_on_all](openvpn-mgmt-codec/tests/protocol_test.rs#L355)
  - [notification_edge_cases.rs](openvpn-mgmt-codec/tests/notification_edge_cases.rs) — [bytecount_non_numeric_falls_back_to_simple](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L150), [log_non_numeric_timestamp_falls_back](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L228), [echo_empty_param](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L254)
  - [parsed_response.rs](openvpn-mgmt-codec/src/parsed_response.rs) — [state_entry_full](openvpn-mgmt-codec/src/parsed_response.rs#L407), [state_history_roundtrip](openvpn-mgmt-codec/src/parsed_response.rs#L462), [current_state_returns_last](openvpn-mgmt-codec/src/parsed_response.rs#L474)
- **Conformance:**
  - [conformance.rs](openvpn-mgmt-codec/tests/conformance.rs) — bytecount toggle, log history, state query
  - [conformance_server.rs](openvpn-mgmt-codec/tests/conformance_server.rs) — bytecount with real tunnel traffic

### UI test checklist

- [ ] Enable bytecount at 1s interval — verify counters update
- [ ] Enable log streaming — verify log entries with severity filtering
- [ ] Verify log levels display correctly (I/D/W/N/F)
- [ ] Enable echo — verify echo messages arrive
- [ ] Query current state — verify parsed [`StateEntry`](openvpn-mgmt-codec/src/parsed_response.rs#L199) with IP/port display
- [ ] Toggle subscriptions off — verify notifications stop
- [ ] Test `StateStream(Recent(5))` — verify recent history returned

---

## 3. Authentication flows

### What to test

| Operation         | Trigger notification                                            | Response command                                                                                          | Types                                                                                                                                       |
| ----------------- | --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Username/password | `>PASSWORD:Need 'Auth'`                                         | [`Username`](openvpn-mgmt-codec/src/command.rs#L167)/[`Password`](openvpn-mgmt-codec/src/command.rs#L177) | [`PasswordNotification::NeedAuth`](openvpn-mgmt-codec/src/message.rs#L14), [`AuthType::Auth`](openvpn-mgmt-codec/src/auth.rs#L17)           |
| Private key PIN   | `>PASSWORD:Need 'Private Key'`                                  | [`Password`](openvpn-mgmt-codec/src/command.rs#L177)                                                      | [`PasswordNotification::NeedPassword`](openvpn-mgmt-codec/src/message.rs#L20), [`AuthType::PrivateKey`](openvpn-mgmt-codec/src/auth.rs#L17) |
| HTTP proxy creds  | `>PASSWORD:Need 'HTTP Proxy'`                                   | `Username`/`Password`                                                                                     | [`AuthType::HttpProxy`](openvpn-mgmt-codec/src/auth.rs#L17)                                                                                 |
| Static challenge  | `>PASSWORD:Need 'Auth' ... SC:`                                 | [`StaticChallengeResponse`](openvpn-mgmt-codec/src/command.rs#L207)                                       | [`PasswordNotification::StaticChallenge`](openvpn-mgmt-codec/src/message.rs#L33)                                                            |
| Dynamic challenge | `>PASSWORD:Verification Failed: 'Auth' ['CRV1:...']`            | [`ChallengeResponse`](openvpn-mgmt-codec/src/command.rs#L195)                                             | [`PasswordNotification::DynamicChallenge`](openvpn-mgmt-codec/src/message.rs#L58)                                                           |
| Auth token        | `>PASSWORD:Auth-Token:...`                                      | (store for reuse)                                                                                         | [`PasswordNotification::AuthToken`](openvpn-mgmt-codec/src/message.rs#L51), [`Redacted`](openvpn-mgmt-codec/src/redacted.rs#L26)            |
| Auth failure      | `>PASSWORD:Verification Failed: 'Auth'`                         | (re-prompt)                                                                                               | [`PasswordNotification::VerificationFailed`](openvpn-mgmt-codec/src/message.rs#L27)                                                         |
| Auth retry        | [`AuthRetry(Interact)`](openvpn-mgmt-codec/src/command.rs#L186) | `SUCCESS:`                                                                                                | [`AuthRetryMode`](openvpn-mgmt-codec/src/auth.rs#L61)                                                                                       |
| RSA signing       | `>RSA_SIGN:base64`                                              | [`RsaSig`](openvpn-mgmt-codec/src/command.rs#L246)                                                        | [`Notification::RsaSign`](openvpn-mgmt-codec/src/message.rs#L209)                                                                           |
| PK signing        | `>PK_SIGN:base64[,algo]`                                        | [`PkSig`](openvpn-mgmt-codec/src/command.rs#L338)                                                         | [`Notification::PkSign`](openvpn-mgmt-codec/src/message.rs#L214)                                                                            |
| Web-auth URL      | `>INFO:WEB_AUTH::url`                                           | (open browser)                                                                                            | [`Notification::Info`](openvpn-mgmt-codec/src/message.rs#L233)                                                                              |
| CR_TEXT response  | `>CLIENT:CR_RESPONSE,cid,kid,b64`                               | [`CrResponse`](openvpn-mgmt-codec/src/command.rs#L329)                                                    | [`ClientEvent::CrResponse`](openvpn-mgmt-codec/src/client_event.rs#L11)                                                                     |

### Codec test coverage

- **Offline:**
  - [protocol_test.rs](openvpn-mgmt-codec/tests/protocol_test.rs) — [password_need_auth](openvpn-mgmt-codec/tests/protocol_test.rs#L531), [password_need_private_key](openvpn-mgmt-codec/tests/protocol_test.rs#L545), [password_verification_failed](openvpn-mgmt-codec/tests/protocol_test.rs#L559), [challenge_response_dynamic_crv1](openvpn-mgmt-codec/tests/protocol_test.rs#L587), [challenge_response_static_scrv1](openvpn-mgmt-codec/tests/protocol_test.rs#L611), [rsa_sign_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L724), [pk_sign_notification_with_algorithm](openvpn-mgmt-codec/tests/protocol_test.rs#L2512), [pk_sign_notification_without_algorithm](openvpn-mgmt-codec/tests/protocol_test.rs#L2525)
  - [notification_edge_cases.rs](openvpn-mgmt-codec/tests/notification_edge_cases.rs) — [password_need_auth_all_known_types](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L268), [password_static_challenge_echo_and_concat_flags](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L337), [password_dynamic_challenge_crv1](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L397)
  - [defensive/real_world.rs](openvpn-mgmt-codec/tests/defensive/real_world.rs) — [pk_sign_with_algorithm_parsed](openvpn-mgmt-codec/tests/defensive/real_world.rs#L348), [pk_sign_without_algorithm_parsed](openvpn-mgmt-codec/tests/defensive/real_world.rs#L362), [pk_sign_empty_payload_degrades_to_simple](openvpn-mgmt-codec/tests/defensive/real_world.rs#L376), [first_info_is_banner_subsequent_are_notifications](openvpn-mgmt-codec/tests/defensive/real_world.rs#L390), [password_auth_token_parsed](openvpn-mgmt-codec/tests/defensive/real_world.rs#L572)
- **Conformance:**
  - [conformance_password.rs](openvpn-mgmt-codec/tests/conformance_password.rs) — real `>PASSWORD:Need 'Auth'` → supply credentials → verify state transitions (port 7508)
  - [conformance_server.rs](openvpn-mgmt-codec/tests/conformance_server.rs) — client-auth flow with ENV (port 7506)

### UI test checklist

- [ ] Connect to password client (port 7508) — verify `>PASSWORD:Need 'Auth'` prompt
- [ ] Enter credentials — verify client proceeds to connect
- [ ] Verify auth token display (redacted in debug via [`Redacted`](openvpn-mgmt-codec/src/redacted.rs#L26))
- [ ] Verify failed auth shows `VerificationFailed` notification
- [ ] Test auth-retry mode toggle (none/interact/nointeract)
- [ ] Verify `>PK_SIGN:` displays algorithm when present
- [ ] Verify `>INFO:WEB_AUTH::url` is surfaced as [`Notification::Info`](openvpn-mgmt-codec/src/message.rs#L233)
      (not `Unrecognized` or `OvpnMessage::Info`)

---

## 4. Server mode (admin panel)

### What to test

| Operation           | Command                                                                                                                        | Response/Notification                                                              | Parsed type                                                                                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client table        | [`Status(V3)`](openvpn-mgmt-codec/src/command.rs#L80)                                                                         | `MultiLine` → [`parse_status()`](openvpn-mgmt-codec/src/status.rs#L226)            | [`StatusResponse`](openvpn-mgmt-codec/src/status.rs#L61), [`ConnectedClient`](openvpn-mgmt-codec/src/status.rs#L91), [`RoutingEntry`](openvpn-mgmt-codec/src/status.rs#L120) |
| Client table (V1)   | [`Status(V1)`](openvpn-mgmt-codec/src/command.rs#L80)                                                                         | `MultiLine` → [`parse_status()`](openvpn-mgmt-codec/src/status.rs#L226)            | Same (fewer fields)                                                                                                                                                          |
| Client statistics   | `Status(V1)` (client mode)                                                                                                     | `MultiLine` → [`parse_client_statistics()`](openvpn-mgmt-codec/src/status.rs#L447) | [`ClientStatistics`](openvpn-mgmt-codec/src/status.rs#L139)                                                                                                                  |
| Approve client      | [`ClientAuth`](openvpn-mgmt-codec/src/command.rs#L256)                                                                         | `SUCCESS:`                                                                         | `>CLIENT:CONNECT` → `>CLIENT:ESTABLISHED`                                                                                                                                    |
| Approve (no config) | [`ClientAuthNt`](openvpn-mgmt-codec/src/command.rs#L267)                                                                       | `SUCCESS:`                                                                         | Same                                                                                                                                                                         |
| Deny client         | [`ClientDeny`](openvpn-mgmt-codec/src/command.rs#L276)                                                                         | `SUCCESS:`                                                                         | Client receives AUTH_FAILED                                                                                                                                                  |
| Deferred auth       | [`ClientPendingAuth`](openvpn-mgmt-codec/src/command.rs#L316)                                                                  | `SUCCESS:`                                                                         | Client waits                                                                                                                                                                 |
| Kill client         | [`ClientKill`](openvpn-mgmt-codec/src/command.rs#L290)                                                                         | `SUCCESS:`                                                                         | `>CLIENT:DISCONNECT`                                                                                                                                                         |
| Load stats          | [`LoadStats`](openvpn-mgmt-codec/src/command.rs#L311) → [`parse_load_stats()`](openvpn-mgmt-codec/src/parsed_response.rs#L114) | `SUCCESS: nclients=N,...`                                                          | [`LoadStats`](openvpn-mgmt-codec/src/parsed_response.rs#L26)                                                                                                                 |
| ENV filter          | [`EnvFilter`](openvpn-mgmt-codec/src/command.rs#L348)                                                                          | `SUCCESS: env_filter_level=N`                                                      | —                                                                                                                                                                            |
| Push update (all)   | [`PushUpdateBroad`](openvpn-mgmt-codec/src/command.rs#L364)                                                                    | `SUCCESS:`                                                                         | (2.7+ only)                                                                                                                                                                  |
| Push update (cid)   | [`PushUpdateCid`](openvpn-mgmt-codec/src/command.rs#L371)                                                                      | `SUCCESS:`                                                                         | (2.7+ only)                                                                                                                                                                  |

### Codec test coverage

- **Offline:**
  - [status.rs](openvpn-mgmt-codec/src/status.rs) module tests — [v3_single_client](openvpn-mgmt-codec/src/status.rs#L523), [v2_full_multiple_clients](openvpn-mgmt-codec/src/status.rs#L577), [v2_old_openvpn_23](openvpn-mgmt-codec/src/status.rs#L604), [v1_server_two_clients](openvpn-mgmt-codec/src/status.rs#L628), [v1_server_empty](openvpn-mgmt-codec/src/status.rs#L651), [v1_server_many_clients](openvpn-mgmt-codec/src/status.rs#L664), [client_statistics_basic](openvpn-mgmt-codec/src/status.rs#L679), [client_statistics_with_compression](openvpn-mgmt-codec/src/status.rs#L695), [client_statistics_missing_key](openvpn-mgmt-codec/src/status.rs#L710), [client_statistics_invalid_number](openvpn-mgmt-codec/src/status.rs#L724), [empty_input](openvpn-mgmt-codec/src/status.rs#L743), [v2v3_unknown_lines_ignored](openvpn-mgmt-codec/src/status.rs#L750)
  - [parsed_response.rs](openvpn-mgmt-codec/src/parsed_response.rs) — [load_stats_normal](openvpn-mgmt-codec/src/parsed_response.rs#L343), [load_stats_missing_field](openvpn-mgmt-codec/src/parsed_response.rs#L359), [load_stats_unexpected_field](openvpn-mgmt-codec/src/parsed_response.rs#L377), [hold_active](openvpn-mgmt-codec/src/parsed_response.rs#L385)
  - [protocol_test.rs](openvpn-mgmt-codec/tests/protocol_test.rs) — [status_v1_server_with_clients](openvpn-mgmt-codec/tests/protocol_test.rs#L145), [status_v2_with_headers](openvpn-mgmt-codec/tests/protocol_test.rs#L162), [status_v3_tab_delimited](openvpn-mgmt-codec/tests/protocol_test.rs#L178), [status_v1_server_empty_no_clients](openvpn-mgmt-codec/tests/protocol_test.rs#L1635), [status_v2_full_with_title_time_dco](openvpn-mgmt-codec/tests/protocol_test.rs#L1689), [success_load_stats_real_format](openvpn-mgmt-codec/tests/protocol_test.rs#L2243), [server_mode_client_auth_session](openvpn-mgmt-codec/tests/protocol_test.rs#L1353)
  - [codec.rs](openvpn-mgmt-codec/src/codec.rs) — [encode_env_filter](openvpn-mgmt-codec/src/codec.rs#L1425), [encode_push_update_broad](openvpn-mgmt-codec/src/codec.rs#L1461), [encode_push_update_cid](openvpn-mgmt-codec/src/codec.rs#L1469)
- **Conformance:**
  - [conformance.rs](openvpn-mgmt-codec/tests/conformance.rs) — status V1/V2/V3 queries against real OpenVPN (port 7505)
  - [conformance_server.rs](openvpn-mgmt-codec/tests/conformance_server.rs) — full lifecycle: client-auth → established → status with real client data → load-stats → bytecount → client-kill → disconnect → reconnect → client-deny → pending-auth → auth-nt → SIGUSR1 (port 7506)

### Test fixtures

| Fixture                                                                                                  | Format        | Source                       |
| -------------------------------------------------------------------------------------------------------- | ------------- | ---------------------------- |
| [status_v3.txt](openvpn-mgmt-codec/tests/fixtures/status_v3.txt)                                         | V3 (tab)      | OpenVPN 2.6.8, 1 client      |
| [status_v2.txt](openvpn-mgmt-codec/tests/fixtures/status_v2.txt)                                         | V2 (comma)    | 1 client                     |
| [status_v2_full.txt](openvpn-mgmt-codec/tests/fixtures/status_v2_full.txt)                               | V2 (comma)    | 2 clients, IPv6, DCO         |
| [status_v2_old.txt](openvpn-mgmt-codec/tests/fixtures/status_v2_old.txt)                                 | V2 (comma)    | OpenVPN 2.3.2, fewer columns |
| [status_v1_server.txt](openvpn-mgmt-codec/tests/fixtures/status_v1_server.txt)                           | V1 (comma)    | 2 clients                    |
| [status_v1_server_empty.txt](openvpn-mgmt-codec/tests/fixtures/status_v1_server_empty.txt)               | V1 (comma)    | No clients                   |
| [status_v1_server_many_clients.txt](openvpn-mgmt-codec/tests/fixtures/status_v1_server_many_clients.txt) | V1 (comma)    | 3 clients                    |
| [status_v1_client.txt](openvpn-mgmt-codec/tests/fixtures/status_v1_client.txt)                           | V1 statistics | Client mode                  |
| [status_v1_client_full.txt](openvpn-mgmt-codec/tests/fixtures/status_v1_client_full.txt)                 | V1 statistics | Client mode with compression |

### UI test checklist

- [ ] Query `status 3` — verify client table with all [`ConnectedClient`](openvpn-mgmt-codec/src/status.rs#L91) columns
- [ ] Verify fields: CN, real address, virtual IP, bytes, cipher
- [ ] Query `status 1` — verify V1 parsing (fewer columns, no CID)
- [ ] Query `status 2` — verify V2 parsing (comma-separated with headers)
- [ ] Test with no connected clients — verify empty table
- [ ] Test with OpenVPN 2.3 format (no IPv6/PeerID/Cipher columns) — see [status_v2_old.txt](openvpn-mgmt-codec/tests/fixtures/status_v2_old.txt)
- [ ] Test client-mode statistics via [`parse_client_statistics()`](openvpn-mgmt-codec/src/status.rs#L447)
- [ ] Approve a connecting client — verify `>CLIENT:ESTABLISHED`
- [ ] Deny a client — verify client receives AUTH_FAILED
- [ ] Kill a client — verify `>CLIENT:DISCONNECT` and table update
- [ ] Query load-stats — verify [`LoadStats`](openvpn-mgmt-codec/src/parsed_response.rs#L26) fields displayed
- [ ] Set env-filter level — verify `SUCCESS: env_filter_level=N`
- [ ] Verify `push-update-broad`/`push-update-cid` encode correctly
      (2.7+ only — expect ERROR on 2.6 containers)

### Status format comparison

```
V1: "OpenVPN CLIENT LIST" header, comma-separated, no time_t fields
    → parse_status() detects by first line
V2: TITLE/TIME/HEADER/CLIENT_LIST prefixes, comma-separated
    → parse_status() detects by absence of tabs
V3: TITLE/TIME/HEADER/CLIENT_LIST prefixes, tab-separated
    → parse_status() detects by tab in first structural line
```

Format detection logic: [detect_separator()](openvpn-mgmt-codec/src/status.rs#L183),
V1 detection: [parse_status()](openvpn-mgmt-codec/src/status.rs#L226),
V1 parser: [parse_status_v1()](openvpn-mgmt-codec/src/status.rs#L237),
V2/V3 parser: [parse_status_v2v3()](openvpn-mgmt-codec/src/status.rs#L336).

---

## 5. Remote/proxy override

### What to test

| Operation     | Trigger                                                          | Response command                                               | Types                                                                   |
| ------------- | ---------------------------------------------------------------- | -------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Accept remote | [`Notification::Remote`](openvpn-mgmt-codec/src/message.rs#L247) | [`Remote(Accept)`](openvpn-mgmt-codec/src/remote_action.rs#L4) | [`TransportProtocol`](openvpn-mgmt-codec/src/transport_protocol.rs#L11) |
| Skip to next  | `>REMOTE:host,port,proto`                                        | [`Remote(Skip)`](openvpn-mgmt-codec/src/remote_action.rs#L4)   | [`RemoteAction`](openvpn-mgmt-codec/src/remote_action.rs#L4)            |
| Modify remote | `>REMOTE:host,port,proto`                                        | [`Remote(Modify)`](openvpn-mgmt-codec/src/remote_action.rs#L4) | `host: String, port: u16`                                               |
| No proxy      | [`Notification::Proxy`](openvpn-mgmt-codec/src/message.rs#L261)  | [`Proxy(None)`](openvpn-mgmt-codec/src/proxy_action.rs#L4)     | [`ProxyAction`](openvpn-mgmt-codec/src/proxy_action.rs#L4)              |
| HTTP proxy    | `>PROXY:idx,type,host`                                           | [`Proxy(Http)`](openvpn-mgmt-codec/src/proxy_action.rs#L4)     | `host, port, non_cleartext_only`                                        |
| SOCKS proxy   | `>PROXY:idx,type,host`                                           | [`Proxy(Socks)`](openvpn-mgmt-codec/src/proxy_action.rs#L4)    | `host, port`                                                            |
| List remotes  | [`RemoteEntryCount`](openvpn-mgmt-codec/src/command.rs#L354)     | `MultiLine` (count)                                            | —                                                                       |
| Get remotes   | [`RemoteEntryGet`](openvpn-mgmt-codec/src/command.rs#L359)       | `MultiLine` (index,remote)                                     | [`RemoteEntryRange`](openvpn-mgmt-codec/src/command.rs#L41)             |

### Codec test coverage

- **Offline:**
  - [protocol_test.rs](openvpn-mgmt-codec/tests/protocol_test.rs) — [remote_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L736), [proxy_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L754), [remote_notification_tcp](openvpn-mgmt-codec/tests/protocol_test.rs#L2447), [proxy_notification_tcp](openvpn-mgmt-codec/tests/protocol_test.rs#L2467)
  - [notification_edge_cases.rs](openvpn-mgmt-codec/tests/notification_edge_cases.rs) — [remote_valid](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L435), [remote_non_numeric_port_falls_back](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L441), [proxy_valid](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L453), [proxy_non_numeric_index_falls_back](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L459)
  - [codec.rs](openvpn-mgmt-codec/src/codec.rs) — [encode_remote_modify](openvpn-mgmt-codec/src/codec.rs#L1408), [encode_proxy_http_nct](openvpn-mgmt-codec/src/codec.rs#L1478), [encode_remote_entry_count](openvpn-mgmt-codec/src/codec.rs#L1433), [encode_remote_entry_get](openvpn-mgmt-codec/src/codec.rs#L1441)
- **Conformance:** [conformance_remote.rs](openvpn-mgmt-codec/tests/conformance_remote.rs) — real `>REMOTE:` notification → accept → state transitions (port 7507)

### UI test checklist

- [ ] Connect to remote client (port 7507) — verify `>REMOTE:` notification
- [ ] Send `Remote(Accept)` — verify client proceeds to connect
- [ ] Verify remote fields: host, port, protocol
- [ ] Test `remote-entry-count` — verify count returned
- [ ] Test `remote-entry-get all` — verify entries listed

---

## 6. Settings and configuration

### What to test

| Operation              | Command                                                                                                                   | Response                                                    |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| Toggle state stream    | [`StateStream`](openvpn-mgmt-codec/src/command.rs#L88)                                                                   | `SUCCESS:`                                                  |
| Toggle log stream      | [`Log`](openvpn-mgmt-codec/src/command.rs#L126)                                                                           | `SUCCESS:`                                                  |
| Toggle echo stream     | [`Echo`](openvpn-mgmt-codec/src/command.rs#L130)                                                                          | `SUCCESS:`                                                  |
| Set bytecount interval | [`ByteCount(N)`](openvpn-mgmt-codec/src/command.rs#L135)                                                                  | `SUCCESS:`                                                  |
| Auth retry mode        | [`AuthRetry`](openvpn-mgmt-codec/src/command.rs#L186)                                                                     | `SUCCESS:`                                                  |
| Get/set verbosity      | [`Verb`](openvpn-mgmt-codec/src/command.rs#L105)                                                                          | `SUCCESS:`                                                  |
| Get/set mute           | [`Mute`](openvpn-mgmt-codec/src/command.rs#L109)                                                                          | `SUCCESS:`                                                  |
| Version info           | [`Version`](openvpn-mgmt-codec/src/command.rs#L92) → [`parse_version()`](openvpn-mgmt-codec/src/parsed_response.rs#L179) | [`VersionInfo`](openvpn-mgmt-codec/src/version_info.rs#L32) |
| Process ID             | [`Pid`](openvpn-mgmt-codec/src/command.rs#L96) → [`parse_pid()`](openvpn-mgmt-codec/src/parsed_response.rs#L93)          | `u32`                                                       |
| Help text              | [`Help`](openvpn-mgmt-codec/src/command.rs#L100)                                                                          | `MultiLine`                                                 |

### Codec test coverage

- **Offline:**
  - [boundary_conditions.rs](openvpn-mgmt-codec/tests/boundary_conditions.rs) — [status_format_display_roundtrip_all](openvpn-mgmt-codec/tests/boundary_conditions.rs#L177), [stream_mode_display_roundtrip_all](openvpn-mgmt-codec/tests/boundary_conditions.rs#L186), [auth_retry_mode_display_roundtrip](openvpn-mgmt-codec/tests/boundary_conditions.rs#L219), [signal_display_roundtrip](openvpn-mgmt-codec/tests/boundary_conditions.rs#L232), [ovpn_command_from_str_basic_commands](openvpn-mgmt-codec/tests/boundary_conditions.rs#L262), [ovpn_command_from_str_status_variants](openvpn-mgmt-codec/tests/boundary_conditions.rs#L275)
  - [codec.rs](openvpn-mgmt-codec/src/codec.rs) — [encode_state_on_all](openvpn-mgmt-codec/src/codec.rs#L1321), [encode_state_recent](openvpn-mgmt-codec/src/codec.rs#L1329), [encode_echo_on_all](openvpn-mgmt-codec/src/codec.rs#L1520)
  - [parsed_response.rs](openvpn-mgmt-codec/src/parsed_response.rs) — [pid_normal](openvpn-mgmt-codec/src/parsed_response.rs#L321), [pid_missing_prefix](openvpn-mgmt-codec/src/parsed_response.rs#L331), [hold_active](openvpn-mgmt-codec/src/parsed_response.rs#L385), [hold_invalid_value](openvpn-mgmt-codec/src/parsed_response.rs#L400), [version_roundtrip](openvpn-mgmt-codec/src/parsed_response.rs#L495)
  - [version_info.rs](openvpn-mgmt-codec/src/version_info.rs) — [parse_typical_version_output](openvpn-mgmt-codec/src/version_info.rs#L104), [parse_short_management_version_header](openvpn-mgmt-codec/src/version_info.rs#L116), [parse_empty_response](openvpn-mgmt-codec/src/version_info.rs#L136)
- **Conformance:** [conformance.rs](openvpn-mgmt-codec/tests/conformance.rs) — version, help, pid, state_stream, log_history, echo_toggle, status_v1/v2/v3, sequential_codec_state, exit (18 tests against port 7505)

### UI test checklist

- [ ] Toggle each [`StreamMode`](openvpn-mgmt-codec/src/stream_mode.rs#L13) (on/off/all) — verify response
- [ ] Set bytecount interval — verify notifications start/stop
- [ ] Query version — verify [`VersionInfo`](openvpn-mgmt-codec/src/version_info.rs#L32) with management version
- [ ] Query PID — verify numeric PID returned
- [ ] Set verbosity — verify level changes
- [ ] Set auth-retry — verify mode accepted

---

## 7. Security and edge cases

### What to test

| Scenario                        | Test approach                                                                                                                                                         |
| ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Newline injection in passwords  | Verify `\n`/`\r` stripped ([`EncoderMode::Sanitize`](openvpn-mgmt-codec/src/codec.rs#L27)) or rejected ([`EncoderMode::Strict`](openvpn-mgmt-codec/src/codec.rs#L35)) |
| NULL byte truncation            | Verify `\0` stripped or rejected via [`wire_safe()`](openvpn-mgmt-codec/src/codec.rs#L66)                                                                             |
| `END` injection in block bodies | Verify escaped to ` END` or rejected via [`EncodeError::EndInBlockBody`](openvpn-mgmt-codec/src/codec.rs#L52)                                                         |
| Quote breakout in auth_type     | Verify `"` and `\` properly escaped via [`quote_and_escape()`](openvpn-mgmt-codec/src/codec.rs#L93)                                                                   |
| Accumulation limit exceeded     | Verify error returned via [`AccumulationLimit`](openvpn-mgmt-codec/src/codec.rs#L124)                                                                                 |
| UTF-8 error recovery            | Verify codec resets state — see [codec.rs:686-688](openvpn-mgmt-codec/src/codec.rs#L686)                                                                              |
| Interleaved notifications       | Verify `>BYTECOUNT:` during multi-line response doesn't corrupt it                                                                                                    |
| Malformed notifications         | Verify all 20+ types degrade to [`Notification::Simple`](openvpn-mgmt-codec/src/message.rs#L275)                                                                      |

### Codec test coverage

- **Offline:**
  - [defensive/](openvpn-mgmt-codec/tests/defensive/) — 63 injection tests + 38 real-world edge cases sourced from CVE-2024-54780, CVE-2024-5594, OpenVPN #645/#908, openvpn-gui #317/#351
  - [decoder_recovery.rs](openvpn-mgmt-codec/tests/decoder_recovery.rs) — 14 tests: [utf8_error_followed_by_valid_success](openvpn-mgmt-codec/tests/decoder_recovery.rs#L22), [utf8_error_during_multiline_accumulation_resets_state](openvpn-mgmt-codec/tests/decoder_recovery.rs#L41), [multiline_limit_error_leaves_multi_line_buf_active](openvpn-mgmt-codec/tests/decoder_recovery.rs#L116), [alternating_utf8_errors_and_valid_messages](openvpn-mgmt-codec/tests/decoder_recovery.rs#L301)
  - [adversarial_roundtrip.rs](openvpn-mgmt-codec/tests/adversarial_roundtrip.rs) — 33 tests: [password_with_backslashes_and_quotes](openvpn-mgmt-codec/tests/adversarial_roundtrip.rs#L59), [rsa_sig_with_end_in_base64](openvpn-mgmt-codec/tests/adversarial_roundtrip.rs#L178), [strict_mode_rejects_newline_in_password](openvpn-mgmt-codec/tests/adversarial_roundtrip.rs#L280), [strict_mode_rejects_end_in_block_body](openvpn-mgmt-codec/tests/adversarial_roundtrip.rs#L308)
  - [notification_edge_cases.rs](openvpn-mgmt-codec/tests/notification_edge_cases.rs) — 59 tests covering every notification type's malformed-input degradation
  - [proptest_roundtrip.rs](openvpn-mgmt-codec/tests/proptest_roundtrip.rs) — 34 property-based tests for encode↔decode roundtrip, injection resistance, structural integrity
- **Conformance:** [conformance_server.rs](openvpn-mgmt-codec/tests/conformance_server.rs) — interleaved notifications test: real tunnel traffic (ping through VPN) generating `>BYTECOUNT:` during rapid status queries

### UI test checklist

- [ ] Paste `test\nkill all` into a password field — verify no command injection
- [ ] Send very long status response — verify accumulation limit triggers error
- [ ] Verify interleaved notifications don't corrupt UI state
- [ ] Verify malformed notifications display as `[UNKNOWN_TYPE] raw payload`

---

## 8. Interactive prompt responses

### What to test

| Prompt        | Notification                                                            | Response command                                                                                                 |
| ------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Need OK       | [`Notification::NeedOk`](openvpn-mgmt-codec/src/message.rs#L193)        | [`NeedOk`](openvpn-mgmt-codec/src/command.rs#L217) with [`NeedOkResponse`](openvpn-mgmt-codec/src/need_ok.rs#L4) |
| Need string   | [`Notification::NeedStr`](openvpn-mgmt-codec/src/message.rs#L201)       | [`NeedStr`](openvpn-mgmt-codec/src/command.rs#L226)                                                              |
| PKCS#11 count | [`Notification::Pkcs11IdCount`](openvpn-mgmt-codec/src/message.rs#L188) | [`Pkcs11IdCount`](openvpn-mgmt-codec/src/command.rs#L236)                                                        |
| PKCS#11 get   | `>PKCS11ID-ENTRY:'idx', ID:'id', BLOB:'blob'`                           | [`Pkcs11IdGet`](openvpn-mgmt-codec/src/command.rs#L240)                                                          |

### Codec test coverage

- **Offline:**
  - [protocol_test.rs](openvpn-mgmt-codec/tests/protocol_test.rs) — [need_ok_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L696), [need_str_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L711), [pkcs11_id_get_parsed](openvpn-mgmt-codec/tests/protocol_test.rs#L1248), [pkcs11_id_count_from_notification](openvpn-mgmt-codec/tests/protocol_test.rs#L3130)
  - [notification_edge_cases.rs](openvpn-mgmt-codec/tests/notification_edge_cases.rs) — [need_ok_valid](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L469), [need_ok_missing_msg_falls_back](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L481), [need_str_valid](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L493), [pkcs11_id_count_valid](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L507), [pkcs11_id_entry_valid](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L525), [pkcs11_id_entry_malformed_falls_back](openvpn-mgmt-codec/tests/notification_edge_cases.rs#L538)
  - [codec.rs](openvpn-mgmt-codec/src/codec.rs) — [encode_needok](openvpn-mgmt-codec/src/codec.rs#L1488), [encode_needstr](openvpn-mgmt-codec/src/codec.rs#L1498), [decode_need_ok_notification](openvpn-mgmt-codec/src/codec.rs#L1745)

### UI test checklist

- [ ] Verify NEED-OK prompt displays name and message
- [ ] Verify OK/Cancel response sends correct wire format
- [ ] Verify NEED-STR prompt accepts freeform input

---

## Test coverage summary

| Test suite                                                                        | Count        | Gate              | Focus                                 |
| --------------------------------------------------------------------------------- | ------------ | ----------------- | ------------------------------------- |
| Unit tests ([src/](openvpn-mgmt-codec/src/))                                      | ~200         | —                 | Types, parsers, encode/decode, Debug  |
| [protocol_test.rs](openvpn-mgmt-codec/tests/protocol_test.rs)                     | 188          | —                 | Realistic server output fixtures      |
| [notification_edge_cases.rs](openvpn-mgmt-codec/tests/notification_edge_cases.rs) | 59           | —                 | Malformed notifications               |
| [boundary_conditions.rs](openvpn-mgmt-codec/tests/boundary_conditions.rs)         | 41           | —                 | FromStr, limits, CRLF, classify       |
| [proptest_roundtrip.rs](openvpn-mgmt-codec/tests/proptest_roundtrip.rs)           | 33           | —                 | Property-based encode↔decode          |
| [adversarial_roundtrip.rs](openvpn-mgmt-codec/tests/adversarial_roundtrip.rs)     | 33           | —                 | Injection attempts                    |
| [defensive/](openvpn-mgmt-codec/tests/defensive/)                                 | ~100         | —                 | CVE regression, real-world edge cases |
| [conformance.rs](openvpn-mgmt-codec/tests/conformance.rs)                         | 18           | conformance-tests | Basic management commands             |
| [conformance_server.rs](openvpn-mgmt-codec/tests/conformance_server.rs)           | 1 (16 steps) | conformance-tests | Full server lifecycle                 |
| [conformance_remote.rs](openvpn-mgmt-codec/tests/conformance_remote.rs)           | 1            | conformance-tests | REMOTE notification flow              |
| [conformance_password.rs](openvpn-mgmt-codec/tests/conformance_password.rs)       | 1            | conformance-tests | PASSWORD notification flow            |
| [decoder_recovery.rs](openvpn-mgmt-codec/tests/decoder_recovery.rs)               | 14           | —                 | Error recovery                        |
| [framed_integration.rs](openvpn-mgmt-codec/tests/framed_integration.rs)           | 11           | —                 | Async Framed I/O                      |
| [stateful_sequences.rs](openvpn-mgmt-codec/tests/stateful_sequences.rs)           | 19           | —                 | Multi-step protocol sequences         |
| **Total**                                                                         | **~720**     |                   |                                       |

### Not yet conformance-tested

| Feature                                                                                                                 | Reason                                                   | Offline coverage                                                                                                                                                                                                                                                             |
| ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`Notification::PkSign`](openvpn-mgmt-codec/src/message.rs#L214)                                                        | Needs `--management-external-key` container              | [pk_sign_with_algorithm_parsed](openvpn-mgmt-codec/tests/defensive/real_world.rs#L348), [pk_sign_without_algorithm_parsed](openvpn-mgmt-codec/tests/defensive/real_world.rs#L362), [pk_sign_notification_with_algorithm](openvpn-mgmt-codec/tests/protocol_test.rs#L2512)    |
| [`Notification::Info`](openvpn-mgmt-codec/src/message.rs#L233)                                                          | No known trigger in basic mode                           | [first_info_is_banner_subsequent_are_notifications](openvpn-mgmt-codec/tests/defensive/real_world.rs#L390)                                                                                                                                                                   |
| [`PushUpdateBroad`](openvpn-mgmt-codec/src/command.rs#L364)/[`PushUpdateCid`](openvpn-mgmt-codec/src/command.rs#L371)   | Requires OpenVPN 2.7+ (not packaged)                     | [encode_push_update_broad](openvpn-mgmt-codec/src/codec.rs#L1461), [encode_push_update_cid](openvpn-mgmt-codec/src/codec.rs#L1469), [parse_push_update_broad](openvpn-mgmt-codec/src/command.rs#L1576), [parse_push_update_cid](openvpn-mgmt-codec/src/command.rs#L1588)     |
| [`EnvFilter`](openvpn-mgmt-codec/src/command.rs#L348)                                                                   | Conformance needs ENV-producing scenario                 | [encode_env_filter](openvpn-mgmt-codec/src/codec.rs#L1425), [parse_env_filter](openvpn-mgmt-codec/src/command.rs#L1538)                                                                                                                                                      |
| [`RemoteEntryCount`](openvpn-mgmt-codec/src/command.rs#L354)/[`RemoteEntryGet`](openvpn-mgmt-codec/src/command.rs#L359) | Needs multi-remote client config                         | [encode_remote_entry_count](openvpn-mgmt-codec/src/codec.rs#L1433), [encode_remote_entry_get](openvpn-mgmt-codec/src/codec.rs#L1441), [parse_remote_entry_count](openvpn-mgmt-codec/src/command.rs#L1546), [parse_remote_entry_get](openvpn-mgmt-codec/src/command.rs#L1554) |
| [`parse_status()`](openvpn-mgmt-codec/src/status.rs#L226) typed output                                                  | Status _responses_ are tested; _parsing_ is offline-only | 12 tests in [status.rs](openvpn-mgmt-codec/src/status.rs#L523) against 8 fixture files                                                                                                                                                                                       |
