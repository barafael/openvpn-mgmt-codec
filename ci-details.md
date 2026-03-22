# Conformance Testing Details

## What the conformance tests found

Two protocol bugs in the codec, both invisible without a real OpenVPN instance:

### 1. Password prompt has no newline

OpenVPN 2.6 sends `ENTER PASSWORD:` as an interactive prompt — 15 raw bytes,
no `\n`, no `\r\n`. The codec's line-oriented decoder waited forever for a
line terminator that never arrived.

No spec documents this. No other implementation we compared against handles
it. Every test we had — unit, proptest, fixture-based — used
`ENTER PASSWORD:\n` because that's what the line-oriented protocol implies.

**Hex dump from CI:**

```text
00000000: 454e 5445 5220 5041 5353 574f 5244 3a    ENTER PASSWORD:
```

**Fix:** detect the prompt in the buffer even without `\n`; skip bare empty
lines outside accumulation contexts to absorb a trailing `\n` from older
versions without producing a spurious `Unrecognized` message.

### 2. Management version header wording changed

OpenVPN 2.6.16 sends `Management Version: 5` instead of
`Management Interface Version: 5` — a silent wording change. The version
parser used exact prefix matching and returned `None`, so any consumer
feature-gating on management version would silently disable features.

**Fix:** fuzzy match any line starting with "management" containing
"version", extract the trailing number. Handles both known formats and
hypothetical future variations.

## Operational details no spec covers

The conformance tests also forced us to understand runtime behaviors that
are absent from `management-notes.txt` and all other documentation:

- **`management-client-auth` requires `auth-user-pass`**: the VPN client
  must send username/password credentials even when using certificate auth.
  Without them, the TLS handshake fails with `Auth Username/Password was
not provided by peer` and `>CLIENT:CONNECT` is never sent to the
  management interface.

- **`nc -z` healthchecks steal the management slot**: OpenVPN's management
  interface accepts one client at a time. A Docker healthcheck using
  `nc -z` connects every second, and OpenVPN accepts each probe as a
  management client, sends `ENTER PASSWORD:`, then processes the disconnect.
  The real test client's TCP connection sits in the kernel accept queue and
  never gets serviced. Fix: use `pidof openvpn` as the healthcheck.

- **`dev null` is not a real device mode**: the original test config used
  `dev null` (copied from a local test script that happened to work). On
  Alpine Linux, OpenVPN interprets this as a device named "null", can't
  determine TUN vs TAP type, and stalls after opening the management port
  but before entering its event loop. Fix: use `dev tun` with
  `/dev/net/tun` mounted; `management-hold` prevents OpenVPN from touching
  the device until hold is released.

- **`connect-retry` uses exponential backoff**: the default `connect-retry 1`
  doubles the interval on each failure up to 300 seconds. After hold release,
  the client's next retry could be 16+ seconds away, eating into the test
  timeout. Fix: `connect-retry 1 1` (initial=1s, max=1s).

- **Server mode goes silent after hold release if initialization fails**:
  the `hold release` command returns `SUCCESS` even when the subsequent
  initialization (TUN creation, UDP binding) hasn't completed yet. If
  initialization fails silently, the management interface stays connected
  but sends zero notifications — no state transitions, no errors. The only
  way to diagnose this is `verb 9` in the server config and checking
  container logs.

- **`client-deny` causes the VPN client to exit permanently**: after
  `client-deny`, the server sends `AUTH_FAILED` to the client. The client
  treats this as a fatal error (`SIGTERM[soft,auth-failure]`) and exits
  instead of reconnecting. Tests that need the client to reconnect must use
  `client-kill` (which sends `RESTART`) before any `client-deny`.

- **`auth-user-pass` (no file) is required for `management-query-passwords`**:
  without the `auth-user-pass` directive, the client never attempts
  username/password authentication at all — the server rejects with
  "Auth Username/Password was not provided by peer". Adding
  `auth-user-pass` without a filename tells OpenVPN it needs credentials;
  `--management-query-passwords` then routes the request to the management
  interface instead of stdin.

- **`>PROXY:` is not sent for UDP connections**: despite enabling
  `--management-query-proxy`, OpenVPN 2.6.16 does not send `>PROXY:`
  notifications when connecting via UDP. The feature may only apply to
  TCP transport or when an actual proxy is configured.

## Infrastructure

### Docker containers

- **`openvpn`** (port 7505) — `dev null`, `management-hold`. Basic management-only, no tunnel.
- **`openvpn-server`** (port 7506 + 1194/udp) — `mode server`, `management-client-auth`, `management-hold`. Full server with PKI and client auth.
- **`openvpn-client`** — `auth-user-pass`, auto-reconnect. VPN client connecting to `openvpn-server`.
- **`openvpn-client-remote`** (port 7507) — `management-query-remote`, `management-query-proxy`, `management-hold`. Client with own management for REMOTE testing.
- **`openvpn-client-password`** (port 7508) — `management-query-passwords`, `auth-user-pass` (no file), `management-hold`. Client that asks management for credentials via `>PASSWORD:`.

PKI (CA + server cert + client cert) is generated at Docker build time
using easy-rsa in a multi-stage Dockerfile. Management password
(`test-password`) is created with `printf` in the Dockerfile to guarantee
Unix line endings regardless of host OS.

### CI execution order

1. **Remote/proxy test** (`conformance_remote.rs`) — runs first because
   the server lifecycle test ends with SIGUSR1 which puts the server back
   in hold mode
2. **Server-mode lifecycle** (`conformance_server.rs`) — single test, ~2 min
3. **Password notification test** (`conformance_password.rs`) — 1 test
4. **Basic tests** (`conformance.rs`) — 18 tests with `--test-threads=1`

## Test coverage

### Basic conformance tests (`conformance.rs`) — 18 tests

Connect to a management-only OpenVPN instance (no tunnel, held mode) on
port 7505. Each test opens its own management connection. Tests run with
`--test-threads=1` because the management interface accepts one client at
a time.

| Test                                                | What it validates                                                |
| --------------------------------------------------- | ---------------------------------------------------------------- |
| `connect_and_authenticate`                          | Password prompt, management auth, INFO banner, HOLD notification |
| `version_returns_multiline_with_management_version` | `version` → MultiLine, management version parsing                |
| `help_returns_multiline`                            | `help` → MultiLine with >10 command descriptions                 |
| `pid_returns_valid_process_id`                      | `pid` → Success, `parse_pid()` returns positive PID              |
| `state_returns_multiline_in_hold`                   | `state` → MultiLine with at least one state entry                |
| `hold_query_parses_correctly`                       | `hold` → Success, `parse_hold()` matches observed hold state     |
| `status_v1_returns_multiline`                       | `status 1` → non-empty MultiLine                                 |
| `status_v2_returns_multiline`                       | `status 2` → non-empty MultiLine                                 |
| `status_v3_returns_multiline`                       | `status 3` → non-empty MultiLine                                 |
| `log_on_off_toggle`                                 | `log on` → Success(ON), `log off` → Success(OFF)                 |
| `echo_on_off_toggle`                                | `echo on` → Success(ON), `echo off` → Success(OFF)               |
| `state_stream_on_off_toggle`                        | `state on` → Success(ON), `state off` → Success(OFF)             |
| `bytecount_toggle`                                  | `bytecount 5` → Success, `bytecount 0` → Success                 |
| `hold_release_triggers_state_notification`          | `hold release` → Success + `>STATE:` notification                |
| `log_all_returns_multiline_history`                 | `log all` → non-empty MultiLine (buffered log history)           |
| `unknown_raw_command_returns_error`                 | Unknown command → `ERROR` response                               |
| `sequential_commands_maintain_codec_state`          | pid→Success, version→MultiLine, help→MultiLine, pid→Success      |
| `exit_closes_connection`                            | `exit` → stream ends (None)                                      |

### Server-mode lifecycle (`conformance_server.rs`) — 1 test, 16 steps

Connects to a full server-mode OpenVPN instance (port 7506) with
`--management-client-auth`, a TUN tunnel, and an auto-connecting VPN
client container. Uses a single management connection for the entire
lifecycle.

| Step                                  | What it validates                                                                                                             |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 1. Connect & authenticate             | Password prompt, auth, INFO banner, HOLD notification                                                                         |
| 2. Enable notifications, release hold | `state on`, `bytecount 2`, `hold release`                                                                                     |
| 3. CLIENT:CONNECT with ENV            | `>CLIENT:CONNECT` with 44+ ENV keys (CN, IP, TLS serial, etc.)                                                                |
| 4. client-auth with config push       | `client-auth {cid} {kid}` with route + DNS push lines                                                                         |
| 5. CLIENT:ESTABLISHED                 | `>CLIENT:ESTABLISHED` with matching CID                                                                                       |
| 6. Status V1/V2/V3                    | Real client data: VPN address in V1, CLIENT_LIST in V2/V3                                                                     |
| 7. load-stats                         | `nclients >= 1`, real byte counts                                                                                             |
| 8. Bytecount notification             | `>BYTECOUNT:` or `>BYTECOUNT_CLI:` within 10s                                                                                 |
| 9. Interleaved notifications          | 25 rapid `status 2` queries with ping traffic; all MultiLine responses intact despite interleaved `>BYTECOUNT:` notifications |
| 10. Kill client                       | `client-kill {cid}` → `>CLIENT:DISCONNECT`                                                                                    |
| 11. Pending auth                      | Reconnect → `client-pending-auth {cid} {kid} "..." 30` → Success                                                              |
| 12. Status during pending             | `status 2` shows client visible while auth is pending                                                                         |
| 13. Approve with auth-nt              | `client-auth-nt {cid} {kid}` → `>CLIENT:ESTABLISHED`                                                                          |
| 14. Kill + reconnect                  | `client-kill` → `>CLIENT:DISCONNECT` → reconnect                                                                              |
| 15. Deny client                       | `client-deny` → `>CLIENT:DISCONNECT`, client exits                                                                            |
| 16. SIGUSR1 + exit                    | `signal SIGUSR1` → state transitions, `exit` → stream ends                                                                    |

### Remote notification test (`conformance_remote.rs`) — 1 test

Connects to the client-remote container's management interface (port 7507)
which has `--management-query-remote` enabled.

| Step                      | What it validates                                                                    |
| ------------------------- | ------------------------------------------------------------------------------------ |
| 1. Connect & authenticate | Password prompt, auth, INFO banner, HOLD on client management                        |
| 2. Release hold           | State notifications enabled, hold released                                           |
| 3. >REMOTE: notification  | `>REMOTE:openvpn-server,1194,udp` — comma-separated parsing, port=1194, protocol=Udp |
| 4. Remote(Accept)         | `remote ACCEPT` wire encoding → Success                                              |
| 5. State transitions      | RESOLVE → WAIT confirm the client acted on the remote response                       |

### Password notification test (`conformance_password.rs`) — 1 test

Connects to both `openvpn-server` (port 7506) and `openvpn-client-password`
(port 7508). The client has `--management-query-passwords` and `auth-user-pass`
(without a filename), so OpenVPN asks the management interface for credentials
instead of reading them from a file.

This is the most complex conformance test — it orchestrates three concurrent
management flows: server hold release, server-side client approval (spawned
task), and client-side password query (main task).

| Step                       | What it validates                                                              |
| -------------------------- | ------------------------------------------------------------------------------ |
| 1. Server setup            | Connect to port 7506, release hold, spawn auto-approve task for CLIENT:CONNECT |
| 2. Client setup            | Connect to port 7508, enable state notifications, release hold                 |
| 3. >PASSWORD: notification | `>PASSWORD:Need 'Auth' username/password` — NeedAuth parsing, AuthType::Auth   |
| 4. Supply credentials      | `username "Auth" testuser` + `password "Auth" testpass` wire encoding          |
| 5. State transitions       | Client proceeds to connect after credentials supplied                          |

## What we learned

### Offline tests encode assumptions, not facts

The two codec bugs found on the first CI run would never have been caught
by any amount of offline testing. The unit tests, property tests, fixture
tests, and adversarial roundtrip tests all agreed on the wire format — and
they were all wrong in the same way. Every fixture used `ENTER PASSWORD:\n`
because the protocol is line-oriented and every other message ends with
`\n`. Every version test used `Management Interface Version:` because
that's what the spec says. The real server disagreed on both.

Conformance testing against a real instance is the only way to validate
the assumptions that all other tests share.

### The protocol documentation is incomplete

`management-notes.txt` documents the command set and notification format
but omits behavioral details that are critical for correct implementation:

- Which config combinations are required for each notification type
  (`auth-user-pass` without a file + `management-query-passwords` for
  `>PASSWORD:Need 'Auth'`; the absence of either fails silently in
  different ways)
- Which notifications are sent for which transport protocols
  (`>PROXY:` is not sent for UDP despite the flag being set)
- The ordering constraints between management operations
  (`hold release` returns `SUCCESS` before initialization completes;
  `client-deny` kills the client permanently while `client-kill` allows
  reconnection)
- Line termination exceptions (`ENTER PASSWORD:` is the only message
  without `\n`)
- Silent behavioral changes between versions (`Management Version:`
  replacing `Management Interface Version:` with no deprecation notice)

Every new test container revealed at least one undocumented interaction.
The operational details section above represents findings that would be
expensive for any consumer of this protocol to rediscover independently.

### Multi-party orchestration is the hard part

The basic management tests (connect, send command, check response) were
straightforward. The real complexity emerged when testing features that
require multiple actors:

- **Server-mode auth** needs a VPN client container to connect and a
  management client to approve — two concurrent TCP sessions plus the
  UDP tunnel
- **Password notifications** need three concurrent flows: server hold
  release, server-side client approval (spawned task), and client-side
  password query (main task)
- **Test ordering** matters because management state persists: SIGUSR1
  restarts the server, `client-deny` kills the client permanently, and
  hold release is a one-time operation

The single-management-connection constraint (OpenVPN accepts one client
at a time) means tests that modify server state affect all subsequent
tests. This drove the design toward one large lifecycle test rather than
many independent tests.

### The codec's stateful decoder is its most critical property

The interleave test — sending 25 rapid status queries while generating
real tunnel traffic — validates the property that matters most in
production: multi-line responses arrive intact even when `>BYTECOUNT:`
and `>STATE:` notifications are interleaved on the wire. This is the
failure mode that would cause data corruption in a real management
client, and it can only be tested with real traffic generating real
notifications at unpredictable times.

### Debugging networked tests requires byte-level visibility

The password prompt bug was diagnosed by adding a `xxd` hex dump in CI:

```text
00000000: 454e 5445 5220 5041 5353 574f 5244 3a    ENTER PASSWORD:
```

Without seeing the raw bytes, the symptom ("all tests hang at recv()")
pointed toward networking issues, Docker port mapping, container health,
and half a dozen other red herrings. The hex dump immediately showed the
15 bytes with no terminator. Adding raw byte diagnostics early in the
debugging process would have saved significant time.

## Effort

The Docker infrastructure was about half a day. The protocol surprises
took the other half. Most of the debugging time was spent on the password
prompt issue — the symptom (all tests hang at `recv()`) gave no indication
that the data was arriving but missing a newline.
