# Specification Cross-Reference

How the codec relates to the authoritative sources for the OpenVPN management
interface protocol. This document is the result of a line-by-line audit
conducted in March 2026.

## Authoritative Sources

| #   | Source                                                                         | Location                                                                                   | Authority                | Notes                                                                                                                          |
| --- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| 1   | `doc/management-notes.txt`                                                     | [openvpn/openvpn](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt) | **De facto spec**        | The only complete protocol description. Defines commands, notifications, framing, escaping, multi-line blocks, and versioning. |
| 2   | `src/openvpn/manage.h`                                                         | [openvpn/openvpn](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h)     | Canonical header         | Defines `MANAGEMENT_VERSION=5`, 13 state names, notification type constants.                                                   |
| 3   | `src/openvpn/manage.c`                                                         | [openvpn/openvpn](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)     | Canonical implementation | Command dispatch table, `SUCCESS:`/`ERROR:` format strings, response formats, password handling (3 attempts).                  |
| 4   | [Community docs](https://openvpn.net/community-docs/management-interface.html) | openvpn.net                                                                                | Official docs            | Higher-level overview. Restates management-notes.txt content. Useful for the config-file lexer escaping rules.                 |
| 5   | OpenVPN 2.6.9 `help` output                                                    | [fixture: help_2_6_9.txt](openvpn-mgmt-codec/tests/fixtures/help_2_6_9.txt)                | Runtime reference        | Captured from jkroepke/openvpn-auth-oauth2 test fixtures. Lists every command the running server accepts.                      |

## Client Library Sources (used for test fixtures and edge cases)

| Source                                                                          | Language | What we extracted                                                                                                                                 |
| ------------------------------------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jkroepke/openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) | Go       | Rich `>CLIENT:CONNECT` ENV sets with TLS chain, `>CLIENT:CR_RESPONSE` with base64, `client-pending-auth` with `WEB_AUTH::` URL, 2.6.9 help output |
| [kumina/openvpn_exporter](https://github.com/kumina/openvpn_exporter)           | Go       | Status V2/V3 formats, old (2.3.2) vs new (2.6.9) column differences, `load-stats` response                                                        |
| [Jamie-/openvpn-api](https://github.com/Jamie-/openvpn-api)                     | Python   | State history, status V1 client/P2P mode, empty server status                                                                                     |
| [tonyseek/openvpn-status](https://github.com/tonyseek/openvpn-status)           | Python   | Status V1 with email-style CNs, multiple clients                                                                                                  |
| [mysteriumnetwork/go-openvpn](https://github.com/mysteriumnetwork/go-openvpn)   | Go       | Full connection lifecycle sequences (archived repo)                                                                                               |
| [NordSecurity/gopenvpn](https://github.com/NordSecurity/gopenvpn)               | Go       | `>STATE:` with hostname                                                                                                                           |
| [OpenVPN/openvpn-gui](https://github.com/OpenVPN/openvpn-gui)                   | C        | Official GUI notification parsing, state transitions, password prompts                                                                            |
| [smithp1992/telnet-openvpn](https://github.com/smithp1992/telnet-openvpn)       | Node.js  | `kill` response format strings                                                                                                                    |

## Protocol Versioning

There is **no "v2 protocol."** The management interface uses a single integer
version negotiated per-session via the `version` command. Features are gated by
thresholds:

| Client sends `version N` | Feature enabled                                                 | OpenVPN version |
| ------------------------ | --------------------------------------------------------------- | --------------- |
| 1 (default)              | Base protocol, `>RSA_SIGN`                                      | 2.1+            |
| 2                        | `>PK_SIGN:{base64}` replaces `>RSA_SIGN`                        | 2.5+            |
| 3                        | `>PK_SIGN:{base64},{algorithm}` (algorithm field added)         | 2.5+            |
| 4                        | Server sends `SUCCESS:` when version is set (previously silent) | 2.6+            |
| 5                        | `client-pending-auth` requires KID argument                     | 2.6+            |

Management version >3 also gates `remote-entry-count` and `remote-entry-get`.

## Command Coverage

Commands the spec defines vs. what the codec implements.

### Implemented and correct

| Codec variant                        | Wire format                                                         | Spec source          | Status    |
| ------------------------------------ | ------------------------------------------------------------------- | -------------------- | --------- |
| `Status(fmt)`                        | `status` / `status 2` / `status 3`                                  | management-notes.txt | Correct   |
| `State`                              | `state`                                                             | management-notes.txt | Correct   |
| `StateStream(mode)`                  | `state on` / `state off` / `state all` / `state on all` / `state N` | management-notes.txt | Correct   |
| `Version`                            | `version`                                                           | management-notes.txt | Correct   |
| `Pid`                                | `pid`                                                               | management-notes.txt | Correct   |
| `Help`                               | `help`                                                              | management-notes.txt | Correct   |
| `Verb(n)`                            | `verb` / `verb N`                                                   | management-notes.txt | Correct   |
| `Mute(n)`                            | `mute` / `mute N`                                                   | management-notes.txt | Correct   |
| `Net`                                | `net`                                                               | management-notes.txt | Correct   |
| `Log(mode)`                          | `log on` / `log off` / etc.                                         | management-notes.txt | Correct   |
| `Echo(mode)`                         | `echo on` / `echo off` / etc.                                       | management-notes.txt | Correct   |
| `ByteCount(n)`                       | `bytecount N`                                                       | management-notes.txt | Correct   |
| `Signal(sig)`                        | `signal SIGUSR1`                                                    | management-notes.txt | Correct   |
| `Kill(target)`                       | `kill CN` / `kill proto:ip:port`                                    | management-notes.txt | Correct   |
| `HoldQuery`                          | `hold`                                                              | management-notes.txt | Correct   |
| `HoldOn` / `HoldOff` / `HoldRelease` | `hold on` / `hold off` / `hold release`                             | management-notes.txt | Correct   |
| `Username{..}`                       | `username "Auth" myuser`                                            | management-notes.txt | Correct   |
| `Password{..}`                       | `password "Private Key" "foo\"bar"`                                 | management-notes.txt | Correct   |
| `AuthRetry(mode)`                    | `auth-retry interact`                                               | management-notes.txt | Correct   |
| `ForgetPasswords`                    | `forget-passwords`                                                  | management-notes.txt | Correct   |
| `ChallengeResponse{..}`              | `password "Auth" "CRV1::state_id::response"`                        | management-notes.txt | Correct   |
| `StaticChallengeResponse{..}`        | `password "Auth" "SCRV1::b64_pw::b64_resp"`                         | management-notes.txt | Correct   |
| `NeedOk{..}`                         | `needok name ok`                                                    | management-notes.txt | Correct   |
| `NeedStr{..}`                        | `needstr name "value"`                                              | management-notes.txt | Correct   |
| `Pkcs11IdCount`                      | `pkcs11-id-count`                                                   | management-notes.txt | Correct   |
| `Pkcs11IdGet(n)`                     | `pkcs11-id-get N`                                                   | management-notes.txt | Correct   |
| `RsaSig{..}`                         | `rsa-sig` + lines + `END`                                           | management-notes.txt | Correct   |
| `ClientAuth{..}`                     | `client-auth CID KID` + lines + `END`                               | management-notes.txt | Correct   |
| `ClientAuthNt{..}`                   | `client-auth-nt CID KID`                                            | management-notes.txt | Correct   |
| `ClientDeny{..}`                     | `client-deny CID KID "reason" ["client-reason"]`                    | management-notes.txt | Correct   |
| `ClientKill{..}`                     | `client-kill CID`                                                   | management-notes.txt | Correct   |
| `ClientPf{..}`                       | `client-pf CID` + lines + `END`                                     | management-notes.txt | Correct   |
| `Remote(action)`                     | `remote ACCEPT` / `remote MOD host port`                            | management-notes.txt | Correct   |
| `Proxy(action)`                      | `proxy NONE` / `proxy HTTP host port`                               | management-notes.txt | Correct   |
| `LoadStats`                          | `load-stats`                                                        | management-notes.txt | Correct   |
| `Certificate{..}`                    | `certificate` + PEM lines + `END`                                   | management-notes.txt | Correct   |
| `ManagementPassword(pw)`             | `{password}\n` (bare line)                                          | management-notes.txt | Correct   |
| `Exit` / `Quit`                      | `exit` / `quit`                                                     | management-notes.txt | Correct   |
| `Raw(s)` / `RawMultiLine(s)`         | passthrough                                                         | N/A (escape hatch)   | By design |

### Fixed (previously wrong, corrected in this audit)

| Codec variant               | Was                                           | Now                                                   | Fix                                                                       |
| --------------------------- | --------------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------------------- |
| `CrResponse { response }`   | `cr-response {CID} {KID} {RESPONSE}`          | `cr-response {base64-response}`                       | Removed spurious CID/KID fields — this is a client-side command           |
| ~~`ClientDenyV2{..}`~~      | `client-deny-v2 ...`                          | **Removed**                                           | Command does not exist in OpenVPN; was hallucinated by a prior AI session |
| `ClientPendingAuth{..}`     | `{CID} {KID} {TIMEOUT} {EXTRA}`               | `{CID} {KID} {EXTRA} {TIMEOUT}`                       | Swapped argument order to match `help` output: `CID KID MSG timeout`      |
| ~~`BypassMessage(s)`~~      | `bypass-message "message"`                    | **Removed**                                           | Absent from manage.c dispatch table — hallucinated command                |
| ~~`ClientPf{..}`~~          | `client-pf {CID}` + lines + `END`             | **Removed**                                           | manage.h: `/* #define MF_CLIENT_PF *REMOVED FEATURE* */`                  |
| `KillTarget::Address`       | `kill {ip}:{port}`                            | `kill {proto}:{ip}:{port}`                            | manage.c parses 3 colon-separated fields; added `protocol` field          |
| `Notification::State`       | `local_port` at pos 5, `remote_port` at pos 7 | `remote_port` at pos 5 (f), `local_port` at pos 7 (h) | Field names were swapped; added `local_addr` (g) and `local_ipv6` (i)     |
| `HoldQuery`                 | `ResponseKind::SingleValue`                   | `SUCCESS: hold=N`                                     | manage.c outputs SUCCESS:-prefixed response                               |
| bare `State`                | `ResponseKind::SingleValue`                   | END-terminated multi-line                             | manage.c calls `man_history()` which outputs `END`                        |
| `OpenVpnState`              | 11 variants                                   | 12 variants                                           | Added `AUTH_PENDING` (manage.h `OPENVPN_STATE_AUTH_PENDING = 12`)         |
| CRV1 parsing                | In `Need 'Auth' username/password CRV1:...`   | In `Verification Failed: 'Auth' ['CRV1:...']`         | management-notes.txt: CRV1 data is in Verification Failed line            |
| SC echo flag                | `echo_str == "1"`                             | `flag & 1 != 0` (multi-bit integer)                   | manage.c: `SC:%d` with bit 0=ECHO, bit 1=FORMAT                           |
| `ClientKill`                | `client-kill {CID}` only                      | `client-kill {CID} [M]`                               | help output: optional message param (def=RESTART)                         |
| `Notification::Proxy`       | `{proto_num, proto_type, host, port}`         | `{index, proxy_type, host}`                           | init.c: `>PROXY:%u,%s,%s` — 3 fields, no port                             |
| `Pkcs11IdGet`               | `ResponseKind::SingleValue` + Phase 4         | `>PKCS11ID-ENTRY:` has `>` prefix                     | Moved to notification dispatcher (Phase 3)                                |
| `ResponseKind::SingleValue` | 3 producers                                   | 0 producers                                           | Removed variant entirely                                                  |

### Missing from codec (spec-defined commands not implemented)

| Command              | Wire format                     | Since           | Notes                                                    |
| -------------------- | ------------------------------- | --------------- | -------------------------------------------------------- |
| `pk-sig`             | `pk-sig` + base64 lines + `END` | 2.5+ (mgmt v2+) | Replacement for `rsa-sig`. Supports ECDSA, RSA-PSS, etc. |
| `env-filter`         | `env-filter [level]`            | 2.6+            | Controls which env vars are sent in `>CLIENT:` blocks    |
| `remote-entry-count` | `remote-entry-count`            | 2.6+ (mgmt v3+) | Query number of `--remote` entries                       |
| `remote-entry-get`   | `remote-entry-get i\|all [j]`   | 2.6+ (mgmt v3+) | Retrieve remote entries by index                         |
| `push-update-broad`  | `push-update-broad "options"`   | 2.7+            | Push option update to all clients                        |
| `push-update-cid`    | `push-update-cid CID "options"` | 2.7+            | Push option update to specific client                    |

## Protocol Framing & Escaping

| Detail                         | Spec says                                 | Codec does                                              | Match?                        |
| ------------------------------ | ----------------------------------------- | ------------------------------------------------------- | ----------------------------- |
| Line delimiter (client→server) | `\n` or `\r\n`                            | `\n`                                                    | Yes                           |
| Line delimiter (server→client) | `\r\n`                                    | Splits on `\n`, strips `\r`                             | Yes                           |
| Multi-line block terminator    | Bare `END` on its own line                | Emits `END\n`                                           | Yes                           |
| Config-file lexer escaping     | `\\` → `\`, `\"` → `"`, `\ ` → space      | `quote_and_escape` implements `\\` and `\"`             | Yes                           |
| Newline in quoted strings      | Not addressed (line layer is below lexer) | Stripped by `quote_and_escape` (defensive, beyond spec) | Yes (hardened)                |
| `END` in multi-line block body | Not addressed (protocol ambiguity)        | Stripped by encoder (defensive, beyond spec)            | Yes (hardened)                |
| NUL bytes                      | Not addressed                             | Stripped by encoder (defensive)                         | Yes (hardened)                |
| Max line length                | Not specified                             | Not enforced                                            | Match (both silent)           |
| CLIENT notification atomicity  | Guaranteed atomic                         | Trusted (no timeout/cap by default)                     | Match                         |
| Echo buffer size               | Hardcoded to 100                          | Not relevant to codec                                   | N/A                           |
| Management password attempts   | 3 before disconnect                       | Not enforced client-side                                | Correct (server-side concern) |

## Security Properties

| Property                      | Spec stance                                               | Codec stance                                      | Notes                         |
| ----------------------------- | --------------------------------------------------------- | ------------------------------------------------- | ----------------------------- |
| Cleartext channel             | Explicitly acknowledged; recommends localhost/unix socket | CLI warns on non-loopback                         | Correct                       |
| Newline injection             | Silent (trusts management client)                         | Encoder strips `\n`/`\r`/`\0` from all fields     | Hardened beyond spec          |
| `END` injection in multi-line | Silent (protocol ambiguity)                               | Encoder strips bare `END` lines from block bodies | Hardened beyond spec          |
| Quote breakout in `auth_type` | Only well-known types shown in spec                       | `AuthType::Custom` validated by encoder           | Hardened beyond spec          |
| Unbounded accumulation        | No limits documented (except echo=100)                    | `AccumulationLimit` enum, unlimited by default    | Configurable defense-in-depth |
| UTF-8 errors mid-accumulation | Not addressed                                             | Decoder resets state on UTF-8 failure             | Hardened beyond spec          |

## Testing Methodology

| Layer                 | Technique                                                                                 | What it found                                                                                            |
| --------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| Spec conformance      | ~190 protocol tests from fixtures captured from real OpenVPN sessions and client libraries | Correct parsing of all notification types, response formats, state names                                 |
| Defensive/injection   | ~100 tests in `tests/defensive/`                                                          | Newline injection, `END` injection, quote breakout, NUL bytes, multi-line truncation, Unicode edge cases |
| Property-based        | 30+ proptest cases in `tests/proptest_roundtrip.rs`                                       | Framing invariants (single `\n`), no bare `END`, codec state independence                                |
| Mutation              | cargo-mutants with `.cargo/mutants.toml` exclusions                                       | Dead code paths, undertested branches                                                                    |
| Real-world edge cases | `tests/defensive/real_world.rs` sourced from CVEs, forums, Android bug reports            | Truncated STATE lines, double-encoded Windows paths, overlong CN/IP fields, stale PID responses          |

## Key Learnings

1. **The spec assumes a trusted local client.** The escaping rules, unquoted
   fields, and lack of `END` escaping all make sense when the management client
   fully controls its own output. A codec library erases that assumption.

2. **`management-notes.txt` is the only spec.** The community docs page is a
   restatement. The help output is runtime truth. When they disagree, `manage.c`
   is authoritative.

3. **There is no "v2 protocol."** The `version N` command gates features
   incrementally. Command names like `client-deny-v2` are not an OpenVPN
   convention — the one in this crate was hallucinated.

4. **`cr-response` is client-side.** It answers a local `CR_TEXT` challenge.
   It does not take CID/KID — those are server-side concepts for
   `>CLIENT:CR_RESPONSE` notifications flowing the other direction.

5. **`client-pending-auth` argument order matters.** The help output shows
   `CID KID MSG timeout`, not `CID KID timeout MSG`. Getting this wrong means
   the server interprets the extra string as the timeout.
