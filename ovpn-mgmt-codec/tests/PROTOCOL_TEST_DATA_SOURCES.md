# Protocol Test Data Sources

Real-world OpenVPN management interface protocol data used to build the test
suite in `tests/protocol_test.rs` and `tests/fixtures/`.

## Primary Sources

| Source                                                                                          | Type             | Key Data Extracted                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [manage.c](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)                 | Canonical source | All `SUCCESS:` format strings (`pid=%d`, `nclients=%d,bytesin=%s,bytesout=%s`, `verb level changed`, etc.), all `ERROR:` messages (`signal '%s' is currently ignored`, `common name '%s' not found`, `command not allowed`, `client-pending-auth command failed. Extra parameter might be too long`), management password handshake (`ENTER PASSWORD:` → `SUCCESS: password is correct` / `ERROR: bad password`), all state names from `openvpn_state` enum |
| [manage.h](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h)                 | Canonical header | 13 state names (`INITIAL`, `CONNECTING`, `WAIT`, `AUTH`, `GET_CONFIG`, `ASSIGN_IP`, `ADD_ROUTES`, `CONNECTED`, `RECONNECTING`, `EXITING`, `RESOLVE`, `TCP_CONNECT`, `AUTH_PENDING`), `MANAGEMENT_VERSION=5`, notification type constants                                                                                                                                                                                                                    |
| [management-notes.txt](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt) | De facto spec    | State line format (9 fields incl. `tun_local_ipv6`), CLIENT ENV variable names, `>CLIENT:CR_RESPONSE,{CID},{KID},{base64}` format, packet filter syntax (`[CLIENTS DROP]`, `[SUBNETS ACCEPT]`, `[END]`), `>PKCS11ID-COUNT:` notification, static challenge `SC:` format, dynamic challenge `CRV1:` format, `SCRV1` response format, atomicity guarantees for `>CLIENT:` blocks                                                                              |
| [OpenVPN community docs](https://openvpn.net/community-docs/management-interface.html)          | Official docs    | Management interface overview, connection flow, password authentication sequence                                                                                                                                                                                                                                                                                                                                                                            |

## Client Libraries & Test Fixtures

| Source                                                                          | Lang    | Key Data Extracted                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ------------------------------------------------------------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [jkroepke/openvpn-auth-oauth2](https://github.com/jkroepke/openvpn-auth-oauth2) | Go      | Rich `>CLIENT:CONNECT` ENV sets with TLS chain (`tls_serial_0`, `tls_digest_0`, `tls_id_0`, `X509_0_CN/OU/O/ST/C`, `tls_serial_1`, `tls_digest_1`), `IV_SSO=webauth,openurl,crtext`, `>CLIENT:CR_RESPONSE` with base64, `client-pending-auth` with `WEB_AUTH::` URL, `>INFOMSG:WEB_AUTH::` and `>INFOMSG:CR_TEXT:` notifications, full 2.6.9 help output with `cr-response`, `pk-sig`, `certificate`, `env-filter`, `remote-entry-count/get`, `client-pending-auth` |
| [kumina/openvpn_exporter](https://github.com/kumina/openvpn_exporter)           | Go      | Status V2 with TITLE/TIME rows and `dco_enabled` GLOBAL_STAT, status V2 old format (2.3.2 — no `Virtual IPv6 Address`, `Client ID`, `Peer ID`, `Data Channel Cipher`), status V3 tab-delimited, `load-stats` response format                                                                                                                                                                                                                                        |
| [Jamie-/openvpn-api](https://github.com/Jamie-/openvpn-api)                     | Python  | State history query format, status V1 client/P2P mode (`OpenVPN STATISTICS` with `TUN/TAP read bytes`, compression stats), empty server status                                                                                                                                                                                                                                                                                                                      |
| [tonyseek/openvpn-status](https://github.com/tonyseek/openvpn-status)           | Python  | Status V1 server with email-style CNs (`foo@example.com`), multiple clients and routing entries                                                                                                                                                                                                                                                                                                                                                                     |
| [mysteriumnetwork/go-openvpn](https://github.com/mysteriumnetwork/go-openvpn)   | Go      | Reconnecting reasons (`tls-error`, `connection-reset`, `ping-restart`, `server-poll-timeout`), full connection state sequences, `>HOLD:Waiting for hold release:0`                                                                                                                                                                                                                                                                                                  |
| [NordSecurity/gopenvpn](https://github.com/NordSecurity/gopenvpn)               | Go      | `>STATE:` with hostname as remote IP, `>PASSWORD:Auth-Token:` notification                                                                                                                                                                                                                                                                                                                                                                                          |
| [OpenVPN/openvpn-gui](https://github.com/OpenVPN/openvpn-gui)                   | C       | All parsed notification types in the official GUI, state transition handling, password prompt flow with static/dynamic challenges                                                                                                                                                                                                                                                                                                                                   |
| [smithp1992/telnet-openvpn](https://github.com/smithp1992/telnet-openvpn)       | Node.js | `kill` response formats (by CN: `common name 'X' found, N client(s) killed`; by address: `N client(s) at address X killed`)                                                                                                                                                                                                                                                                                                                                         |

## Notification Formats

| Notification            | Source               | Wire Format                                                                    |
| ----------------------- | -------------------- | ------------------------------------------------------------------------------ |
| `>STATE:` (13 states)   | manage.h             | `{ts},{state},{desc},{tun_ip},{remote},{port},{local},{port}`                  |
| `>BYTECOUNT_CLI:`       | manage.c             | `{CID},{bytes_in},{bytes_out}`                                                 |
| `>PASSWORD:` + `SC:`    | management-notes.txt | `Need 'Auth' username/password SC:{0\|1},{challenge}`                          |
| `>PASSWORD:` + `CRV1:`  | management-notes.txt | `Need 'Auth' username/password CRV1:{flags}:{state_id}:{user_b64}:{challenge}` |
| `>PASSWORD:Auth-Token:` | gopenvpn             | `Auth-Token:{token}`                                                           |
| `>CLIENT:CR_RESPONSE`   | openvpn-auth-oauth2  | `CR_RESPONSE,{CID},{KID},{base64_response}`                                    |
| `>CLIENT:ADDRESS`       | manage.c             | `ADDRESS,{CID},{IP},{PRIMARY}` (single-line, no ENV)                           |
| `>INFOMSG:WEB_AUTH::`   | openvpn-auth-oauth2  | SSO web auth URL                                                               |
| `>INFOMSG:CR_TEXT:`     | openvpn-auth-oauth2  | `CR_TEXT:{flags}:{challenge_text}`                                             |
| `>PK_SIGN:` (mgmt v>2)  | manage.c             | `{base64_data},{algorithm}` (`RSA_PKCS1_PSS_PADDING`/`ECDSA`/…)                |
| `>NEED-CERTIFICATE:`    | manage.c             | `macosx-keychain:subject:o=OpenVPN-TEST`                                       |
| `>NOTIFY:`              | manage.c             | `info,remote-exit,EXIT`                                                        |
| `>UPDOWN:`              | manage.c             | `UP,tun0,1500,1500,10.8.0.2,10.8.0.1,init`                                     |
| `>PKCS11ID-COUNT:`      | management-notes.txt | `{count}`                                                                      |
| `>FATAL:`               | multiple             | TUN/TAP errno, TAP-Windows adapters, connection timeout                        |

## Protocol Framing

| Detail                                                         | Source                                |
| -------------------------------------------------------------- | ------------------------------------- |
| Server sends `\r\n`; client sends `\n` or `\r\n`               | All client libraries                  |
| Multi-line blocks terminated by bare `END` line                | management-notes.txt                  |
| Only `>CLIENT:` blocks are atomic (no interleaving guaranteed) | management-notes.txt                  |
| Other notifications CAN interleave during multi-line responses | manage.c                              |
| Escaping matches OpenVPN config-file lexer (`\\`, `\"`)        | management-notes.txt §Command Parsing |
| Management protocol version: currently 5                       | manage.h `MANAGEMENT_VERSION`         |
| 3 password attempts before connection close                    | manage.c `man_check_password()`       |
| `SCRV1:{b64_password}:{b64_response}` static challenge reply   | management-notes.txt                  |
| `CRV1::{state_id}::{response}` dynamic challenge reply         | management-notes.txt                  |

## Fixture → Source Mapping

| Fixture File                        | Primary Source                         |
| ----------------------------------- | -------------------------------------- |
| `status_v1_server_empty.txt`        | openvpn-auth-oauth2 mock data          |
| `status_v1_server_many_clients.txt` | tonyseek/openvpn-status examples       |
| `status_v2_full.txt`                | kumina/openvpn_exporter (2.6.9 format) |
| `status_v2_old.txt`                 | kumina/openvpn_exporter (2.3.2 format) |
| `status_v1_client_full.txt`         | Jamie-/openvpn-api mock data           |
| `help_2_6_9.txt`                    | openvpn-auth-oauth2 test fixtures      |
| `client_connect_tls_rich.txt`       | openvpn-auth-oauth2 CONNECT mock       |
| `client_cr_response.txt`            | openvpn-auth-oauth2 CR_RESPONSE mock   |
| `version_old.txt`                   | kumina/openvpn_exporter (2.3.2)        |
| `version_2_6_9.txt`                 | openvpn-auth-oauth2 (2.6.9)            |
| `full_connection_lifecycle.txt`     | mysteriumnetwork/go-openvpn captures   |
| `state_ipv6.txt`                    | NordSecurity/gopenvpn                  |
| `log_history_real.txt`              | manage.c log format strings            |
| `packet_filter.txt`                 | management-notes.txt example           |
