# UI Readiness — Response Parsing Gaps

The command surface is **100% complete** — every operation a UI needs
can be sent. The gaps are on the **response/notification parsing** side.

---

## Gap 1: Status response parsing (HIGH — blocks client table UI)

`Status(V3)` returns `MultiLine(Vec<String>)` with raw tab-delimited rows.
A UI needs typed structs.

**Source:** The V3 format is defined in
[`management-notes.txt`](https://github.com/OpenVPN/openvpn/blob/master/doc/management-notes.txt)
and implemented by
[`man_status()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c).

**V3 wire format** (tab-delimited, `HEADER` / `CLIENT_LIST` / `ROUTING_TABLE` / `GLOBAL_STATS` / `END`):

```
TITLE	OpenVPN 2.6.16 ...
TIME	...	unix_timestamp
HEADER	CLIENT_LIST	Common Name	Real Address	Virtual Address	Virtual IPv6 Address	Bytes Received	Bytes Sent	Connected Since	Connected Since (time_t)	Username	Client ID	Peer ID	Data Channel Cipher
CLIENT_LIST	cn	1.2.3.4:5678	10.8.0.2		1234	5678	...	1234567890	user	0	0	AES-256-GCM
HEADER	ROUTING_TABLE	Virtual Address	Common Name	Real Address	Last Ref	Last Ref (time_t)
ROUTING_TABLE	10.8.0.2	cn	1.2.3.4:5678	...	1234567890
GLOBAL_STATS	Max bcast/mcast queue length	0
END
```

**Implementation plan:**

- New module `status.rs` with:
  ```rust
  pub struct StatusResponse {
      pub title: String,
      pub timestamp: u64,
      pub clients: Vec<ConnectedClient>,
      pub routes: Vec<RoutingEntry>,
      pub global_stats: Vec<(String, String)>,
  }

  pub struct ConnectedClient {
      pub common_name: String,
      pub real_address: String,
      pub virtual_address: String,
      pub virtual_ipv6: String,
      pub bytes_in: u64,
      pub bytes_out: u64,
      pub connected_since: u64,
      pub username: String,
      pub cid: u64,
      pub peer_id: u64,
      pub cipher: String,
  }

  pub struct RoutingEntry {
      pub virtual_address: String,
      pub common_name: String,
      pub real_address: String,
      pub last_ref: u64,
  }
  ```
- Add `parse_status(lines: &[String]) -> Result<StatusResponse, ParseResponseError>`
  to `parsed_response.rs`
- V1 and V2 have different column layouts — start with V3 (most structured),
  add V1/V2 if needed
- **Source for V1/V2 differences:**
  [`man_status()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)
  dispatches to `print_status()` with format parameter

---

## Gap 2: `>PK_SIGN:` notification (MEDIUM — blocks ECDSA external key)

OpenVPN 2.5+ sends `>PK_SIGN:` instead of `>RSA_SIGN:` for non-RSA key types.
The codec only recognizes `>RSA_SIGN:` — `>PK_SIGN:` falls back to `Simple`.

**Source:**
[`man_send_cc_message()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)
dispatches `>PK_SIGN:` when `IEC_PK_SIGN` is set.
[`manage.h`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h)
defines `IEC_PK_SIGN = 3`.

**Wire format:**

```
>PK_SIGN:algorithm,keyid,base64_data
```

The extra `algorithm` and `keyid` fields distinguish it from `>RSA_SIGN:data`.
See [`ssl_openssl.c` `get_sig_from_man()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/ssl_openssl.c).

**Implementation plan:**

- Add `Notification::PkSign { algorithm: String, key_id: String, data: String }`
- Parse `>PK_SIGN:` in the notification dispatcher alongside `>RSA_SIGN:`
- Fallback to `Simple` on parse failure (forward-compat)

---

## Gap 3: `>INFO:` after connection (LOW — informational only)

The codec emits `OvpnMessage::Info(String)` for the initial banner
(`>INFO:OpenVPN Management Interface ...`). Later `>INFO:` messages —
notably `>INFO:WEB_AUTH::` for web-based authentication
([source](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)) —
arrive as `Unrecognized`.

**Source:**
`>INFO:` is sent by
[`management_notify_generic()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)
and can appear at any time, not just at connection start.

**Implementation plan:**

- Add `Notification::Info { message: String }` variant
- Route all `>INFO:` lines after the initial banner to this variant
  instead of `Unrecognized`
- The initial banner remains `OvpnMessage::Info` (pre-notification codec state)

---

## Conformance testing

- **Gap 1 (status parsing):** Already covered — the existing conformance
  tests query `status 1`, `status 2`, `status 3` with a connected client.
  Add assertions on the parsed structs.
- **Gap 2 (`>PK_SIGN:`):** Needs `--management-external-key` container.
  The test PKI setup in
  [`conformance/Dockerfile.server`](conformance/Dockerfile.server)
  could be extended to use an external key callback.
  May be complex — defer to a follow-up if needed.
- **Gap 3 (`>INFO:`):** Can be tested in the basic container if OpenVPN
  sends `>INFO:` in any scenario. Otherwise, unit tests suffice.

## Order of implementation

1. **`>PK_SIGN:` notification** — small, isolated parser change
2. **`>INFO:` notification** — small, isolated dispatcher change
3. **Status response parsing** — largest piece, new module + types
