# Missing Commands — Implementation Plan

Six management interface commands documented in
[`specs.md:131-136`](specs.md#L131) are absent from the codec.
All evidence below comes from the OpenVPN source tree at
[`src/openvpn/manage.c`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)
and
[`src/openvpn/manage.h`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h).
The current management version is **5**
([`manage.h` `MANAGEMENT_VERSION`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h)).

---

## 1. `pk-sig` — External key signature

Replacement for `rsa-sig`. Supports ECDSA, RSA-PSS, and other key types.

**Wire format:**
```
pk-sig
{base64_line_1}
{base64_line_2}
END
```

**Response:** `SUCCESS` / `ERROR` (only valid while a `>PK_SIGN` challenge
is pending — [`EKS_SOLICIT` state](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.h)).

**Help text:**
[`man_help()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c):
```
pk-sig                 : Enter a signature in response to >PK_SIGN challenge
                         Enter signature base64 on subsequent lines followed by END
```

**Handler:**
[`man_pk_sig()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c) —
structurally identical to `man_rsa_sig()`. Both set `IEC_PK_SIGN` and
accumulate base64 input.

**Implementation:**
- Add `OvpnCommand::PkSig { base64_lines: Vec<String> }` — same shape as
  `RsaSig`.
- Encoder: `write_block(dst, "pk-sig", &base64_lines, mode)`
- `expected_response` → `SuccessOrError`
- `FromStr`: `"pk-sig"` with comma-separated lines (same as `rsa-sig`
  pattern in the existing parser).

---

## 2. `env-filter` — Control CLIENT ENV verbosity

Sets which env vars are included in `>CLIENT:ENV` blocks.

**Wire format:** `env-filter [level]`

**Response:** `SUCCESS: env_filter_level=N`

**Help text:**
```
env-filter [level]     : Set env-var filter level
```

**Handler:**
[`man_env_filter()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c):
```c
static void man_env_filter(struct management *man, const int level)
{
    man->connection.env_filter_level = level;
    msg(M_CLIENT, "SUCCESS: env_filter_level=%d", level);
}
```

**Implementation:**
- Add `OvpnCommand::EnvFilter(u32)` — single integer argument, default 0.
- Encoder: `env-filter {level}`
- `expected_response` → `SuccessOrError`
- `FromStr`: `"env-filter"` + optional number (default 0).

---

## 3. `remote-entry-count` — Query remote entry count

Returns the number of `--remote` entries configured on the server.

**Wire format:** `remote-entry-count`

**Response:** Multi-line — a single number, then `END`.

**Help text:**
```
remote-entry-count     : Get number of available remote entries.
```

**Handler:**
[`man_remote_entry_count()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c):
```c
count = (*man->persist.callback.remote_entry_count)(...);
msg(M_CLIENT, "%u", count);
msg(M_CLIENT, "END");
```

**Version gate:** Requires management version >= 3
([`specs.md:44`](specs.md#L44)).

**Implementation:**
- Add `OvpnCommand::RemoteEntryCount`
- Encoder: `remote-entry-count`
- `expected_response` → `MultiLine`
- `FromStr`: `"remote-entry-count"`
- Consider adding `parse_remote_entry_count(lines: &[String]) -> Option<u32>`
  to `parsed_response.rs`.

---

## 4. `remote-entry-get` — Retrieve remote entries

Fetches `--remote` entries by index or all at once.

**Wire format:** `remote-entry-get i|all [j]`

**Response:** Multi-line — `index,remote_string` per line, then `END`.

**Help text:**
```
remote-entry-get  i|all [j]: Get remote entry at index = i to to j-1 or all.
```

**Handler:**
[`man_remote_entry_get()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c):
```c
for (unsigned int i = from; i < min_uint(to, count); i++) {
    msg(M_CLIENT, "%u,%s", i, remote);
}
msg(M_CLIENT, "END");
```

**Version gate:** Same as `remote-entry-count` — management version >= 3.

**Implementation:**
- Add `OvpnCommand::RemoteEntryGet(RemoteEntryRange)` with:
  ```rust
  pub enum RemoteEntryRange {
      Single(u32),
      Range { from: u32, to: u32 },
      All,
  }
  ```
- Encoder: `remote-entry-get {i}` / `remote-entry-get {i} {j}` /
  `remote-entry-get all`
- `expected_response` → `MultiLine`
- `FromStr`: `"remote-entry-get"` + `"all"` | number [number]

---

## 5. `push-update-broad` — Broadcast push update (OpenVPN 2.7+)

Server-mode only. Pushes option updates to all connected clients.

**Wire format:** `push-update-broad "options"`

**Response:** `SUCCESS: push-update command succeeded` /
`ERROR: push-update command failed`

**Help text:**
```
push-update-broad options : Broadcast a message to update the specified options.
                            Ex. push-update-broad "route something, -dns"
```

**Handler:**
[`man_push_update()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)
with `UPT_BROADCAST`.

**Implementation:**
- Add `OvpnCommand::PushUpdateBroad { options: String }`
- Encoder: `push-update-broad {quoted_options}` (use `quote_and_escape`)
- `expected_response` → `SuccessOrError`
- `FromStr`: `"push-update-broad"` + rest as options string.

---

## 6. `push-update-cid` — Per-client push update (OpenVPN 2.7+)

Server-mode only. Pushes option update to a specific client.

**Wire format:** `push-update-cid CID "options"`

**Response:** Same as `push-update-broad`, plus
`ERROR: push-update-cid fail during cid parsing` on bad CID.

**Help text:**
```
push-update-cid CID options : Send an update message to the client identified by CID.
```

**Handler:** Same
[`man_push_update()`](https://github.com/OpenVPN/openvpn/blob/master/src/openvpn/manage.c)
with `UPT_BY_CID`. Parses CID with `parse_cid()`.

**Implementation:**
- Add `OvpnCommand::PushUpdateCid { cid: u64, options: String }`
- Encoder: `push-update-cid {cid} {quoted_options}`
- `expected_response` → `SuccessOrError`
- `FromStr`: `"push-update-cid"` + cid + rest as options.

---

## Shared work

- Add all 6 to the `OvpnCommand` enum in
  [`command.rs`](openvpn-mgmt-codec/src/command.rs).
- Add encoder arms in
  [`codec.rs`](openvpn-mgmt-codec/src/codec.rs) `Encoder::encode`.
- Add `expected_response` arms.
- Add `FromStr` arms in `OvpnCommand::from_str`.
- Add `RemoteEntryRange` enum (new file or in `command.rs`).
- Update `strum::IntoStaticStr` labels (automatic via derive).
- Tests: encode roundtrip, `FromStr` happy + unhappy paths.
- Update [`README.md`](openvpn-mgmt-codec/README.md) command count.
- Update [`specs.md`](specs.md) to mark these as implemented.

## Order of implementation

1. `env-filter` — simplest (single integer, `SuccessOrError`)
2. `pk-sig` — clone of existing `RsaSig`
3. `remote-entry-count` — simple `MultiLine`
4. `remote-entry-get` — needs `RemoteEntryRange` enum
5. `push-update-broad` — `SuccessOrError` with quoted string
6. `push-update-cid` — like above plus CID
