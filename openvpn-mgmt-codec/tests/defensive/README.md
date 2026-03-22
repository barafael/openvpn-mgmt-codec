# Defensive Tests (Beyond Spec)

Tests in this directory verify encoder hardening against protocol-level
injection attacks that the [OpenVPN management interface spec][spec] does
not address.

The spec was written for a trusted, local management client and assumes
the client never emits malformed wire data. A codec **library** cannot
make that assumption — callers may pass attacker-influenced strings into
command fields. These tests cover the gap.

## What is tested

| Category                                | Risk                                                             | Example                                                           |
| --------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------- |
| Newline injection in `quote_and_escape` | Embedded `\n` splits one command into two on the wire            | `password "Auth" "hunter2\nsignal SIGTERM"`                       |
| Newline injection in unescaped fields   | Fields like `kill {cn}` are interpolated without any escaping    | `kill victim\nsignal SIGTERM`                                     |
| `END` injection in multi-line blocks    | A body line equal to `"END"` terminates the block early          | `client-auth` config line of `"END"` followed by injected command |
| `AuthType::Unknown` quote breakout      | Manual `"..."` wrapping without escaping lets `"` break framing  | `username "Auth" injected" "admin"`                               |
| Round-trip proof                        | Encode a malicious payload, decode it, observe multiple messages | Proves the decoder actually parses the injected commands          |

## Current status

All tests **pass**. The encoder strips `\n`, `\r`, and `\0` from both
quoted (`quote_and_escape`) and unquoted (`sanitize_line`) fields, escapes
bare `END` lines in multi-line block bodies, and properly quotes
`AuthType::Unknown` values. These tests serve as the regression suite.

## Relationship to protocol_test.rs

`tests/protocol_test.rs` tests spec-compliant behavior with realistic
server output. This directory tests **beyond** the spec — inputs the
spec never contemplated but that a library must handle safely.

[spec]: https://openvpn.net/community-docs/management-interface.html
