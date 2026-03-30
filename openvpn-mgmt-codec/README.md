# openvpn-mgmt-codec

A Rust [`tokio_util::codec`] for the
[OpenVPN management interface](https://openvpn.net/community-resources/management-interface/)
protocol. It gives you fully typed, escape-aware command encoding and
stateful response decoding so you can talk to an OpenVPN daemon over TCP
or a Unix socket without hand-rolling string parsing.

## Features

- **Type-safe commands** -- every management-interface command is a variant
  of `OvpnCommand`; the compiler prevents malformed protocol strings.
- **Stateful decoder** -- tracks which command was sent so it can
  disambiguate single-line replies, multi-line blocks, and real-time
  notifications (even when they arrive interleaved).
- **Command pipelining** -- send multiple commands without waiting for each
  response; the codec queues expected response types internally.
- **Automatic escaping** -- backslashes and double-quotes are escaped
  following the OpenVPN config-file lexer rules.
- **Full protocol coverage** -- 50+ commands including auth, signals,
  client management, PKCS#11, external keys, proxy/remote overrides,
  and a `Raw` escape hatch for anything new.
- **Split-based API** -- `management_split` gives independent sink and
  event stream halves for use with `select!` loops and concurrent
  notification handling.
- **High-level session** -- `ManagementSession` wraps the split API with
  typed send-and-receive methods for sequential usage.
- **Status & state parsing** -- typed parsers for `status`, `state`,
  `version`, and `hold` responses.

## Quick start

Add the crate to your project:

```toml
[dependencies]
openvpn-mgmt-codec = "1"
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }
```

### Split API (recommended)

Use `management_split` to get independent command sink and event stream
halves. This works with `select!`, can be moved across tasks, and is the
primary way to use this crate:

```rust,no_run
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::StreamExt;
use openvpn_mgmt_codec::{
    ManagementEvent, OvpnCodec, StatusFormat,
    split::{ManagementSink, management_split},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:7505").await?;
    let framed = Framed::new(stream, OvpnCodec::new());
    let (mut sink, mut events) = management_split(framed);

    sink.status(StatusFormat::V3).await?;

    while let Some(event) = events.next().await {
        match event? {
            ManagementEvent::Notification(n) => println!("event: {n:?}"),
            ManagementEvent::Response(r) => println!("response: {r:?}"),
        }
    }

    Ok(())
}
```

### Sequential session

`ManagementSession` wraps the split API for simple command/response
usage. Notifications are stashed and available via
`drain_notifications()`:

```rust,no_run
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use openvpn_mgmt_codec::{ManagementSession, OvpnCodec, StatusFormat};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:7505").await?;
    let framed = Framed::new(stream, OvpnCodec::new());
    let mut session = ManagementSession::new(framed);

    let version = session.version().await?;
    println!("version: {:?}", version.openvpn_version_line());

    let status = session.status(StatusFormat::V3).await?;
    for c in &status.clients {
        println!("{}: {}B in", c.common_name, c.bytes_in);
    }

    session.hold_release().await?;
    Ok(())
}
```

### Startup helpers

`connection_sequence` and `server_connection_sequence` return the
commands that a management client typically sends right after connecting
(enable log/state streaming, request PID, start byte-count
notifications, release the hold):

```rust,no_run
use openvpn_mgmt_codec::command::{connection_sequence, server_connection_sequence};

// Client mode — bytecount every 5 s
let cmds = connection_sequence(5);

// Server mode — bytecount every 5 s, env-filter level 0 (all vars)
let cmds = server_connection_sequence(5, 0);
```

## Architecture

The crate is split into two layers:

- **`openvpn-mgmt-frame`** — low-level line framing. Classifies each wire
  line into a `Frame` variant (Success, Error, Notification, End, Line,
  etc.) without tracking protocol state. Useful if you need raw access.
- **`openvpn-mgmt-codec`** (this crate) — adds command tracking,
  multi-line accumulation, notification parsing, and the high-level API.

`OvpnCodec` implements `Encoder<OvpnCommand>` and `Decoder` (Item =
`OvpnMessage`).

| Direction | Type          | Description |
| --------- | ------------- | ----------- |
| Encode    | `OvpnCommand` | One of 50+ command variants — serialised with proper escaping and multi-line framing. |
| Decode    | `OvpnMessage` | `Success`, `Error`, `MultiLine`, `Notification`, `Info`, `PasswordPrompt`, or `Unrecognized`. |

Real-time notifications (`>STATE:`, `>BYTECOUNT:`, `>CLIENT:`, etc.) are
emitted as `OvpnMessage::Notification` and can arrive at any time,
including in the middle of a multi-line response block. The codec handles
this transparently.

## Compatibility

This crate is built against **tokio-util 0.7** and **tokio 1**.

MSRV: **1.85** (Rust edition 2024).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
