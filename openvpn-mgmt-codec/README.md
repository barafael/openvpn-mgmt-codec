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
- **Full protocol coverage** -- 50 commands including auth, signals,
  client management, PKCS#11, external keys, proxy/remote overrides,
  and a `Raw` escape hatch for anything new.
- **High-level client** -- `ManagementClient` separates command responses
  from async notifications and returns parsed results directly.
- **Stream classification** -- the `ClassifyExt` trait splits a raw
  message stream into `Response` and `Notification` variants.
- **Status & state parsing** -- typed parsers for `status`, `state`,
  `version`, and `hold` responses.

## Quick start

Add the crate to your project:

```toml
[dependencies]
openvpn-mgmt-codec = "0.7"
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }
```

Then wrap a TCP stream with the codec:

```rust,no_run
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::{OvpnCodec, OvpnCommand, OvpnMessage, StatusFormat};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:7505").await?;
    let mut framed = Framed::new(stream, OvpnCodec::new());

    // ask for status
    framed.send(OvpnCommand::Status(StatusFormat::V3)).await?;

    // read responses
    while let Some(msg) = framed.next().await {
        match msg? {
            OvpnMessage::Success(text)     => println!("OK: {text}"),
            OvpnMessage::Error(text)       => eprintln!("ERR: {text}"),
            OvpnMessage::MultiLine(lines)  => {
                for line in &lines {
                    println!("  {line}");
                }
            }
            OvpnMessage::Notification(n)   => println!("event: {n:?}"),
            other                          => println!("{other:?}"),
        }
    }

    Ok(())
}
```

## Choosing an API level

The crate offers two ways to talk to OpenVPN:

| API | When to use |
| --- | --- |
| **`ManagementClient`** | Most applications. Sends commands and returns typed responses; dispatches notifications to a `broadcast` channel. See the [`client`](https://docs.rs/openvpn-mgmt-codec/latest/openvpn_mgmt_codec/client/) module. |
| **`Framed<T, OvpnCodec>`** | When you need full control over the stream (custom backpressure, multiplexing, or integration with an existing tower/axum stack). |

Both layers share the same `OvpnCommand` / `OvpnMessage` types.

### High-level client

`ManagementClient` handles command/response pairing and forwards
notifications to a broadcast channel:

```rust,no_run
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio_util::codec::Framed;
use openvpn_mgmt_codec::{
    ManagementClient, Notification, OvpnCodec, StatusFormat,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let stream = TcpStream::connect("127.0.0.1:7505").await?;
    let framed = Framed::new(stream, OvpnCodec::new());

    let (notification_tx, mut notification_rx) = broadcast::channel::<Notification>(256);
    let mut client = ManagementClient::new(framed, notification_tx);

    let version = client.version().await?;
    println!("version: {:?}", version.openvpn_version_line());

    let status = client.status(StatusFormat::V3).await?;
    for c in &status.clients {
        println!("{}: {}B in", c.common_name, c.bytes_in);
    }

    client.hold_release().await?;
    Ok(())
}
```

### Startup helpers

`connection_sequence` and `server_connection_sequence` return the
commands that a management client typically sends right after connecting
(enable log/state streaming, request PID, start byte-count
notifications, release the hold). Use them to avoid hand-rolling the
same boilerplate:

```rust,no_run
use openvpn_mgmt_codec::command::{connection_sequence, server_connection_sequence};

// Client mode — bytecount every 5 s
let cmds = connection_sequence(5);

// Server mode — bytecount every 5 s, env-filter level 0 (all vars)
let cmds = server_connection_sequence(5, 0);
```

## How it works

`OvpnCodec` implements `Encoder<OvpnCommand>` and `Decoder` (Item =
`OvpnMessage`).

| Direction | Type          | Description                                                                                                    |
| --------- | ------------- | -------------------------------------------------------------------------------------------------------------- |
| Encode    | `OvpnCommand` | One of 50 command variants -- serialised to the wire format with proper escaping and multi-line framing.       |
| Decode    | `OvpnMessage` | `Success`, `Error`, `MultiLine`, `Pkcs11IdEntry`, `Notification`, `Info`, `PasswordPrompt`, or `Unrecognized`. |

Real-time notifications (`>STATE:`, `>BYTECOUNT:`, `>CLIENT:`, etc.) are
emitted as `OvpnMessage::Notification` and can arrive at any time,
including in the middle of a multi-line response block. The codec handles
this transparently.

## Compatibility

This crate is built against **tokio-util 0.7** and **tokio 1**. The
public API exposes `tokio_util::codec::{Encoder, Decoder, Framed}` and
`tokio::sync::broadcast` — upgrading those dependencies in a
semver-incompatible way will require a major version bump of this crate.

MSRV: **1.85** (Rust edition 2024).

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
