# ovpn-mgmt-codec

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
- **Automatic escaping** -- backslashes and double-quotes are escaped
  following the OpenVPN config-file lexer rules.
- **Full protocol coverage** -- 45+ commands including auth, signals,
  client management, PKCS#11, external keys, proxy/remote overrides,
  and a `Raw` escape hatch for anything new.

## Quick start

Add the crate to your project:

```toml
[dependencies]
ovpn-mgmt-codec = "0.1"
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }
```

Then wrap a TCP stream with the codec:

```rust
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use futures::{SinkExt, StreamExt};
use ovpn_mgmt_codec::{OvpnCodec, OvpnCommand, OvpnMessage, StatusFormat};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

## How it works

`OvpnCodec` implements `Encoder<OvpnCommand>` and `Decoder` (Item =
`OvpnMessage`).

| Direction | Type          | Description                                                                                               |
|-----------|---------------|-----------------------------------------------------------------------------------------------------------|
| Encode    | `OvpnCommand` | One of 45+ command variants -- serialised to the wire format with proper escaping and multi-line framing. |
| Decode    | `OvpnMessage` | `Success`, `Error`, `SingleValue`, `MultiLine`, `Notification`, `Info`, or `Unrecognized`.                |

Real-time notifications (`>STATE:`, `>BYTECOUNT:`, `>CLIENT:`, etc.) are
emitted as `OvpnMessage::Notification` and can arrive at any time,
including in the middle of a multi-line response block. The codec handles
this transparently.
