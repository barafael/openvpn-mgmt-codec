//! Server-mode example: OpenVPN connects to *us* (`--management-client`).
//!
//! When OpenVPN is started with `--management-client`, it dials out to
//! a listening management program rather than the other way around. This
//! is the standard pattern for auth plugins and process managers.
//!
//! Usage:
//!   cargo run --example server_mode -- [bind_addr]
//!
//! Then start OpenVPN with:
//!   openvpn --config your.ovpn \
//!           --management 127.0.0.1 7505 \
//!           --management-client \
//!           --management-hold
//!
//! The codec is transport-agnostic — it works the same whether *you*
//! connect to OpenVPN or OpenVPN connects to *you*. The only difference
//! is who calls `bind`/`listen` vs `connect`.

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::command::connection_sequence;
use openvpn_mgmt_codec::stream::{classify, ManagementEvent};
use openvpn_mgmt_codec::{OvpnCodec, OvpnCommand};
use tokio::net::TcpListener;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7505".to_string());

    let listener = TcpListener::bind(&addr).await?;
    println!("listening on {addr}, waiting for OpenVPN to connect...");

    loop {
        let (stream, peer) = listener.accept().await?;
        println!("accepted connection from {peer}");

        let framed = Framed::new(stream, OvpnCodec::new());
        let (mut sink, raw_stream) = framed.split();
        let mut mgmt = ManagementStream::new(raw_stream);

        // Run the standard startup sequence.
        for cmd in connection_sequence(5) {
            sink.send(cmd).await?;
        }

        // Process events until the connection closes.
        while let Some(event) = mgmt.next().await {
            match event? {
                ManagementEvent::Notification(n) => {
                    println!("notification: {n:?}");

                    // Auto-approve all client connections (demo only!).
                    if let openvpn_mgmt_codec::Notification::Client {
                        event: openvpn_mgmt_codec::ClientEvent::Connect,
                        cid,
                        kid: Some(kid),
                        ..
                    } = &n
                    {
                        println!("  -> auto-approving client {cid}");
                        sink.send(OvpnCommand::ClientAuthNt {
                            cid: *cid,
                            kid: *kid,
                        })
                        .await?;
                    }
                }
                ManagementEvent::Response(msg) => {
                    println!("response: {msg:?}");
                }
            }
        }

        println!("connection from {peer} closed, waiting for next...");
    }
}
