//! Client-mode example: we connect to OpenVPN's management interface.
//!
//! This is the default management mode: OpenVPN listens on a socket and
//! we dial in. Start OpenVPN with:
//!
//!   openvpn --config your.ovpn \
//!           --management 127.0.0.1 7505 \
//!           --management-hold
//!
//! Then run:
//!   cargo run --example client_mode -- [addr]
//!
//! The example connects, runs the standard startup sequence, and prints
//! every event until the connection is lost. It reconnects with
//! exponential backoff so you can restart OpenVPN without restarting
//! this program.

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::command::connection_sequence;
use openvpn_mgmt_codec::stream::{ManagementEvent, classify};
use openvpn_mgmt_codec::{Notification, OvpnCodec, OvpnCommand, StatusFormat};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7505".to_string());

    let mut backoff = std::time::Duration::from_secs(1);

    loop {
        println!("connecting to {addr}...");

        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                backoff = std::time::Duration::from_secs(1);
                println!("connected to {addr}");

                if let Err(e) = handle_connection(stream).await {
                    eprintln!("session error: {e}");
                }

                println!("connection lost, reconnecting...");
            }
            Err(e) => {
                eprintln!("connect failed: {e}, retrying in {backoff:?}");
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
    }
}

async fn handle_connection(stream: TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let framed = Framed::new(stream, OvpnCodec::new());
    let (mut sink, raw_stream) = framed.split();
    let mut mgmt = raw_stream.map(classify);

    // Run the standard startup sequence (enable log/state streaming,
    // request pid, set up bytecount reporting, release hold).
    for cmd in connection_sequence(5) {
        sink.send(cmd).await?;
    }

    // Request an initial status dump.
    sink.send(OvpnCommand::Status(StatusFormat::V3)).await?;

    while let Some(event) = mgmt.next().await {
        match event? {
            ManagementEvent::Notification(n) => {
                println!("notification: {n:?}");

                if let Notification::Fatal { message } = &n {
                    eprintln!("OpenVPN fatal: {message}");
                    break;
                }
            }
            ManagementEvent::Response(msg) => {
                println!("response: {msg:?}");
            }
        }
    }

    Ok(())
}
