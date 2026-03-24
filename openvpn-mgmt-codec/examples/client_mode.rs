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

use clap::Parser;
use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::{
    Notification, OvpnCodec, OvpnCommand, StatusFormat,
    command::connection_sequence,
    stream::{ManagementEvent, classify},
};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

/// Client-mode example: connect to OpenVPN's management interface.
#[derive(Parser)]
struct Args {
    /// Address to connect to.
    #[arg(default_value = "127.0.0.1:7505")]
    address: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "client_mode=debug,openvpn_mgmt_codec=info".parse().unwrap()),
        )
        .init();

    let addr = Args::parse().address;

    let mut backoff = std::time::Duration::from_secs(1);

    loop {
        info!(%addr, "connecting");

        match TcpStream::connect(&addr).await {
            Ok(stream) => {
                backoff = std::time::Duration::from_secs(1);
                info!(%addr, "connected");

                if let Err(error) = handle_connection(stream).await {
                    error!(%error, "session error");
                }

                warn!("connection lost, reconnecting");
            }
            Err(error) => {
                warn!(%error, ?backoff, "connect failed, retrying");
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
    }
}

async fn handle_connection(stream: TcpStream) -> anyhow::Result<()> {
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
            ManagementEvent::Notification(notification) => {
                info!(?notification, "notification");

                if let Notification::Fatal { message } = &notification {
                    error!(%message, "OpenVPN fatal");
                    break;
                }
            }
            ManagementEvent::Response(response) => {
                debug!(?response, "response");
            }
        }
    }

    Ok(())
}
