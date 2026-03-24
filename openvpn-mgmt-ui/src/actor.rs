//! Connection actor — manages the TCP link to an OpenVPN management socket.
//!
//! The actor is a plain struct ([`ConnectionActor`]) whose
//! [`event_loop`](ConnectionActor::event_loop) method consumes `self`, processes
//! messages, and returns `self` on shutdown.  The caller controls channel
//! creation and spawning, enabling deterministic testing.
//!
//! Two `mpsc` channels connect the actor to the Iced UI:
//!
//! - **commands in** (`mpsc::Receiver<ActorCommand>`): the UI sends connect,
//!   disconnect, and send-command messages.
//! - **events out** (`mpsc::UnboundedSender<ActorEvent>`): the actor sends
//!   connected, disconnected, and decoded-message events back to the UI.

use std::time::Duration;

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::{OvpnCodec, OvpnCommand, OvpnMessage};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_util::codec::Framed;

/// Maximum time to wait for a single startup command response before
/// giving up and moving to the next command.
const STARTUP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

// -------------------------------------------------------------------
// Public channel types
// -------------------------------------------------------------------

/// Commands the UI can send to the actor.
#[derive(Debug)]
pub(crate) enum ActorCommand {
    /// Establish a TCP connection to `host:port` and run the given startup
    /// commands immediately after the socket opens.
    Connect {
        host: String,
        port: String,
        startup_commands: Vec<OvpnCommand>,
    },
    /// Tear down the current connection.
    Disconnect,
    /// Forward a typed management command over the wire.
    Send(OvpnCommand),
}

/// Events the actor reports back to the UI.
#[derive(Debug, Clone)]
pub(crate) enum ActorEvent {
    /// TCP connection established and startup sequence sent.
    Connected,
    /// Connection lost or intentionally closed. The optional string carries
    /// an error message when the disconnect was unexpected.
    Disconnected(Option<String>),
    /// A decoded message or notification arrived from OpenVPN.
    Message(OvpnMessage),
}

/// The UI dropped its receiver — the actor should shut down.
struct UiGone;

/// Extension trait on `mpsc::Sender<ActorEvent>` that maps a closed
/// channel into `Err(UiGone)` so callers can `?`-propagate.
trait SendEvent {
    async fn send_event(&self, event: ActorEvent) -> Result<(), UiGone>;
}

impl SendEvent for mpsc::Sender<ActorEvent> {
    async fn send_event(&self, event: ActorEvent) -> Result<(), UiGone> {
        self.send(event).await.map_err(|_| UiGone)
    }
}

// -------------------------------------------------------------------
// Actor
// -------------------------------------------------------------------

/// Connection actor — a stateless bridge between the UI and an OpenVPN
/// management socket.
///
/// Follows the "actor as pure data + event loop" pattern: the struct holds
/// no I/O resources; the [`event_loop`](Self::event_loop) method borrows
/// channels from the caller and returns `self` on shutdown.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConnectionActor;

impl ConnectionActor {
    pub(crate) fn new() -> Self {
        Self
    }

    /// Run the actor's event loop until shutdown.
    ///
    /// The loop idles until it receives a [`ActorCommand::Connect`], then
    /// bridges the TCP connection with the UI.  On disconnect it returns to
    /// idle.  The loop exits (returning `self`) when:
    ///
    /// - All senders for `cmd_rx` are dropped (**natural shutdown**).
    /// - The UI drops its event receiver (detected via failed sends).
    pub(crate) async fn event_loop(
        self,
        mut cmd_rx: mpsc::Receiver<ActorCommand>,
        event_tx: mpsc::Sender<ActorEvent>,
    ) -> Self {
        loop {
            let Some(cmd) = cmd_rx.recv().await else {
                return self; // Natural shutdown — all senders dropped.
            };

            match cmd {
                ActorCommand::Connect {
                    host,
                    port,
                    startup_commands,
                } => {
                    if run_connection(&mut cmd_rx, &event_tx, &host, &port, startup_commands)
                        .await
                        .is_err()
                    {
                        return self; // UI gone.
                    }
                }
                // Ignore non-Connect commands while disconnected.
                ActorCommand::Disconnect | ActorCommand::Send(_) => {}
            }
        }
    }
}

async fn run_connection(
    cmd_rx: &mut mpsc::Receiver<ActorCommand>,
    tx: &mpsc::Sender<ActorEvent>,
    host: &str,
    port: &str,
    startup_commands: Vec<OvpnCommand>,
) -> Result<(), UiGone> {
    let addr = socket_addr(host, port);
    tracing::info!(addr, "connecting");

    let stream = match TcpStream::connect(&addr).await {
        Ok(stream) => stream,
        Err(error) => {
            tracing::warn!(addr, %error, "connection failed");
            tx.send_event(ActorEvent::Disconnected(Some(error.to_string())))
                .await?;
            return Ok(());
        }
    };

    let framed = Framed::new(stream, OvpnCodec::new());
    let (mut sink, mut stream) = framed.split();

    tracing::info!(addr, "connected");
    tx.send_event(ActorEvent::Connected).await?;

    // Run the caller-supplied startup sequence.
    // The codec is sequential: we must wait for each response before
    // sending the next command.  Notifications (>STATE:, >LOG:, etc.)
    // can arrive between command/response pairs and are forwarded
    // immediately.  A timeout prevents hangs when a response never
    // arrives (e.g. log history flood at high verbosity).
    tracing::debug!(count = startup_commands.len(), "running startup sequence");
    for cmd in startup_commands {
        if let Err(error) = sink.send(cmd).await {
            tx.send_event(ActorEvent::Disconnected(Some(error.to_string())))
                .await?;
            return Ok(());
        }
        let deadline = tokio::time::Instant::now() + STARTUP_RESPONSE_TIMEOUT;
        loop {
            match tokio::time::timeout_at(deadline, stream.next()).await {
                Ok(Some(Ok(msg))) => {
                    // Notifications / Info / PasswordPrompt are async —
                    // anything else is a command response.
                    let is_async = matches!(
                        msg,
                        OvpnMessage::Notification(_)
                            | OvpnMessage::Info(_)
                            | OvpnMessage::PasswordPrompt
                    );
                    tx.send_event(ActorEvent::Message(msg)).await?;
                    if !is_async {
                        break;
                    }
                }
                Ok(Some(Err(error))) => {
                    tx.send_event(ActorEvent::Disconnected(Some(error.to_string())))
                        .await?;
                    return Ok(());
                }
                Ok(None) => {
                    tx.send_event(ActorEvent::Disconnected(None)).await?;
                    return Ok(());
                }
                Err(_timeout) => {
                    tracing::warn!("startup command timed out, moving on");
                    break;
                }
            }
        }
    }

    // Multiplex commands from the UI and messages from OpenVPN.
    loop {
        tokio::select! {
            // Incoming management message.
            msg = stream.next() => {
                match msg {
                    Some(Ok(msg)) => {
                        tx.send_event(ActorEvent::Message(msg)).await?;
                    }
                    Some(Err(error)) => {
                        tx.send_event(ActorEvent::Disconnected(Some(error.to_string()))).await?;
                        return Ok(());
                    }
                    None => {
                        tx.send_event(ActorEvent::Disconnected(None)).await?;
                        return Ok(());
                    }
                }
            }

            // Command from the UI.
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else {
                    return Err(UiGone); // UI gone.
                };
                match cmd {
                    ActorCommand::Connect { .. } => {
                        tx.send_event(ActorEvent::Disconnected(None)).await?;
                        return Ok(());
                    }
                    ActorCommand::Disconnect => {
                        tracing::info!("disconnecting (user request)");
                        let _ = sink.send(OvpnCommand::Quit).await;
                        tx.send_event(ActorEvent::Disconnected(None)).await?;
                        return Ok(());
                    }
                    ActorCommand::Send(ovpn_cmd) => {
                        tracing::debug!(?ovpn_cmd, "sending");
                        if let Err(error) = sink.send(ovpn_cmd).await {
                            tracing::warn!(%error, "send failed, disconnecting");
                            tx.send_event(ActorEvent::Disconnected(Some(error.to_string()))).await?;
                            return Ok(());
                        }
                    }
                }
            }
        }
    }
}

/// Build a `host:port` string suitable for [`TcpStream::connect`].
///
/// IPv6 literals are wrapped in brackets so that `ToSocketAddrs` can
/// distinguish the colon-separated address from the port delimiter.
fn socket_addr(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4() {
        assert_eq!(socket_addr("127.0.0.1", "1194"), "127.0.0.1:1194");
    }

    #[test]
    fn ipv6_loopback() {
        assert_eq!(socket_addr("::1", "1194"), "[::1]:1194");
    }

    #[test]
    fn ipv6_global() {
        assert_eq!(socket_addr("2001:db8::1", "443"), "[2001:db8::1]:443");
    }

    #[test]
    fn ipv6_full() {
        assert_eq!(
            socket_addr("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "9090"),
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:9090"
        );
    }

    #[test]
    fn dns_name() {
        assert_eq!(
            socket_addr("vpn.example.com", "1194"),
            "vpn.example.com:1194"
        );
    }

    #[test]
    fn long_dns_name() {
        assert_eq!(
            socket_addr("vpn.us-east-1.prod.example.internal", "443"),
            "vpn.us-east-1.prod.example.internal:443"
        );
    }

    #[test]
    fn localhost() {
        assert_eq!(socket_addr("localhost", "1194"), "localhost:1194");
    }
}
