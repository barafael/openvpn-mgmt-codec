//! Helpers for categorizing [`OvpnMessage`]s into responses and notifications.
//!
//! The raw codec yields [`OvpnMessage`] variants, and callers typically
//! need to branch on "is this a response to a command I sent?" vs. "is
//! this an asynchronous notification?". This module provides
//! [`ManagementEvent`] (the two-variant enum) and [`classify`] (a mapping
//! function suitable for use with stream combinators like
//! `StreamExt::map`).
//!
//! # Notification interleaving
//!
//! [`ManagementEvent::Notification`] can appear **between** sending a
//! command and receiving its [`ManagementEvent::Response`]. Consumers
//! should always handle both variants in their stream loop — do not
//! assume the next item after sending a command will be its response.
//!
//! # Example
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use tokio_util::codec::Framed;
//! use futures::{SinkExt, StreamExt};
//! use openvpn_mgmt_codec::{OvpnCodec, OvpnCommand, StatusFormat};
//! use openvpn_mgmt_codec::stream::{ManagementEvent, classify};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let stream = TcpStream::connect("127.0.0.1:7505").await?;
//! let framed = Framed::new(stream, OvpnCodec::new());
//! let (mut sink, raw_stream) = framed.split();
//!
//! let mut mgmt = raw_stream.map(classify);
//!
//! sink.send(OvpnCommand::Status(StatusFormat::V3)).await?;
//!
//! while let Some(event) = mgmt.next().await {
//!     match event? {
//!         ManagementEvent::Notification(n) => {
//!             println!("async notification: {n:?}");
//!         }
//!         ManagementEvent::Response(msg) => {
//!             println!("command response: {msg:?}");
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::io;

use crate::message::{Notification, OvpnMessage};

/// A management-interface event, categorized as either a command response
/// or an asynchronous notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagementEvent {
    /// A command response: [`OvpnMessage::Success`], [`OvpnMessage::Error`],
    /// [`OvpnMessage::MultiLine`], [`OvpnMessage::Pkcs11IdEntry`],
    /// [`OvpnMessage::Info`], [`OvpnMessage::PasswordPrompt`], or
    /// [`OvpnMessage::Unrecognized`].
    Response(OvpnMessage),

    /// A real-time notification from the daemon.
    Notification(Notification),
}

impl From<OvpnMessage> for ManagementEvent {
    fn from(msg: OvpnMessage) -> Self {
        match msg {
            OvpnMessage::Notification(n) => Self::Notification(n),
            other => Self::Response(other),
        }
    }
}

/// Classify an [`OvpnMessage`] result into a [`ManagementEvent`] result.
///
/// This function is designed to be passed directly to a stream combinator:
///
/// ```ignore
/// use futures::StreamExt;
/// let events = raw_stream.map(classify);
/// ```
///
/// # Extracting notifications with timeout
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use tokio::net::TcpStream;
/// use tokio_util::codec::Framed;
/// use futures::{SinkExt, StreamExt};
/// use openvpn_mgmt_codec::{OvpnCodec, OvpnCommand};
///
/// let stream = TcpStream::connect("127.0.0.1:7505").await?;
/// let mut framed = Framed::new(stream, OvpnCodec::new());
///
/// // Send a command and read the response with a timeout.
/// framed.send(OvpnCommand::Pid).await?;
/// let response = tokio::time::timeout(
///     std::time::Duration::from_secs(5),
///     framed.next(),
/// ).await?
///  .ok_or("stream ended")?
///  ?;
/// println!("got: {response:?}");
/// # Ok(())
/// # }
/// ```
///
/// # Reconnection with backoff
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use tokio::net::TcpStream;
/// use tokio_util::codec::Framed;
/// use futures::StreamExt;
/// use openvpn_mgmt_codec::{OvpnCodec, OvpnMessage};
///
/// let mut backoff = std::time::Duration::from_secs(1);
/// loop {
///     match TcpStream::connect("127.0.0.1:7505").await {
///         Ok(stream) => {
///             backoff = std::time::Duration::from_secs(1); // reset
///             let mut framed = Framed::new(stream, OvpnCodec::new());
///             while let Some(msg) = framed.next().await {
///                 match msg {
///                     Ok(m) => println!("{m:?}"),
///                     Err(e) => { eprintln!("decode error: {e}"); break; }
///                 }
///             }
///             eprintln!("connection closed, reconnecting...");
///         }
///         Err(e) => {
///             eprintln!("connect failed: {e}, retrying in {backoff:?}");
///         }
///     }
///     tokio::time::sleep(backoff).await;
///     backoff = (backoff * 2).min(std::time::Duration::from_secs(30));
/// }
/// # }
/// ```
///
/// # Detecting connection loss via `>FATAL:`
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use tokio::net::TcpStream;
/// use tokio_util::codec::Framed;
/// use futures::StreamExt;
/// use openvpn_mgmt_codec::{OvpnCodec, OvpnMessage, Notification};
///
/// let stream = TcpStream::connect("127.0.0.1:7505").await?;
/// let mut framed = Framed::new(stream, OvpnCodec::new());
///
/// while let Some(msg) = framed.next().await {
///     match msg? {
///         OvpnMessage::Notification(Notification::Fatal { message }) => {
///             eprintln!("OpenVPN fatal: {message}");
///             // Trigger graceful shutdown / reconnection.
///             break;
///         }
///         other => println!("{other:?}"),
///     }
/// }
/// // Stream ended — either FATAL or the daemon closed the connection.
/// // In both cases, you should reconnect (see reconnection example above).
/// # Ok(())
/// # }
/// ```
pub fn classify(result: Result<OvpnMessage, io::Error>) -> Result<ManagementEvent, io::Error> {
    result.map(ManagementEvent::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Notification;

    #[test]
    fn success_maps_to_response() {
        let msg = OvpnMessage::Success("pid=42".to_string());
        let event: ManagementEvent = msg.into();
        assert_eq!(
            event,
            ManagementEvent::Response(OvpnMessage::Success("pid=42".to_string()))
        );
    }

    #[test]
    fn notification_maps_to_notification() {
        let msg = OvpnMessage::Notification(Notification::Hold {
            text: "Waiting".to_string(),
        });
        let event: ManagementEvent = msg.into();
        assert!(matches!(
            event,
            ManagementEvent::Notification(Notification::Hold { .. })
        ));
    }

    #[test]
    fn info_maps_to_response() {
        let msg = OvpnMessage::Info("banner".to_string());
        let event: ManagementEvent = msg.into();
        assert!(matches!(
            event,
            ManagementEvent::Response(OvpnMessage::Info(_))
        ));
    }

    #[test]
    fn classify_maps_ok() {
        let result: Result<OvpnMessage, io::Error> =
            Ok(OvpnMessage::Success("it worked!".to_string()));
        let event = classify(result).unwrap();
        assert_eq!(
            event,
            ManagementEvent::Response(OvpnMessage::Success("it worked!".to_string()))
        );
    }

    #[test]
    fn classify_passes_through_error() {
        let result: Result<OvpnMessage, io::Error> = Err(io::Error::other("fail"));
        assert!(classify(result).is_err());
    }
}
