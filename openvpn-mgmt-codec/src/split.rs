//! Split-based management interface for concurrent command/notification
//! handling.
//!
//! [`management_split`] breaks a `Framed<T, OvpnCodec>` into two parts:
//!
//! - A [`CommandSink`] for sending typed commands (implements
//!   [`ManagementSink`]).
//! - An [`EventStream`] that yields [`ManagementEvent`] values —
//!   responses and notifications from the server in wire order.
//!
//! The stream yields events exactly as they arrive on the wire.
//! Notifications and responses can be interleaved — use
//! [`recv_response()`](EventStream::recv_response) to skip notifications
//! when waiting for a command response. Skipped notifications are stashed
//! and come out on subsequent [`.next()`](futures_core::Stream::poll_next)
//! calls, so nothing is lost.
//!
//! # Example — event loop
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use tokio_util::codec::Framed;
//! use openvpn_mgmt_codec::{
//!     ManagementEvent, OvpnCodec,
//!     split::{management_split, ManagementSink},
//! };
//! use futures::StreamExt;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:7505").await?;
//! let framed = Framed::new(stream, OvpnCodec::new());
//!
//! let (mut sink, mut events) = management_split(framed);
//!
//! while let Some(event) = events.next().await {
//!     match event? {
//!         ManagementEvent::Notification(notif) => {
//!             println!("notification: {notif:?}");
//!         }
//!         ManagementEvent::Response(resp) => {
//!             println!("response: {resp:?}");
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Example — skip-and-stash for queries
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use tokio_util::codec::Framed;
//! use openvpn_mgmt_codec::{
//!     OvpnCodec, StatusFormat,
//!     split::{management_split, ManagementSink},
//! };
//!
//! # async fn example() -> anyhow::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:7505").await?;
//! let framed = Framed::new(stream, OvpnCodec::new());
//! let (mut sink, mut events) = management_split(framed);
//!
//! // recv_response() skips any interleaved notifications (they're stashed
//! // internally and will appear on subsequent .next() calls).
//! sink.pid().await?;
//! let pid_response = events.recv_response().await?;
//!
//! sink.status(StatusFormat::V3).await?;
//! let status_lines = events.recv_multi_line().await?;
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::{SinkExt, Stream, StreamExt as _};
use tokio_util::codec::Framed;

use crate::auth::{AuthRetryMode, AuthType};
use crate::client_deny::ClientDeny;
use crate::codec::OvpnCodec;
use crate::command::{OvpnCommand, RemoteEntryRange};
use crate::kill_target::KillTarget;
use crate::management_event::ManagementEvent;
use crate::message::{Notification, OvpnMessage};
use crate::need_ok::NeedOkResponse;
use crate::proxy_action::ProxyAction;
use crate::redacted::Redacted;
use crate::remote_action::RemoteAction;
use crate::session::SessionError;
use crate::signal::Signal;
use crate::status_format::StatusFormat;
use crate::stream_mode::StreamMode;

/// The write half of a split management connection.
pub type CommandSink<T> = futures_util::stream::SplitSink<Framed<T, OvpnCodec>, OvpnCommand>;

/// Split a framed transport into a command sink and an event stream.
///
/// See the [module documentation](self) for usage examples.
pub fn management_split<T>(framed: Framed<T, OvpnCodec>) -> (CommandSink<T>, EventStream<T>)
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite,
{
    let (sink, stream) = framed.split();
    let event_stream = EventStream {
        inner: stream,
        stash: VecDeque::new(),
    };
    (sink, event_stream)
}

/// The read half of a split management connection.
///
/// Yields [`ManagementEvent`] values in wire order. Use
/// [`recv_response()`](Self::recv_response) to skip notifications when
/// waiting for a command response — skipped notifications are stashed
/// and come out on subsequent [`.next()`](Stream::poll_next) calls.
pub struct EventStream<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> {
    inner: futures_util::stream::SplitStream<Framed<T, OvpnCodec>>,
    stash: VecDeque<Notification>,
}

impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> EventStream<T> {
    /// Drain any notifications that were stashed while
    /// [`recv_response()`](Self::recv_response) was scanning for a
    /// command response.
    pub fn drain_notifications(&mut self) -> impl Iterator<Item = Notification> + '_ {
        self.stash.drain(..)
    }
}

impl<T> Stream for EventStream<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    type Item = Result<ManagementEvent, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // Drain stashed notifications first (put there by recv_response).
        if let Some(notification) = self.stash.pop_front() {
            return Poll::Ready(Some(Ok(ManagementEvent::Notification(notification))));
        }

        // Then poll the transport.
        Pin::new(&mut self.inner)
            .poll_next(cx)
            .map(|opt| opt.map(|result| result.map(ManagementEvent::from)))
    }
}

/// Convenience methods on [`EventStream`] for reading typed responses.
///
/// These methods skip interleaved notifications while scanning for the
/// next command response. Skipped notifications are stashed internally
/// and will be yielded by subsequent [`.next()`](Stream::poll_next)
/// calls, so nothing is lost.
impl<T> EventStream<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Read events until a command response arrives.
    ///
    /// Any notifications encountered while scanning are stashed and will
    /// appear on subsequent `.next()` calls.
    pub async fn recv_response(&mut self) -> Result<OvpnMessage, SessionError> {
        use futures_util::StreamExt as _;
        // Poll the inner transport directly (not self.next()) to avoid
        // re-yielding notifications we just stashed.
        loop {
            let msg = self
                .inner
                .next()
                .await
                .ok_or(SessionError::ConnectionClosed)?
                .map_err(SessionError::Io)?;

            match msg {
                OvpnMessage::Notification(n) => {
                    self.stash.push_back(n);
                }
                other => return Ok(other),
            }
        }
    }

    /// Read until a `SUCCESS:` response, returning the payload string.
    pub async fn recv_success(&mut self) -> Result<String, SessionError> {
        match self.recv_response().await? {
            OvpnMessage::Success(payload) => Ok(payload),
            OvpnMessage::Error(msg) => Err(SessionError::ServerError(msg)),
            other => Err(SessionError::UnexpectedResponse(other)),
        }
    }

    /// Read until a multi-line response.
    pub async fn recv_multi_line(&mut self) -> Result<Vec<String>, SessionError> {
        match self.recv_response().await? {
            OvpnMessage::MultiLine(lines) => Ok(lines),
            OvpnMessage::Error(msg) => Err(SessionError::ServerError(msg)),
            other => Err(SessionError::UnexpectedResponse(other)),
        }
    }

    /// Read until `SUCCESS:` and discard the payload.
    pub async fn recv_ok(&mut self) -> Result<(), SessionError> {
        self.recv_success().await?;
        Ok(())
    }
}

/// Extension trait adding typed command methods to the write half of a
/// split management connection.
///
/// All methods are fire-and-forget at the sink level — they send the
/// command but do not wait for or parse the response. Use the
/// [`EventStream`] returned by [`management_split`] to read responses.
pub trait ManagementSink {
    /// Send a raw [`OvpnCommand`].
    fn send_command(
        &mut self,
        cmd: OvpnCommand,
    ) -> impl Future<Output = Result<(), io::Error>> + Send;

    // --- Informational ---

    /// Request connection status.
    fn status(
        &mut self,
        format: StatusFormat,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Status(format))
    }

    /// Query current state.
    fn state(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::State)
    }

    /// Control real-time state notifications.
    fn state_stream(
        &mut self,
        mode: StreamMode,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::StateStream(mode))
    }

    /// Query version information.
    fn version(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Version)
    }

    /// Set management client version.
    fn set_version(&mut self, version: u32) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::SetVersion(version))
    }

    /// Query the PID.
    fn pid(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Pid)
    }

    /// List available commands.
    fn help(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Help)
    }

    /// Query or set log verbosity.
    fn verb(&mut self, level: Option<u8>) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Verb(level))
    }

    /// Query or set mute threshold.
    fn mute(
        &mut self,
        threshold: Option<u32>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Mute(threshold))
    }

    /// Show network adapter list (Windows).
    fn net(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Net)
    }

    // --- Notification control ---

    /// Control real-time log streaming.
    fn log(&mut self, mode: StreamMode) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Log(mode))
    }

    /// Control real-time echo notifications.
    fn echo(&mut self, mode: StreamMode) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Echo(mode))
    }

    /// Enable/disable byte count notifications.
    fn bytecount(&mut self, interval: u32) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ByteCount(interval))
    }

    // --- Connection control ---

    /// Send a signal to the daemon.
    fn signal(&mut self, signal: Signal) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Signal(signal))
    }

    /// Kill a client connection (server mode).
    fn kill(&mut self, target: KillTarget) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Kill(target))
    }

    /// Query the hold flag.
    fn hold_query(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::HoldQuery)
    }

    /// Set hold flag on.
    fn hold_on(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::HoldOn)
    }

    /// Clear hold flag.
    fn hold_off(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::HoldOff)
    }

    /// Release from hold.
    fn hold_release(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::HoldRelease)
    }

    // --- Authentication ---

    /// Supply a username.
    fn username(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Username {
            auth_type,
            value: Redacted::new(value.into()),
        })
    }

    /// Supply a password.
    fn password(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Password {
            auth_type,
            value: Redacted::new(value.into()),
        })
    }

    /// Set auth-retry strategy.
    fn auth_retry(
        &mut self,
        mode: AuthRetryMode,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::AuthRetry(mode))
    }

    /// Forget all passwords.
    fn forget_passwords(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ForgetPasswords)
    }

    /// Respond to a CRV1 dynamic challenge.
    fn challenge_response(
        &mut self,
        state_id: impl Into<String>,
        response: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ChallengeResponse {
            state_id: state_id.into(),
            response: Redacted::new(response.into()),
        })
    }

    /// Respond to a static challenge.
    fn static_challenge_response(
        &mut self,
        password: impl Into<String>,
        response: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::StaticChallengeResponse {
            password: Redacted::new(password.into()),
            response: Redacted::new(response.into()),
        })
    }

    /// Respond to a CR_TEXT challenge.
    fn cr_response(
        &mut self,
        response: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::CrResponse {
            response: Redacted::new(response.into()),
        })
    }

    // --- Interactive prompts ---

    /// Respond to a `>NEED-OK:` prompt.
    fn need_ok(
        &mut self,
        name: impl Into<String>,
        response: NeedOkResponse,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::NeedOk {
            name: name.into(),
            response,
        })
    }

    /// Respond to a `>NEED-STR:` prompt.
    fn need_str(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::NeedStr {
            name: name.into(),
            value: value.into(),
        })
    }

    // --- PKCS#11 ---

    /// Query PKCS#11 certificate count.
    fn pkcs11_id_count(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Pkcs11IdCount)
    }

    /// Retrieve a PKCS#11 certificate by index.
    fn pkcs11_id_get(&mut self, index: u32) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Pkcs11IdGet(index))
    }

    // --- External key / signatures ---

    /// Provide an RSA signature.
    fn rsa_sig(
        &mut self,
        base64_lines: Vec<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::RsaSig { base64_lines })
    }

    /// Provide a PK signature.
    fn pk_sig(
        &mut self,
        base64_lines: Vec<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::PkSig { base64_lines })
    }

    /// Supply an external certificate.
    fn certificate(
        &mut self,
        pem_lines: Vec<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Certificate { pem_lines })
    }

    // --- Client management (server mode) ---

    /// Authorize a client and push config.
    fn client_auth(
        &mut self,
        cid: u64,
        kid: u64,
        config_lines: Vec<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ClientAuth {
            cid,
            kid,
            config_lines,
        })
    }

    /// Authorize a client without config.
    fn client_auth_nt(
        &mut self,
        cid: u64,
        kid: u64,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ClientAuthNt { cid, kid })
    }

    /// Deny a client connection.
    fn client_deny(
        &mut self,
        deny: ClientDeny,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ClientDeny(deny))
    }

    /// Kill a client session by CID.
    fn client_kill(
        &mut self,
        cid: u64,
        message: Option<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ClientKill { cid, message })
    }

    /// Defer authentication for a client.
    fn client_pending_auth(
        &mut self,
        cid: u64,
        kid: u64,
        extra: impl Into<String>,
        timeout: u32,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ClientPendingAuth {
            cid,
            kid,
            extra: extra.into(),
            timeout,
        })
    }

    // --- Remote / Proxy ---

    /// Respond to a `>REMOTE:` notification.
    fn remote(
        &mut self,
        action: RemoteAction,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Remote(action))
    }

    /// Respond to a `>PROXY:` notification.
    fn proxy(&mut self, action: ProxyAction) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Proxy(action))
    }

    // --- Server stats ---

    /// Request aggregated server stats.
    fn load_stats(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::LoadStats)
    }

    // --- ENV filter ---

    /// Set env-var filter level.
    fn env_filter(&mut self, level: u32) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::EnvFilter(level))
    }

    // --- Remote entries ---

    /// Query remote entry count.
    fn remote_entry_count(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::RemoteEntryCount)
    }

    /// Retrieve remote entries.
    fn remote_entry_get(
        &mut self,
        range: RemoteEntryRange,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::RemoteEntryGet(range))
    }

    // --- Management auth ---

    /// Authenticate to the management interface.
    fn management_password(
        &mut self,
        password: impl Into<String>,
    ) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::ManagementPassword(Redacted::new(
            password.into(),
        )))
    }

    // --- Lifecycle ---

    /// Close the management session.
    fn exit(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        self.send_command(OvpnCommand::Exit)
    }
}

impl<T> ManagementSink for CommandSink<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    async fn send_command(&mut self, cmd: OvpnCommand) -> Result<(), io::Error> {
        SinkExt::send(self, cmd).await
    }
}
