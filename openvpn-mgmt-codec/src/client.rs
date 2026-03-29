//! High-level management client with notification dispatch.
//!
//! [`ManagementClient`] wraps a `Framed<T, OvpnCodec>` transport and splits
//! the multiplexed stream into two independent channels:
//!
//! - **Command methods** (`version`, `status`, `hold_release`, etc.) send a
//!   command and return its response directly.
//! - **Notifications** are forwarded to a [`tokio::sync::broadcast`] channel
//!   that any number of subscribers can consume independently.
//!
//! # Example
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use tokio::sync::broadcast;
//! use tokio_util::codec::Framed;
//! use openvpn_mgmt_codec::{Notification, OvpnCodec, StatusFormat};
//! use openvpn_mgmt_codec::client::ManagementClient;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:7505").await?;
//! let framed = Framed::new(stream, OvpnCodec::new());
//!
//! // Create the broadcast channel — you control capacity and lifetime.
//! let (notification_tx, _) = broadcast::channel::<Notification>(256);
//! let mut rx = notification_tx.subscribe();
//! let mut client = ManagementClient::new(framed, notification_tx);
//!
//! // Spawn a notification consumer
//! tokio::spawn(async move {
//!     while let Ok(notif) = rx.recv().await {
//!         println!("notification: {notif:?}");
//!     }
//! });
//!
//! // Commands return their response directly
//! let version = client.version().await?;
//! println!("management version: {:?}", version.management_version());
//!
//! let status = client.status(StatusFormat::V3).await?;
//! client.hold_release().await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Concurrent notification handling
//!
//! Every command method takes `&mut self`, which means you cannot
//! simultaneously listen for incoming notifications on the transport
//! while sending commands. For interactive applications that need a
//! `select!` loop over both UI events and OpenVPN messages, use the raw
//! [`OvpnCodec`](crate::OvpnCodec) with
//! [`Framed::split()`](tokio_util::codec::Framed::split) to get
//! independent read/write halves. Call
//! [`into_framed`](ManagementClient::into_framed) to recover the
//! transport from this client.
//!
//! # Extracting the transport
//!
//! Call [`ManagementClient::into_framed`] to recover the underlying
//! `Framed<T, OvpnCodec>` when you need raw access or want to drop back
//! to the low-level stream API.

use std::io;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tokio_util::codec::Framed;

use crate::auth::{AuthRetryMode, AuthType};
use crate::client_deny::ClientDeny;
use crate::codec::OvpnCodec;
use crate::command::{OvpnCommand, RemoteEntryRange};
use crate::kill_target::KillTarget;
use crate::message::{Notification, OvpnMessage};
use crate::need_ok::NeedOkResponse;
use crate::parsed_response::{self, LoadStats, StateEntry};
use crate::proxy_action::ProxyAction;
use crate::redacted::Redacted;
use crate::remote_action::RemoteAction;
use crate::signal::Signal;
use crate::status::{self, ClientStatistics, StatusResponse};
use crate::status_format::StatusFormat;
use crate::stream_mode::StreamMode;
use crate::version_info::VersionInfo;

/// Errors returned by [`ManagementClient`] command methods.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The transport returned an I/O error.
    #[error("transport error: {0}")]
    Io(#[from] io::Error),

    /// The connection was closed before a response arrived.
    #[error("connection closed while awaiting response")]
    ConnectionClosed,

    /// The server returned `ERROR: {0}`.
    #[error("server error: {0}")]
    ServerError(String),

    /// The response type did not match what the command expected.
    #[error("unexpected response: {0:?}")]
    UnexpectedResponse(OvpnMessage),

    /// A `SUCCESS:` payload could not be parsed.
    #[error("response parse error: {0}")]
    ParseResponse(#[from] parsed_response::ParseResponseError),

    /// A `status` response could not be parsed.
    #[error("status parse error: {0}")]
    ParseStatus(#[from] status::ParseStatusError),

    /// A `version` response could not be parsed.
    #[error("version parse error: {0}")]
    ParseVersion(#[from] crate::version_info::ParseVersionError),
}

/// A high-level client for the OpenVPN management interface.
///
/// See the [module documentation](self) for usage examples.
pub struct ManagementClient<T> {
    framed: Framed<T, OvpnCodec>,
    notification_tx: broadcast::Sender<Notification>,
}

impl<T> ManagementClient<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// Wrap a framed transport with an existing broadcast sender for
    /// notification dispatch.
    ///
    /// The caller creates the [`broadcast::channel`] and passes the sender
    /// here. This gives full control over channel capacity and lifetime.
    /// Call [`broadcast::Sender::subscribe`] on your copy of the sender to
    /// create receivers — multiple independent subscribers are supported.
    pub fn new(
        framed: Framed<T, OvpnCodec>,
        notification_tx: broadcast::Sender<Notification>,
    ) -> Self {
        Self {
            framed,
            notification_tx,
        }
    }

    /// Recover the underlying framed transport.
    pub fn into_framed(self) -> Framed<T, OvpnCodec> {
        self.framed
    }

    // --- Internal helpers ---

    /// Read frames until a non-notification message arrives. Interleaved
    /// notifications are forwarded to the broadcast channel.
    async fn recv_response(&mut self) -> Result<OvpnMessage, ClientError> {
        loop {
            let msg = self
                .framed
                .next()
                .await
                .ok_or(ClientError::ConnectionClosed)??;

            match msg {
                OvpnMessage::Notification(notification) => {
                    // No active receivers is fine — notifications are best-effort.
                    self.notification_tx
                        .send(notification)
                        .inspect_err(|error| {
                            tracing::debug!(%error, "no notification subscribers");
                        })
                        .ok();
                }
                other => return Ok(other),
            }
        }
    }

    /// Send a command and read frames until a non-notification response
    /// arrives.
    async fn send_and_recv(&mut self, cmd: OvpnCommand) -> Result<OvpnMessage, ClientError> {
        self.framed.send(cmd).await?;
        self.recv_response().await
    }

    /// Send a command that expects `SUCCESS:` and return the payload string.
    async fn send_expect_success(&mut self, cmd: OvpnCommand) -> Result<String, ClientError> {
        match self.send_and_recv(cmd).await? {
            OvpnMessage::Success(payload) => Ok(payload),
            OvpnMessage::Error(msg) => Err(ClientError::ServerError(msg)),
            other => Err(ClientError::UnexpectedResponse(other)),
        }
    }

    /// Send a command that expects a multi-line response.
    async fn send_expect_multi_line(
        &mut self,
        cmd: OvpnCommand,
    ) -> Result<Vec<String>, ClientError> {
        match self.send_and_recv(cmd).await? {
            OvpnMessage::MultiLine(lines) => Ok(lines),
            OvpnMessage::Error(msg) => Err(ClientError::ServerError(msg)),
            other => Err(ClientError::UnexpectedResponse(other)),
        }
    }

    /// Send a command that expects `SUCCESS:` and discard the payload.
    async fn send_expect_ok(&mut self, cmd: OvpnCommand) -> Result<(), ClientError> {
        self.send_expect_success(cmd).await?;
        Ok(())
    }

    /// Send a stream-mode command (`log`, `state`, `echo`).
    ///
    /// History-returning modes produce `Some(lines)`, on/off modes
    /// produce `None`.
    async fn send_stream_command(
        &mut self,
        mode: StreamMode,
        cmd: OvpnCommand,
    ) -> Result<Option<Vec<String>>, ClientError> {
        if mode.returns_history() {
            Ok(Some(self.send_expect_multi_line(cmd).await?))
        } else {
            self.send_expect_ok(cmd).await?;
            Ok(None)
        }
    }

    // --- Public command methods ---

    // -- Informational --

    /// Query the connection status in the given format.
    ///
    /// Returns the raw multi-line response. Use [`status`](Self::status)
    /// for a typed result.
    pub async fn status_raw(&mut self, format: StatusFormat) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::Status(format))
            .await
    }

    /// Query and parse the server-mode connection status.
    pub async fn status(&mut self, format: StatusFormat) -> Result<StatusResponse, ClientError> {
        let lines = self.status_raw(format).await?;
        Ok(status::parse_status(&lines)?)
    }

    /// Query and parse client-mode statistics.
    pub async fn client_statistics(
        &mut self,
        format: StatusFormat,
    ) -> Result<ClientStatistics, ClientError> {
        let lines = self.status_raw(format).await?;
        Ok(status::parse_client_statistics(&lines)?)
    }

    /// Query the current state as a multi-line history.
    pub async fn state(&mut self) -> Result<Vec<StateEntry>, ClientError> {
        let lines = self.send_expect_multi_line(OvpnCommand::State).await?;
        Ok(parsed_response::parse_state_history(&lines)?)
    }

    /// Query the most recent state entry.
    pub async fn current_state(&mut self) -> Result<StateEntry, ClientError> {
        let lines = self.send_expect_multi_line(OvpnCommand::State).await?;
        Ok(parsed_response::parse_current_state(&lines)?)
    }

    /// Control real-time state notifications.
    ///
    /// Streaming modes (`All`, `OnAll`, `Recent`) return accumulated history
    /// lines. `On`/`Off` return `Ok(None)`.
    pub async fn state_stream(
        &mut self,
        mode: StreamMode,
    ) -> Result<Option<Vec<StateEntry>>, ClientError> {
        match self
            .send_stream_command(mode, OvpnCommand::StateStream(mode))
            .await?
        {
            Some(lines) => Ok(Some(parsed_response::parse_state_history(&lines)?)),
            None => Ok(None),
        }
    }

    /// Query the OpenVPN and management interface version.
    pub async fn version(&mut self) -> Result<VersionInfo, ClientError> {
        let lines = self.send_expect_multi_line(OvpnCommand::Version).await?;
        Ok(parsed_response::parse_version(&lines)?)
    }

    /// Set the management client version to announce feature support.
    ///
    /// For versions < 4 this produces no response from the server.
    /// For versions >= 4 a `SUCCESS:` response is expected.
    pub async fn set_version(&mut self, version: u32) -> Result<(), ClientError> {
        let cmd = OvpnCommand::SetVersion(version);
        if version < 4 {
            self.framed.send(cmd).await?;
            Ok(())
        } else {
            self.send_expect_ok(cmd).await
        }
    }

    /// Query the PID of the OpenVPN process.
    pub async fn pid(&mut self) -> Result<u32, ClientError> {
        let payload = self.send_expect_success(OvpnCommand::Pid).await?;
        Ok(parsed_response::parse_pid(&payload)?)
    }

    /// List available management commands.
    pub async fn help(&mut self) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::Help).await
    }

    /// Query or set the log verbosity level.
    pub async fn verb(&mut self, level: Option<u8>) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Verb(level)).await
    }

    /// Query or set the mute threshold.
    pub async fn mute(&mut self, threshold: Option<u32>) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Mute(threshold)).await
    }

    /// (Windows) Show network adapter list.
    pub async fn net(&mut self) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::Net).await
    }

    // -- Notification control --

    /// Control real-time log streaming.
    ///
    /// Streaming modes return accumulated log history. `On`/`Off` return `Ok(None)`.
    pub async fn log(&mut self, mode: StreamMode) -> Result<Option<Vec<String>>, ClientError> {
        self.send_stream_command(mode, OvpnCommand::Log(mode)).await
    }

    /// Control real-time echo notifications.
    pub async fn echo(&mut self, mode: StreamMode) -> Result<Option<Vec<String>>, ClientError> {
        self.send_stream_command(mode, OvpnCommand::Echo(mode))
            .await
    }

    /// Enable or disable byte count notifications at N-second intervals.
    /// Pass 0 to disable.
    pub async fn bytecount(&mut self, interval: u32) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ByteCount(interval)).await
    }

    // -- Connection control --

    /// Send a signal to the OpenVPN daemon.
    pub async fn signal(&mut self, signal: Signal) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Signal(signal)).await
    }

    /// Kill a specific client connection (server mode).
    pub async fn kill(&mut self, target: KillTarget) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Kill(target)).await
    }

    /// Query the current hold flag.
    pub async fn hold_query(&mut self) -> Result<bool, ClientError> {
        let payload = self.send_expect_success(OvpnCommand::HoldQuery).await?;
        Ok(parsed_response::parse_hold(&payload)?)
    }

    /// Set the hold flag on.
    pub async fn hold_on(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::HoldOn).await
    }

    /// Clear the hold flag.
    pub async fn hold_off(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::HoldOff).await
    }

    /// Release from hold state and start OpenVPN.
    pub async fn hold_release(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::HoldRelease).await
    }

    // -- Authentication --

    /// Supply a username for the given auth type.
    pub async fn username(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Username {
            auth_type,
            value: Redacted::new(value.into()),
        })
        .await
    }

    /// Supply a password for the given auth type.
    pub async fn password(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Password {
            auth_type,
            value: Redacted::new(value.into()),
        })
        .await
    }

    /// Set the auth-retry strategy.
    pub async fn auth_retry(&mut self, mode: AuthRetryMode) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::AuthRetry(mode)).await
    }

    /// Forget all passwords entered during this management session.
    pub async fn forget_passwords(&mut self) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ForgetPasswords).await
    }

    /// Respond to a CRV1 dynamic challenge.
    pub async fn challenge_response(
        &mut self,
        state_id: impl Into<String>,
        response: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ChallengeResponse {
            state_id: state_id.into(),
            response: Redacted::new(response.into()),
        })
        .await
    }

    /// Respond to a static challenge.
    ///
    /// Pass the plaintext password and response — base64 encoding is
    /// handled automatically by the encoder.
    pub async fn static_challenge_response(
        &mut self,
        password: impl Into<String>,
        response: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::StaticChallengeResponse {
            password: Redacted::new(password.into()),
            response: Redacted::new(response.into()),
        })
        .await
    }

    /// Respond to a CR_TEXT challenge.
    pub async fn cr_response(&mut self, response: impl Into<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::CrResponse {
            response: Redacted::new(response.into()),
        })
        .await
    }

    // -- Interactive prompts --

    /// Respond to a `>NEED-OK:` prompt.
    pub async fn need_ok(
        &mut self,
        name: impl Into<String>,
        response: NeedOkResponse,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::NeedOk {
            name: name.into(),
            response,
        })
        .await
    }

    /// Respond to a `>NEED-STR:` prompt.
    pub async fn need_str(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::NeedStr {
            name: name.into(),
            value: value.into(),
        })
        .await
    }

    // -- PKCS#11 --

    /// Query available PKCS#11 certificate count.
    pub async fn pkcs11_id_count(&mut self) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Pkcs11IdCount).await
    }

    /// Retrieve a PKCS#11 certificate by index.
    pub async fn pkcs11_id_get(&mut self, index: u32) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Pkcs11IdGet(index))
            .await
    }

    // -- External key / signatures --

    /// Provide an RSA signature in response to `>RSA_SIGN:`.
    pub async fn rsa_sig(&mut self, base64_lines: Vec<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::RsaSig { base64_lines })
            .await
    }

    /// Provide a signature in response to `>PK_SIGN:`.
    pub async fn pk_sig(&mut self, base64_lines: Vec<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::PkSig { base64_lines })
            .await
    }

    /// Supply an external certificate in response to `>NEED-CERTIFICATE:`.
    pub async fn certificate(&mut self, pem_lines: Vec<String>) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Certificate { pem_lines })
            .await
    }

    // -- Client management (server mode) --

    /// Authorize a client and push config directives.
    pub async fn client_auth(
        &mut self,
        cid: u64,
        kid: u64,
        config_lines: Vec<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientAuth {
            cid,
            kid,
            config_lines,
        })
        .await
    }

    /// Authorize a client without pushing any config.
    pub async fn client_auth_nt(&mut self, cid: u64, kid: u64) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientAuthNt { cid, kid })
            .await
    }

    /// Deny a client connection.
    pub async fn client_deny(&mut self, deny: ClientDeny) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientDeny(deny)).await
    }

    /// Kill a client session by CID.
    pub async fn client_kill(
        &mut self,
        cid: u64,
        message: Option<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientKill { cid, message })
            .await
    }

    /// Defer authentication for a client.
    pub async fn client_pending_auth(
        &mut self,
        cid: u64,
        kid: u64,
        extra: impl Into<String>,
        timeout: u32,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ClientPendingAuth {
            cid,
            kid,
            extra: extra.into(),
            timeout,
        })
        .await
    }

    // -- Remote / Proxy override --

    /// Respond to a `>REMOTE:` notification.
    pub async fn remote(&mut self, action: RemoteAction) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Remote(action)).await
    }

    /// Respond to a `>PROXY:` notification.
    pub async fn proxy(&mut self, action: ProxyAction) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::Proxy(action)).await
    }

    // -- Server statistics --

    /// Request aggregated server stats.
    pub async fn load_stats(&mut self) -> Result<LoadStats, ClientError> {
        let payload = self.send_expect_success(OvpnCommand::LoadStats).await?;
        Ok(parsed_response::parse_load_stats(&payload)?)
    }

    // -- ENV filter --

    /// Set the env-var filter level for `>CLIENT:ENV` blocks.
    pub async fn env_filter(&mut self, level: u32) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::EnvFilter(level)).await
    }

    // -- Remote entry queries --

    /// Query the number of `--remote` entries.
    pub async fn remote_entry_count(&mut self) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::RemoteEntryCount)
            .await
    }

    /// Retrieve `--remote` entries.
    pub async fn remote_entry_get(
        &mut self,
        range: RemoteEntryRange,
    ) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::RemoteEntryGet(range))
            .await
    }

    // -- Push updates (server mode) --

    /// Broadcast a push option update to all connected clients.
    pub async fn push_update_broad(
        &mut self,
        options: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::PushUpdateBroad {
            options: options.into(),
        })
        .await
    }

    /// Push an option update to a specific client.
    pub async fn push_update_cid(
        &mut self,
        cid: u64,
        options: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::PushUpdateCid {
            cid,
            options: options.into(),
        })
        .await
    }

    // -- Management interface auth --

    /// Authenticate to the management interface.
    pub async fn management_password(
        &mut self,
        password: impl Into<String>,
    ) -> Result<(), ClientError> {
        self.send_expect_ok(OvpnCommand::ManagementPassword(Redacted::new(
            password.into(),
        )))
        .await
    }

    // -- Session lifecycle --

    /// Close the management session. Consumes the client since the
    /// connection is no longer usable.
    pub async fn exit(mut self) -> Result<(), ClientError> {
        self.framed.send(OvpnCommand::Exit).await?;
        Ok(())
    }

    // -- Raw escape hatch --

    /// Send a raw command expecting `SUCCESS:`/`ERROR:`.
    pub async fn raw(&mut self, command: impl Into<String>) -> Result<String, ClientError> {
        self.send_expect_success(OvpnCommand::Raw(command.into()))
            .await
    }

    /// Send a raw command expecting a multi-line response.
    pub async fn raw_multi_line(
        &mut self,
        command: impl Into<String>,
    ) -> Result<Vec<String>, ClientError> {
        self.send_expect_multi_line(OvpnCommand::RawMultiLine(command.into()))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    /// Pre-load a duplex stream with canned server responses, then build
    /// a `ManagementClient` on the other end.
    ///
    /// The duplex buffer (8 KB) absorbs the client's outgoing commands so
    /// no spawned task is needed to drain them.  The client's `next()` reads
    /// the pre-written response data sequentially — fully deterministic,
    /// no concurrency.
    ///
    /// Returns the server half so the caller keeps it alive (dropping it
    /// would close the pipe before the client can write its command).
    ///
    /// Inspired by the "enqueue-then-run" pattern from
    /// <https://barafael.github.io/posts/more-actors-with-tokio/>
    async fn mock_client_with(
        lines: &[&str],
    ) -> (
        ManagementClient<DuplexStream>,
        broadcast::Sender<Notification>,
        DuplexStream,
    ) {
        let (client_stream, mut server_stream) = tokio::io::duplex(8192);
        for line in lines {
            server_stream.write_all(line.as_bytes()).await.unwrap();
            server_stream.write_all(b"\r\n").await.unwrap();
        }
        server_stream.flush().await.unwrap();

        let framed = Framed::new(client_stream, OvpnCodec::new());
        let (notification_tx, _) = broadcast::channel(64);
        let client = ManagementClient::new(framed, notification_tx.clone());
        (client, notification_tx, server_stream)
    }

    // --- Parsed SUCCESS responses ---

    #[tokio::test]
    async fn pid_returns_parsed_value() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: pid=42"]).await;
        assert_eq!(client.pid().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn load_stats_parsed() {
        let (mut client, _, _server) =
            mock_client_with(&["SUCCESS: nclients=3,bytesin=100000,bytesout=50000"]).await;
        let stats = client.load_stats().await.unwrap();
        assert_eq!(stats.nclients, 3);
        assert_eq!(stats.bytesin, 100_000);
        assert_eq!(stats.bytesout, 50_000);
    }

    #[tokio::test]
    async fn hold_query_parsed() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: hold=1"]).await;
        assert!(client.hold_query().await.unwrap());
    }

    #[tokio::test]
    async fn hold_query_returns_false() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: hold=0"]).await;
        assert!(!client.hold_query().await.unwrap());
    }

    // --- send_expect_ok wrappers ---
    //
    // Each command method is exercised against a canned SUCCESS response
    // to verify the mock transport round-trip doesn't panic or return an
    // unexpected error variant.

    macro_rules! ok_test {
        ($name:ident, $response:expr, |$client:ident| $call:expr) => {
            #[tokio::test]
            async fn $name() {
                let (mut $client, _, _server) = mock_client_with(&[$response]).await;
                $call.unwrap();
            }
        };
    }

    ok_test!(hold_on_ok, "SUCCESS: hold on", |c| c.hold_on().await);
    ok_test!(hold_off_ok, "SUCCESS: hold off", |c| c.hold_off().await);
    ok_test!(hold_release_ok, "SUCCESS: hold release", |c| c
        .hold_release()
        .await);
    ok_test!(signal_ok, "SUCCESS: signal SIGUSR1", |c| c
        .signal(Signal::SigUsr1)
        .await);
    ok_test!(
        kill_ok,
        "SUCCESS: common name 'test' found, 1 client(s) killed",
        |c| c.kill(KillTarget::CommonName("test".into())).await
    );
    ok_test!(username_ok, "SUCCESS: username ok", |c| c
        .username(AuthType::Auth, "admin")
        .await);
    ok_test!(password_ok, "SUCCESS: password ok", |c| c
        .password(AuthType::Auth, "hunter2")
        .await);
    ok_test!(auth_retry_ok, "SUCCESS: auth-retry interact", |c| c
        .auth_retry(AuthRetryMode::Interact)
        .await);
    ok_test!(forget_passwords_ok, "SUCCESS: forget-passwords", |c| c
        .forget_passwords()
        .await);
    ok_test!(challenge_response_ok, "SUCCESS: password ok", |c| c
        .challenge_response("state123", "123456")
        .await);
    ok_test!(static_challenge_response_ok, "SUCCESS: password ok", |c| c
        .static_challenge_response("cGFzcw==", "cmVzcA==")
        .await);
    ok_test!(cr_response_ok, "SUCCESS: cr-response ok", |c| c
        .cr_response("123456")
        .await);
    ok_test!(need_ok_ok, "SUCCESS: needok ok", |c| c
        .need_ok("token-insertion", NeedOkResponse::Ok)
        .await);
    ok_test!(need_str_ok, "SUCCESS: needstr ok", |c| c
        .need_str("prompt", "myvalue")
        .await);
    ok_test!(bytecount_ok, "SUCCESS: bytecount interval changed", |c| c
        .bytecount(5)
        .await);
    ok_test!(env_filter_ok, "SUCCESS: env-filter ok", |c| c
        .env_filter(2)
        .await);
    ok_test!(
        management_password_ok,
        "SUCCESS: password is correct",
        |c| c.management_password("s3cret").await
    );
    ok_test!(
        client_auth_ok,
        "SUCCESS: client-auth command succeeded",
        |c| c
            .client_auth(0, 1, vec!["push \"route 10.0.0.0 255.0.0.0\"".into()])
            .await
    );
    ok_test!(
        client_auth_nt_ok,
        "SUCCESS: client-auth-nt command succeeded",
        |c| c.client_auth_nt(5, 0).await
    );
    ok_test!(
        client_deny_ok,
        "SUCCESS: client-deny command succeeded",
        |c| c
            .client_deny(ClientDeny::builder().cid(1).kid(0).reason("banned").build())
            .await
    );
    ok_test!(
        client_kill_ok,
        "SUCCESS: client-kill command succeeded",
        |c| c.client_kill(7, Some("goodbye".into())).await
    );
    ok_test!(
        client_pending_auth_ok,
        "SUCCESS: client-pending-auth command succeeded",
        |c| c
            .client_pending_auth(0, 0, "WEB_AUTH::https://auth.example.com", 30)
            .await
    );
    ok_test!(remote_ok, "SUCCESS: remote ok", |c| c
        .remote(RemoteAction::Accept)
        .await);
    ok_test!(proxy_ok, "SUCCESS: proxy ok", |c| c
        .proxy(ProxyAction::None)
        .await);
    ok_test!(rsa_sig_ok, "SUCCESS: rsa-sig ok", |c| c
        .rsa_sig(vec!["AABBCCDD==".into()])
        .await);
    ok_test!(pk_sig_ok, "SUCCESS: pk-sig ok", |c| c
        .pk_sig(vec!["EEFF0011==".into()])
        .await);
    ok_test!(certificate_ok, "SUCCESS: certificate ok", |c| c
        .certificate(vec![
            "-----BEGIN CERTIFICATE-----".into(),
            "AAAA".into(),
            "-----END CERTIFICATE-----".into(),
        ])
        .await);
    ok_test!(push_update_broad_ok, "SUCCESS: push-update ok", |c| c
        .push_update_broad("push \"route 10.0.0.0 255.0.0.0\"")
        .await);
    ok_test!(push_update_cid_ok, "SUCCESS: push-update ok", |c| c
        .push_update_cid(3, "push \"route 10.0.0.0 255.0.0.0\"")
        .await);

    // --- send_expect_success wrappers (return parsed payload) ---

    #[tokio::test]
    async fn verb_query_returns_payload() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: verb=3"]).await;
        assert_eq!(client.verb(None).await.unwrap(), "verb=3");
    }

    #[tokio::test]
    async fn verb_set_returns_payload() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: verb level changed"]).await;
        assert_eq!(client.verb(Some(5)).await.unwrap(), "verb level changed");
    }

    #[tokio::test]
    async fn mute_returns_payload() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: mute=40"]).await;
        assert_eq!(client.mute(Some(40)).await.unwrap(), "mute=40");
    }

    #[tokio::test]
    async fn pkcs11_id_count_returns_payload() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: 2"]).await;
        assert_eq!(client.pkcs11_id_count().await.unwrap(), "2");
    }

    #[tokio::test]
    async fn pkcs11_id_get_returns_payload() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: pkcs11-id=cert0"]).await;
        assert_eq!(client.pkcs11_id_get(0).await.unwrap(), "pkcs11-id=cert0");
    }

    #[tokio::test]
    async fn raw_returns_success_payload() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: pid=99"]).await;
        assert_eq!(client.raw("pid").await.unwrap(), "pid=99");
    }

    #[tokio::test]
    async fn raw_server_error() {
        let (mut client, _, _server) = mock_client_with(&["ERROR: unknown command"]).await;
        let err = client.raw("nonsense").await.unwrap_err();
        assert!(matches!(&err, ClientError::ServerError(msg) if msg == "unknown command"));
    }

    // --- send_expect_multi_line wrappers ---

    #[tokio::test]
    async fn status_raw_returns_lines() {
        let (mut client, _, _server) = mock_client_with(&[
            "TITLE,OpenVPN 2.6.9",
            "HEADER,CLIENT_LIST,Common Name",
            "END",
        ])
        .await;
        let lines = client.status_raw(StatusFormat::V2).await.unwrap();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("TITLE"));
    }

    #[tokio::test]
    async fn help_returns_lines() {
        let (mut client, _, _server) = mock_client_with(&[
            "Management Interface for OpenVPN",
            "Commands:",
            "help",
            "END",
        ])
        .await;
        let lines = client.help().await.unwrap();
        assert!(lines.len() >= 2);
    }

    #[tokio::test]
    async fn net_returns_lines() {
        let (mut client, _, _server) = mock_client_with(&["Adapter: eth0", "END"]).await;
        let lines = client.net().await.unwrap();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("eth0"));
    }

    #[tokio::test]
    async fn raw_multi_line_returns_lines() {
        let (mut client, _, _server) = mock_client_with(&["line one", "line two", "END"]).await;
        let lines = client.raw_multi_line("custom-cmd").await.unwrap();
        assert_eq!(lines, vec!["line one", "line two"]);
    }

    #[tokio::test]
    async fn remote_entry_count_returns_lines() {
        let (mut client, _, _server) = mock_client_with(&["3", "END"]).await;
        let lines = client.remote_entry_count().await.unwrap();
        assert_eq!(lines, vec!["3"]);
    }

    #[tokio::test]
    async fn remote_entry_get_returns_lines() {
        let (mut client, _, _server) = mock_client_with(&[
            "vpn1.example.com 1194 udp",
            "vpn2.example.com 443 tcp",
            "END",
        ])
        .await;
        let lines = client
            .remote_entry_get(RemoteEntryRange::All)
            .await
            .unwrap();
        assert_eq!(lines.len(), 2);
    }

    // --- Parsed multi-line response methods ---

    #[tokio::test]
    async fn state_returns_parsed_entries() {
        let (mut client, _, _server) = mock_client_with(&[
            "1700000000,CONNECTED,SUCCESS,10.8.0.1,1.2.3.4,1194,,,",
            "END",
        ])
        .await;
        let entries = client.state().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].name,
            crate::openvpn_state::OpenVpnState::Connected
        );
    }

    #[tokio::test]
    async fn current_state_returns_single_entry() {
        let (mut client, _, _server) = mock_client_with(&[
            "1700000000,CONNECTED,SUCCESS,10.8.0.1,1.2.3.4,1194,,,",
            "END",
        ])
        .await;
        let entry = client.current_state().await.unwrap();
        assert_eq!(entry.name, crate::openvpn_state::OpenVpnState::Connected);
    }

    // --- Stream commands ---

    #[tokio::test]
    async fn log_on_returns_none() {
        let (mut client, _, _server) =
            mock_client_with(&["SUCCESS: real-time log notification set to ON"]).await;
        assert!(client.log(StreamMode::On).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn log_all_returns_history() {
        let (mut client, _, _server) = mock_client_with(&[
            "1700000000,I,Log entry one",
            "1700000001,D,Log entry two",
            "END",
        ])
        .await;
        let lines = client.log(StreamMode::All).await.unwrap().unwrap();
        assert_eq!(lines.len(), 2);
    }

    #[tokio::test]
    async fn echo_off_returns_none() {
        let (mut client, _, _server) =
            mock_client_with(&["SUCCESS: real-time echo notification set to OFF"]).await;
        assert!(client.echo(StreamMode::Off).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn state_stream_on_returns_none() {
        let (mut client, _, _server) =
            mock_client_with(&["SUCCESS: real-time state notification set to ON"]).await;
        assert!(client.state_stream(StreamMode::On).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn state_stream_all_returns_parsed_history() {
        let (mut client, _, _server) = mock_client_with(&[
            "1700000000,CONNECTED,SUCCESS,10.8.0.1,1.2.3.4,1194,,,",
            "END",
        ])
        .await;
        let entries = client.state_stream(StreamMode::All).await.unwrap().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].name,
            crate::openvpn_state::OpenVpnState::Connected
        );
    }

    // --- Special methods ---

    #[tokio::test]
    async fn set_version_below_4_sends_without_response() {
        let (mut client, _, _server) = mock_client_with(&[]).await;
        client.set_version(3).await.unwrap();
    }

    #[tokio::test]
    async fn set_version_4_expects_success() {
        let (mut client, _, _server) =
            mock_client_with(&["SUCCESS: Management client version set to 4"]).await;
        client.set_version(4).await.unwrap();
    }

    #[tokio::test]
    async fn exit_consumes_client() {
        let (client, _, _server) = mock_client_with(&[]).await;
        client.exit().await.unwrap();
    }

    #[tokio::test]
    async fn into_framed_recovers_transport() {
        let (client, _, _server) = mock_client_with(&[]).await;
        let _framed = client.into_framed();
    }

    // --- Notification forwarding (needs duplex for bidirectional I/O) ---

    #[tokio::test]
    async fn notifications_forwarded_during_command() {
        let (mut client, tx, _server) =
            mock_client_with(&[">BYTECOUNT:1024,2048", "SUCCESS: pid=99"]).await;
        let mut rx = tx.subscribe();

        let pid = client.pid().await.unwrap();
        assert_eq!(pid, 99);

        let notif = rx.try_recv().unwrap();
        assert!(
            matches!(
                notif,
                Notification::ByteCount {
                    bytes_in: 1024,
                    bytes_out: 2048
                }
            ),
            "expected ByteCount, got {notif:?}"
        );
    }

    #[tokio::test]
    async fn multiple_notification_subscribers() {
        let (mut client, tx, _server) =
            mock_client_with(&[">HOLD:Waiting for hold release:5", "SUCCESS: pid=1"]).await;
        let mut rx1 = tx.subscribe();
        let mut rx2 = tx.subscribe();

        assert_eq!(client.pid().await.unwrap(), 1);

        assert!(matches!(rx1.try_recv().unwrap(), Notification::Hold { .. }));
        assert!(matches!(rx2.try_recv().unwrap(), Notification::Hold { .. }));
    }

    // --- Notification edge cases ---

    #[tokio::test]
    async fn notification_with_no_subscribers_does_not_error() {
        // All receivers are dropped — the send error in inspect_err should
        // be logged but not cause the command to fail.
        let (mut client, tx, _server) =
            mock_client_with(&[">BYTECOUNT:100,200", "SUCCESS: pid=1"]).await;
        drop(tx); // drop the sender so there are zero subscribers
        let pid = client.pid().await.unwrap();
        assert_eq!(pid, 1);
    }

    // --- Error paths ---

    #[tokio::test]
    async fn server_error_maps_to_client_error() {
        let (mut client, _, _server) = mock_client_with(&["ERROR: command not allowed"]).await;
        let err = client.hold_release().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::ServerError(msg) if msg == "command not allowed"),
            "expected ServerError, got {err:?}"
        );
    }

    #[tokio::test]
    async fn connection_closed_returns_error() {
        // Drop the server half so the client sees EOF.
        let (mut client, _, server) = mock_client_with(&[]).await;
        drop(server);
        let err = client.pid().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::ConnectionClosed | ClientError::Io(_)),
            "expected connection error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unexpected_response_for_success_command() {
        // Multi-line response when SUCCESS was expected.
        let (mut client, _, _server) = mock_client_with(&["line one", "END"]).await;
        let err = client.pid().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::UnexpectedResponse(_)),
            "expected UnexpectedResponse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unexpected_response_for_multi_line_command() {
        // SUCCESS when multi-line was expected.
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: unexpected"]).await;
        let err = client.help().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::UnexpectedResponse(_)),
            "expected UnexpectedResponse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn parse_error_for_malformed_pid() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: pid=notanumber"]).await;
        let err = client.pid().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::ParseResponse(_)),
            "expected ParseResponse, got {err:?}"
        );
    }

    #[tokio::test]
    async fn parse_error_for_malformed_load_stats() {
        let (mut client, _, _server) = mock_client_with(&["SUCCESS: garbage"]).await;
        let err = client.load_stats().await.unwrap_err();
        assert!(
            matches!(&err, ClientError::ParseResponse(_)),
            "expected ParseResponse, got {err:?}"
        );
    }

    // --- version ---

    #[tokio::test]
    async fn version_returns_parsed_info() {
        let (mut client, _, _server) = mock_client_with(&[
            "OpenVPN Version: OpenVPN 2.6.9 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [MH/PKTINFO] [AEAD]",
            "Management Interface Version: 5",
            "END",
        ]).await;
        let info = client.version().await.unwrap();
        assert_eq!(info.management_version(), Some(5));
        assert!(info.openvpn_version_line().unwrap().contains("2.6.9"));
    }

    #[tokio::test]
    async fn version_old_format_management_version_1() {
        let (mut client, _, _server) = mock_client_with(&[
            "OpenVPN Version: OpenVPN 2.3.2 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [EPOLL] [PKCS11] [eurephia] [MH] [IPv6] built on Dec  2 2014",
            "Management Version: 1",
            "END",
        ]).await;
        let info = client.version().await.unwrap();
        assert_eq!(info.management_version(), Some(1));
        assert!(info.openvpn_version_line().unwrap().contains("2.3.2"));
    }

    #[tokio::test]
    async fn version_server_error() {
        let (mut client, _, _server) = mock_client_with(&["ERROR: command failed"]).await;
        let err = client.version().await.unwrap_err();
        assert!(matches!(err, ClientError::ServerError(_)));
    }

    // --- status ---

    #[tokio::test]
    async fn status_v1_server_mode_parsed() {
        let (mut client, _, _server) = mock_client_with(&[
            "OpenVPN CLIENT LIST",
            "Updated,2024-03-21 14:30:00",
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
            "client1,203.0.113.10:52841,1548576,984320,2024-03-21 09:15:00",
            "client2,203.0.113.20:41293,2097152,1048576,2024-03-21 10:00:00",
            "ROUTING TABLE",
            "Virtual Address,Common Name,Real Address,Last Ref",
            "10.8.0.6,client1,203.0.113.10:52841,2024-03-21 14:29:50",
            "10.8.0.10,client2,203.0.113.20:41293,2024-03-21 14:29:55",
            "GLOBAL STATS",
            "Max bcast/mcast queue length,3",
            "END",
        ])
        .await;
        let status = client.status(StatusFormat::V1).await.unwrap();
        assert_eq!(status.clients.len(), 2);
        assert_eq!(status.clients[0].common_name, "client1");
        assert_eq!(status.clients[0].bytes_in, 1_548_576);
        assert_eq!(status.clients[1].common_name, "client2");
        assert_eq!(status.routes.len(), 2);
        assert_eq!(status.routes[0].virtual_address, "10.8.0.6");
        assert!(
            status
                .global_stats
                .iter()
                .any(|(k, v)| k == "Max bcast/mcast queue length" && v == "3")
        );
    }

    #[tokio::test]
    async fn status_v2_server_mode_parsed() {
        let (mut client, _, _server) = mock_client_with(&[
            "TITLE,OpenVPN 2.6.9 x86_64-pc-linux-gnu",
            "TIME,2024-03-23 16:00:26,1711209626",
            "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Virtual IPv6 Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t),Username,Client ID,Peer ID,Data Channel Cipher",
            "CLIENT_LIST,alice,10.0.0.1:51234,10.8.0.6,,521679042,155407560,Fri Dec 30 13:41:11 2016,1483101671,UNDEF,1,1,AES-256-GCM",
            "HEADER,ROUTING_TABLE,Virtual Address,Common Name,Real Address,Last Ref,Last Ref (time_t)",
            "ROUTING_TABLE,10.8.0.6,alice,10.0.0.1:51234,Sat Dec 31 15:06:04 2016,1483193164",
            "GLOBAL_STATS,Max bcast/mcast queue length,0",
            "END",
        ]).await;
        let status = client.status(StatusFormat::V2).await.unwrap();
        assert_eq!(
            status.title.as_deref(),
            Some("OpenVPN 2.6.9 x86_64-pc-linux-gnu")
        );
        assert_eq!(status.clients.len(), 1);
        assert_eq!(status.clients[0].common_name, "alice");
        assert_eq!(status.clients[0].bytes_in, 521_679_042);
        assert_eq!(status.routes.len(), 1);
    }

    #[tokio::test]
    async fn status_empty_server() {
        let (mut client, _, _server) = mock_client_with(&[
            "OpenVPN CLIENT LIST",
            "Updated,2024-03-21 14:30:00",
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
            "ROUTING TABLE",
            "Virtual Address,Common Name,Real Address,Last Ref",
            "GLOBAL STATS",
            "Max bcast/mcast queue length,0",
            "END",
        ])
        .await;
        let status = client.status(StatusFormat::V1).await.unwrap();
        assert!(status.clients.is_empty());
        assert!(status.routes.is_empty());
    }

    #[tokio::test]
    async fn status_server_error() {
        let (mut client, _, _server) = mock_client_with(&["ERROR: command failed"]).await;
        let err = client.status(StatusFormat::V1).await.unwrap_err();
        assert!(matches!(err, ClientError::ServerError(_)));
    }

    #[tokio::test]
    async fn status_with_interleaved_notification() {
        let (mut client, tx, _server) = mock_client_with(&[
            ">BYTECOUNT:5000,6000",
            "OpenVPN CLIENT LIST",
            "Updated,2024-03-21 14:30:00",
            "Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since",
            "client1,10.0.0.1:1234,100,200,2024-03-21",
            "ROUTING TABLE",
            "Virtual Address,Common Name,Real Address,Last Ref",
            "GLOBAL STATS",
            "Max bcast/mcast queue length,0",
            "END",
        ])
        .await;
        let mut rx = tx.subscribe();

        let status = client.status(StatusFormat::V1).await.unwrap();
        assert_eq!(status.clients.len(), 1);

        let notif = rx.try_recv().unwrap();
        assert!(matches!(notif, Notification::ByteCount { .. }));
    }

    // --- client_statistics ---

    #[tokio::test]
    async fn client_statistics_parsed() {
        let (mut client, _, _server) = mock_client_with(&[
            "OpenVPN STATISTICS",
            "Updated,2024-03-21 14:30:00",
            "TUN/TAP read bytes,1548576",
            "TUN/TAP write bytes,984320",
            "TCP/UDP read bytes,1600000",
            "TCP/UDP write bytes,1020000",
            "Auth read bytes,0",
            "END",
        ])
        .await;
        let stats = client.client_statistics(StatusFormat::V1).await.unwrap();
        assert_eq!(stats.tun_tap_read_bytes, 1_548_576);
        assert_eq!(stats.tun_tap_write_bytes, 984_320);
        assert_eq!(stats.tcp_udp_read_bytes, 1_600_000);
        assert_eq!(stats.tcp_udp_write_bytes, 1_020_000);
        assert_eq!(stats.auth_read_bytes, 0);
        assert!(stats.pre_compress_bytes.is_none());
    }

    #[tokio::test]
    async fn client_statistics_with_compression() {
        let (mut client, _, _server) = mock_client_with(&[
            "OpenVPN STATISTICS",
            "Updated,Tue Mar 21 10:39:09 2017",
            "TUN/TAP read bytes,153789941",
            "TUN/TAP write bytes,308764078",
            "TCP/UDP read bytes,292806201",
            "TCP/UDP write bytes,197558969",
            "Auth read bytes,308854782",
            "pre-compress bytes,45388190",
            "post-compress bytes,45446864",
            "pre-decompress bytes,162596168",
            "post-decompress bytes,216965355",
            "END",
        ])
        .await;
        let stats = client.client_statistics(StatusFormat::V1).await.unwrap();
        assert_eq!(stats.tun_tap_read_bytes, 153_789_941);
        assert_eq!(stats.pre_compress_bytes, Some(45_388_190));
        assert_eq!(stats.post_compress_bytes, Some(45_446_864));
        assert_eq!(stats.pre_decompress_bytes, Some(162_596_168));
        assert_eq!(stats.post_decompress_bytes, Some(216_965_355));
    }

    #[tokio::test]
    async fn client_statistics_server_error() {
        let (mut client, _, _server) = mock_client_with(&["ERROR: not available"]).await;
        let err = client
            .client_statistics(StatusFormat::V1)
            .await
            .unwrap_err();
        assert!(matches!(err, ClientError::ServerError(_)));
    }
}
