//! High-level management client for sequential command/response usage.
//!
//! [`ManagementSession`] wraps a `Framed<T, OvpnCodec>` transport and
//! provides typed methods that send a command and return its parsed
//! response. Interleaved notifications are stashed and accessible via
//! [`drain_notifications()`](ManagementSession::drain_notifications).
//!
//! # Example
//!
//! ```no_run
//! use tokio::net::TcpStream;
//! use tokio_util::codec::Framed;
//! use openvpn_mgmt_codec::{OvpnCodec, StatusFormat};
//! use openvpn_mgmt_codec::session::ManagementSession;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let stream = TcpStream::connect("127.0.0.1:7505").await?;
//! let framed = Framed::new(stream, OvpnCodec::new());
//! let mut client = ManagementSession::new(framed);
//!
//! let version = client.version().await?;
//! println!("management version: {:?}", version.management_version());
//!
//! let status = client.status(StatusFormat::V3).await?;
//! client.hold_release().await?;
//!
//! // Notifications that arrived between commands:
//! for notif in client.drain_notifications() {
//!     println!("notification: {notif:?}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Concurrent notification handling
//!
//! Every command method takes `&mut self`. For applications that need
//! to simultaneously react to notifications and send commands (e.g. in a
//! `select!` loop), use [`management_split`](crate::management_split)
//! instead — it gives independent sink and stream halves.

use std::io;

use tokio_util::codec::Framed;

use crate::{
    auth::{AuthRetryMode, AuthType},
    client_deny::ClientDeny,
    codec::OvpnCodec,
    command::{OvpnCommand, RemoteEntryRange},
    kill_target::KillTarget,
    message::{Notification, OvpnMessage},
    need_ok::NeedOkResponse,
    parsed_response::{self, LoadStats, StateEntry},
    proxy_action::ProxyAction,
    redacted::Redacted,
    remote_action::RemoteAction,
    signal::Signal,
    split::{CommandSink, EventStream, ManagementSink, management_split},
    status::{self, ClientStatistics, StatusResponse},
    status_format::StatusFormat,
    stream_mode::StreamMode,
    version_info::VersionInfo,
};

/// Errors returned by [`ManagementSession`] command methods.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
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
}

/// A high-level client for the OpenVPN management interface.
///
/// See the [module documentation](self) for usage examples.
pub struct ManagementSession<T: tokio::io::AsyncRead + tokio::io::AsyncWrite> {
    sink: CommandSink<T>,
    events: EventStream<T>,
}

impl<T> ManagementSession<T>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// Wrap a framed transport.
    pub fn new(framed: Framed<T, OvpnCodec>) -> Self {
        let (sink, events) = management_split(framed);
        Self { sink, events }
    }

    /// Decompose into the underlying sink and event stream.
    ///
    /// Use this when you need to move to the split-based API (e.g. for
    /// `select!` loops).
    pub fn into_split(self) -> (CommandSink<T>, EventStream<T>) {
        (self.sink, self.events)
    }

    /// Drain any notifications that were stashed while waiting for
    /// command responses.
    pub fn drain_notifications(&mut self) -> impl Iterator<Item = Notification> + '_ {
        self.events.drain_notifications()
    }

    // --- Internal helpers ---

    async fn send_expect_success(&mut self, cmd: OvpnCommand) -> Result<String, SessionError> {
        self.sink.send_command(cmd).await?;
        self.events.recv_success().await
    }

    async fn send_expect_multi_line(
        &mut self,
        cmd: OvpnCommand,
    ) -> Result<Vec<String>, SessionError> {
        self.sink.send_command(cmd).await?;
        self.events.recv_multi_line().await
    }

    async fn send_expect_ok(&mut self, cmd: OvpnCommand) -> Result<(), SessionError> {
        self.sink.send_command(cmd).await?;
        self.events.recv_ok().await
    }

    async fn send_stream_command(
        &mut self,
        mode: StreamMode,
        cmd: OvpnCommand,
    ) -> Result<Option<Vec<String>>, SessionError> {
        if mode.returns_history() {
            Ok(Some(self.send_expect_multi_line(cmd).await?))
        } else {
            self.send_expect_ok(cmd).await?;
            Ok(None)
        }
    }

    // --- Public command methods ---

    /// Query the connection status in the given format (raw lines).
    pub async fn status_raw(&mut self, format: StatusFormat) -> Result<Vec<String>, SessionError> {
        self.send_expect_multi_line(OvpnCommand::Status(format))
            .await
    }

    /// Query and parse the server-mode connection status.
    pub async fn status(&mut self, format: StatusFormat) -> Result<StatusResponse, SessionError> {
        let lines = self.status_raw(format).await?;
        Ok(status::parse_status(&lines)?)
    }

    /// Query and parse client-mode statistics.
    pub async fn client_statistics(
        &mut self,
        format: StatusFormat,
    ) -> Result<ClientStatistics, SessionError> {
        let lines = self.status_raw(format).await?;
        Ok(status::parse_client_statistics(&lines)?)
    }

    /// Query the current state as a multi-line history.
    pub async fn state(&mut self) -> Result<Vec<StateEntry>, SessionError> {
        let lines = self.send_expect_multi_line(OvpnCommand::State).await?;
        Ok(parsed_response::parse_state_history(&lines)?)
    }

    /// Query the most recent state entry.
    pub async fn current_state(&mut self) -> Result<StateEntry, SessionError> {
        let lines = self.send_expect_multi_line(OvpnCommand::State).await?;
        Ok(parsed_response::parse_current_state(&lines)?)
    }

    /// Control real-time state notifications.
    pub async fn state_stream(
        &mut self,
        mode: StreamMode,
    ) -> Result<Option<Vec<StateEntry>>, SessionError> {
        match self
            .send_stream_command(mode, OvpnCommand::StateStream(mode))
            .await?
        {
            Some(lines) => Ok(Some(parsed_response::parse_state_history(&lines)?)),
            None => Ok(None),
        }
    }

    /// Query the OpenVPN and management interface version.
    pub async fn version(&mut self) -> Result<VersionInfo, SessionError> {
        let lines = self.send_expect_multi_line(OvpnCommand::Version).await?;
        Ok(parsed_response::parse_version(&lines)?)
    }

    /// Set the management client version to announce feature support.
    pub async fn set_version(&mut self, version: u32) -> Result<(), SessionError> {
        let cmd = OvpnCommand::SetVersion(version);
        if version < 4 {
            self.sink.send_command(cmd).await?;
            Ok(())
        } else {
            self.send_expect_ok(cmd).await
        }
    }

    /// Query the PID of the OpenVPN process.
    pub async fn pid(&mut self) -> Result<u32, SessionError> {
        let payload = self.send_expect_success(OvpnCommand::Pid).await?;
        Ok(parsed_response::parse_pid(&payload)?)
    }

    /// List available management commands.
    pub async fn help(&mut self) -> Result<Vec<String>, SessionError> {
        self.send_expect_multi_line(OvpnCommand::Help).await
    }

    /// Query or set the log verbosity level.
    pub async fn verb(&mut self, level: Option<u8>) -> Result<String, SessionError> {
        self.send_expect_success(OvpnCommand::Verb(level)).await
    }

    /// Query or set the mute threshold.
    pub async fn mute(&mut self, threshold: Option<u32>) -> Result<String, SessionError> {
        self.send_expect_success(OvpnCommand::Mute(threshold)).await
    }

    /// (Windows) Show network adapter list.
    pub async fn net(&mut self) -> Result<Vec<String>, SessionError> {
        self.send_expect_multi_line(OvpnCommand::Net).await
    }

    /// Control real-time log streaming.
    pub async fn log(&mut self, mode: StreamMode) -> Result<Option<Vec<String>>, SessionError> {
        self.send_stream_command(mode, OvpnCommand::Log(mode)).await
    }

    /// Control real-time echo notifications.
    pub async fn echo(&mut self, mode: StreamMode) -> Result<Option<Vec<String>>, SessionError> {
        self.send_stream_command(mode, OvpnCommand::Echo(mode))
            .await
    }

    /// Enable or disable byte count notifications.
    pub async fn bytecount(&mut self, interval: u32) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ByteCount(interval)).await
    }

    /// Send a signal to the OpenVPN daemon.
    pub async fn signal(&mut self, signal: Signal) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::Signal(signal)).await
    }

    /// Kill a specific client connection (server mode).
    pub async fn kill(&mut self, target: KillTarget) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::Kill(target)).await
    }

    /// Query the current hold flag.
    pub async fn hold_query(&mut self) -> Result<bool, SessionError> {
        let payload = self.send_expect_success(OvpnCommand::HoldQuery).await?;
        Ok(parsed_response::parse_hold(&payload)?)
    }

    /// Set the hold flag on.
    pub async fn hold_on(&mut self) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::HoldOn).await
    }

    /// Clear the hold flag.
    pub async fn hold_off(&mut self) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::HoldOff).await
    }

    /// Release from hold state and start OpenVPN.
    pub async fn hold_release(&mut self) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::HoldRelease).await
    }

    /// Supply a username for the given auth type.
    pub async fn username(
        &mut self,
        auth_type: AuthType,
        value: impl Into<String>,
    ) -> Result<(), SessionError> {
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
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::Password {
            auth_type,
            value: Redacted::new(value.into()),
        })
        .await
    }

    /// Set the auth-retry strategy.
    pub async fn auth_retry(&mut self, mode: AuthRetryMode) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::AuthRetry(mode)).await
    }

    /// Forget all passwords entered during this management session.
    pub async fn forget_passwords(&mut self) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ForgetPasswords).await
    }

    /// Respond to a CRV1 dynamic challenge.
    pub async fn challenge_response(
        &mut self,
        state_id: impl Into<String>,
        response: impl Into<String>,
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ChallengeResponse {
            state_id: state_id.into(),
            response: Redacted::new(response.into()),
        })
        .await
    }

    /// Respond to a static challenge.
    pub async fn static_challenge_response(
        &mut self,
        password: impl Into<String>,
        response: impl Into<String>,
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::StaticChallengeResponse {
            password: Redacted::new(password.into()),
            response: Redacted::new(response.into()),
        })
        .await
    }

    /// Respond to a CR_TEXT challenge.
    pub async fn cr_response(&mut self, response: impl Into<String>) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::CrResponse {
            response: Redacted::new(response.into()),
        })
        .await
    }

    /// Respond to a `>NEED-OK:` prompt.
    pub async fn need_ok(
        &mut self,
        name: impl Into<String>,
        response: NeedOkResponse,
    ) -> Result<(), SessionError> {
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
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::NeedStr {
            name: name.into(),
            value: value.into(),
        })
        .await
    }

    /// Query available PKCS#11 certificate count.
    pub async fn pkcs11_id_count(&mut self) -> Result<String, SessionError> {
        self.send_expect_success(OvpnCommand::Pkcs11IdCount).await
    }

    /// Retrieve a PKCS#11 certificate by index.
    pub async fn pkcs11_id_get(&mut self, index: u32) -> Result<String, SessionError> {
        self.send_expect_success(OvpnCommand::Pkcs11IdGet(index))
            .await
    }

    /// Provide an RSA signature in response to `>RSA_SIGN:`.
    pub async fn rsa_sig(&mut self, base64_lines: Vec<String>) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::RsaSig { base64_lines })
            .await
    }

    /// Provide a signature in response to `>PK_SIGN:`.
    pub async fn pk_sig(&mut self, base64_lines: Vec<String>) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::PkSig { base64_lines })
            .await
    }

    /// Supply an external certificate in response to `>NEED-CERTIFICATE:`.
    pub async fn certificate(&mut self, pem_lines: Vec<String>) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::Certificate { pem_lines })
            .await
    }

    /// Authorize a client and push config directives.
    pub async fn client_auth(
        &mut self,
        cid: u64,
        kid: u64,
        config_lines: Vec<String>,
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ClientAuth {
            cid,
            kid,
            config_lines,
        })
        .await
    }

    /// Authorize a client without pushing any config.
    pub async fn client_auth_nt(&mut self, cid: u64, kid: u64) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ClientAuthNt { cid, kid })
            .await
    }

    /// Deny a client connection.
    pub async fn client_deny(&mut self, deny: ClientDeny) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ClientDeny(deny)).await
    }

    /// Kill a client session by CID.
    pub async fn client_kill(
        &mut self,
        cid: u64,
        message: Option<String>,
    ) -> Result<(), SessionError> {
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
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ClientPendingAuth {
            cid,
            kid,
            extra: extra.into(),
            timeout,
        })
        .await
    }

    /// Respond to a `>REMOTE:` notification.
    pub async fn remote(&mut self, action: RemoteAction) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::Remote(action)).await
    }

    /// Respond to a `>PROXY:` notification.
    pub async fn proxy(&mut self, action: ProxyAction) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::Proxy(action)).await
    }

    /// Request aggregated server stats.
    pub async fn load_stats(&mut self) -> Result<LoadStats, SessionError> {
        let payload = self.send_expect_success(OvpnCommand::LoadStats).await?;
        Ok(parsed_response::parse_load_stats(&payload)?)
    }

    /// Set the env-var filter level for `>CLIENT:ENV` blocks.
    pub async fn env_filter(&mut self, level: u32) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::EnvFilter(level)).await
    }

    /// Query the number of `--remote` entries.
    pub async fn remote_entry_count(&mut self) -> Result<Vec<String>, SessionError> {
        self.send_expect_multi_line(OvpnCommand::RemoteEntryCount)
            .await
    }

    /// Retrieve `--remote` entries.
    pub async fn remote_entry_get(
        &mut self,
        range: RemoteEntryRange,
    ) -> Result<Vec<String>, SessionError> {
        self.send_expect_multi_line(OvpnCommand::RemoteEntryGet(range))
            .await
    }

    /// Broadcast a push option update to all connected clients.
    pub async fn push_update_broad(
        &mut self,
        options: impl Into<String>,
    ) -> Result<(), SessionError> {
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
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::PushUpdateCid {
            cid,
            options: options.into(),
        })
        .await
    }

    /// Authenticate to the management interface.
    pub async fn management_password(
        &mut self,
        password: impl Into<String>,
    ) -> Result<(), SessionError> {
        self.send_expect_ok(OvpnCommand::ManagementPassword(Redacted::new(
            password.into(),
        )))
        .await
    }

    /// Close the management session.
    pub async fn exit(mut self) -> Result<(), SessionError> {
        self.sink.send_command(OvpnCommand::Exit).await?;
        Ok(())
    }

    /// Send a raw command expecting `SUCCESS:`/`ERROR:`.
    pub async fn raw(&mut self, command: impl Into<String>) -> Result<String, SessionError> {
        self.send_expect_success(OvpnCommand::Raw(command.into()))
            .await
    }
}
