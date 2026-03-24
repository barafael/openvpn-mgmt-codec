#![forbid(unsafe_code)]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(coverage_nightly, coverage(off))]

//! OpenVPN Management UI — an Iced desktop client for the OpenVPN management
//! interface.
//!
//! Connects to a running OpenVPN daemon over TCP, sends typed commands via
//! [`openvpn_mgmt_codec`], and presents real-time state, logs, client events,
//! and an interactive command prompt in a Gruvbox-themed GUI.

mod actor;
mod chart;
mod completions;
mod message;
mod style;
mod view;

use iced::{Font, Task, Theme};

// -------------------------------------------------------------------
// Font
// -------------------------------------------------------------------

pub(crate) const SPACE_MONO: Font = Font::with_name("Space Mono");

use tokio::sync::mpsc;

use openvpn_mgmt_codec::{
    AuthRetryMode, KillTarget, LoadStats, LogLevel, Notification, OpenVpnState, OvpnCommand,
    OvpnMessage, PasswordNotification, Redacted, Signal, StatusFormat, StreamMode,
};

use actor::{ActorCommand, ActorEvent};
use message::{
    ConnectionState, Message, OperationsForm, OpsMsg, StartupMsg, StartupOptions,
    StartupStreamMode, Tab,
};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

const MAX_LOG_ENTRIES: usize = 500;
const MAX_COMMAND_HISTORY: usize = 100;

// -------------------------------------------------------------------
// Error type
// -------------------------------------------------------------------

/// The actor's command channel is closed — the actor task has exited.
#[derive(Debug)]
struct ActorGone;

// -------------------------------------------------------------------
// Auxiliary data
// -------------------------------------------------------------------

/// One entry in the real-time log tab.
#[derive(Debug, Clone)]
pub(crate) struct LogEntry {
    pub level: LogLevel,
    pub timestamp: String,
    pub message: String,
}

/// A client seen via `>CLIENT:` notifications (server mode).
#[derive(Debug, Clone)]
pub(crate) struct ClientInfo {
    pub cid: u64,
    pub common_name: String,
    pub address: String,
}

/// A command the user sent together with its response lines.
#[derive(Debug, Clone)]
pub(crate) struct CommandHistoryEntry {
    pub command: String,
    pub response_lines: Vec<String>,
}

// -------------------------------------------------------------------
// App state
// -------------------------------------------------------------------

pub(crate) struct App {
    // Connection
    host: String,
    port: String,
    management_password: String,
    connection_state: ConnectionState,
    actor_tx: Option<mpsc::Sender<ActorCommand>>,
    last_error: Option<String>,
    pub(crate) startup: StartupOptions,

    // Data from OpenVPN
    vpn_state: Option<OpenVpnState>,
    vpn_state_description: Option<String>,
    local_ip: Option<String>,
    remote_addr: Option<String>,
    version_lines: Option<Vec<String>>,
    pid: Option<u32>,
    bytes_in: u64,
    bytes_out: u64,
    load_stats: Option<LoadStats>,
    /// Rolling throughput samples (bytes/sec) for the chart.
    pub(crate) throughput: chart::ThroughputHistory,

    // Log
    log_entries: Vec<LogEntry>,
    /// Index of the currently selected log entry (for copy).
    selected_log_index: Option<usize>,

    // Clients (server mode)
    clients: Vec<ClientInfo>,

    // Operations tab
    pub(crate) ops: OperationsForm,

    // Commands page
    command_input: String,
    /// Whether `command_input` currently parses as a recognised command.
    pub(crate) command_valid: bool,
    /// When true, any non-empty input is accepted (sent as `Raw`).
    pub(crate) raw_mode: bool,
    command_history: Vec<CommandHistoryEntry>,
    /// When `true` the next response (Success / Error / MultiLine) is
    /// appended to the most recent history entry instead of being discarded.
    awaiting_command_response: bool,

    // UI
    active_tab: Tab,
    /// Whether the Ctrl key is currently held (shows theme picker).
    pub(crate) ctrl_held: bool,
    /// The active iced theme.
    pub(crate) theme: Theme,
}

// -------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------

fn main() -> iced::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    tracing::info!("openvpn-mgmt-ui starting");
    iced::application(App::new, App::update, App::view)
        .title("OpenVPN Management UI")
        .font(lucide_icons::LUCIDE_FONT_BYTES)
        .font(include_bytes!("../fonts/SpaceMono-Regular.ttf"))
        .default_font(SPACE_MONO)
        .theme(|app: &App| app.theme.clone())
        .subscription(|app: &App| app.subscription())
        .scale_factor(|_| 0.9)
        .antialiasing(true)
        .run()
}

// -------------------------------------------------------------------
// Initialisation
// -------------------------------------------------------------------

impl App {
    fn new() -> (Self, Task<Message>) {
        let (event_tx, event_rx) = mpsc::channel::<ActorEvent>(128);
        let (cmd_tx, cmd_rx) = mpsc::channel::<ActorCommand>(32);

        // The caller controls spawning — the actor is a plain struct whose
        // event_loop consumes self and returns on natural shutdown.
        let actor = actor::ConnectionActor::new();
        tokio::spawn(actor.event_loop(cmd_rx, event_tx));

        // Drain the actor event channel into iced Messages.
        let event_task = Task::run(
            iced::futures::stream::unfold(event_rx, |mut rx| async move {
                let event = rx.recv().await?;
                Some((Message::Actor(event), rx))
            }),
            std::convert::identity,
        );

        let app = Self {
            host: "127.0.0.1".to_string(),
            port: "7505".to_string(),
            management_password: String::new(),
            connection_state: ConnectionState::default(),
            actor_tx: Some(cmd_tx),
            last_error: None,
            startup: StartupOptions::default(),

            vpn_state: None,
            vpn_state_description: None,
            local_ip: None,
            remote_addr: None,
            version_lines: None,
            pid: None,
            bytes_in: 0,
            bytes_out: 0,
            load_stats: None,
            throughput: chart::ThroughputHistory::default(),

            log_entries: Vec::new(),
            selected_log_index: None,
            clients: Vec::new(),

            ops: OperationsForm {
                bytecount_input: "2".to_string(),
                ..OperationsForm::default()
            },

            command_input: String::new(),
            command_valid: false,
            raw_mode: false,
            command_history: Vec::new(),
            awaiting_command_response: false,

            active_tab: Tab::Status,
            ctrl_held: false,
            theme: Theme::GruvboxDark,
        };

        (app, event_task)
    }
}

// -------------------------------------------------------------------
// Update
// -------------------------------------------------------------------

impl App {
    fn update(&mut self, msg: Message) -> Task<Message> {
        match msg {
            // -- Connection form -------------------------------------------------
            Message::HostChanged(value) => {
                self.host = value;
            }
            Message::PortChanged(value) => {
                self.port = value;
            }
            Message::PasswordChanged(value) => {
                self.management_password = value;
            }
            Message::Connect => {
                tracing::info!(host = %self.host, port = %self.port, "connect requested");
                self.connection_state = ConnectionState::Connecting;
                self.last_error = None;
                self.reset_session_data();
                let startup_commands = self.build_startup_commands();
                if self
                    .send_actor(ActorCommand::Connect {
                        host: self.host.clone(),
                        port: self.port.clone(),
                        startup_commands,
                    })
                    .is_err()
                {
                    self.on_actor_gone();
                }
            }
            Message::Disconnect => {
                tracing::info!("disconnect requested");
                if self.send_actor(ActorCommand::Disconnect).is_err() {
                    self.on_actor_gone();
                }
            }
            Message::VerbReset => {
                tracing::info!("verb reset: disconnect → reconnect with verb 4");
                if self.send_actor(ActorCommand::Disconnect).is_err() {
                    self.on_actor_gone();
                    return Task::none();
                }
                self.connection_state = ConnectionState::Connecting;
                self.last_error = None;
                self.reset_session_data();
                // Build startup commands with verb 4 injected before streaming.
                let mut startup_commands = Vec::new();
                if !self.management_password.is_empty() {
                    startup_commands.push(OvpnCommand::ManagementPassword(Redacted::new(
                        self.management_password.clone(),
                    )));
                }
                startup_commands.push(OvpnCommand::Verb(Some(4)));
                // Append the normal startup commands (which will include
                // log/state/etc. — now at safe verbosity).
                startup_commands.extend(self.build_startup_commands().into_iter().skip(
                    // Skip the password if already added above.
                    if self.management_password.is_empty() {
                        0
                    } else {
                        1
                    },
                ));
                let host = self.host.clone();
                let port = self.port.clone();
                return Task::perform(
                    async {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    },
                    move |()| Message::ReconnectReady {
                        host,
                        port,
                        startup_commands,
                    },
                );
            }

            Message::Reconnect => {
                tracing::info!("reconnect requested");
                if self.send_actor(ActorCommand::Disconnect).is_err() {
                    self.on_actor_gone();
                    return Task::none();
                }
                self.connection_state = ConnectionState::Connecting;
                self.last_error = None;
                self.reset_session_data();
                let startup_commands = self.build_startup_commands();
                let host = self.host.clone();
                let port = self.port.clone();
                return Task::perform(
                    async {
                        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    },
                    move |()| Message::ReconnectReady {
                        host,
                        port,
                        startup_commands,
                    },
                );
            }

            Message::ReconnectReady {
                host,
                port,
                startup_commands,
            } => {
                if self
                    .send_actor(ActorCommand::Connect {
                        host,
                        port,
                        startup_commands,
                    })
                    .is_err()
                {
                    self.on_actor_gone();
                }
            }

            // -- Actor events ----------------------------------------------------
            Message::Actor(event) => match event {
                ActorEvent::Connected => {
                    tracing::info!("connected");
                    self.connection_state = ConnectionState::Connected;
                    self.last_error = None;
                }
                ActorEvent::Disconnected(err) => {
                    if let Some(reason) = &err {
                        tracing::warn!(reason, "disconnected");
                    } else {
                        tracing::info!("disconnected");
                    }
                    self.connection_state = ConnectionState::Disconnected;
                    self.last_error = err;
                }
                ActorEvent::Message(ovpn_msg) => {
                    self.handle_ovpn_message(ovpn_msg);
                }
            },

            // -- Tabs ------------------------------------------------------------
            Message::TabSelected(tab) => {
                self.active_tab = tab;
            }

            // -- Startup options --------------------------------------------------
            Message::Startup(startup_msg) => match startup_msg {
                StartupMsg::LogMode(mode) => self.startup.log = mode,
                StartupMsg::StateMode(mode) => self.startup.state = mode,
                StartupMsg::EchoMode(mode) => self.startup.echo = mode,
                StartupMsg::ByteCountIntervalChanged(value) => {
                    self.startup.bytecount_interval = value;
                }
                StartupMsg::HoldReleaseToggled(value) => self.startup.hold_release = value,
                StartupMsg::QueryVersionToggled(value) => self.startup.query_version = value,
            },

            // -- Operations tab ---------------------------------------------------
            Message::Ops(OpsMsg::VerbReset) => {
                self.ops.verb_input = "4".to_string();
                return self.update(Message::VerbReset);
            }
            Message::Ops(ops_msg) => {
                if self.handle_ops(ops_msg).is_err() {
                    self.on_actor_gone();
                }
            }

            // -- Commands page ---------------------------------------------------
            Message::CommandInputChanged(value) => {
                self.command_input = value;
            }
            Message::PickSuggestion(name) => {
                // Insert command name + trailing space so the user can
                // immediately start typing arguments.
                self.command_input = format!("{name} ");
                // Early return — revalidate here since the bottom call is skipped.
                self.revalidate_command();
                return iced::widget::operation::focus(view::COMMAND_INPUT_ID.clone());
            }
            Message::ToggleRawMode(enabled) => {
                self.raw_mode = enabled;
            }
            Message::SendCommand => {
                if !self.command_valid {
                    return Task::none();
                }
                let input = self.command_input.trim().to_string();
                self.command_input.clear();

                match input.parse::<OvpnCommand>() {
                    Ok(command) => {
                        tracing::debug!(input, "command sent");
                        if self.send_and_record(&input, command).is_err() {
                            self.on_actor_gone();
                        }
                    }
                    Err(error) => {
                        tracing::warn!(input, %error, "command parse failed");
                        self.command_history.push(CommandHistoryEntry {
                            command: input,
                            response_lines: vec![format!("parse error: {error}")],
                        });
                    }
                }
            }

            // -- Log tab ---------------------------------------------------------
            Message::SelectLogEntry(index) => {
                self.selected_log_index = Some(index);
            }
            Message::CopyLogEntry => {
                if let Some(index) = self.selected_log_index
                    && let Some(entry) = self.log_entries.get(index)
                {
                    let label = entry.level.label();
                    let line = if entry.timestamp.is_empty() {
                        format!("[{label}] {}", entry.message)
                    } else {
                        format!("[{label}] {} {}", entry.timestamp, entry.message)
                    };
                    return iced::clipboard::write(line);
                }
            }

            // -- Status refresh --------------------------------------------------
            Message::RefreshStatus => {
                let cmds = [
                    OvpnCommand::Version,
                    OvpnCommand::Pid,
                    OvpnCommand::State,
                    OvpnCommand::LoadStats,
                ];
                for cmd in cmds {
                    if self.send_actor(ActorCommand::Send(cmd)).is_err() {
                        self.on_actor_gone();
                        break;
                    }
                }
            }

            // -- Keyboard modifiers ----------------------------------------------
            Message::ModifiersChanged(modifiers) => {
                self.ctrl_held = modifiers.control();
            }

            // -- Theme -----------------------------------------------------------
            Message::ThemeSelected(theme) => {
                self.theme = theme;
            }
        }

        self.revalidate_command();
        Task::none()
    }
}

// -------------------------------------------------------------------
// Message routing
// -------------------------------------------------------------------

impl App {
    fn handle_ovpn_message(&mut self, msg: OvpnMessage) {
        match msg {
            OvpnMessage::Success(payload) => {
                self.ingest_success(&payload);
                self.append_command_response(format!("SUCCESS: {payload}"));
            }
            OvpnMessage::Error(payload) => {
                self.append_command_response(format!("ERROR: {payload}"));
            }
            OvpnMessage::MultiLine(lines) => {
                self.ingest_multiline(&lines);
                self.append_command_response_lines(
                    lines.iter().map(|line| format!("  {line}")).collect(),
                );
            }
            OvpnMessage::Notification(notif) => {
                self.handle_notification(notif);
            }
            OvpnMessage::Info(info) => {
                self.add_log(LogLevel::Info, "", &info);
            }
            OvpnMessage::PasswordPrompt => {
                self.add_log(LogLevel::Warning, "", "Management password required");
            }
            OvpnMessage::Pkcs11IdEntry { index, id, blob } => {
                self.append_command_response(format!("PKCS11: index={index} id={id} blob={blob}"));
            }
            OvpnMessage::Unrecognized { line, kind } => {
                self.add_log(
                    LogLevel::Warning,
                    "",
                    &format!("Unrecognized ({kind:?}): {line}"),
                );
            }
        }
    }

    fn handle_notification(&mut self, notif: Notification) {
        match notif {
            Notification::State {
                timestamp,
                name,
                description,
                local_ip,
                remote_ip,
                remote_port,
                ..
            } => {
                tracing::info!(%name, %description, "vpn state changed");
                self.vpn_state = Some(name);
                self.vpn_state_description = Some(description.clone());
                self.local_ip = if local_ip.is_empty() {
                    None
                } else {
                    Some(local_ip)
                };
                self.remote_addr = if remote_ip.is_empty() {
                    None
                } else if let Some(port) = remote_port {
                    Some(format!("{remote_ip}:{port}"))
                } else {
                    Some(remote_ip.clone())
                };
                self.add_log(
                    LogLevel::Info,
                    &format_timestamp(timestamp),
                    &format!(
                        "State → {} — {description}",
                        self.vpn_state.as_ref().unwrap()
                    ),
                );
            }
            Notification::ByteCount {
                bytes_in,
                bytes_out,
            } => {
                // Feed the throughput chart before overwriting the totals.
                let interval = self.startup.bytecount_interval.parse::<u32>().unwrap_or(2);
                self.throughput.push(bytes_in, bytes_out, interval);
                self.bytes_in = bytes_in;
                self.bytes_out = bytes_out;
            }
            Notification::ByteCountCli {
                cid,
                bytes_in,
                bytes_out,
            } => {
                self.add_log(
                    LogLevel::Debug,
                    "",
                    &format!("ByteCount cid={cid} in={bytes_in} out={bytes_out}"),
                );
            }
            Notification::Log {
                timestamp,
                level,
                message,
            } => {
                self.add_log(level, &format_timestamp(timestamp), &message);
            }
            Notification::Echo { timestamp, param } => {
                self.add_log(
                    LogLevel::Info,
                    &format_timestamp(timestamp),
                    &format!("Echo: {param}"),
                );
            }
            Notification::Hold { text } => {
                tracing::warn!(text, "hold");
                self.add_log(LogLevel::Warning, "", &format!("Hold: {text}"));
            }
            Notification::Fatal { message } => {
                tracing::error!(message, "fatal from openvpn");
                self.add_log(LogLevel::Fatal, "", &format!("FATAL: {message}"));
            }
            Notification::Client {
                event,
                cid,
                kid,
                env,
            } => {
                // Extract common_name from env if present.
                let common_name = env
                    .iter()
                    .find(|(key, _)| key == "common_name")
                    .map(|(_, val)| val.clone())
                    .unwrap_or_else(|| format!("{event}"));
                let address = env
                    .iter()
                    .find(|(key, _)| key == "untrusted_ip" || key == "IV_IP")
                    .map(|(_, val)| val.clone())
                    .unwrap_or_default();

                let kid_label = kid.map_or(String::new(), |kid_val| format!(" kid={kid_val}"));
                self.add_log(
                    LogLevel::Info,
                    "",
                    &format!("Client {event} cid={cid}{kid_label} cn={common_name}"),
                );

                // Track client connects / disconnects.
                match event.to_string().as_str() {
                    "CONNECT" | "REAUTH" | "ESTABLISHED"
                        if !self.clients.iter().any(|client| client.cid == cid) =>
                    {
                        self.clients.push(ClientInfo {
                            cid,
                            common_name,
                            address,
                        });
                    }
                    "DISCONNECT" => {
                        self.clients.retain(|client| client.cid != cid);
                    }
                    _ => {}
                }
            }
            Notification::ClientAddress { cid, addr, primary } => {
                self.add_log(
                    LogLevel::Debug,
                    "",
                    &format!("Client address cid={cid} addr={addr} primary={primary}"),
                );
            }
            Notification::Password(password_notif) => match password_notif {
                PasswordNotification::NeedAuth { auth_type } => {
                    self.add_log(
                        LogLevel::Warning,
                        "",
                        &format!("Need '{auth_type}' username/password"),
                    );
                }
                PasswordNotification::NeedPassword { auth_type } => {
                    self.add_log(
                        LogLevel::Warning,
                        "",
                        &format!("Need '{auth_type}' password"),
                    );
                }
                PasswordNotification::VerificationFailed { auth_type } => {
                    self.add_log(
                        LogLevel::Warning,
                        "",
                        &format!("Auth verification failed: '{auth_type}'"),
                    );
                }
                PasswordNotification::StaticChallenge { challenge, .. } => {
                    self.add_log(
                        LogLevel::Warning,
                        "",
                        &format!("Static challenge: {challenge}"),
                    );
                }
                PasswordNotification::DynamicChallenge { challenge, .. } => {
                    self.add_log(
                        LogLevel::Warning,
                        "",
                        &format!("Dynamic challenge: {challenge}"),
                    );
                }
                PasswordNotification::AuthToken { token } => {
                    self.add_log(LogLevel::Info, "", &format!("Auth token received: {token}"));
                }
            },
            Notification::NeedOk { name, message } => {
                self.add_log(
                    LogLevel::Warning,
                    "",
                    &format!("NEED-OK '{name}': {message}"),
                );
            }
            Notification::NeedStr { name, message } => {
                self.add_log(
                    LogLevel::Warning,
                    "",
                    &format!("NEED-STR '{name}': {message}"),
                );
            }
            Notification::Remote {
                host,
                port,
                protocol,
            } => {
                self.add_log(
                    LogLevel::Info,
                    "",
                    &format!("Remote: {host}:{port} ({protocol})"),
                );
            }
            Notification::Proxy {
                index,
                proxy_type,
                host,
            } => {
                self.add_log(
                    LogLevel::Info,
                    "",
                    &format!("Proxy #{index}: {proxy_type} {host}"),
                );
            }
            Notification::RsaSign { data } => {
                self.add_log(
                    LogLevel::Info,
                    "",
                    &format!("RSA sign request: {}", &data[..data.len().min(40)]),
                );
            }
            Notification::Pkcs11IdCount { count } => {
                self.add_log(LogLevel::Info, "", &format!("PKCS#11 ID count: {count}"));
            }
            Notification::PkSign { data, algorithm } => {
                let algo = algorithm.as_deref().unwrap_or("unknown");
                self.add_log(
                    LogLevel::Info,
                    "",
                    &format!("PK sign request ({algo}): {}", &data[..data.len().min(40)]),
                );
            }
            Notification::Info { message } => {
                self.add_log(LogLevel::Info, "", &message);
            }
            Notification::Simple { kind, payload } => {
                self.add_log(LogLevel::Info, "", &format!("[{kind}] {payload}"));
            }
        }
    }

    fn handle_ops(&mut self, msg: OpsMsg) -> Result<(), ActorGone> {
        match msg {
            // -- Query -----------------------------------------------------------
            OpsMsg::Version => self.send_and_record("version", OvpnCommand::Version)?,
            OpsMsg::Status1 => {
                self.send_and_record("status 1", OvpnCommand::Status(StatusFormat::V1))?;
            }
            OpsMsg::Status2 => {
                self.send_and_record("status 2", OvpnCommand::Status(StatusFormat::V2))?;
            }
            OpsMsg::Status3 => {
                self.send_and_record("status 3", OvpnCommand::Status(StatusFormat::V3))?;
            }
            OpsMsg::Pid => self.send_and_record("pid", OvpnCommand::Pid)?,
            OpsMsg::Help => self.send_and_record("help", OvpnCommand::Help)?,
            OpsMsg::LoadStats => self.send_and_record("load-stats", OvpnCommand::LoadStats)?,
            OpsMsg::Net => self.send_and_record("net", OvpnCommand::Net)?,

            // -- Streaming -------------------------------------------------------
            OpsMsg::LogOn => self.send_and_record("log on", OvpnCommand::Log(StreamMode::On))?,
            OpsMsg::LogOff => {
                self.send_and_record("log off", OvpnCommand::Log(StreamMode::Off))?;
            }
            OpsMsg::LogAll => {
                self.send_and_record("log all", OvpnCommand::Log(StreamMode::All))?;
            }
            OpsMsg::StateOn => {
                self.send_and_record("state on", OvpnCommand::StateStream(StreamMode::On))?;
            }
            OpsMsg::StateOff => {
                self.send_and_record("state off", OvpnCommand::StateStream(StreamMode::Off))?;
            }
            OpsMsg::StateAll => {
                self.send_and_record("state all", OvpnCommand::StateStream(StreamMode::All))?;
            }
            OpsMsg::EchoOn => {
                self.send_and_record("echo on", OvpnCommand::Echo(StreamMode::On))?;
            }
            OpsMsg::EchoOff => {
                self.send_and_record("echo off", OvpnCommand::Echo(StreamMode::Off))?;
            }
            OpsMsg::EchoAll => {
                self.send_and_record("echo all", OvpnCommand::Echo(StreamMode::All))?;
            }
            OpsMsg::ByteCountIntervalChanged(value) => self.ops.bytecount_input = value,
            OpsMsg::ByteCountApply => {
                if let Ok(seconds) = self.ops.bytecount_input.parse::<u32>() {
                    self.send_and_record(
                        &format!("bytecount {seconds}"),
                        OvpnCommand::ByteCount(seconds),
                    )?;
                }
            }
            OpsMsg::ByteCountOff => {
                self.send_and_record("bytecount 0", OvpnCommand::ByteCount(0))?;
            }

            // -- Signals ---------------------------------------------------------
            OpsMsg::SignalHup => {
                self.send_and_record("signal SIGHUP", OvpnCommand::Signal(Signal::SigHup))?;
            }
            OpsMsg::SignalTerm => {
                self.send_and_record("signal SIGTERM", OvpnCommand::Signal(Signal::SigTerm))?;
            }
            OpsMsg::SignalUsr1 => {
                self.send_and_record("signal SIGUSR1", OvpnCommand::Signal(Signal::SigUsr1))?;
            }
            OpsMsg::SignalUsr2 => {
                self.send_and_record("signal SIGUSR2", OvpnCommand::Signal(Signal::SigUsr2))?;
            }

            // -- Hold ------------------------------------------------------------
            OpsMsg::HoldQuery => self.send_and_record("hold", OvpnCommand::HoldQuery)?,
            OpsMsg::HoldOn => self.send_and_record("hold on", OvpnCommand::HoldOn)?,
            OpsMsg::HoldOff => self.send_and_record("hold off", OvpnCommand::HoldOff)?,
            OpsMsg::HoldRelease => {
                self.send_and_record("hold release", OvpnCommand::HoldRelease)?;
            }

            // -- Verbosity -------------------------------------------------------
            OpsMsg::VerbInputChanged(value) => self.ops.verb_input = value,
            OpsMsg::VerbGet => self.send_and_record("verb", OvpnCommand::Verb(None))?,
            OpsMsg::VerbSet => {
                if let Ok(level) = self.ops.verb_input.parse::<u8>() {
                    self.send_and_record(&format!("verb {level}"), OvpnCommand::Verb(Some(level)))?;
                }
            }
            OpsMsg::VerbReset => unreachable!("handled in update()"),
            OpsMsg::MuteInputChanged(value) => self.ops.mute_input = value,
            OpsMsg::MuteGet => self.send_and_record("mute", OvpnCommand::Mute(None))?,
            OpsMsg::MuteSet => {
                if let Ok(threshold) = self.ops.mute_input.parse::<u32>() {
                    self.send_and_record(
                        &format!("mute {threshold}"),
                        OvpnCommand::Mute(Some(threshold)),
                    )?;
                }
            }

            // -- Auth ------------------------------------------------------------
            OpsMsg::AuthRetryNone => {
                self.send_and_record(
                    "auth-retry none",
                    OvpnCommand::AuthRetry(AuthRetryMode::None),
                )?;
            }
            OpsMsg::AuthRetryInteract => {
                self.send_and_record(
                    "auth-retry interact",
                    OvpnCommand::AuthRetry(AuthRetryMode::Interact),
                )?;
            }
            OpsMsg::AuthRetryNoInteract => {
                self.send_and_record(
                    "auth-retry nointeract",
                    OvpnCommand::AuthRetry(AuthRetryMode::NoInteract),
                )?;
            }
            OpsMsg::ForgetPasswords => {
                self.send_and_record("forget-passwords", OvpnCommand::ForgetPasswords)?;
            }

            // -- Kill ------------------------------------------------------------
            OpsMsg::KillInputChanged(value) => self.ops.kill_input = value,
            OpsMsg::KillSend => {
                let target = self.ops.kill_input.trim().to_string();
                if !target.is_empty() {
                    self.send_and_record(
                        &format!("kill {target}"),
                        OvpnCommand::Kill(KillTarget::CommonName(target)),
                    )?;
                }
            }

            // -- Client management -----------------------------------------------
            OpsMsg::ClientCidChanged(value) => self.ops.client_cid = value,
            OpsMsg::ClientKidChanged(value) => self.ops.client_kid = value,
            OpsMsg::ClientDenyReasonChanged(value) => self.ops.client_deny_reason = value,
            OpsMsg::ClientAuthNt => {
                if let (Ok(cid), Ok(kid)) = (
                    self.ops.client_cid.parse::<u64>(),
                    self.ops.client_kid.parse::<u64>(),
                ) {
                    self.send_and_record(
                        &format!("client-auth-nt {cid} {kid}"),
                        OvpnCommand::ClientAuthNt { cid, kid },
                    )?;
                }
            }
            OpsMsg::ClientDeny => {
                if let (Ok(cid), Ok(kid)) = (
                    self.ops.client_cid.parse::<u64>(),
                    self.ops.client_kid.parse::<u64>(),
                ) {
                    let reason = self.ops.client_deny_reason.clone();
                    let client_reason = None;
                    self.send_and_record(
                        &format!("client-deny {cid} {kid} {reason}"),
                        OvpnCommand::ClientDeny {
                            cid,
                            kid,
                            reason,
                            client_reason,
                        },
                    )?;
                }
            }
            OpsMsg::ClientKill => {
                if let Ok(cid) = self.ops.client_cid.parse::<u64>() {
                    self.send_and_record(
                        &format!("client-kill {cid}"),
                        OvpnCommand::ClientKill { cid, message: None },
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Try to extract structured data from a `SUCCESS:` payload.
    fn ingest_success(&mut self, payload: &str) {
        // `pid` response: "pid=12345"
        if let Some(rest) = payload.strip_prefix("pid=")
            && let Ok(pid) = rest.parse::<u32>()
        {
            self.pid = Some(pid);
        }

        // `load-stats` response: "nclients=0,bytesin=0,bytesout=0"
        if payload.starts_with("nclients=")
            && let Ok(stats) = openvpn_mgmt_codec::parsed_response::parse_load_stats(payload)
        {
            self.load_stats = Some(stats);
        }

        // `verb` response: "verb=3"
        if let Some(rest) = payload.strip_prefix("verb=") {
            self.ops.verb_input = rest.to_string();
        }

        // `mute` response: "mute=0"
        if let Some(rest) = payload.strip_prefix("mute=") {
            self.ops.mute_input = rest.to_string();
        }
    }

    /// Try to extract structured data from a multi-line response.
    fn ingest_multiline(&mut self, lines: &[String]) {
        // Version info: lines contain "OpenVPN Version:" and "Management Version:"
        if lines
            .iter()
            .any(|line| line.contains("OpenVPN Version:") || line.contains("Management Version:"))
        {
            self.version_lines = Some(lines.to_vec());
        }

        // State history: lines like "1711234567,CONNECTED,SUCCESS,10.8.0.2,1.2.3.4,..."
        // Take the last (most recent) line that parses as a state.
        for line in lines.iter().rev() {
            let fields: Vec<&str> = line.splitn(9, ',').collect();
            if fields.len() >= 3
                && let Ok(state) = fields[1].parse::<OpenVpnState>()
            {
                self.vpn_state = Some(state);
                self.vpn_state_description = Some(fields[2].to_string());
                if fields.len() > 3 && !fields[3].is_empty() {
                    self.local_ip = Some(fields[3].to_string());
                }
                if fields.len() > 4 && !fields[4].is_empty() {
                    let remote = if fields.len() > 5 && !fields[5].is_empty() {
                        format!("{}:{}", fields[4], fields[5])
                    } else {
                        fields[4].to_string()
                    };
                    self.remote_addr = Some(remote);
                }
                break;
            }
        }
    }

    /// Append text to the most recent command-history entry (if awaiting).
    /// Append a single response line (Success / Error).
    fn append_command_response(&mut self, line: String) {
        if self.awaiting_command_response {
            if let Some(entry) = self.command_history.last_mut() {
                entry.response_lines.push(line);
            }
            self.awaiting_command_response = false;
        }
    }

    /// Append all lines of a multi-line response at once.
    fn append_command_response_lines(&mut self, lines: Vec<String>) {
        if self.awaiting_command_response {
            if let Some(entry) = self.command_history.last_mut() {
                entry.response_lines.extend(lines);
            }
            self.awaiting_command_response = false;
        }
    }

    fn add_log(&mut self, level: LogLevel, timestamp: &str, message: &str) {
        self.log_entries.push(LogEntry {
            level,
            timestamp: timestamp.to_string(),
            message: message.to_string(),
        });
        if self.log_entries.len() > MAX_LOG_ENTRIES {
            self.log_entries
                .drain(0..self.log_entries.len() - MAX_LOG_ENTRIES);
        }
    }

    fn send_actor(&self, command: ActorCommand) -> Result<(), ActorGone> {
        let tx = self.actor_tx.as_ref().ok_or(ActorGone)?;
        tx.try_send(command).map_err(|_| ActorGone)
    }

    /// Send a command and record it in the output history so the response
    /// is visible in the console output pane.
    fn send_and_record(&mut self, label: &str, command: OvpnCommand) -> Result<(), ActorGone> {
        self.command_history.push(CommandHistoryEntry {
            command: label.to_string(),
            response_lines: Vec::new(),
        });
        if self.command_history.len() > MAX_COMMAND_HISTORY {
            self.command_history
                .drain(0..self.command_history.len() - MAX_COMMAND_HISTORY);
        }
        self.awaiting_command_response = true;
        self.send_actor(ActorCommand::Send(command))
    }

    /// The actor's command channel is broken — transition to disconnected.
    fn on_actor_gone(&mut self) {
        tracing::warn!("actor command channel closed");
        self.actor_tx = None;
        self.connection_state = ConnectionState::Disconnected;
        self.last_error = Some("Connection actor exited".to_string());
    }

    /// Build the command sequence sent immediately after TCP connect,
    /// driven by the user-visible startup options.
    fn build_startup_commands(&self) -> Vec<OvpnCommand> {
        let mut commands = Vec::new();

        if !self.management_password.is_empty() {
            commands.push(OvpnCommand::ManagementPassword(Redacted::new(
                self.management_password.clone(),
            )));
        }

        let to_stream_mode = |startup_mode: StartupStreamMode| match startup_mode {
            StartupStreamMode::Off => None,
            StartupStreamMode::On => Some(StreamMode::On),
            StartupStreamMode::OnAll => Some(StreamMode::OnAll),
        };

        if let Some(mode) = to_stream_mode(self.startup.log) {
            commands.push(OvpnCommand::Log(mode));
        }
        if let Some(mode) = to_stream_mode(self.startup.state) {
            commands.push(OvpnCommand::StateStream(mode));
        }
        if let Some(mode) = to_stream_mode(self.startup.echo) {
            commands.push(OvpnCommand::Echo(mode));
        }

        commands.push(OvpnCommand::Pid);
        // One-shot state query so we always know the current state,
        // even if no >STATE: transition fires during connect.
        commands.push(OvpnCommand::State);

        if self.startup.query_version {
            commands.push(OvpnCommand::Version);
        }

        if let Ok(seconds) = self.startup.bytecount_interval.parse::<u32>()
            && seconds > 0
        {
            commands.push(OvpnCommand::ByteCount(seconds));
        }

        if self.startup.hold_release {
            commands.push(OvpnCommand::HoldRelease);
        }

        commands
    }

    /// Recompute `command_valid` from the current input and raw-mode flag.
    fn revalidate_command(&mut self) {
        let trimmed = self.command_input.trim();
        self.command_valid = if self.raw_mode {
            true
        } else {
            !trimmed.is_empty()
                && trimmed
                    .parse::<OvpnCommand>()
                    .is_ok_and(|cmd| !matches!(cmd, OvpnCommand::Raw(_)))
        };
    }

    fn reset_session_data(&mut self) {
        self.vpn_state = None;
        self.vpn_state_description = None;
        self.local_ip = None;
        self.remote_addr = None;
        self.version_lines = None;
        self.pid = None;
        self.bytes_in = 0;
        self.bytes_out = 0;
        self.load_stats = None;
        self.throughput.reset();
        self.log_entries.clear();
        self.selected_log_index = None;
        self.clients.clear();
        self.ops = OperationsForm {
            bytecount_input: "2".to_string(),
            ..OperationsForm::default()
        };
        self.command_history.clear();
        self.awaiting_command_response = false;
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(iced::keyboard::Event::ModifiersChanged(modifiers)) => {
                Some(Message::ModifiersChanged(modifiers))
            }
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Character(ref ch),
                modifiers,
                ..
            }) if modifiers.control() && ch.as_ref() == "c" => Some(Message::CopyLogEntry),
            _ => None,
        })
    }
}

// -------------------------------------------------------------------
// Timestamp formatting (matches openvpn-mgmt-cli)
// -------------------------------------------------------------------

fn format_timestamp(ts: u64) -> String {
    if ts == 0 {
        return String::new();
    }
    let secs = ts % 60;
    let mins_total = ts / 60;
    let mins = mins_total % 60;
    let hours_total = mins_total / 60;
    let hours = hours_total % 24;
    let days_total = hours_total / 24;
    let (year, month, day) = days_to_ymd(days_total);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{mins:02}:{secs:02}")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    days += 719_468;
    let era = days / 146_097;
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- format_timestamp ---

    #[test]
    fn format_timestamp_zero_returns_empty() {
        assert_eq!(format_timestamp(0), "");
    }

    #[test]
    fn format_timestamp_unix_epoch() {
        // 1970-01-01 00:00:01
        assert_eq!(format_timestamp(1), "1970-01-01 00:00:01");
    }

    #[test]
    fn format_timestamp_known_date() {
        // 2024-03-21 14:30:00 UTC = 1711031400
        assert_eq!(format_timestamp(1_711_031_400), "2024-03-21 14:30:00");
    }

    #[test]
    fn format_timestamp_y2k() {
        // 2000-01-01 00:00:00 UTC = 946684800
        assert_eq!(format_timestamp(946_684_800), "2000-01-01 00:00:00");
    }

    #[test]
    fn format_timestamp_leap_day() {
        // 2024-02-29 12:00:00 UTC = 1709208000
        assert_eq!(format_timestamp(1_709_208_000), "2024-02-29 12:00:00");
    }

    // --- days_to_ymd ---

    #[test]
    fn days_to_ymd_epoch() {
        assert_eq!(days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn days_to_ymd_known_date() {
        // 2024-03-21 is day 19803 since epoch
        assert_eq!(days_to_ymd(19803), (2024, 3, 21));
    }

    #[test]
    fn days_to_ymd_leap_day() {
        // 2024-02-29 is day 19782 since epoch
        assert_eq!(days_to_ymd(19782), (2024, 2, 29));
    }

    #[test]
    fn days_to_ymd_dec_31() {
        // 2023-12-31 is day 19722 since epoch
        assert_eq!(days_to_ymd(19722), (2023, 12, 31));
    }

    #[test]
    fn days_to_ymd_jan_1_2000() {
        // 2000-01-01 is day 10957 since epoch
        assert_eq!(days_to_ymd(10957), (2000, 1, 1));
    }
}
