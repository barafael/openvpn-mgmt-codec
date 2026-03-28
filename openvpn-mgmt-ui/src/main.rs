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
    AuthRetryMode, ClientDeny, KillTarget, LoadStats, LogLevel, Notification, OpenVpnState,
    OvpnCommand, OvpnMessage, PasswordNotification, Redacted, Signal, StatusFormat, StreamMode,
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

/// Start a 350ms timer that sends the given message (used for copy flash).
fn flash_timer(msg: Message) -> Task<Message> {
    Task::perform(
        async { tokio::time::sleep(std::time::Duration::from_millis(350)).await },
        move |()| msg,
    )
}

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
    /// Temporary flash highlight on the selected log entry after copy.
    log_flash_index: Option<usize>,

    // Clients (server mode)
    clients: Vec<ClientInfo>,

    // Help
    help_lines: Option<Vec<String>>,

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
    /// Selected entry index in console output (index into reversed command_history).
    selected_console_entry: Option<usize>,
    /// Temporary flash highlight on a console entry after copy.
    console_flash_entry: Option<usize>,

    // UI
    active_tab: Tab,
    /// Whether the Ctrl key is currently held (shows theme picker).
    pub(crate) ctrl_held: bool,
    /// The active iced theme.
    pub(crate) theme: Theme,
    /// Dot animation counter for "Connecting" state (0..=2).
    pub(crate) connecting_dots: u8,
    /// Whether the demo chart is active (feeds synthetic throughput data).
    #[cfg(debug_assertions)]
    pub(crate) demo_chart: bool,
    /// Cumulative synthetic byte counters and current rates for smooth random walk.
    #[cfg(debug_assertions)]
    demo_state: DemoState,
}

#[cfg(debug_assertions)]
#[derive(Default)]
struct DemoState {
    cumulative_in: u64,
    cumulative_out: u64,
    rate_in: f64,
    rate_out: f64,
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
            log_flash_index: None,
            clients: Vec::new(),

            help_lines: None,

            ops: OperationsForm::default(),

            command_input: String::new(),
            command_valid: false,
            raw_mode: false,
            command_history: Vec::new(),
            awaiting_command_response: false,
            selected_console_entry: None,
            console_flash_entry: None,

            active_tab: Tab::Dashboard,
            ctrl_held: false,
            theme: Theme::GruvboxDark,
            connecting_dots: 0,
            #[cfg(debug_assertions)]
            demo_chart: false,
            #[cfg(debug_assertions)]
            demo_state: DemoState::default(),
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
            Message::Startup(startup_msg) => {
                if self.handle_startup(startup_msg).is_err() {
                    self.on_actor_gone();
                }
            }

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
                    self.log_flash_index = Some(index);
                    return Task::batch([
                        iced::clipboard::write(line),
                        flash_timer(Message::ClearLogFlash),
                    ]);
                }
            }
            Message::ClearLogFlash => {
                self.log_flash_index = None;
            }

            // -- Console output --------------------------------------------------
            Message::SelectConsoleEntry(entry_index) => {
                self.selected_console_entry = Some(entry_index);
            }
            Message::CopyConsoleEntry => {
                if let Some(rev_idx) = self.selected_console_entry
                    && let Some(text) = self.console_entry_text(rev_idx)
                {
                    self.console_flash_entry = Some(rev_idx);
                    return Task::batch([
                        iced::clipboard::write(text),
                        flash_timer(Message::ClearConsoleFlash),
                    ]);
                }
            }
            Message::ClearConsoleFlash => {
                self.console_flash_entry = None;
            }

            // -- Ctrl+C: dispatch to active tab --------------------------------
            Message::CopySelection => match self.active_tab {
                Tab::Log => return self.update(Message::CopyLogEntry),
                Tab::Console => return self.update(Message::CopyConsoleEntry),
                _ => {}
            },

            // -- Arrow navigation ------------------------------------------------
            Message::SelectionUp => match self.active_tab {
                Tab::Log if !self.log_entries.is_empty() => {
                    // List is displayed newest-first; "up" visually = older = higher index.
                    let max = self.log_entries.len() - 1;
                    self.selected_log_index = Some(match self.selected_log_index {
                        Some(idx) => (idx + 1).min(max),
                        None => max, // start at top (newest) when nothing selected
                    });
                }
                Tab::Console if !self.command_history.is_empty() => {
                    // Displayed newest-first; index 0 = top. Up = lower index.
                    self.selected_console_entry = Some(match self.selected_console_entry {
                        Some(idx) if idx > 0 => idx - 1,
                        Some(_) => 0,
                        None => 0,
                    });
                }
                _ => {}
            },
            Message::SelectionDown => match self.active_tab {
                Tab::Log if !self.log_entries.is_empty() => {
                    self.selected_log_index = Some(match self.selected_log_index {
                        Some(idx) if idx > 0 => idx - 1,
                        Some(_) => 0,
                        None => self.log_entries.len() - 1,
                    });
                }
                Tab::Console if !self.command_history.is_empty() => {
                    let max = self.command_history.len() - 1;
                    self.selected_console_entry = Some(match self.selected_console_entry {
                        Some(idx) => (idx + 1).min(max),
                        None => 0,
                    });
                }
                _ => {}
            },

            // -- Status refresh --------------------------------------------------
            Message::RefreshStatus => {
                let cmds = [
                    OvpnCommand::Version,
                    OvpnCommand::Pid,
                    OvpnCommand::State,
                    OvpnCommand::LoadStats,
                    OvpnCommand::Verb(None),
                    OvpnCommand::Mute(None),
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

            // -- Animation -------------------------------------------------------
            Message::ConnectingTick => {
                self.connecting_dots = (self.connecting_dots + 1) % 4;
            }

            // -- Debug -----------------------------------------------------------
            #[cfg(debug_assertions)]
            Message::ToggleDemoChart => {
                self.demo_chart = !self.demo_chart;
                if self.demo_chart {
                    self.demo_state = DemoState {
                        rate_in: 200_000.0,
                        rate_out: 80_000.0,
                        ..DemoState::default()
                    };
                    self.throughput.reset();
                }
            }
            #[cfg(debug_assertions)]
            Message::DemoChartTick => {
                use rand::Rng;
                let mut rng = rand::rng();
                let ds = &mut self.demo_state;
                // Random walk with mean-reversion: rates drift smoothly.
                ds.rate_in +=
                    (200_000.0 - ds.rate_in) * 0.05 + rng.random_range(-40_000.0f64..40_000.0);
                ds.rate_out +=
                    (80_000.0 - ds.rate_out) * 0.05 + rng.random_range(-15_000.0f64..15_000.0);
                ds.rate_in = ds.rate_in.max(1000.0);
                ds.rate_out = ds.rate_out.max(500.0);
                ds.cumulative_in += ds.rate_in as u64;
                ds.cumulative_out += ds.rate_out as u64;
                self.throughput.push(ds.cumulative_in, ds.cumulative_out, 1);
                self.bytes_in = ds.cumulative_in;
                self.bytes_out = ds.cumulative_out;
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
            OvpnMessage::Notification(notification) => {
                self.handle_notification(notification);
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

    fn handle_notification(&mut self, notification: Notification) {
        match notification {
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
                let log_line = format!("State → {name} — {description}");
                self.vpn_state = Some(name);
                self.vpn_state_description = Some(description.clone());
                self.local_ip = (!local_ip.is_empty()).then_some(local_ip);
                self.remote_addr = (!remote_ip.is_empty()).then(|| {
                    remote_port
                        .map(|port| format!("{remote_ip}:{port}"))
                        .unwrap_or(remote_ip)
                });
                self.add_log(LogLevel::Info, &format_timestamp(timestamp), &log_line);
            }
            Notification::ByteCount {
                bytes_in,
                bytes_out,
            } => {
                // Feed the throughput chart before overwriting the totals.
                self.throughput
                    .push(bytes_in, bytes_out, self.startup.bytecount_interval);
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
                    .get("common_name")
                    .cloned()
                    .unwrap_or_else(|| format!("{event}"));
                let address = env
                    .get("untrusted_ip")
                    .or_else(|| env.get("IV_IP"))
                    .cloned()
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
            Notification::Password(password_notification) => match password_notification {
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
            Notification::InfoMsg { extra } => {
                self.add_log(LogLevel::Info, "", &format!("INFOMSG: {extra}"));
            }
            Notification::NeedCertificate { hint } => {
                self.add_log(LogLevel::Warning, "", &format!("Need certificate: {hint}"));
            }
            Notification::Simple { kind, payload } => {
                self.add_log(LogLevel::Info, "", &format!("[{kind}] {payload}"));
            }
        }
    }

    /// Handle startup-option changes. When connected, stream-mode and
    /// bytecount changes are sent immediately so the tab controls
    /// double as live toggles.
    fn handle_startup(&mut self, msg: StartupMsg) -> Result<(), ActorGone> {
        match msg {
            StartupMsg::LogMode(mode) => {
                self.startup.log = mode;
                self.apply_stream_mode("log", mode, OvpnCommand::Log)?;
            }
            StartupMsg::StateMode(mode) => {
                self.startup.state = mode;
                self.apply_stream_mode("state", mode, OvpnCommand::StateStream)?;
            }
            StartupMsg::EchoMode(mode) => {
                self.startup.echo = mode;
                self.apply_stream_mode("echo", mode, OvpnCommand::Echo)?;
            }
            StartupMsg::ByteCountIntervalChanged(value) => {
                if let Ok(seconds) = value.parse::<u32>() {
                    self.startup.bytecount_interval = seconds;
                }
            }
            StartupMsg::ByteCountApply => {
                let seconds = self.startup.bytecount_interval;
                self.send_if_connected(
                    &format!("bytecount {seconds}"),
                    OvpnCommand::ByteCount(seconds),
                )?;
            }
            StartupMsg::ByteCountOff => {
                self.send_if_connected("bytecount 0", OvpnCommand::ByteCount(0))?;
            }
            StartupMsg::HoldReleaseToggled(value) => self.startup.hold_release = value,
            StartupMsg::QueryVersionToggled(value) => self.startup.query_version = value,
        }
        Ok(())
    }

    /// Send a stream-mode change for a given channel when connected.
    fn apply_stream_mode(
        &mut self,
        label: &str,
        mode: StartupStreamMode,
        make_cmd: fn(StreamMode) -> OvpnCommand,
    ) -> Result<(), ActorGone> {
        let stream = mode.to_stream_mode();
        self.send_if_connected(label, make_cmd(stream))
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
            OpsMsg::LoadStats => self.send_and_record("load-stats", OvpnCommand::LoadStats)?,
            OpsMsg::Net => self.send_and_record("net", OvpnCommand::Net)?,

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
                    self.send_and_record(
                        &format!("client-deny {cid} {kid} {reason}"),
                        OvpnCommand::ClientDeny(ClientDeny {
                            cid,
                            kid,
                            reason,
                            client_reason: None,
                        }),
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

        // Help output: lines like "auth-retry t           : ...", "bytecount n : ..."
        if lines
            .iter()
            .any(|line| line.starts_with("help") && line.contains(':'))
        {
            self.help_lines = Some(lines.to_vec());
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

    /// Return the full text of a console entry by reverse index.
    ///
    /// Joins the command line and all response lines into a single string.
    fn console_entry_text(&self, rev_index: usize) -> Option<String> {
        let entry = self.command_history.iter().rev().nth(rev_index)?;
        let mut text = format!("❯ {}", entry.command);
        for line in &entry.response_lines {
            text.push('\n');
            text.push_str(line);
        }
        Some(text)
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
        let sender = self.actor_tx.as_ref().ok_or(ActorGone)?;
        sender.try_send(command).map_err(|_| ActorGone)
    }

    /// Send a command (with console recording) only if currently connected.
    /// Returns `Ok(())` silently when disconnected.
    fn send_if_connected(&mut self, label: &str, command: OvpnCommand) -> Result<(), ActorGone> {
        if self.connection_state == ConnectionState::Connected {
            self.send_and_record(label, command)?;
        }
        Ok(())
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

        // Quick commands first — these return a single Success/MultiLine
        // and won't flood the connection.
        commands.push(OvpnCommand::Pid);
        // One-shot state query so we always know the current state,
        // even if no >STATE: transition fires during connect.
        commands.push(OvpnCommand::State);

        if self.startup.bytecount_interval > 0 {
            commands.push(OvpnCommand::ByteCount(self.startup.bytecount_interval));
        }

        if self.startup.hold_release {
            commands.push(OvpnCommand::HoldRelease);
        }

        // Streaming commands — may produce large history dumps that
        // eat the timeout, so run them after the quick essentials.
        if self.startup.log != StartupStreamMode::Off {
            commands.push(OvpnCommand::Log(self.startup.log.to_stream_mode()));
        }
        if self.startup.state != StartupStreamMode::Off {
            commands.push(OvpnCommand::StateStream(
                self.startup.state.to_stream_mode(),
            ));
        }
        if self.startup.echo != StartupStreamMode::Off {
            commands.push(OvpnCommand::Echo(self.startup.echo.to_stream_mode()));
        }

        // Non-critical queries last — OK if these time out.
        if self.startup.query_version {
            commands.push(OvpnCommand::Version);
        }
        commands.push(OvpnCommand::Help);

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
        self.log_flash_index = None;
        self.clients.clear();
        self.help_lines = None;
        self.ops = OperationsForm::default();
        self.command_history.clear();
        self.awaiting_command_response = false;
        self.selected_console_entry = None;
        self.console_flash_entry = None;
    }

    fn subscription(&self) -> iced::Subscription<Message> {
        let keyboard = iced::event::listen_with(|event, _status, _window| match event {
            iced::Event::Keyboard(iced::keyboard::Event::ModifiersChanged(modifiers)) => {
                Some(Message::ModifiersChanged(modifiers))
            }
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Character(ref ch),
                modifiers,
                ..
            }) if modifiers.control() && ch.as_ref() == "c" => Some(Message::CopySelection),
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Named(iced::keyboard::key::Named::ArrowUp),
                ..
            }) => Some(Message::SelectionUp),
            iced::Event::Keyboard(iced::keyboard::Event::KeyPressed {
                key: iced::keyboard::Key::Named(iced::keyboard::key::Named::ArrowDown),
                ..
            }) => Some(Message::SelectionDown),
            _ => None,
        });

        let mut subs = vec![keyboard];

        if self.connection_state == ConnectionState::Connecting {
            subs.push(
                iced::time::every(std::time::Duration::from_millis(400))
                    .map(|_| Message::ConnectingTick),
            );
        }

        #[cfg(debug_assertions)]
        if self.demo_chart {
            subs.push(
                iced::time::every(std::time::Duration::from_secs(1))
                    .map(|_| Message::DemoChartTick),
            );
        }

        iced::Subscription::batch(subs)
    }
}

use openvpn_mgmt_codec::timestamp::format_local_style as format_timestamp;
