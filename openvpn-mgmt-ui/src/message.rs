//! Top-level message types for the Iced update loop.

use crate::actor::ActorEvent;
use openvpn_mgmt_codec::{OvpnCommand, StreamMode};

// -------------------------------------------------------------------
// Right-panel tabs
// -------------------------------------------------------------------

/// Selectable tabs in the right panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Tab {
    /// Connection state, traffic, throughput, version, PID.
    Dashboard,
    /// Command input, operation buttons, and shell-like output.
    Console,
    /// Real-time OpenVPN log stream.
    Log,
    /// Connected clients (server mode).
    Clients,
    /// Management interface command help.
    Help,
}

// -------------------------------------------------------------------
// Connection state
// -------------------------------------------------------------------

/// Coarse connection lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) enum ConnectionState {
    #[default]
    Disconnected,
    Connecting,
    Connected,
}

// -------------------------------------------------------------------
// Startup options (left panel, above dashboard)
// -------------------------------------------------------------------

/// Which streaming mode to use for a channel on connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum StartupStreamMode {
    Off,
    On,
    #[default]
    OnAll,
}

impl StartupStreamMode {
    /// Map to the protocol's [`StreamMode`].
    pub fn to_stream_mode(self) -> StreamMode {
        match self {
            Self::Off => StreamMode::Off,
            Self::On => StreamMode::On,
            Self::OnAll => StreamMode::OnAll,
        }
    }
}

/// Configurable options applied by the actor immediately after connecting.
#[derive(Debug, Clone)]
pub(crate) struct StartupOptions {
    pub log: StartupStreamMode,
    pub state: StartupStreamMode,
    pub echo: StartupStreamMode,
    pub bytecount_interval: String,
    pub hold_release: bool,
    pub query_version: bool,
}

impl Default for StartupOptions {
    fn default() -> Self {
        Self {
            log: StartupStreamMode::On,
            state: StartupStreamMode::On,
            echo: StartupStreamMode::Off,
            bytecount_interval: "2".to_string(),
            hold_release: true,
            query_version: true,
        }
    }
}

/// Messages for the startup-options section.
#[derive(Debug, Clone)]
pub(crate) enum StartupMsg {
    LogMode(StartupStreamMode),
    StateMode(StartupStreamMode),
    EchoMode(StartupStreamMode),
    ByteCountIntervalChanged(String),
    ByteCountApply,
    ByteCountOff,
    HoldReleaseToggled(bool),
    QueryVersionToggled(bool),
}

// -------------------------------------------------------------------
// Operations tab form state
// -------------------------------------------------------------------

/// Mutable form fields for the Operations tab mini-forms.
#[derive(Debug, Clone, Default)]
pub(crate) struct OperationsForm {
    // Verbosity
    pub verb_input: String,
    pub mute_input: String,

    // Kill
    pub kill_input: String,

    // Client management (server mode)
    pub client_cid: String,
    pub client_kid: String,
    pub client_deny_reason: String,
}

// -------------------------------------------------------------------
// Operations messages
// -------------------------------------------------------------------

/// Messages specific to the Operations tab.
#[derive(Debug, Clone)]
pub(crate) enum OpsMsg {
    // -- Query (one-click) --
    Version,
    Status1,
    Status2,
    Status3,
    Pid,
    Help,
    LoadStats,
    Net,

    // -- Signals --
    SignalHup,
    SignalTerm,
    SignalUsr1,
    SignalUsr2,

    // -- Hold --
    HoldQuery,
    HoldOn,
    HoldOff,
    HoldRelease,

    // -- Verbosity --
    VerbInputChanged(String),
    VerbGet,
    VerbSet,
    VerbReset,
    MuteInputChanged(String),
    MuteGet,
    MuteSet,

    // -- Auth --
    AuthRetryNone,
    AuthRetryInteract,
    AuthRetryNoInteract,
    ForgetPasswords,

    // -- Kill --
    KillInputChanged(String),
    KillSend,

    // -- Client management --
    ClientCidChanged(String),
    ClientKidChanged(String),
    ClientDenyReasonChanged(String),
    ClientAuthNt,
    ClientDeny,
    ClientKill,
}

// -------------------------------------------------------------------
// Message
// -------------------------------------------------------------------

/// Every user interaction and async result funnels through this enum.
#[derive(Debug, Clone)]
pub(crate) enum Message {
    // -- Connection form --
    /// The host text-input changed.
    HostChanged(String),
    /// The port text-input changed.
    PortChanged(String),
    /// The management password text-input changed.
    PasswordChanged(String),
    /// The user pressed Connect.
    Connect,
    /// The user pressed Disconnect.
    Disconnect,
    /// The user pressed Reconnect (disconnect → 500 ms pause → connect).
    Reconnect,
    /// The reconnect delay has elapsed — time to issue a new Connect.
    ReconnectReady {
        host: String,
        port: String,
        startup_commands: Vec<OvpnCommand>,
    },

    // -- Actor --
    /// An event arrived from the connection actor.
    Actor(ActorEvent),

    // -- Tabs --
    /// The user selected a right-panel tab.
    TabSelected(Tab),

    // -- Startup options --
    /// A startup-options field changed.
    Startup(StartupMsg),

    // -- Operations tab --
    /// A message from the Operations tab.
    Ops(OpsMsg),

    // -- Commands page --
    /// The command text-input changed.
    CommandInputChanged(String),
    /// The user pressed Send (or Enter) on the command input.
    SendCommand,
    /// The user picked an auto-complete suggestion (inserts the command name).
    PickSuggestion(&'static str),
    /// Toggle raw-mode (accept any non-empty input as a `Raw` command).
    ToggleRawMode(bool),

    // -- Log tab --
    /// The user clicked a log entry to select it.
    SelectLogEntry(usize),
    /// Copy the selected log entry to the clipboard (Ctrl+C).
    CopyLogEntry,

    // -- Console output --
    /// Click a console output line: copy to clipboard and flash-highlight it.
    CopyConsoleLine(usize),
    /// Timer callback: clear the console flash highlight.
    ClearConsoleFlash,

    // -- Verb reset (disconnect → reconnect with verb 4) --
    /// Disconnect and reconnect with verb 4 to escape a log flood.
    VerbReset,

    // -- Status page --
    /// Request a manual refresh of version / load-stats / state.
    RefreshStatus,

    // -- Keyboard modifiers --
    /// Keyboard modifiers changed (tracks Ctrl-held state).
    ModifiersChanged(iced::keyboard::Modifiers),

    // -- Theme --
    /// The user picked a new theme.
    ThemeSelected(iced::Theme),
}
