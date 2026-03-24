//! All view functions — left panel + tabbed right panel.

use iced::widget::{
    Space, checkbox, column, container, mouse_area, pick_list, radio, row, rule, scrollable, text,
    text_input, tooltip,
};
use iced::{Element, Font, Length, Padding, Theme};
use iced_anim::widget::button::{self, button};
use iced_aw::{TabLabel, Tabs};
use lucide_icons::Icon as LucideIcon;
use lucide_icons::iced as lucide;

use openvpn_mgmt_codec::LogLevel;

use crate::App;
use crate::message::{ConnectionState, Message, OpsMsg, StartupMsg, StartupStreamMode, Tab};
use crate::style::{card, log_row_selected, tab_style, text_label, text_muted, text_warning};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

pub(crate) const LOG_DISPLAY_LIMIT: usize = 200;

/// Stable widget ID for the command text input (used for re-focusing).
pub(crate) static COMMAND_INPUT_ID: std::sync::LazyLock<iced::widget::Id> =
    std::sync::LazyLock::new(iced::widget::Id::unique);

// -------------------------------------------------------------------
// Root view
// -------------------------------------------------------------------

impl App {
    pub(crate) fn view(&self) -> Element<'_, Message> {
        let main_row = row![
            // Left panel — connection + dashboard
            container(
                scrollable(container(self.view_left_panel()).padding(Padding {
                    top: 0.0,
                    right: 16.0,
                    bottom: 16.0,
                    left: 0.0,
                }))
                .height(Length::Fill),
            )
            .width(Length::FillPortion(1))
            .padding(16),
            rule::vertical(1),
            // Right panel — tabs
            container(
                Tabs::new(Message::TabSelected)
                    .push(
                        Tab::Status,
                        TabLabel::IconText(LucideIcon::Activity.unicode(), "Status".into()),
                        self.view_tab_status(),
                    )
                    .push(
                        Tab::Console,
                        TabLabel::IconText(LucideIcon::Terminal.unicode(), "Console".into()),
                        self.view_tab_console(),
                    )
                    .push(
                        Tab::Log,
                        TabLabel::IconText(LucideIcon::ScrollText.unicode(), "Log".into()),
                        self.view_tab_log(),
                    )
                    .push(
                        Tab::Clients,
                        TabLabel::IconText(LucideIcon::Users.unicode(), "Clients".into()),
                        self.view_tab_clients(),
                    )
                    .set_active_tab(&self.active_tab)
                    .tab_bar_position(iced_aw::TabBarPosition::Top)
                    .tab_bar_style(tab_style)
                    .icon_font(Font::with_name("lucide"))
                    .icon_size(12.0)
                    .text_size(13.0)
                    .tab_label_spacing(6.0)
                    .tab_label_padding(Padding::from([6.0, 14.0]))
                    .height(Length::Fill),
            )
            .width(Length::FillPortion(2)),
        ]
        .height(Length::Fill);

        main_row.into()
    }
}

// -------------------------------------------------------------------
// Left panel
// -------------------------------------------------------------------

impl App {
    fn view_left_panel(&self) -> Element<'_, Message> {
        let is_connected = self.connection_state == ConnectionState::Connected;
        let is_connecting = self.connection_state == ConnectionState::Connecting;

        // Connection status indicator
        let status_indicator: Element<'_, Message> = match self.connection_state {
            ConnectionState::Disconnected => {
                text("● Disconnected").style(text_muted).size(12).into()
            }
            ConnectionState::Connecting => {
                text("● Connecting…").style(text_warning).size(12).into()
            }
            ConnectionState::Connected => text("● Connected").style(text::success).size(12).into(),
        };

        // Connect / Disconnect / Reconnect buttons
        let connect_btn: Element<'_, Message> = if is_connected {
            row![
                button(
                    row![lucide::icon_unplug().size(14), text("Disconnect").size(14),]
                        .spacing(6)
                        .align_y(iced::Alignment::Center),
                )
                .on_press(Message::Disconnect)
                .style(button::danger)
                .width(Length::Fill),
                button(
                    row![
                        lucide::icon_refresh_cw().size(14),
                        text("Reconnect").size(14),
                    ]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
                )
                .on_press(Message::Reconnect)
                .style(button::secondary)
                .width(Length::Fill),
            ]
            .spacing(6)
            .into()
        } else {
            let can_connect = !is_connecting && !self.host.is_empty() && !self.port.is_empty();
            button(
                row![lucide::icon_plug().size(14), text("Connect").size(14),]
                    .spacing(6)
                    .align_y(iced::Alignment::Center),
            )
            .on_press_maybe(can_connect.then_some(Message::Connect))
            .width(Length::Fill)
            .into()
        };

        let connect_hint: Element<'_, Message> = if is_connected {
            text(
                "The management port accepts only one client at a time. \
                  Additional connections will be refused.",
            )
            .size(10)
            .style(text_muted)
            .into()
        } else {
            Space::new().height(0).into()
        };

        // Last error
        let error_row: Element<'_, Message> = if let Some(err) = &self.last_error {
            column![
                Space::new().height(4),
                text(err.clone()).size(11).style(text::danger),
            ]
            .into()
        } else {
            Space::new().height(0).into()
        };

        // Quick dashboard (only when connected)
        let dashboard: Element<'_, Message> = if is_connected {
            let state_text = self
                .vpn_state
                .as_ref()
                .map_or("—".to_string(), |state| state.to_string());
            let pid_text = self.pid.map_or("—".to_string(), |pid| pid.to_string());
            let bytes_text = format!(
                "↓ {}  ↑ {}",
                format_bytes(self.bytes_in),
                format_bytes(self.bytes_out),
            );

            column![
                Space::new().height(12),
                section_heading("Dashboard"),
                container(
                    column![
                        key_value_row("State", state_text),
                        key_value_row("PID", pid_text),
                        key_value_row("Traffic", bytes_text),
                    ]
                    .spacing(4),
                )
                .padding(12)
                .width(Length::Fill)
                .class(card()),
                Space::new().height(8),
                with_tooltip(
                    button(
                        row![lucide::icon_refresh_cw().size(12), text("Refresh").size(12),]
                            .spacing(6)
                            .align_y(iced::Alignment::Center),
                    )
                    .on_press(Message::RefreshStatus)
                    .style(button::secondary),
                    "Request fresh version, PID, state, and load-stats from OpenVPN.",
                ),
            ]
            .spacing(6)
            .into()
        } else {
            Space::new().height(0).into()
        };

        // Startup options (editable before connecting)
        let startup = &self.startup;
        let startup_section = column![
            Space::new().height(4),
            section_heading("Startup Options"),
            stream_mode_row("Log", startup.log, |mode| {
                Message::Startup(StartupMsg::LogMode(mode))
            }),
            stream_mode_row("State", startup.state, |mode| {
                Message::Startup(StartupMsg::StateMode(mode))
            }),
            stream_mode_row("Echo", startup.echo, |mode| {
                Message::Startup(StartupMsg::EchoMode(mode))
            }),
            row![
                text("ByteCount").size(11).style(text_label).width(55),
                text_input("sec", &startup.bytecount_interval)
                    .on_input(|value| {
                        Message::Startup(StartupMsg::ByteCountIntervalChanged(value))
                    })
                    .width(50)
                    .size(11),
                text("s").size(11).style(text_muted),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
            checkbox(startup.hold_release)
                .label("Release hold")
                .on_toggle(|toggled| Message::Startup(StartupMsg::HoldReleaseToggled(toggled)))
                .size(14)
                .text_size(11),
            checkbox(startup.query_version)
                .label("Query version")
                .on_toggle(|toggled| Message::Startup(StartupMsg::QueryVersionToggled(toggled)))
                .size(14)
                .text_size(11),
        ]
        .spacing(6);

        // Theme picker (visible while Ctrl is held)
        let theme_picker: Element<'_, Message> = if self.ctrl_held {
            column![
                Space::new().height(4),
                section_heading("Theme"),
                pick_list(Theme::ALL, Some(&self.theme), Message::ThemeSelected)
                    .text_size(11)
                    .width(Length::Fill),
            ]
            .spacing(6)
            .into()
        } else {
            Space::new().height(0).into()
        };

        column![
            status_indicator,
            Space::new().height(12),
            section_heading("Connection"),
            labeled_input("Host", &self.host, Message::HostChanged),
            labeled_input("Port", &self.port, Message::PortChanged),
            column![
                text("Password").size(11).style(text_label),
                text_input("optional", &self.management_password)
                    .on_input(Message::PasswordChanged)
                    .secure(true),
            ]
            .spacing(3)
            .width(Length::Fill),
            Space::new().height(4),
            connect_btn,
            connect_hint,
            error_row,
            startup_section,
            dashboard,
            theme_picker,
        ]
        .spacing(8)
        .width(Length::Fill)
        .into()
    }
}

// -------------------------------------------------------------------
// Tab: Status
// -------------------------------------------------------------------

impl App {
    fn view_tab_status(&self) -> Element<'_, Message> {
        if self.connection_state != ConnectionState::Connected {
            return centered_placeholder("Connect to an OpenVPN management port to see status.");
        }

        let state_text = self
            .vpn_state
            .as_ref()
            .map_or("—".to_string(), |state| state.to_string());
        let state_desc = self.vpn_state_description.as_deref().unwrap_or("—");

        let mut rows: Vec<Element<'_, Message>> = vec![
            section_heading("Connection State"),
            key_value_row("State", state_text),
            key_value_row("Description", state_desc.to_string()),
            key_value_row(
                "Local IP",
                self.local_ip.as_deref().unwrap_or("—").to_string(),
            ),
            key_value_row(
                "Remote",
                self.remote_addr.as_deref().unwrap_or("—").to_string(),
            ),
            Space::new().height(8).into(),
            section_heading("Traffic"),
            key_value_row("Bytes In", format_bytes(self.bytes_in)),
            key_value_row("Bytes Out", format_bytes(self.bytes_out)),
        ];

        if let Some(stats) = &self.load_stats {
            rows.push(Space::new().height(2).into());
            rows.push(key_value_row("Clients", stats.nclients.to_string()));
            rows.push(key_value_row(
                "Server Bytes In",
                format_bytes(stats.bytesin),
            ));
            rows.push(key_value_row(
                "Server Bytes Out",
                format_bytes(stats.bytesout),
            ));
        }

        rows.push(Space::new().height(8).into());
        rows.push(section_heading("Throughput"));
        rows.push(
            row![
                text("↓").size(10).style(text::success),
                text("in").size(10).style(text_muted),
                Space::new().width(12),
                text("↑").size(10).style(text::primary),
                text("out").size(10).style(text_muted),
            ]
            .spacing(4)
            .align_y(iced::Alignment::Center)
            .into(),
        );
        rows.push(crate::chart::throughput_chart_sized(
            &self.throughput,
            200.0,
        ));

        rows.push(Space::new().height(8).into());
        rows.push(section_heading("Version"));

        if let Some(ref lines) = self.version_lines {
            for line in lines {
                rows.push(text(line.clone()).size(12).into());
            }
        } else {
            rows.push(text("—").style(text_muted).into());
        }

        rows.push(Space::new().height(8).into());
        rows.push(section_heading("Process"));
        rows.push(key_value_row(
            "PID",
            self.pid.map_or("—".to_string(), |pid| pid.to_string()),
        ));

        tab_scrollable(column(rows).spacing(3))
    }
}

// -------------------------------------------------------------------
// Tab: Console (merged Operations + Commands)
// -------------------------------------------------------------------

impl App {
    fn view_tab_console(&self) -> Element<'_, Message> {
        let connected = self.connection_state == ConnectionState::Connected;

        // ── Top: command input + autocomplete ───────────────────────────
        let input_row = row![
            text_input(
                "Type a command (e.g. version, status, state on)…",
                &self.command_input
            )
            .id(COMMAND_INPUT_ID.clone())
            .on_input(Message::CommandInputChanged)
            .on_submit(Message::SendCommand)
            .size(13),
            button(
                row![
                    lucide::icon_send_horizontal().size(13),
                    text("Send").size(13),
                ]
                .spacing(4)
                .align_y(iced::Alignment::Center),
            )
            .on_press_maybe(self.command_valid.then_some(Message::SendCommand))
            .style(button::primary),
            checkbox(self.raw_mode)
                .label("Raw")
                .on_toggle(Message::ToggleRawMode)
                .size(14)
                .text_size(12),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center);

        let suggestions = self.view_suggestions();

        // ── Middle: scrollable operations ───────────────────────────────
        let operations = self.view_operations_pane(connected);

        // ── Bottom: shell-like output ──────────────────────────────────
        let output = self.view_output_pane();

        // ── Assemble ────────────────────────────────────────────────────
        column![
            // Input bar (fixed)
            container(column![input_row, suggestions,].spacing(0)).padding(Padding {
                top: 12.0,
                left: 16.0,
                right: 16.0,
                bottom: 4.0,
            }),
            rule::horizontal(1),
            // Operations (scrollable, ~2/3)
            scrollable(container(operations).padding(Padding {
                top: 8.0,
                left: 16.0,
                right: 16.0,
                bottom: 8.0,
            }))
            .height(Length::FillPortion(2)),
            rule::horizontal(1),
            // Output (scrollable, ~1/3)
            container(column![
                container(text("Output").size(11).style(text_label)).padding(Padding {
                    top: 6.0,
                    left: 16.0,
                    right: 16.0,
                    bottom: 2.0,
                }),
                scrollable(container(output).padding(Padding {
                    top: 0.0,
                    left: 16.0,
                    right: 16.0,
                    bottom: 8.0,
                }))
                .height(Length::Fill),
            ])
            .height(Length::FillPortion(1)),
        ]
        .height(Length::Fill)
        .into()
    }

    /// The operations button grid (used inside the console tab).
    fn view_operations_pane(&self, connected: bool) -> Element<'_, Message> {
        let form = &self.ops;
        // -- Query -------------------------------------------------------
        let query_section = column![
            section_heading("Query"),
            row![
                ops_btn("Version", OpsMsg::Version, connected),
                ops_btn("PID", OpsMsg::Pid, connected),
                ops_btn("Help", OpsMsg::Help, connected),
                ops_btn("Load Stats", OpsMsg::LoadStats, connected),
                ops_btn("Net", OpsMsg::Net, connected),
            ]
            .spacing(6),
            row![
                ops_btn("Status V1", OpsMsg::Status1, connected),
                ops_btn("Status V2", OpsMsg::Status2, connected),
                ops_btn("Status V3", OpsMsg::Status3, connected),
            ]
            .spacing(6),
        ]
        .spacing(6);

        // -- Streaming ---------------------------------------------------
        let streaming_section = column![
            section_heading("Streaming"),
            row![
                text("Log").size(12).style(text_label).width(50),
                ops_btn("On", OpsMsg::LogOn, connected),
                ops_btn("Off", OpsMsg::LogOff, connected),
                ops_btn("All", OpsMsg::LogAll, connected),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
            row![
                text("State").size(12).style(text_label).width(50),
                ops_btn("On", OpsMsg::StateOn, connected),
                ops_btn("Off", OpsMsg::StateOff, connected),
                ops_btn("All", OpsMsg::StateAll, connected),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
            row![
                text("Echo").size(12).style(text_label).width(50),
                ops_btn("On", OpsMsg::EchoOn, connected),
                ops_btn("Off", OpsMsg::EchoOff, connected),
                ops_btn("All", OpsMsg::EchoAll, connected),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
            row![
                text("ByteCount").size(12).style(text_label).width(80),
                text_input("seconds", &form.bytecount_input)
                    .on_input(|value| Message::Ops(OpsMsg::ByteCountIntervalChanged(value)))
                    .width(70)
                    .size(12),
                ops_btn("Apply", OpsMsg::ByteCountApply, connected),
                ops_btn("Off", OpsMsg::ByteCountOff, connected),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
        ]
        .spacing(6);

        // -- Signals & Hold ----------------------------------------------
        let signals_hold = row![
            column![
                section_heading("Signals"),
                row![
                    ops_btn("SIGHUP", OpsMsg::SignalHup, connected),
                    ops_btn("SIGUSR1", OpsMsg::SignalUsr1, connected),
                    ops_btn("SIGUSR2", OpsMsg::SignalUsr2, connected),
                    ops_btn_danger("SIGTERM", OpsMsg::SignalTerm, connected),
                ]
                .spacing(6),
            ]
            .spacing(6)
            .width(Length::FillPortion(1)),
            column![
                section_heading("Hold"),
                row![
                    ops_btn("Query", OpsMsg::HoldQuery, connected),
                    ops_btn("On", OpsMsg::HoldOn, connected),
                    ops_btn("Off", OpsMsg::HoldOff, connected),
                    ops_btn("Release", OpsMsg::HoldRelease, connected),
                ]
                .spacing(6),
            ]
            .spacing(6)
            .width(Length::FillPortion(1)),
        ]
        .spacing(16);

        // -- Verbosity ---------------------------------------------------
        let verbosity_section = column![
            section_heading("Verbosity"),
            row![
                text("Verb").size(12).style(text_label).width(50),
                text_input("0–15", &form.verb_input)
                    .on_input(|value| Message::Ops(OpsMsg::VerbInputChanged(value)))
                    .width(60)
                    .size(12),
                ops_btn("Get", OpsMsg::VerbGet, connected),
                ops_btn("Set", OpsMsg::VerbSet, connected),
                ops_btn_danger("Reset", OpsMsg::VerbReset, connected),
                Space::new().width(16),
                text("Mute").size(12).style(text_label),
                text_input("threshold", &form.mute_input)
                    .on_input(|value| Message::Ops(OpsMsg::MuteInputChanged(value)))
                    .width(60)
                    .size(12),
                ops_btn("Get", OpsMsg::MuteGet, connected),
                ops_btn("Set", OpsMsg::MuteSet, connected),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
        ]
        .spacing(6);

        // -- Auth --------------------------------------------------------
        let auth_section = column![
            section_heading("Authentication"),
            row![
                text("auth-retry").size(12).style(text_label),
                ops_btn("none", OpsMsg::AuthRetryNone, connected),
                ops_btn("interact", OpsMsg::AuthRetryInteract, connected),
                ops_btn("nointeract", OpsMsg::AuthRetryNoInteract, connected),
                Space::new().width(12),
                ops_btn("Forget Passwords", OpsMsg::ForgetPasswords, connected),
            ]
            .spacing(6)
            .align_y(iced::Alignment::Center),
        ]
        .spacing(6);

        // -- Kill + Client Management (side by side) ---------------------
        let kill_client = row![
            column![
                section_heading("Kill Client"),
                row![
                    text_input("Common Name", &form.kill_input)
                        .on_input(|value| Message::Ops(OpsMsg::KillInputChanged(value)))
                        .size(12),
                    ops_btn("Kill", OpsMsg::KillSend, connected),
                ]
                .spacing(6)
                .align_y(iced::Alignment::Center),
            ]
            .spacing(6)
            .width(Length::FillPortion(1)),
            column![
                section_heading("Client Mgmt (Server)"),
                row![
                    text_input("CID", &form.client_cid)
                        .on_input(|value| Message::Ops(OpsMsg::ClientCidChanged(value)))
                        .width(60)
                        .size(12),
                    text_input("KID", &form.client_kid)
                        .on_input(|value| Message::Ops(OpsMsg::ClientKidChanged(value)))
                        .width(60)
                        .size(12),
                    text_input("deny reason", &form.client_deny_reason)
                        .on_input(|value| Message::Ops(OpsMsg::ClientDenyReasonChanged(value)))
                        .size(12),
                ]
                .spacing(4)
                .align_y(iced::Alignment::Center),
                row![
                    ops_btn("Authorize", OpsMsg::ClientAuthNt, connected),
                    ops_btn_danger("Deny", OpsMsg::ClientDeny, connected),
                    ops_btn_danger("Kill", OpsMsg::ClientKill, connected),
                ]
                .spacing(6),
            ]
            .spacing(6)
            .width(Length::FillPortion(2)),
        ]
        .spacing(16);

        column![
            query_section,
            Space::new().height(6),
            streaming_section,
            Space::new().height(6),
            signals_hold,
            Space::new().height(6),
            verbosity_section,
            Space::new().height(6),
            auth_section,
            Space::new().height(6),
            kill_client,
        ]
        .spacing(4)
        .width(Length::Fill)
        .into()
    }

    /// Shell-like output pane showing command history with responses.
    fn view_output_pane(&self) -> Element<'_, Message> {
        if self.command_history.is_empty() {
            return text("Responses will appear here.")
                .style(text_muted)
                .size(11)
                .into();
        }

        let lines: Vec<Element<'_, Message>> = self
            .command_history
            .iter()
            .rev()
            .flat_map(|entry| {
                let mut rows: Vec<Element<'_, Message>> = Vec::new();
                rows.push(
                    text(format!("❯ {}", entry.command))
                        .size(11)
                        .style(text::primary)
                        .into(),
                );
                for line in &entry.response_lines {
                    rows.push(text(format!("  {line}")).size(11).into());
                }
                rows
            })
            .collect();

        column(lines).spacing(1).width(Length::Fill).into()
    }

    /// Build the auto-complete suggestion list based on the current input.
    fn view_suggestions(&self) -> Element<'_, Message> {
        // Only show suggestions when there is typed text and no arguments yet
        // (i.e. the user is still typing the command name).
        let trimmed = self.command_input.trim();
        if trimmed.is_empty() {
            return Space::new().height(0).into();
        }

        // Extract the first word (the command being typed).
        let first_word = trimmed.split_whitespace().next().unwrap_or("");
        let has_args = trimmed.contains(char::is_whitespace);

        // If the user already typed a space (entering args), only show
        // a single hint for the exact command match, if any.
        let matches = if has_args {
            crate::completions::fuzzy_match(first_word)
                .into_iter()
                .filter(|e| e.name == first_word)
                .collect::<Vec<_>>()
        } else {
            let mut m = crate::completions::fuzzy_match(first_word);
            m.truncate(10);
            m
        };

        if matches.is_empty() {
            return Space::new().height(0).into();
        }

        // If the only match is the exact command and user is typing args,
        // show just the args hint.
        if has_args && let Some(entry) = matches.first() {
            if entry.args.is_empty() {
                return Space::new().height(0).into();
            }
            return container(
                text(format!("{} {}", entry.name, entry.args))
                    .size(11)
                    .style(text_muted),
            )
            .padding(Padding {
                top: 4.0,
                bottom: 8.0,
                left: 4.0,
                ..Padding::ZERO
            })
            .into();
        }

        let suggestion_rows: Vec<Element<'_, Message>> = matches
            .iter()
            .map(|entry| {
                let args_el: Element<'_, Message> = if entry.args.is_empty() {
                    Space::new().width(0).into()
                } else {
                    text(entry.args).size(11).style(text_muted).into()
                };

                button(
                    row![
                        text(entry.name).size(12).style(text::primary),
                        Space::new().width(8),
                        args_el,
                    ]
                    .align_y(iced::Alignment::Center),
                )
                .on_press(Message::PickSuggestion(entry.name))
                .style(button::text)
                .padding([2, 6])
                .width(Length::Fill)
                .into()
            })
            .collect();

        container(column(suggestion_rows).spacing(0).width(Length::Fill))
            .padding(Padding {
                top: 4.0,
                bottom: 4.0,
                ..Padding::ZERO
            })
            .width(Length::Fill)
            .class(card())
            .into()
    }
}

/// Small secondary button — disabled (grayed out) when `enabled` is false.
fn ops_btn(label: &str, msg: OpsMsg, enabled: bool) -> Element<'_, Message> {
    button(text(label.to_string()).size(12))
        .on_press_maybe(enabled.then_some(Message::Ops(msg)))
        .style(button::secondary)
        .into()
}

/// Small danger-styled button — disabled (grayed out) when `enabled` is false.
fn ops_btn_danger(label: &str, msg: OpsMsg, enabled: bool) -> Element<'_, Message> {
    button(text(label.to_string()).size(12))
        .on_press_maybe(enabled.then_some(Message::Ops(msg)))
        .style(button::danger)
        .into()
}

// -------------------------------------------------------------------
// Tab: Log
// -------------------------------------------------------------------

impl App {
    fn view_tab_log(&self) -> Element<'_, Message> {
        if self.log_entries.is_empty() {
            return centered_placeholder("No log entries yet. Connect and enable log streaming.");
        }

        let log_lines: Vec<Element<'_, Message>> = self
            .log_entries
            .iter()
            .enumerate()
            .rev()
            .take(LOG_DISPLAY_LIMIT)
            .map(|(idx, entry)| {
                let level_label = entry.level.label();
                let level_style: fn(&Theme) -> text::Style = match &entry.level {
                    LogLevel::Fatal | LogLevel::NonFatal => text::danger,
                    LogLevel::Warning => text_warning,
                    LogLevel::Debug => text_muted,
                    _ => text_label,
                };
                let is_selected = self.selected_log_index == Some(idx);
                let log_row = row![
                    container(text(format!("[{level_label}]")).size(11).style(level_style))
                        .width(56),
                    container(text(&entry.timestamp).size(11).style(text_muted)).width(80),
                    text(&entry.message).size(11),
                ]
                .spacing(4);
                let styled_row: Element<'_, Message> = if is_selected {
                    container(log_row)
                        .padding(Padding::from([1, 4]))
                        .style(log_row_selected())
                        .width(Length::Fill)
                        .into()
                } else {
                    container(log_row)
                        .padding(Padding::from([1, 4]))
                        .width(Length::Fill)
                        .into()
                };
                mouse_area(styled_row)
                    .on_press(Message::SelectLogEntry(idx))
                    .into()
            })
            .collect();

        tab_scrollable(column(log_lines).spacing(2).width(Length::Fill))
    }
}

// -------------------------------------------------------------------
// Tab: Clients
// -------------------------------------------------------------------

impl App {
    fn view_tab_clients(&self) -> Element<'_, Message> {
        if self.connection_state != ConnectionState::Connected {
            return centered_placeholder("Connect to view clients.");
        }

        if self.clients.is_empty() {
            return centered_placeholder(
                "No clients connected. Client events appear in server mode \
                 (--management-client-auth).",
            );
        }

        let header = row![
            container(text("CID").size(11).style(text_label)).width(60),
            container(text("CN / Event").size(11).style(text_label)).width(Length::Fill),
            container(text("Address").size(11).style(text_label)).width(160),
        ]
        .spacing(8);

        let mut rows: Vec<Element<'_, Message>> = vec![header.into(), rule::horizontal(1).into()];

        for client in &self.clients {
            rows.push(
                row![
                    container(text(client.cid.to_string()).size(12)).width(60),
                    container(text(&client.common_name).size(12)).width(Length::Fill),
                    container(text(&client.address).size(12)).width(160),
                ]
                .spacing(8)
                .into(),
            );
        }

        tab_scrollable(column(rows).spacing(4).width(Length::Fill))
    }
}

// -------------------------------------------------------------------
// Shared helpers
// -------------------------------------------------------------------

pub(crate) fn section_heading<M: 'static>(title: &str) -> Element<'static, M> {
    column![
        text(title.to_string()).size(13).style(text::primary),
        rule::horizontal(1),
    ]
    .spacing(4)
    .into()
}

fn labeled_input<'a>(
    label: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    column![
        text(label).size(11).style(text_label),
        text_input(label, value).on_input(on_input),
    ]
    .spacing(3)
    .width(Length::Fill)
    .into()
}

fn key_value_row<M: 'static>(key: &str, value: impl Into<String>) -> Element<'static, M> {
    row![
        container(text(format!("{key}:")).size(13).style(text_label)).width(Length::FillPortion(5)),
        container(text(value.into()).size(13)).width(Length::FillPortion(6)),
    ]
    .spacing(4)
    .into()
}

#[expect(dead_code, reason = "reserved for field-level tooltips")]
fn help_icon<'a, M: 'static>(help_text: &'static str) -> Element<'a, M> {
    tooltip(
        container(text("?").size(10).style(text_muted)).padding([1, 4]),
        container(text(help_text).size(11))
            .max_width(280)
            .padding([6, 10])
            .style(|theme: &iced::Theme| container::Style {
                background: Some(theme.extended_palette().background.weak.color.into()),
                border: iced::Border {
                    radius: 4.0.into(),
                    width: 1.0,
                    color: theme.extended_palette().background.strong.color,
                },
                ..Default::default()
            }),
        tooltip::Position::FollowCursor,
    )
    .into()
}

fn with_tooltip<'a, M: 'static>(
    content: impl Into<Element<'a, M>>,
    help_text: &'static str,
) -> Element<'a, M> {
    tooltip(
        content,
        container(text(help_text).size(11))
            .max_width(280)
            .padding([6, 10])
            .style(|theme: &iced::Theme| container::Style {
                background: Some(theme.extended_palette().background.weak.color.into()),
                border: iced::Border {
                    radius: 4.0.into(),
                    width: 1.0,
                    color: theme.extended_palette().background.strong.color,
                },
                ..Default::default()
            }),
        tooltip::Position::Top,
    )
    .into()
}

/// A row of three radio buttons for Off / On / On+All stream mode.
fn stream_mode_row(
    label: &str,
    current: StartupStreamMode,
    on_select: fn(StartupStreamMode) -> Message,
) -> Element<'_, Message> {
    row![
        text(label).size(11).style(text_label).width(55),
        radio("Off", StartupStreamMode::Off, Some(current), on_select)
            .size(14)
            .text_size(11),
        radio("On", StartupStreamMode::On, Some(current), on_select)
            .size(14)
            .text_size(11),
        radio("On+All", StartupStreamMode::OnAll, Some(current), on_select)
            .size(14)
            .text_size(11),
    ]
    .spacing(6)
    .align_y(iced::Alignment::Center)
    .into()
}

fn centered_placeholder(msg: &str) -> Element<'_, Message> {
    container(text(msg.to_string()).style(text_muted))
        .padding(Padding {
            top: 24.0,
            ..Padding::new(8.0)
        })
        .into()
}

fn tab_scrollable<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    scrollable(container(content).padding(Padding {
        top: 24.0,
        left: 16.0,
        right: 16.0,
        bottom: 8.0,
    }))
    .height(Length::Fill)
    .into()
}

/// Format a byte count in a human-friendly way.
fn format_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;

    if n >= GIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes_plain() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1023), "1023 B");
    }

    #[test]
    fn format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1536), "1.5 KiB");
    }

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(5 * 1024 * 1024), "5.0 MiB");
    }

    #[test]
    fn format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(3 * 1024 * 1024 * 1024), "3.0 GiB");
    }
}
