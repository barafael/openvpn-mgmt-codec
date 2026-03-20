//! Interactive CLI for the OpenVPN management interface.
//!
//! Connects to a running OpenVPN management socket and lets you send
//! typed commands while printing decoded messages in real time.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p openvpn-mgmt-cli -- 127.0.0.1:7505
//! cargo run -p openvpn-mgmt-cli -- /var/run/openvpn.sock   # Unix socket
//! ```
//!
//! Once connected, type a command name at the `ovpn>` prompt (e.g. `version`,
//! `status`, `state on`). Type `help` to list commands, `quit` to disconnect.

use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::{
    AuthRetryMode, AuthType, KillTarget, NeedOkResponse, Notification, OvpnCodec, OvpnCommand,
    OvpnMessage, PasswordNotification, ProxyAction, RemoteAction, Signal, StatusFormat, StreamMode,
};
use std::env;
use std::io::Write as _;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::UnixStream;

const USAGE: &str = "\
openvpn-mgmt-cli — interactive OpenVPN management interface client

USAGE:
    openvpn-mgmt-cli [ADDRESS]

ADDRESS defaults to 127.0.0.1:7505.
On Unix, a path to a Unix domain socket is also accepted.

COMMANDS (at the ovpn> prompt):
    version                        Show OpenVPN and management interface version
    status [1|2|3]                 Dump connection status (format V1/V2/V3)
    state [on|off|all|on all|N]    Query or stream state changes
    log   [on|off|all|on all|N]    Query or stream log messages
    echo  [on|off|all|on all|N]    Query or stream echo parameters
    pid                            Show OpenVPN PID
    help                           List management commands
    net                            (Windows) Show adapter/route info
    load-stats                     Aggregated server statistics
    verb [N]                       Get/set log verbosity (0-15)
    mute [N]                       Get/set mute threshold
    bytecount N                    Enable byte-count notifications (0 to disable)
    signal SIGHUP|SIGTERM|...      Send signal to daemon
    kill <cn|ip:port>              Kill client by common name or address
    hold [on|off|release]          Query/set hold state
    username <type> <value>        Supply username
    password <type> <value>        Supply password
    auth-retry none|interact|...   Set auth-retry strategy
    forget-passwords               Forget cached passwords
    needok <name> ok|cancel        Respond to NEED-OK prompt
    needstr <name> <value>         Respond to NEED-STR prompt
    pkcs11-id-count                Query PKCS#11 cert count
    pkcs11-id-get N                Get PKCS#11 cert by index
    client-auth <cid> <kid> [lines]  Authorize client (lines comma-separated)
    client-auth-nt <cid> <kid>     Authorize client (no config push)
    client-deny <cid> <kid> <reason> [client-reason]  Deny client
    client-kill <cid>              Kill client by CID
    remote accept|skip|mod <h> <p> Respond to REMOTE prompt
    proxy none|http|socks ...      Respond to PROXY prompt
    raw-ml <command>               Send raw command, expect multi-line response
    exit / quit                    Disconnect
    <anything else>                Sent as raw command";

/// Parse a user-typed line into an `OvpnCommand`.
fn parse_input(line: &str) -> Result<OvpnCommand, String> {
    let line = line.trim();
    let (cmd, args) = line
        .split_once(char::is_whitespace)
        .map(|(c, a)| (c, a.trim()))
        .unwrap_or((line, ""));

    match cmd {
        // ── Informational ────────────────────────────────────────
        "version" => Ok(OvpnCommand::Version),
        "pid" => Ok(OvpnCommand::Pid),
        "help" => Ok(OvpnCommand::Help),
        "net" => Ok(OvpnCommand::Net),
        "load-stats" => Ok(OvpnCommand::LoadStats),

        "status" => match args {
            "" | "1" => Ok(OvpnCommand::Status(StatusFormat::V1)),
            "2" => Ok(OvpnCommand::Status(StatusFormat::V2)),
            "3" => Ok(OvpnCommand::Status(StatusFormat::V3)),
            _ => Err(format!("invalid status format: {args} (use 1, 2, or 3)")),
        },

        "state" => match args {
            "" => Ok(OvpnCommand::State),
            other => parse_stream_mode(other).map(OvpnCommand::StateStream),
        },

        "log" => parse_stream_mode(args).map(OvpnCommand::Log),
        "echo" => parse_stream_mode(args).map(OvpnCommand::Echo),

        "verb" => {
            if args.is_empty() {
                Ok(OvpnCommand::Verb(None))
            } else {
                args.parse::<u8>()
                    .map(|n| OvpnCommand::Verb(Some(n)))
                    .map_err(|_| format!("invalid verbosity: {args} (0-15)"))
            }
        }

        "mute" => {
            if args.is_empty() {
                Ok(OvpnCommand::Mute(None))
            } else {
                args.parse::<u32>()
                    .map(|n| OvpnCommand::Mute(Some(n)))
                    .map_err(|_| format!("invalid mute value: {args}"))
            }
        }

        "bytecount" => args
            .parse::<u32>()
            .map(OvpnCommand::ByteCount)
            .map_err(|_| format!("bytecount requires a number, got: {args}")),

        // ── Connection control ───────────────────────────────────
        "signal" => match args {
            "SIGHUP" => Ok(OvpnCommand::Signal(Signal::SigHup)),
            "SIGTERM" => Ok(OvpnCommand::Signal(Signal::SigTerm)),
            "SIGUSR1" => Ok(OvpnCommand::Signal(Signal::SigUsr1)),
            "SIGUSR2" => Ok(OvpnCommand::Signal(Signal::SigUsr2)),
            _ => Err(format!(
                "unknown signal: {args} (use SIGHUP/SIGTERM/SIGUSR1/SIGUSR2)"
            )),
        },

        "kill" => {
            if args.is_empty() {
                return Err("kill requires a target (common name or ip:port)".into());
            }
            if let Some((ip, port_str)) = args.rsplit_once(':')
                && let Ok(port) = port_str.parse::<u16>()
            {
                return Ok(OvpnCommand::Kill(KillTarget::Address {
                    ip: ip.to_string(),
                    port,
                }));
            }
            Ok(OvpnCommand::Kill(KillTarget::CommonName(args.to_string())))
        }

        "hold" => match args {
            "" => Ok(OvpnCommand::HoldQuery),
            "on" => Ok(OvpnCommand::HoldOn),
            "off" => Ok(OvpnCommand::HoldOff),
            "release" => Ok(OvpnCommand::HoldRelease),
            _ => Err(format!("invalid hold argument: {args}")),
        },

        // ── Authentication ───────────────────────────────────────
        "username" => {
            let (auth_type, value) = args
                .split_once(char::is_whitespace)
                .ok_or("usage: username <auth-type> <value>")?;
            Ok(OvpnCommand::Username {
                auth_type: parse_auth_type(auth_type),
                value: value.trim().to_string(),
            })
        }

        "password" => {
            let (auth_type, value) = args
                .split_once(char::is_whitespace)
                .ok_or("usage: password <auth-type> <value>")?;
            Ok(OvpnCommand::Password {
                auth_type: parse_auth_type(auth_type),
                value: value.trim().to_string(),
            })
        }

        "auth-retry" => match args {
            "none" => Ok(OvpnCommand::AuthRetry(AuthRetryMode::None)),
            "interact" => Ok(OvpnCommand::AuthRetry(AuthRetryMode::Interact)),
            "nointeract" => Ok(OvpnCommand::AuthRetry(AuthRetryMode::NoInteract)),
            _ => Err(format!(
                "invalid auth-retry mode: {args} (use none/interact/nointeract)"
            )),
        },

        "forget-passwords" => Ok(OvpnCommand::ForgetPasswords),

        // ── Interactive prompts ──────────────────────────────────
        "needok" => {
            let (name, resp) = args
                .rsplit_once(char::is_whitespace)
                .ok_or("usage: needok <name> ok|cancel")?;
            let response = match resp {
                "ok" => NeedOkResponse::Ok,
                "cancel" => NeedOkResponse::Cancel,
                _ => return Err(format!("invalid needok response: {resp} (use ok/cancel)")),
            };
            Ok(OvpnCommand::NeedOk {
                name: name.trim().to_string(),
                response,
            })
        }

        "needstr" => {
            let (name, value) = args
                .split_once(char::is_whitespace)
                .ok_or("usage: needstr <name> <value>")?;
            Ok(OvpnCommand::NeedStr {
                name: name.to_string(),
                value: value.trim().to_string(),
            })
        }

        // ── PKCS#11 ─────────────────────────────────────────────
        "pkcs11-id-count" => Ok(OvpnCommand::Pkcs11IdCount),

        "pkcs11-id-get" => args
            .parse::<u32>()
            .map(OvpnCommand::Pkcs11IdGet)
            .map_err(|_| format!("pkcs11-id-get requires a number, got: {args}")),

        // ── Client management (server mode) ─────────────────────
        "client-auth" => {
            let mut parts = args.splitn(3, char::is_whitespace);
            let cid = parts
                .next()
                .ok_or("usage: client-auth <cid> <kid> [config-lines]")?
                .parse::<u64>()
                .map_err(|_| "cid must be a number")?;
            let kid = parts
                .next()
                .ok_or("usage: client-auth <cid> <kid> [config-lines]")?
                .parse::<u64>()
                .map_err(|_| "kid must be a number")?;
            let config_lines = match parts.next() {
                Some(rest) => rest.split(',').map(|s| s.trim().to_string()).collect(),
                None => vec![],
            };
            Ok(OvpnCommand::ClientAuth {
                cid,
                kid,
                config_lines,
            })
        }

        "client-auth-nt" => {
            let (cid_s, kid_s) = args
                .split_once(char::is_whitespace)
                .ok_or("usage: client-auth-nt <cid> <kid>")?;
            Ok(OvpnCommand::ClientAuthNt {
                cid: cid_s.parse().map_err(|_| "cid must be a number")?,
                kid: kid_s.trim().parse().map_err(|_| "kid must be a number")?,
            })
        }

        "client-deny" => {
            let mut parts = args.splitn(4, char::is_whitespace);
            let cid = parts
                .next()
                .ok_or("usage: client-deny <cid> <kid> <reason> [client-reason]")?
                .parse::<u64>()
                .map_err(|_| "cid must be a number")?;
            let kid = parts
                .next()
                .ok_or("usage: client-deny <cid> <kid> <reason> [client-reason]")?
                .parse::<u64>()
                .map_err(|_| "kid must be a number")?;
            let reason = parts
                .next()
                .ok_or("usage: client-deny <cid> <kid> <reason> [client-reason]")?
                .to_string();
            let client_reason = parts.next().map(ToOwned::to_owned);
            Ok(OvpnCommand::ClientDeny {
                cid,
                kid,
                reason,
                client_reason,
            })
        }

        "client-kill" => {
            let cid = args
                .parse::<u64>()
                .map_err(|_| format!("client-kill requires a CID number, got: {args}"))?;
            Ok(OvpnCommand::ClientKill { cid })
        }

        // ── Remote/Proxy override ────────────────────────────────
        "remote" => match args.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["accept" | "ACCEPT"] => Ok(OvpnCommand::Remote(RemoteAction::Accept)),
            ["skip" | "SKIP"] => Ok(OvpnCommand::Remote(RemoteAction::Skip)),
            ["mod" | "MOD", host, port] => Ok(OvpnCommand::Remote(RemoteAction::Modify {
                host: host.to_string(),
                port: port.parse().map_err(|_| "port must be a number")?,
            })),
            _ => Err("usage: remote accept|skip|mod <host> <port>".into()),
        },

        "proxy" => match args.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["none" | "NONE"] => Ok(OvpnCommand::Proxy(ProxyAction::None)),
            ["http" | "HTTP", host, port] => Ok(OvpnCommand::Proxy(ProxyAction::Http {
                host: host.to_string(),
                port: port.parse().map_err(|_| "port must be a number")?,
                non_cleartext_only: false,
            })),
            ["http" | "HTTP", host, port, "nct"] => Ok(OvpnCommand::Proxy(ProxyAction::Http {
                host: host.to_string(),
                port: port.parse().map_err(|_| "port must be a number")?,
                non_cleartext_only: true,
            })),
            ["socks" | "SOCKS", host, port] => Ok(OvpnCommand::Proxy(ProxyAction::Socks {
                host: host.to_string(),
                port: port.parse().map_err(|_| "port must be a number")?,
            })),
            _ => Err("usage: proxy none|http <host> <port> [nct]|socks <host> <port>".into()),
        },

        // ── Raw multi-line ──────────────────────────────────────
        "raw-ml" => {
            if args.is_empty() {
                return Err("usage: raw-ml <command>".into());
            }
            Ok(OvpnCommand::RawMultiLine(args.to_string()))
        }

        // ── Lifecycle ────────────────────────────────────────────
        "exit" => Ok(OvpnCommand::Exit),
        "quit" => Ok(OvpnCommand::Quit),

        // ── Fallback: send as raw command ────────────────────────
        _ => Ok(OvpnCommand::Raw(line.to_string())),
    }
}

fn parse_stream_mode(args: &str) -> Result<StreamMode, String> {
    match args {
        "on" => Ok(StreamMode::On),
        "off" => Ok(StreamMode::Off),
        "all" => Ok(StreamMode::All),
        "on all" => Ok(StreamMode::OnAll),
        n => n
            .parse::<u32>()
            .map(StreamMode::Recent)
            .map_err(|_| format!("invalid stream mode: {args} (use on/off/all/on all/N)")),
    }
}

fn parse_auth_type(s: &str) -> AuthType {
    match s {
        "Auth" => AuthType::Auth,
        "PrivateKey" | "Private Key" => AuthType::PrivateKey,
        "HTTPProxy" | "HTTP Proxy" => AuthType::HttpProxy,
        "SOCKSProxy" | "SOCKS Proxy" => AuthType::SocksProxy,
        other => AuthType::Custom(other.to_string()),
    }
}

/// Format a Unix timestamp as a local datetime string.
fn format_timestamp(ts: u64) -> String {
    // Manual conversion: ts is seconds since Unix epoch.
    // We format as UTC since we don't have a timezone library.
    let secs = ts % 60;
    let mins_total = ts / 60;
    let mins = mins_total % 60;
    let hours_total = mins_total / 60;
    let hours = hours_total % 24;
    let days_total = hours_total / 24;

    // Days since epoch to Y-M-D (simplified Gregorian).
    let (year, month, day) = days_to_ymd(days_total);
    format!("{year:04}-{month:02}-{day:02}T{hours:02}:{mins:02}:{secs:02}Z")
}

fn days_to_ymd(mut days: u64) -> (u64, u64, u64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
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

/// Pretty-print a decoded message.
fn print_message(msg: &OvpnMessage) {
    match msg {
        OvpnMessage::Success(text) => println!("SUCCESS: {text}"),
        OvpnMessage::Error(text) => eprintln!("ERROR: {text}"),
        OvpnMessage::MultiLine(lines) => {
            for line in lines {
                println!("  {line}");
            }
        }
        OvpnMessage::SingleValue(val) => println!("{val}"),
        OvpnMessage::Info(info) => println!("[INFO] {info}"),
        OvpnMessage::PasswordPrompt => {
            println!("[MGMT] Management password required (type the password and press enter)");
        }
        OvpnMessage::Notification(notif) => print_notification(notif),
        OvpnMessage::Pkcs11IdEntry { index, id, blob } => {
            println!("[PKCS11] index={index} id={id} blob={blob}");
        }
        OvpnMessage::Unrecognized { line, kind } => {
            eprintln!("[UNRECOGNIZED ({kind:?})] {line}");
        }
    }
}

fn print_notification(notif: &Notification) {
    match notif {
        Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            ..
        } => {
            let ts = format_timestamp(*timestamp);
            println!("[STATE] {name} — {description} (local={local_ip}, remote={remote_ip}, {ts})");
        }
        Notification::ByteCount {
            bytes_in,
            bytes_out,
        } => {
            println!("[BYTECOUNT] in={bytes_in} out={bytes_out}");
        }
        Notification::ByteCountCli {
            cid,
            bytes_in,
            bytes_out,
        } => {
            println!("[BYTECOUNT_CLI] cid={cid} in={bytes_in} out={bytes_out}");
        }
        Notification::Log {
            timestamp,
            level,
            message,
        } => {
            let ts = format_timestamp(*timestamp);
            println!("[LOG {level}] {message} ({ts})");
        }
        Notification::Echo { timestamp, param } => {
            let ts = format_timestamp(*timestamp);
            println!("[ECHO] {param} ({ts})");
        }
        Notification::Hold { text } => {
            println!("[HOLD] {text}");
        }
        Notification::Fatal { message } => {
            eprintln!("[FATAL] {message}");
        }
        Notification::Client {
            event,
            cid,
            kid,
            env,
        } => {
            match kid {
                Some(k) => println!("[CLIENT:{event}] cid={cid} kid={k}"),
                None => println!("[CLIENT:{event}] cid={cid}"),
            }
            for (k, v) in env {
                println!("  {k}={v}");
            }
        }
        Notification::ClientAddress { cid, addr, primary } => {
            println!("[CLIENT:ADDRESS] cid={cid} addr={addr} primary={primary}");
        }
        Notification::Password(pw) => match pw {
            PasswordNotification::NeedAuth { auth_type } => {
                println!("[PASSWORD] Need '{auth_type}' username/password");
            }
            PasswordNotification::NeedPassword { auth_type } => {
                println!("[PASSWORD] Need '{auth_type}' password");
            }
            PasswordNotification::VerificationFailed { auth_type } => {
                eprintln!("[PASSWORD] Verification failed: '{auth_type}'");
            }
            PasswordNotification::StaticChallenge { echo, challenge } => {
                println!("[PASSWORD] Static challenge (echo={echo}): {challenge}");
            }
            PasswordNotification::DynamicChallenge {
                challenge,
                state_id,
                ..
            } => {
                println!("[PASSWORD] Dynamic challenge (state={state_id}): {challenge}");
            }
        },
        Notification::NeedOk { name, message } => {
            println!("[NEED-OK] '{name}': {message}");
        }
        Notification::NeedStr { name, message } => {
            println!("[NEED-STR] '{name}': {message}");
        }
        Notification::Remote {
            host,
            port,
            protocol,
        } => {
            println!("[REMOTE] {host}:{port} ({protocol})");
        }
        Notification::Proxy {
            proto_type,
            host,
            port,
            ..
        } => {
            println!("[PROXY] {proto_type} {host}:{port}");
        }
        Notification::RsaSign { data } => {
            println!("[RSA_SIGN] {data}");
        }
        Notification::Pkcs11IdCount { count } => {
            println!("[PKCS11ID-COUNT] {count}");
        }
        Notification::Simple { kind, payload } => {
            println!("[{kind}] {payload}");
        }
    }
}

/// Run the event loop over a generic `Framed` transport.
///
/// Multiplexes stdin and the management socket in a single `select!` loop —
/// no spawned tasks, no channels, no `Send` bounds.
async fn run<T>(framed: Framed<T, OvpnCodec>) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut sink, mut stream) = framed.split();
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();
    let mut connected = true;

    loop {
        // Only show the prompt when we're ready for input and still connected.
        if connected {
            eprint!("ovpn> ");
            std::io::stderr().flush()?;
        }

        tokio::select! {
            // Incoming message from the management socket.
            msg = stream.next(), if connected => {
                match msg {
                    Some(Ok(msg)) => print_message(&msg),
                    Some(Err(e)) => {
                        eprintln!("[CONN ERROR] {e}");
                        connected = false;
                    }
                    None => {
                        println!("[DISCONNECTED]");
                        break;
                    }
                }
            }
            // User input from stdin.
            result = lines.next_line() => {
                let Some(line) = result? else {
                    break // EOF
                };
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                if !connected {
                    eprintln!("not connected");
                    break;
                }
                match parse_input(&line) {
                    Ok(cmd) => {
                        let is_exit = matches!(cmd, OvpnCommand::Exit | OvpnCommand::Quit);
                        if let Err(e) = sink.send(cmd).await {
                            eprintln!("[SEND ERROR] {e}");
                            break;
                        }
                        if is_exit {
                            break;
                        }
                    }
                    Err(e) => eprintln!("parse error: {e}"),
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = match env::args().nth(1) {
        Some(a) if a == "--help" || a == "-h" => {
            println!("{USAGE}");
            return Ok(());
        }
        Some(a) => a,
        None => "127.0.0.1:7505".to_string(),
    };

    // If the address looks like a file path, try connecting as a Unix socket.
    #[cfg(unix)]
    if Path::new(&addr).exists() || addr.starts_with('/') || addr.starts_with("./") {
        println!("Connecting to Unix socket {addr}...");
        let stream = UnixStream::connect(&addr).await?;
        let framed = Framed::new(stream, OvpnCodec::new());
        return run(framed).await;
    }

    warn_if_non_loopback(&addr);
    println!("Connecting to {addr}...");
    let stream = TcpStream::connect(&addr).await?;
    let framed = Framed::new(stream, OvpnCodec::new());
    run(framed).await
}

/// Warn on stderr if the TCP address is not a loopback address.
/// The management protocol is unencrypted — non-local connections
/// expose passwords and session data in cleartext.
fn warn_if_non_loopback(addr: &str) {
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    // Strip IPv6 brackets: [::1] → ::1
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match host {
        "127.0.0.1" | "localhost" | "::1" => {}
        _ => {
            eprintln!(
                "WARNING: connecting to non-loopback address '{addr}'.\n\
                 The management protocol is unencrypted — passwords and\n\
                 session data will be sent in cleartext.\n\
                 See: https://openvpn.net/community-docs/management-interface.html"
            );
        }
    }
}
