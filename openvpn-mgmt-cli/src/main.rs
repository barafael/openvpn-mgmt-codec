#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
#![cfg_attr(coverage_nightly, coverage(off))]
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

use clap::Parser;
use futures::{SinkExt, StreamExt};
use openvpn_mgmt_codec::{Notification, OvpnCodec, OvpnCommand, OvpnMessage, PasswordNotification};
use std::io::Write as _;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::UnixStream;

const RUNTIME_COMMANDS: &str = "\
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

/// Interactive OpenVPN management interface client.
///
/// Connects to a running OpenVPN management socket and lets you send
/// typed commands while printing decoded messages in real time.
#[derive(Parser)]
#[command(after_help = RUNTIME_COMMANDS)]
struct Cli {
    /// Management interface address [default: 127.0.0.1:7505].
    /// On Unix, a path to a Unix domain socket is also accepted.
    #[arg(default_value = "127.0.0.1:7505")]
    address: String,
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
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let month_offset = (5 * doy + 2) / 153;
    let day = doy - (153 * month_offset + 2) / 5 + 1;
    let month = if month_offset < 10 { month_offset + 3 } else { month_offset - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
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
        OvpnMessage::Info(info) => println!("[INFO] {info}"),
        OvpnMessage::PasswordPrompt => {
            println!("[MGMT] Management password required (type the password and press enter)");
        }
        OvpnMessage::Notification(notification) => print_notification(notification),
        OvpnMessage::Pkcs11IdEntry { index, id, blob } => {
            println!("[PKCS11] index={index} id={id} blob={blob}");
        }
        OvpnMessage::Unrecognized { line, kind } => {
            eprintln!("[UNRECOGNIZED ({kind:?})] {line}");
        }
    }
}

fn print_notification(notification: &Notification) {
    match notification {
        Notification::State {
            timestamp,
            name,
            description,
            local_ip,
            remote_ip,
            ..
        } => {
            let formatted_timestamp = format_timestamp(*timestamp);
            println!("[STATE] {name} — {description} (local={local_ip}, remote={remote_ip}, {formatted_timestamp})");
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
            let formatted_timestamp = format_timestamp(*timestamp);
            println!("[LOG {level}] {message} ({formatted_timestamp})");
        }
        Notification::Echo { timestamp, param } => {
            let formatted_timestamp = format_timestamp(*timestamp);
            println!("[ECHO] {param} ({formatted_timestamp})");
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
            // Intentionally prints all env values including `password` —
            // this is a local dev/debug tool, not a production log sink.
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
            PasswordNotification::StaticChallenge {
                echo, challenge, ..
            } => {
                println!("[PASSWORD] Static challenge (echo={echo}): {challenge}");
            }
            PasswordNotification::DynamicChallenge {
                challenge,
                state_id,
                ..
            } => {
                println!("[PASSWORD] Dynamic challenge (state={state_id}): {challenge}");
            }
            PasswordNotification::AuthToken { token } => {
                println!("[PASSWORD] Auth-Token: {token}");
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
            index,
            proxy_type,
            host,
        } => {
            println!("[PROXY] #{index} {proxy_type} {host}");
        }
        Notification::RsaSign { data } => {
            println!("[RSA_SIGN] {data}");
        }
        Notification::PkSign { data, algorithm } => match algorithm {
            Some(algo) => println!("[PK_SIGN] algo={algo} {data}"),
            None => println!("[PK_SIGN] {data}"),
        },
        Notification::Info { message } => {
            println!("[INFO] {message}");
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
                    Some(Err(error)) => {
                        eprintln!("[CONN ERROR] {error}");
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
                match line.parse::<OvpnCommand>() {
                    Ok(cmd) => {
                        let is_exit = matches!(cmd, OvpnCommand::Exit | OvpnCommand::Quit);
                        if let Err(error) = sink.send(cmd).await {
                            eprintln!("[SEND ERROR] {error}");
                            break;
                        }
                        if is_exit {
                            break;
                        }
                    }
                    Err(error) => eprintln!("parse error: {error}"),
                }
            }
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let addr = cli.address;

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
        .and_then(|inner| inner.strip_suffix(']'))
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
