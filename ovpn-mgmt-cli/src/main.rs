//! Interactive CLI for the OpenVPN management interface.
//!
//! Connects to a running OpenVPN management socket and lets you send
//! typed commands while printing decoded messages in real time.
//!
//! # Usage
//!
//! ```sh
//! cargo run -p ovpn-mgmt-cli -- 127.0.0.1:7505
//! cargo run -p ovpn-mgmt-cli -- /var/run/openvpn.sock   # Unix socket
//! ```
//!
//! Once connected, type a command name at the `ovpn>` prompt (e.g. `version`,
//! `status`, `state on`). Type `help` to list commands, `quit` to disconnect.

use futures::{SinkExt, StreamExt};
use ovpn_mgmt_codec::{
    AuthType, KillTarget, Notification, OvpnCodec, OvpnCommand, OvpnMessage,
    PasswordNotification, Signal, StatusFormat, StreamMode,
};
use std::env;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::UnixStream;

/// Parse a user-typed line into an `OvpnCommand`.
fn parse_input(line: &str) -> Result<OvpnCommand, String> {
    let line = line.trim();
    let (cmd, args) = line
        .split_once(char::is_whitespace)
        .map(|(c, a)| (c, a.trim()))
        .unwrap_or((line, ""));

    match cmd {
        // Informational
        "version" => Ok(OvpnCommand::Version),
        "pid" => Ok(OvpnCommand::Pid),
        "help" => Ok(OvpnCommand::Help),
        "net" => Ok(OvpnCommand::Net),
        "load-stats" => Ok(OvpnCommand::LoadStats),

        "status" => match args {
            "" | "1" => Ok(OvpnCommand::Status(StatusFormat::V1)),
            "2" => Ok(OvpnCommand::Status(StatusFormat::V2)),
            "3" => Ok(OvpnCommand::Status(StatusFormat::V3)),
            _ => Err(format!("invalid status format: {args}")),
        },

        "state" => match args {
            "" => Ok(OvpnCommand::State),
            "on" => Ok(OvpnCommand::StateStream(StreamMode::On)),
            "off" => Ok(OvpnCommand::StateStream(StreamMode::Off)),
            "all" => Ok(OvpnCommand::StateStream(StreamMode::All)),
            "on all" => Ok(OvpnCommand::StateStream(StreamMode::OnAll)),
            n => n
                .parse::<u32>()
                .map(|n| OvpnCommand::StateStream(StreamMode::Recent(n)))
                .map_err(|_| format!("invalid state argument: {args}")),
        },

        "log" => parse_stream_mode(args).map(OvpnCommand::Log),
        "echo" => parse_stream_mode(args).map(OvpnCommand::Echo),

        "verb" => {
            if args.is_empty() {
                Ok(OvpnCommand::Verb(None))
            } else {
                args.parse::<u8>()
                    .map(|n| OvpnCommand::Verb(Some(n)))
                    .map_err(|_| format!("invalid verbosity: {args}"))
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

        // Connection control
        "signal" => match args {
            "SIGHUP" => Ok(OvpnCommand::Signal(Signal::SigHup)),
            "SIGTERM" => Ok(OvpnCommand::Signal(Signal::SigTerm)),
            "SIGUSR1" => Ok(OvpnCommand::Signal(Signal::SigUsr1)),
            "SIGUSR2" => Ok(OvpnCommand::Signal(Signal::SigUsr2)),
            _ => Err(format!("unknown signal: {args} (use SIGHUP/SIGTERM/SIGUSR1/SIGUSR2)")),
        },

        "kill" => {
            if args.is_empty() {
                return Err("kill requires a target (common name or ip:port)".into());
            }
            if let Some((ip, port_str)) = args.rsplit_once(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return Ok(OvpnCommand::Kill(KillTarget::Address {
                        ip: ip.to_owned(),
                        port,
                    }));
                }
            }
            Ok(OvpnCommand::Kill(KillTarget::CommonName(args.to_owned())))
        }

        "hold" => match args {
            "" => Ok(OvpnCommand::HoldQuery),
            "on" => Ok(OvpnCommand::HoldOn),
            "off" => Ok(OvpnCommand::HoldOff),
            "release" => Ok(OvpnCommand::HoldRelease),
            _ => Err(format!("invalid hold argument: {args}")),
        },

        // Authentication
        "username" => {
            let (auth_type, value) = args
                .split_once(char::is_whitespace)
                .ok_or("usage: username <auth-type> <value>")?;
            Ok(OvpnCommand::Username {
                auth_type: parse_auth_type(auth_type),
                value: value.trim().to_owned(),
            })
        }

        "password" => {
            let (auth_type, value) = args
                .split_once(char::is_whitespace)
                .ok_or("usage: password <auth-type> <value>")?;
            Ok(OvpnCommand::Password {
                auth_type: parse_auth_type(auth_type),
                value: value.trim().to_owned(),
            })
        }

        "forget-passwords" => Ok(OvpnCommand::ForgetPasswords),

        // Lifecycle
        "exit" => Ok(OvpnCommand::Exit),
        "quit" => Ok(OvpnCommand::Quit),

        // Fallback: send as raw command
        _ => Ok(OvpnCommand::Raw(line.to_owned())),
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
            .map_err(|_| format!("invalid stream mode: {args}")),
    }
}

fn parse_auth_type(s: &str) -> AuthType {
    match s {
        "Auth" => AuthType::Auth,
        "PrivateKey" | "Private Key" => AuthType::PrivateKey,
        "HTTPProxy" | "HTTP Proxy" => AuthType::HttpProxy,
        "SOCKSProxy" | "SOCKS Proxy" => AuthType::SocksProxy,
        other => AuthType::Custom(other.to_owned()),
    }
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
        OvpnMessage::PasswordPrompt => println!("[MGMT] Enter management password:"),
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
            println!("[STATE] {name} — {description} (local={local_ip}, remote={remote_ip}, t={timestamp})");
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
            flags,
            message,
        } => {
            println!("[LOG {flags}] {message} (t={timestamp})");
        }
        Notification::Echo { timestamp, param } => {
            println!("[ECHO] {param} (t={timestamp})");
        }
        Notification::Hold { text } => {
            println!("[HOLD] {text}");
        }
        Notification::Fatal { message } => {
            eprintln!("[FATAL] {message}");
        }
        Notification::Client {
            event,
            header_args,
            env,
        } => {
            println!("[CLIENT:{event}] {header_args}");
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
            proto_type, host, port, ..
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
async fn run<T>(framed: Framed<T, OvpnCodec>) -> anyhow::Result<()>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = framed.split();
    let stdin = BufReader::new(io::stdin());
    let mut lines = stdin.lines();

    // Spawn a task to print incoming messages.
    let reader = tokio::spawn(async move {
        while let Some(result) = stream.next().await {
            match result {
                Ok(msg) => print_message(&msg),
                Err(e) => {
                    eprintln!("[CONN ERROR] {e}");
                    break;
                }
            }
        }
        println!("[DISCONNECTED]");
    });

    // Read commands from stdin.
    loop {
        eprint!("ovpn> ");
        let line = match lines.next_line().await? {
            Some(l) => l,
            None => break, // EOF
        };
        let line = line.trim().to_owned();
        if line.is_empty() {
            continue;
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

    reader.abort();
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:7505".to_owned());

    // If the address looks like a file path, try connecting as a Unix socket.
    #[cfg(unix)]
    if Path::new(&addr).exists() || addr.starts_with('/') || addr.starts_with("./") {
        println!("Connecting to Unix socket {addr}...");
        let stream = UnixStream::connect(&addr).await?;
        let framed = Framed::new(stream, OvpnCodec::new());
        return run(framed).await;
    }

    println!("Connecting to {addr}...");
    let stream = TcpStream::connect(&addr).await?;
    let framed = Framed::new(stream, OvpnCodec::new());
    run(framed).await
}
