# openvpn-mgmt-ui

A desktop GUI for the OpenVPN management interface, built with
[Iced](https://iced.rs/) and
[openvpn-mgmt-codec](../openvpn-mgmt-codec/).

## Features

- **Dashboard** — connection state, traffic counters, version, PID, load
  stats, and a real-time throughput chart.
- **Log viewer** — live log stream with severity filtering.
- **Console** — interactive command prompt with fuzzy-matched autocomplete
  against the full management command catalog.
- **Clients** — connected-client list (server mode).
- **Help** — built-in management command reference.

## Running

```sh
cargo run -p openvpn-mgmt-ui
```

Connect to a running OpenVPN daemon by entering the management socket
address (default `127.0.0.1:7505`) and clicking **Connect**. If the
daemon was started with `--management-hold`, the UI releases the hold
automatically as part of its startup sequence.

Logging is controlled via the `RUST_LOG` environment variable
(default: `info`).

## Architecture

The UI uses an **actor pattern**: a background Tokio task
([`actor.rs`](src/actor.rs)) owns the TCP connection and communicates
with the Iced event loop over `mpsc` channels. The actor uses the raw
`OvpnCodec` (rather than `ManagementClient`) because the `select!` loop
must multiplex UI commands and OpenVPN messages concurrently —
`ManagementClient` takes `&mut self` per command, which would block
notification delivery.
