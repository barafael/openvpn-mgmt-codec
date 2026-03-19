# ovpn-mgmt-cli

Interactive CLI for the OpenVPN management interface. Connects to a running
OpenVPN management socket and lets you send typed commands while printing
decoded messages in real time.

## Usage

```sh
cargo run -p ovpn-mgmt-cli -- 127.0.0.1:7505
cargo run -p ovpn-mgmt-cli -- /var/run/openvpn.sock   # Unix socket
cargo run -p ovpn-mgmt-cli -- --help
```

The address defaults to `127.0.0.1:7505` if omitted. On Unix, a path to a
Unix domain socket is also accepted.

## Commands

At the `ovpn>` prompt:

```text
version                              Show OpenVPN and management interface version
status [1|2|3]                       Dump connection status (format V1/V2/V3)
state [on|off|all|on all|N]          Query or stream state changes
log   [on|off|all|on all|N]          Query or stream log messages
echo  [on|off|all|on all|N]          Query or stream echo parameters
pid                                  Show OpenVPN PID
help                                 List management commands
net                                  (Windows) Show adapter/route info
load-stats                           Aggregated server statistics
verb [N]                             Get/set log verbosity (0-15)
mute [N]                             Get/set mute threshold
bytecount N                          Enable byte-count notifications (0 to disable)
signal SIGHUP|SIGTERM|SIGUSR1|SIGUSR2  Send signal to daemon
kill <cn|ip:port>                    Kill client by common name or address
hold [on|off|release]                Query/set hold state
username <type> <value>              Supply username
password <type> <value>              Supply password
auth-retry none|interact|nointeract  Set auth-retry strategy
forget-passwords                     Forget cached passwords
needok <name> ok|cancel              Respond to NEED-OK prompt
needstr <name> <value>               Respond to NEED-STR prompt
pkcs11-id-count                      Query PKCS#11 cert count
pkcs11-id-get N                      Get PKCS#11 cert by index
client-auth <cid> <kid> [lines]      Authorize client (config lines comma-separated)
client-auth-nt <cid> <kid>           Authorize client (no config push)
client-deny <cid> <kid> <reason> [client-reason]  Deny client
client-kill <cid>                    Kill client by CID
remote accept|skip|mod <host> <port> Respond to REMOTE prompt
proxy none|http <h> <p> [nct]|socks <h> <p>  Respond to PROXY prompt
exit / quit                          Disconnect
```

Anything not recognized is sent as a raw command.

## Testing against a real OpenVPN instance

You can test the CLI against a real OpenVPN process without affecting your
network. The `--management-hold` flag makes OpenVPN open the management port
and pause before doing anything — no tunnel, no routing changes.

### Prerequisites

- OpenVPN installed (any recent version)
- Administrator / root privileges (OpenVPN requires them even with `dev null`)

### Quick start

Helper scripts in the repository root build the CLI, start OpenVPN in held
mode, connect the CLI, and clean up on exit:

```sh
# Linux / macOS (do NOT run the script itself under sudo — it uses sudo
# internally only for OpenVPN, so cargo/rustup remain available)
./test-mgmt.sh
./test-mgmt.sh /usr/sbin/openvpn   # explicit path

# Windows (elevated PowerShell)
.\test-mgmt.ps1
.\test-mgmt.ps1 -OpenVpnPath "D:\tools\openvpn\bin\openvpn.exe"
```

### Manual setup

1. Start OpenVPN with the included config:

   ```sh
   sudo openvpn --config test-mgmt.ovpn
   ```

2. In another terminal, connect the CLI:

   ```sh
   cargo run -p ovpn-mgmt-cli -- 127.0.0.1:7505
   ```

### Things to try

Once connected you'll see the `>INFO:` banner and a `>HOLD:` notification.

```text
ovpn> version          # read-only, always works
ovpn> help             # list all management commands
ovpn> status           # dump connection status
ovpn> pid              # show OpenVPN PID
ovpn> state on         # start streaming state notifications
ovpn> log on           # stream log output
ovpn> verb             # query current verbosity
ovpn> verb 5           # set verbosity
ovpn> bytecount 2      # byte-count notifications every 2s (zeros in hold)
ovpn> hold release     # let OpenVPN proceed (no remote, so it just idles)
ovpn> signal SIGUSR2   # dump stats to log
ovpn> hold on          # re-enable hold
ovpn> signal SIGUSR1   # soft restart back into held state
ovpn> quit             # disconnect
```

Since there is no `remote` directive in the test config, OpenVPN never connects anywhere.
Your internet stays untouched.
