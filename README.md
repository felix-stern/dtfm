# dtfm & lmdtfy

Human-in-the-loop (HITL) execution gateway and CLI dispatcher for autonomous AI agents and remote engineers.

`dtfm` (*Do That For Me*) runs on the operator's workstation, listening on a secure Unix domain socket and prompting the operator for approval before executing commands.

`lmdtfy` (*Let Me Do That For You*) runs inside the agent's environment (local container, VM, or remote server over SSH), dispatching commands to `dtfm` with an explicit reason (`--why`).

---

## Architecture

```
Agent / Remote Host                        Operator Workstation
┌──────────────────┐                       ┌───────────────────┐
│   lmdtfy exec    │ ─── [Unix Domain] ──> │       dtfm        │
│  --why "Reason"  │     Socket / ssh -R   │  [y] [e] [n] TTY  │
│  apt-get update  │ <── Output / Code ──  │  Execute & Stream │
└──────────────────┘                       └───────────────────┘
```

- **Interactive Approvals**: Requests are displayed unambiguously in POSIX shell syntax with stripped terminal control escapes and Trojan Source bidi characters.
- **Fail-Closed Security**: Dead stdin/EOF, stale queued keystrokes, and closed client connections immediately reject execution (exit code `126`). Custom environment variables are rejected upfront to prevent hijacking (`LD_*`, `PATH`, etc.).
- **Bounded Resources**: Stream message size is capped at 4 MB; subprocess output buffers are bounded to 1 MB.
- **Process Isolation**: Grandchild processes run in a dedicated process group and are terminated cleanly on timeout or operator cancellation (`SIGKILL`).

---

## Installation & Build

Requires Go 1.22+.

```bash
# Build local binaries in bin/
make

# Run tests with race detection
make test

# Cross-compile static binaries (darwin-arm64, darwin-amd64, linux-amd64, linux-arm64)
make cross
```

---

## Usage

### 1. Operator: Start `dtfm`

```bash
# Start listening on the default socket (/run/user/<uid>/lmdtfy.sock or ~/.lmdtfy.sock)
dtfm

# Listen on a custom socket path (e.g. in private directory or home)
dtfm --socket /tmp/lmdtfy-1000/lmdtfy.sock
```

### 2. Configure SSH Remote Forwarding (`dtfm ssh-config`)

To streamline connecting from an operator laptop to a remote host (VM, container, or server) where an agent runs, use the built-in `ssh-config` helper:

```bash
# Inspect the required RemoteForward snippet for a target host:
dtfm ssh-config dev-box

# Atomically append or update ~/.ssh/config with strict 0600 permissions:
dtfm ssh-config dev-box --write
```

Once configured, standard `ssh dev-box` automatically forwards the remote agent socket to your operator session!

### 3. Agent: Ping or Execute via `lmdtfy`

```bash
# Check if an operator session is active
lmdtfy ping [--socket <path>]

# Execute a command with required reason
lmdtfy exec --why "Install project dependencies" npm install

# Specify custom timeout, socket, or working directory
lmdtfy exec --why "Run unit tests" --timeout 120 --cwd /opt/project go test ./...
```

---

## Remote Usage over SSH (`ssh -R`)

When connecting from an operator workstation to a remote VM or container, `RemoteForward` tunnels requests from the remote agent back to the operator's `dtfm` approval listener.

### Streamlined Onboarding (`dtfm ssh-config`)

Different operating systems and hosts introduce path asymmetry:
- On Linux, agents expect the socket at `$XDG_RUNTIME_DIR/lmdtfy.sock` (`/run/user/<remote_uid>/lmdtfy.sock`).
- On macOS operator laptops, the default socket lives in `~/.lmdtfy.sock` (OpenSSH `%d` expands to the local client's home path, which does not match remote Linux paths).

`dtfm ssh-config <host> [--write]` resolves this by querying the remote UID via `ssh <host> id -u` and generating the exact OpenSSH snippet:

```bash
# Preview configuration snippet:
dtfm ssh-config user@remote-host

# Output:
# # Added by dtfm ssh-config
# Host remote-host
#     User user
#     RemoteForward /run/user/1000/lmdtfy.sock /Users/ivan/.lmdtfy.sock
#     StreamLocalBindUnlink yes

# Atomically update ~/.ssh/config:
dtfm ssh-config remote-host -w
```

### Manual Ad-hoc Forwarding

If connecting without an `~/.ssh/config` entry, forward explicitly using `ssh -R`:

```bash
# Forward local Linux dtfm socket to remote Linux host:
ssh -R /run/user/1000/lmdtfy.sock:/run/user/1000/lmdtfy.sock user@remote-host

# Forward local macOS dtfm socket (~/.lmdtfy.sock) to remote Linux host:
ssh -R /run/user/1000/lmdtfy.sock:/Users/alice/.lmdtfy.sock user@remote-host
```

### Zero-Install Shell Snippet

For zero-install inspection without compiling `dtfm`:

```bash
REMOTE_UID=$(ssh user@remote-host id -u)
[ -d "${XDG_RUNTIME_DIR:-}" ] && LOCAL_SOCK="$XDG_RUNTIME_DIR/lmdtfy.sock" || LOCAL_SOCK="$HOME/.lmdtfy.sock"
printf "# Added by dtfm ssh-config\nHost remote-host\n    RemoteForward /run/user/%s/lmdtfy.sock %s\n    StreamLocalBindUnlink yes\n" "$REMOTE_UID" "$LOCAL_SOCK"
```

> **Note on environments**: `dtfm ssh-config` configures `/run/user/<remote_uid>/lmdtfy.sock` for remote Linux hosts with systemd (`XDG_RUNTIME_DIR`). For non-systemd containers or remote macOS hosts (where `/run/user/<uid>` is absent and `lmdtfy` falls back to `~/.lmdtfy.sock`), configure `RemoteForward /remote/home/.lmdtfy.sock <local_socket>` directly.

> **Note on sshd configuration**: Ensure `StreamLocalBindUnlink yes` is enabled in remote `/etc/ssh/sshd_config` so stale socket paths are automatically rebound on reconnect.

---

## CLI Options

### `dtfm ssh-config`

| Flag | Description | Default |
|------|-------------|---------|
| `-w`, `--write` | Atomically append or update host block in `~/.ssh/config` (`0600`) | `false` |
| `--socket` | Local Unix domain socket path to forward | `protocol.DefaultSocketPath()` |
| `--config` | Custom target SSH configuration file | `~/.ssh/config` |

### `lmdtfy exec`

| Flag | Description | Default |
|------|-------------|---------|
| `--why` | Explanation of why this command needs to be executed (**required**) | |
| `--socket` | Path to Unix domain socket | `/run/user/<uid>/lmdtfy.sock` or `~/.lmdtfy.sock` |
| `--timeout` | Timeout in seconds bounding review and execution separately | `300` |
| `--cwd` | Working directory on the operator's machine | `dtfm`'s current directory |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Command executed successfully (or exit code of the executed command) |
| `1` | General CLI error or socket communication failure |
| `2` | Session inactive (`dtfm` is not running or socket is closed) |
| `124` | Execution timed out (waiting for operator review or during command run) |
| `126` | Command execution rejected by operator or denied by security policy |
| `127` | Command failed to start (executable not found or permission error) |
| `128+N` | Command terminated by signal `N` (e.g. `130` for `SIGINT`, `137` for `SIGKILL`) |

---

## License

Apache 2.0
