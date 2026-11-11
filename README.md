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

### Prebuilt Binaries (GitHub Releases)

Hermetic, statically linked binaries are published on [GitHub Releases](https://github.com/iinozemtsev-lab/dtfm/releases) for `darwin-arm64`, `darwin-amd64`, `linux-amd64`, and `linux-arm64`:

```bash
# Example: Download release archive and checksum file (replace v0.1.0 with target version)
curl -LO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.1.0/dtfm_0.1.0_linux_amd64.tar.gz
curl -LO https://github.com/iinozemtsev-lab/dtfm/releases/download/v0.1.0/SHA256SUMS

# Verify cryptographic integrity
sha256sum --ignore-missing -c SHA256SUMS

# Extract binaries and install
tar -xzf dtfm_0.1.0_linux_amd64.tar.gz
sudo install -m 0755 dtfm lmdtfy /usr/local/bin/
```

### Build from Source

Requires Go 1.22+.

```bash
# Build local binaries in bin/
make

# Run unit tests and race detection
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

### `dtfm`

| Flag / Subcommand | Description | Default |
|-------------------|-------------|---------|
| `--socket <path>` | Path to listen Unix domain socket | `/run/user/<uid>/lmdtfy.sock` or `~/.lmdtfy.sock` |
| `-v`, `--version` | Display version and exit | |
| `version` | Subcommand to display version and exit | |
| `-h`, `--help` | Display help and exit | |

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

### `lmdtfy version`

```bash
lmdtfy version
# or
lmdtfy -v
# or
lmdtfy --version
```

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

## Release Process & Version Tagging

This repository adheres to [Semantic Versioning](https://semver.org/) and follows [Keep a Changelog](https://keepachangelog.com/). Releases are fully automated via GitHub Actions (`.github/workflows/release.yml`).

### Step-by-Step Release Workflow

1. **Update `CHANGELOG.md`**:
   - Move completed changes from the `[Unreleased]` section into a new version block:
     ```markdown
     ## [0.2.0] - 2026-11-15
     ### Added
     ...
     ```
   - Update comparison links at the bottom of `CHANGELOG.md`.

2. **Commit and Merge**:
   - Submit a pull request with the updated `CHANGELOG.md` and any final version bumps.
   - Once approved and merged to `main`, pull the latest `main`.

3. **Trigger the Release**:
   You can cut and publish the release either manually from GitHub Actions or by pushing a Git tag.

   #### Option A: Manual Workflow Dispatch (Recommended)
   Trigger the release directly from GitHub Actions without local tag manipulation. The workflow requires running against `refs/heads/main`, validates strict SemVer format (`vMAJOR.MINOR.PATCH` with no leading zeros) upfront, verifies that the target commit is an ancestor of `main`, checks for collisions, and automatically creates the Git tag at the verified `main` commit SHA (`GITHUB_SHA`) upon release publication:
   - **GitHub Actions Web UI**: Navigate to **Actions** &rarr; **Release** &rarr; **Run workflow**, ensure `Use workflow from: Branch: main` is selected, enter the version tag (e.g. `v0.2.0`), and click **Run workflow**.
   - **GitHub CLI**:
     ```bash
     gh workflow run release.yml --ref main -f version=v0.2.0
     ```

   #### Option B: Tag Push
   Alternatively, create an annotated semver tag locally and push it to `upstream` (or `origin` depending on your remote naming):
   ```bash
   git tag -a v0.2.0 -m "Release v0.2.0"
   git push upstream v0.2.0
   ```

4. **Automated Publishing & Verification**:
   The `.github/workflows/release.yml` pipeline automatically:
   - Validates strict SemVer tag format (`vMAJOR.MINOR.PATCH` with no leading zeros).
   - Enforces execution against `refs/heads/main` on manual dispatch and verifies commit ancestry on `origin/main`.
   - Fails closed if a published release already exists or if Git tag collisions are detected.
   - Runs all pre-release quality gates (`go mod verify`, `gofmt -s`, `go vet`, `go test -race`, and changelog extractor validation).
   - Extracts release notes from `CHANGELOG.md` corresponding to the target tag (with fallback to automatic GitHub release notes).
   - Builds hermetic, stripped static binaries (`CGO_ENABLED=0`, `-trimpath -ldflags="-s -w -X 'main.version=${TAG}'"`) for:
     - `darwin/arm64` (Apple Silicon)
     - `darwin/amd64` (macOS Intel)
     - `linux/amd64` (Linux x86_64)
     - `linux/arm64` (Linux ARM64 / aarch64)
   - Verifies static ELF linkage (no dynamic or interpreter sections) across all Linux binaries.
   - Packages tarball archives (`dtfm_<VERSION>_<OS>_<ARCH>.tar.gz`) containing `dtfm`, `lmdtfy`, `README.md`, `LICENSE`, and `CHANGELOG.md` with reproducible `0:0` ownership and `SOURCE_DATE_EPOCH` timestamps.
   - Generates and validates cryptographic `SHA256SUMS`.
   - Publishes the GitHub Release live with attached binary assets and checksums (automatically creating the tag on `main` for manual dispatch, or verifying the pushed tag).

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full historical release notes.

---

## License

Apache 2.0
