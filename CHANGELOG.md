# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- GitHub Actions CI workflow (`.github/workflows/ci.yml`) validating formatting, `go vet`, multi-OS unit/race tests (`ubuntu-latest`, `macos-latest`), and static cross-compilation targets ([#3](https://github.com/iinozemtsev-lab/dtfm/issues/3)).
- Automated GitHub Releases workflow (`.github/workflows/release.yml`) triggering on semver git tags (`v*`), compiling hermetic stripped static binaries (`CGO_ENABLED=0`), packaging multi-architecture tarballs with documentation and license, computing cryptographic `SHA256SUMS`, and publishing assets with automated release notes ([#3](https://github.com/iinozemtsev-lab/dtfm/issues/3)).
- CLI version flags (`--version`, `-v`, `-version`) and `version` subcommands across `dtfm` and `lmdtfy` binaries with linker version injection support via `-ldflags="-s -w -X 'main.version=${TAG}'"` and build info fallback ([#3](https://github.com/iinozemtsev-lab/dtfm/issues/3)).
- One-shot OpenSSH configuration helper `dtfm ssh-config <host> [--write]` querying remote UID via `ssh <host> id -u` and generating or atomically updating `RemoteForward` host blocks in `~/.ssh/config` ([#2](https://github.com/iinozemtsev-lab/dtfm/issues/2), [#4](https://github.com/iinozemtsev-lab/dtfm/pull/4)).

## [0.1.0] - 2026-11-10

### Added
- **Human-in-the-Loop Operator Terminal Server (`dtfm`)**:
  - Validated Unix domain socket listener (`/run/user/<uid>/lmdtfy.sock` on Linux or `~/.lmdtfy.sock` on macOS; fallback `/tmp/lmdtfy-<uid>/lmdtfy.sock`).
  - Interactive `/dev/tty` prompter with `[y] Run / [e] Edit / [n] Reject` commands.
  - TTY input queue flushing (`TCFLSH` on Linux, `TIOCFLUSH` on Darwin) before prompting to prevent queued or pre-typed keystroke hijacking.
  - Termios save and restore (`TCSAFLUSH`), raw character-at-a-time input mode, and `VSUSP` disablement during child process execution.
  - Subprocess execution isolation with child `Stdin` bound to `/dev/null` to prevent background command hijacking, while preserving direct `/dev/tty` terminal access for authenticating commands (e.g. `sudo`, `ssh`).
  - Process group isolation (`Setpgid: true`) and graceful-then-forceful termination (`SIGKILL` + `WaitDelay`) on session interrupts or client disconnects.
  - Active client-disconnect detection and prompt cancellation.
- **Agent Command Execution Dispatcher CLI (`lmdtfy`)**:
  - `ping` subcommand to verify active operator listening sessions before invoking actions.
  - `exec` subcommand with mandatory `--why <reason>` transparency flag, `--timeout <sec>`, and optional `--cwd <dir>`.
  - Deterministic POSIX exit code contract: `0` (success or child code), `1` (CLI/comm error), `2` (inactive session), `124` (timeout), `126` (rejected or security violation), `127` (exec spawn failure), `128+N` (signal termination).
- **Wire Protocol & Security Controls (`pkg/protocol`)**:
  - JSON wire envelope format over Unix domain socket with 4 MB maximum message size bound and 1 MB captured output cap.
  - Upfront rejection of custom agent-supplied environment variables (`req.Env`) returning `StatusRejected` / exit code `126`.
  - Lossless terminal escape code, ANSI OSC command injection, and Unicode Trojan Source bidi/variation-selector sanitization (`SanitizeTerminalText`).
  - Unambiguous POSIX and ANSI-C `$'...'` command formatting and shell quoting (`FormatCommand`).
  - Strict Unix domain socket path ancestor and symlink verification (`EnsureSocketDir`, `ValidateClientSocketPath`) to prevent directory traversal and symlink hijacking.
- **Build Infrastructure**:
  - Multi-platform static compilation targets in `Makefile` (`make cross`) for `darwin-arm64`, `darwin-amd64`, `linux-amd64`, and `linux-arm64` (`CGO_ENABLED=0`).

[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/iinozemtsev-lab/dtfm/releases/tag/v0.1.0
