# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-11-14

### Added
- Cryptographically signed SLSA v1.0 build provenance and artifact attestations for all release archives, standalone binaries, and checksum files in `.github/workflows/release.yml` using `actions/attest-build-provenance@v4`, with least-privilege hermetic build isolation and pre-publish attestation verification ([#31](https://github.com/iinozemtsev-lab/dtfm/issues/31)).

## [0.3.0] - 2026-11-11

### Added
- Automated changelog finalization on manual `workflow_dispatch` releases via `scripts/finalize-changelog.py`, automatically rotating `[Unreleased]` changes into `## [<VERSION>] - <YYYY-MM-DD>`, updating Keep a Changelog comparison links, committing `chore(release): finalize changelog for <TAG>` to `main` after pre-release quality gates and builds succeed, and bundling the finalized changelog into all distribution archives ([#18](https://github.com/iinozemtsev-lab/dtfm/issues/18)).
- In-memory streaming WebSocket relay server (`cmd/relay`) with bounded memory budgets, zero persistence, and automatic session idle timeout eviction ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).
- Authenticated End-to-End Encryption (E2EE) cryptographic transport framing (`pkg/e2ee`) using AES-256-GCM with bilateral 32-byte CSPRNG handshake nonces, 64-bit monotonic counter nonces, zero-knowledge HKDF upgrade authorization, directional subkey derivation via HKDF-SHA256, and session ID binding in Additional Authenticated Data (AAD) ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).
- Operator relay adapter (`dtfm --relay`) generating ephemeral session pairing tokens and links (`<session-id>#<key>`) with approval prompter bridging ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).
- Agent relay adapter (`lmdtfy --relay <TOKEN_OR_URL>`) for transparent E2EE `ping` and `exec` execution across NATs and cloud environments without SSH keys ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).
- End-to-end integration test suite simulating full relay WebSocket pairing, cryptographic verification, zero-knowledge payload assertions, and CLI lifecycle execution ([#16](https://github.com/iinozemtsev-lab/dtfm/issues/16)).

## [0.2.0] - 2026-11-11

### Added
- Agent onboarding manual (`docs/lmdtfy_guide.md`) providing 1-line installation, gateway discovery (`lmdtfy ping`), execution instructions (`lmdtfy exec --why`), and deterministic POSIX exit code error-handling rules for autonomous coding agents ([#10](https://github.com/iinozemtsev-lab/dtfm/issues/10)).
- Manual release dispatch support (`workflow_dispatch`) in `.github/workflows/release.yml` with strict SemVer validation, `main` branch and ancestry verification, fail-closed existing-tag/release collision guards, automated Git tag creation on release publish, and single-step release creation ([#6](https://github.com/iinozemtsev-lab/dtfm/issues/6)).
- GitHub Actions CI workflow (`.github/workflows/ci.yml`) validating formatting, `go vet`, multi-OS unit/race tests (`ubuntu-latest`, `macos-latest`), and static cross-compilation targets ([#3](https://github.com/iinozemtsev-lab/dtfm/issues/3)).
- Automated GitHub Releases workflow (`.github/workflows/release.yml`) triggering on semver git tags (`v*`), compiling hermetic stripped static binaries (`CGO_ENABLED=0`), packaging multi-architecture tarballs with documentation and license, computing cryptographic `SHA256SUMS`, and publishing assets with automated release notes ([#3](https://github.com/iinozemtsev-lab/dtfm/issues/3)).
- CLI version flags (`--version`, `-v`, `-version`) and `version` subcommands across `dtfm` and `lmdtfy` binaries with linker version injection support via `-ldflags="-s -w -X 'main.version=${TAG}'"` and build info fallback ([#3](https://github.com/iinozemtsev-lab/dtfm/issues/3)).
- One-shot OpenSSH configuration helper `dtfm ssh-config <host> [--write]` querying remote UID via `ssh <host> id -u` and generating or atomically updating `RemoteForward` host blocks in `~/.ssh/config` ([#2](https://github.com/iinozemtsev-lab/dtfm/issues/2), [#4](https://github.com/iinozemtsev-lab/dtfm/pull/4)).

### Changed
- Streamlined `README.md` into a concise ~120-line document with a theme-aware Mermaid sequence diagram, consolidated Quickstart flow, and extracted maintainer release procedures into `docs/releasing.md` ([#8](https://github.com/iinozemtsev-lab/dtfm/issues/8)).
- Updated `LICENSE` with explicit copyright attribution (`Copyright 2026 Ivan Inozemtsev`) and added 2-line SPDX headers across all Go source files ([#8](https://github.com/iinozemtsev-lab/dtfm/issues/8)).

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

[Unreleased]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/iinozemtsev-lab/dtfm/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/iinozemtsev-lab/dtfm/compare/6d8f9d2...v0.2.0
[0.1.0]: https://github.com/iinozemtsev-lab/dtfm/commit/6d8f9d2
