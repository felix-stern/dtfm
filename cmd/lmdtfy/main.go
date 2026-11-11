// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

var version = "dev"

func getVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
	}
	return "dev"
}

// generateID creates a random hex string for correlating request and response envelopes.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `lmdtfy — Agent-side dispatcher for human-in-the-loop command execution

Usage:
  lmdtfy ping [--socket <path>] [--relay <token-or-url>] [--relay-url <url>]
  lmdtfy exec --why "<reason>" [--socket <path>] [--relay <token-or-url>] [--relay-url <url>] [--timeout <sec>] [--cwd <dir>] <command> [args...]
  lmdtfy version
  lmdtfy -h, --help

Options:
  --why              Explanation of why this command needs to be executed (required for exec)
  --socket           Path to lmdtfy Unix domain socket (default: /run/user/<uid>/lmdtfy.sock or ~/.lmdtfy.sock)
  --relay            Agent Magic Link or session pairing token for WebSocket relay execution
  --relay-url        Custom WebSocket relay endpoint URL
  --timeout          Timeout in seconds bounding operator review and command execution separately (default: 300; worst-case ~2x wait)
  --cwd              Working directory on target machine (default: dtfm's current directory)
  -v, --version      Display version and exit
  -h, --help         Display help and exit

Environment Variables:
  LMDTFY_RELAY       Default relay token or URL when --relay flag is omitted
  LMDTFY_RELAY_URL   Default relay endpoint URL when --relay-url flag is omitted
  LMDTFY_SOCKET      Default socket path when --socket flag is omitted

Exit Codes:
  0          Command executed successfully (or exit code of the executed command)
  1          General CLI error or socket communication failure
  2          LMDTFY session is inactive (socket closed or server not running)
  124        Execution timed out (waiting for review or during command run)
  126        Command execution rejected by operator or denied by security policy
  127        Command failed to start (binary not found or permission error)
`)
}

func isLoopbackHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	h = strings.Trim(h, "[]")
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func connectClient(sockPath, relayToken, relayURL string) (net.Conn, int, error) {
	if relayToken == "" {
		relayToken = os.Getenv("LMDTFY_RELAY")
	}
	if relayURL == "" {
		relayURL = os.Getenv("LMDTFY_RELAY_URL")
	}

	if relayToken != "" {
		cfg, err := e2ee.ParseRelayToken(relayToken, relayURL)
		if err != nil {
			return nil, 1, fmt.Errorf("invalid relay token: %w", err)
		}

		targetURL := cfg.RelayURL
		if relayURL != "" {
			targetURL = relayURL
		}

		u, err := url.Parse(targetURL)
		if err == nil && u.Scheme == "ws" && !isLoopbackHost(u.Hostname()) {
			fmt.Fprintf(os.Stderr, "[warning: connecting over unencrypted ws:// to non-loopback relay host %s]\n", u.Hostname())
		}

		conn, err := DialRelay(targetURL, cfg.SessionID, cfg.SecretKey)
		if err != nil {
			var rErr *RelayError
			if errors.As(err, &rErr) {
				return nil, rErr.Code, rErr
			}
			return nil, 2, fmt.Errorf("🔴 LMDTFY session is inactive: %w", err)
		}
		return conn, 0, nil
	}

	if sockPath == "" {
		if envSock := os.Getenv("LMDTFY_SOCKET"); envSock != "" {
			sockPath = envSock
		} else {
			sockPath = protocol.DefaultSocketPath()
		}
	}

	if err := protocol.ValidateClientSocketPath(sockPath); err != nil {
		return nil, 1, fmt.Errorf("error validating socket directory for %s: %w", sockPath, err)
	}

	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		return nil, 2, fmt.Errorf("🔴 LMDTFY session is inactive (cannot connect to %s): %w", sockPath, err)
	}
	return conn, 0, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 1
	}

	// Only scan leading top-level flags BEFORE the subcommand token
	var globalRelay string
	var globalRelayURL string
	subcmdIdx := -1

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") {
			subcmdIdx = i
			break
		}
		if (arg == "--relay" || arg == "-relay") && i+1 < len(args) {
			globalRelay = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--relay=") {
			globalRelay = strings.TrimPrefix(arg, "--relay=")
		} else if strings.HasPrefix(arg, "-relay=") {
			globalRelay = strings.TrimPrefix(arg, "-relay=")
		} else if (arg == "--relay-url" || arg == "-relay-url") && i+1 < len(args) {
			globalRelayURL = args[i+1]
			i++
		} else if strings.HasPrefix(arg, "--relay-url=") {
			globalRelayURL = strings.TrimPrefix(arg, "--relay-url=")
		} else if strings.HasPrefix(arg, "-relay-url=") {
			globalRelayURL = strings.TrimPrefix(arg, "-relay-url=")
		} else {
			// Other flag like -v, -h
			subcmdIdx = i
			break
		}
	}

	if subcmdIdx == -1 {
		printUsage(stderr)
		return 1
	}

	remaining := args[subcmdIdx:]
	subcommand := remaining[0]
	subArgs := remaining[1:]

	if subcommand == "ping" || subcommand == "exec" {
		var extra []string
		if globalRelay != "" {
			extra = append(extra, "--relay", globalRelay)
		}
		if globalRelayURL != "" {
			extra = append(extra, "--relay-url", globalRelayURL)
		}
		if len(extra) > 0 {
			subArgs = append(extra, subArgs...)
		}
	}

	switch subcommand {
	case "-v", "--version", "-version", "version":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "lmdtfy: %q does not accept extra arguments: %q\n", subcommand, subArgs)
			return 1
		}
		fmt.Fprintf(stdout, "lmdtfy %s\n", getVersion())
		return 0
	case "-h", "--help", "help":
		if len(subArgs) > 0 {
			fmt.Fprintf(stderr, "lmdtfy: %q does not accept extra arguments: %q\n", subcommand, subArgs)
			return 1
		}
		printUsage(stdout)
		return 0
	case "ping":
		return runPing(subArgs, stdout, stderr)
	case "exec":
		return runExec(subArgs, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage(stderr)
		return 1
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func runPing(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ping", flag.ContinueOnError)
	fs.SetOutput(stderr)
	sockPath := fs.String("socket", protocol.DefaultSocketPath(), "Socket path")
	relay := fs.String("relay", "", "Agent Magic Link or session pairing token for WebSocket relay execution")
	relayURL := fs.String("relay-url", "", "Custom WebSocket relay endpoint")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "ping: unexpected arguments: %q\n", fs.Args())
		return 1
	}

	return executePingRelay(*sockPath, *relay, *relayURL, stdout, stderr)
}

func executePing(sockPath string, stdout, stderr io.Writer) int {
	return executePingRelay(sockPath, "", "", stdout, stderr)
}

func executePingRelay(sockPath, relayToken, relayURL string, stdout, stderr io.Writer) int {
	conn, exitCode, err := connectClient(sockPath, relayToken, relayURL)
	if err != nil {
		fmt.Fprintln(stderr, err.Error())
		return exitCode
	}
	defer conn.Close()

	// Bound total ping roundtrip to 5 seconds
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var randBytes [16]byte
	_, _ = rand.Read(randBytes[:])
	pingID := hex.EncodeToString(randBytes[:])

	req := protocol.PingRequest{
		ID:        pingID,
		Timestamp: time.Now(),
	}
	env, err := protocol.NewEnvelope(protocol.TypePing, req)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to create ping envelope: %v\n", err)
		return 1
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(env); err != nil {
		fmt.Fprintf(stderr, "Failed to send ping: %v\n", err)
		return 1
	}

	decoder := json.NewDecoder(io.LimitReader(conn, protocol.MaxResponseEnvelopeBytes))
	var respEnv protocol.Envelope
	if err := decoder.Decode(&respEnv); err != nil {
		fmt.Fprintf(stderr, "Failed to read ping response: %v\n", err)
		return 1
	}

	if respEnv.Type == protocol.TypeError {
		var errPayload protocol.ErrorPayload
		_ = json.Unmarshal(respEnv.Data, &errPayload)
		fmt.Fprintf(stderr, "Server returned error: %s\n", protocol.SanitizeTerminalText(errPayload.Message))
		return 1
	}

	if respEnv.Version != protocol.ProtocolVersion {
		fmt.Fprintf(stderr, "Error: unsupported protocol version: %s (expected %s)\n", protocol.SanitizeTerminalText(respEnv.Version), protocol.ProtocolVersion)
		return 1
	}

	if respEnv.Type != protocol.TypePingResp {
		fmt.Fprintf(stderr, "Error: unexpected response envelope type: %s (expected %s)\n", protocol.SanitizeTerminalText(respEnv.Type), protocol.TypePingResp)
		return 1
	}

	var resp protocol.PingResponse
	if err := json.Unmarshal(respEnv.Data, &resp); err != nil {
		fmt.Fprintf(stderr, "Failed to decode ping payload: %v\n", err)
		return 1
	}

	if req.ID != "" && resp.ID != req.ID {
		fmt.Fprintf(stderr, "Error: ping response ID mismatch (got %s, expected %s)\n",
			protocol.SanitizeTerminalText(resp.ID),
			protocol.SanitizeTerminalText(req.ID))
		return 1
	}

	if !resp.Active {
		fmt.Fprintln(stderr, "🔴 LMDTFY session is inactive (server reported inactive)")
		return 2
	}

	fmt.Fprintf(stdout, "🟢 LMDTFY session is ACTIVE (User: %s @ %s, Time: %s)\n",
		protocol.SanitizeTerminalText(resp.User),
		protocol.SanitizeTerminalText(resp.Hostname),
		resp.Timestamp.Format(time.RFC3339))
	return 0
}

func runExec(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	fs.SetOutput(stderr)
	why := fs.String("why", "", "Reason for command execution")
	sockPath := fs.String("socket", protocol.DefaultSocketPath(), "Socket path")
	relay := fs.String("relay", "", "Agent Magic Link or session pairing token for WebSocket relay execution")
	relayURL := fs.String("relay-url", "", "Custom WebSocket relay endpoint")
	timeout := fs.Int("timeout", protocol.DefaultTimeoutSeconds, "Timeout in seconds bounding operator review and command execution separately")
	cwd := fs.String("cwd", "", "Working directory on the target machine (default: dtfm's current directory)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 || strings.TrimSpace(cmdArgs[0]) == "" {
		fmt.Fprintln(stderr, "Error: no command provided to execute")
		printUsage(stderr)
		return 1
	}

	if strings.TrimSpace(*why) == "" {
		fmt.Fprintln(stderr, "Error: --why flag is mandatory for agent transparency and cannot be empty")
		return 1
	}

	if *timeout <= 0 {
		fmt.Fprintf(stderr, "Error: --timeout must be greater than 0, got %d\n", *timeout)
		return 1
	}

	return executeExecRelay(cmdArgs, *sockPath, *relay, *relayURL, *timeout, *why, *cwd, stdout, stderr)
}

func executeExec(cmdArgs []string, sockPath string, timeout int, why string, cwd string, stdout, stderr io.Writer) int {
	return executeExecRelay(cmdArgs, sockPath, "", "", timeout, why, cwd, stdout, stderr)
}

func executeExecRelay(cmdArgs []string, sockPath, relayToken, relayURL string, timeout int, why string, cwd string, stdout, stderr io.Writer) int {
	if strings.TrimSpace(why) == "" {
		fmt.Fprintln(stderr, "Error: --why cannot be empty")
		return 1
	}
	if len(cmdArgs) == 0 || strings.TrimSpace(cmdArgs[0]) == "" {
		fmt.Fprintln(stderr, "Error: command cannot be empty")
		return 1
	}
	if timeout <= 0 {
		fmt.Fprintf(stderr, "Error: timeout must be greater than 0, got %d\n", timeout)
		return 1
	}
	if timeout > protocol.MaxTimeoutSeconds {
		timeout = protocol.MaxTimeoutSeconds
	}

	conn, exitCode, err := connectClient(sockPath, relayToken, relayURL)
	if err != nil {
		if exitCode == 2 {
			fmt.Fprintf(stderr, "Error: %v\nPlease ask the user to start 'dtfm' on their machine.\n", err)
		} else {
			fmt.Fprintf(stderr, "Error: %v\n", err)
		}
		return exitCode
	}
	defer conn.Close()

	// Client deadline must accommodate queue wait + operator approval + command execution + grace
	_ = conn.SetDeadline(time.Now().Add(time.Duration(2*timeout+30) * time.Second))

	req := protocol.CommandRequest{
		ID:             generateID(),
		Reason:         why,
		Command:        cmdArgs[0],
		Args:           cmdArgs[1:],
		Cwd:            cwd,
		TimeoutSeconds: timeout,
		CreatedAt:      time.Now(),
	}

	env, err := protocol.NewEnvelope(protocol.TypeExec, req)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to construct request envelope: %v\n", err)
		return 1
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(env); err != nil {
		fmt.Fprintf(stderr, "Error sending request to local client: %v\n", err)
		return 1
	}

	decoder := json.NewDecoder(io.LimitReader(conn, protocol.MaxResponseEnvelopeBytes))
	var respEnv protocol.Envelope
	if err := decoder.Decode(&respEnv); err != nil {
		if errors.Is(err, io.EOF) {
			fmt.Fprintln(stderr, "Error: connection closed by local client before receiving response.")
		} else {
			fmt.Fprintf(stderr, "Error decoding response: %v\n", err)
		}
		return 1
	}

	if respEnv.Type == protocol.TypeError {
		var errPayload protocol.ErrorPayload
		_ = json.Unmarshal(respEnv.Data, &errPayload)
		fmt.Fprintf(stderr, "Server error: %s\n", protocol.SanitizeTerminalText(errPayload.Message))
		return 1
	}

	if respEnv.Version != protocol.ProtocolVersion {
		fmt.Fprintf(stderr, "Error: unsupported protocol version: %s (expected %s)\n", protocol.SanitizeTerminalText(respEnv.Version), protocol.ProtocolVersion)
		return 1
	}

	if respEnv.Type != protocol.TypeExecResp {
		fmt.Fprintf(stderr, "Error: unexpected response envelope type: %s (expected %s)\n", protocol.SanitizeTerminalText(respEnv.Type), protocol.TypeExecResp)
		return 1
	}

	var resp protocol.CommandResponse
	if err := json.Unmarshal(respEnv.Data, &resp); err != nil {
		fmt.Fprintf(stderr, "Failed to decode command response: %v\n", err)
		return 1
	}

	if resp.ID != req.ID {
		fmt.Fprintf(stderr, "Error: response ID mismatch: got %s, expected %s\n",
			protocol.SanitizeTerminalText(resp.ID),
			protocol.SanitizeTerminalText(req.ID))
		return 1
	}

	if resp.Stdout != "" {
		_, _ = io.WriteString(stdout, resp.Stdout)
	}
	if resp.Stderr != "" {
		_, _ = io.WriteString(stderr, resp.Stderr)
	}

	switch resp.Status {
	case protocol.StatusApproved:
		if resp.ModifiedCommand != "" {
			fmt.Fprintf(stderr, "\n[lmdtfy note: command was modified by user: %s]\n", protocol.SanitizeTerminalText(resp.ModifiedCommand))
		}
		if resp.Error != "" {
			fmt.Fprintf(stderr, "\n[lmdtfy execution note: %s]\n", protocol.SanitizeTerminalText(resp.Error))
		}
		return resp.ExitCode
	case protocol.StatusRejected:
		fmt.Fprintf(stderr, "\n❌ Command was REJECTED by user. Reason: %s\n", protocol.SanitizeTerminalText(resp.RejectReason))
		return protocol.ExitCodeRejected
	case protocol.StatusTimeout:
		msg := resp.Error
		if msg == "" {
			msg = "Command execution TIMED OUT waiting for user approval."
		}
		fmt.Fprintf(stderr, "\n⏳ %s\n", protocol.SanitizeTerminalText(msg))
		return protocol.ExitCodeTimeout
	case protocol.StatusError:
		msg := resp.Error
		if msg == "" {
			msg = "Command execution error"
		}
		fmt.Fprintf(stderr, "\n❌ Command execution error: %s\n", protocol.SanitizeTerminalText(msg))
		if resp.ExitCode != 0 {
			return resp.ExitCode
		}
		return protocol.ExitCodeError
	default:
		fmt.Fprintf(stderr, "\n❌ Command execution failed: %s\n", protocol.SanitizeTerminalText(resp.Error))
		return 1
	}
}
