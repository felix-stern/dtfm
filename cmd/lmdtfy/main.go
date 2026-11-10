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
	"os"
	"strings"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

// generateID creates a random hex string for correlating request and response envelopes.
func generateID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp if crypto/rand fails
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	switch subcommand {
	case "-h", "--help", "help":
		printUsage()
		os.Exit(0)
	case "ping":
		runPing(os.Args[2:])
	case "exec":
		runExec(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `lmdtfy — Agent-side dispatcher for human-in-the-loop command execution

Usage:
  lmdtfy ping [--socket <path>]
  lmdtfy exec --why "<reason>" [--socket <path>] [--timeout <sec>] [--cwd <dir>] <command> [args...]

Options:
  --why      Explanation of why this command needs to be executed (required for exec)
  --socket   Path to lmdtfy Unix domain socket (default: /run/user/<uid>/lmdtfy.sock or ~/.lmdtfy.sock)
  --timeout  Timeout in seconds bounding operator review and command execution separately (default: 300; worst-case ~2x wait)
  --cwd      Working directory on target machine (default: dtfm's current directory)

Exit Codes:
  0          Command executed successfully (or exit code of the executed command)
  1          General CLI error or socket communication failure
  2          LMDTFY session is inactive (socket closed or server not running)
  124        Execution timed out (waiting for review or during command run)
  126        Command execution rejected by operator or denied by security policy
  127        Command failed to start (binary not found or permission error)
`)
}

func runPing(args []string) {
	fs := flag.NewFlagSet("ping", flag.ExitOnError)
	sockPath := fs.String("socket", protocol.DefaultSocketPath(), "Socket path")
	_ = fs.Parse(args)

	code := executePing(*sockPath, os.Stdout, os.Stderr)
	os.Exit(code)
}

func executePing(sockPath string, stdout, stderr io.Writer) int {
	if err := protocol.ValidateClientSocketPath(sockPath); err != nil {
		fmt.Fprintf(stderr, "Error validating socket directory for %s: %v\n", sockPath, err)
		return 1
	}

	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "🔴 LMDTFY session is inactive (cannot connect to %s): %v\n", sockPath, err)
		return 2
	}
	defer conn.Close()

	// Bound total ping roundtrip to 5 seconds
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := protocol.PingRequest{Timestamp: time.Now()}
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

	decoder := json.NewDecoder(io.LimitReader(conn, 16*1024*1024))
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

func runExec(args []string) {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	why := fs.String("why", "", "Reason for command execution")
	sockPath := fs.String("socket", protocol.DefaultSocketPath(), "Socket path")
	timeout := fs.Int("timeout", protocol.DefaultTimeoutSeconds, "Timeout in seconds bounding operator review and command execution separately")
	cwd := fs.String("cwd", "", "Working directory on the target machine (default: dtfm's current directory)")
	_ = fs.Parse(args)

	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 || strings.TrimSpace(cmdArgs[0]) == "" {
		fmt.Fprintln(os.Stderr, "Error: no command provided to execute")
		printUsage()
		os.Exit(1)
	}

	if strings.TrimSpace(*why) == "" {
		fmt.Fprintln(os.Stderr, "Error: --why flag is mandatory for agent transparency and cannot be empty")
		os.Exit(1)
	}

	if *timeout <= 0 {
		fmt.Fprintf(os.Stderr, "Error: --timeout must be greater than 0, got %d\n", *timeout)
		os.Exit(1)
	}

	code := executeExec(cmdArgs, *sockPath, *timeout, *why, *cwd, os.Stdout, os.Stderr)
	os.Exit(code)
}

func executeExec(cmdArgs []string, sockPath string, timeout int, why string, cwd string, stdout, stderr io.Writer) int {
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

	if err := protocol.ValidateClientSocketPath(sockPath); err != nil {
		fmt.Fprintf(stderr, "Error validating socket directory for %s: %v\n", sockPath, err)
		return 1
	}

	conn, err := net.DialTimeout("unix", sockPath, 5*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "Error: LMDTFY session is inactive (cannot connect to socket %s).\nPlease ask the user to start 'dtfm' on their machine.\n", sockPath)
		return 2
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

	decoder := json.NewDecoder(io.LimitReader(conn, 16*1024*1024))
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
