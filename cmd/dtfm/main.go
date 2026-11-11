// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
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

func printMainUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  dtfm [options]                    Start dtfm operator server (default)")
	fmt.Fprintln(w, "  dtfm --relay [options]            Start dtfm in public/private WebSocket relay mode")
	fmt.Fprintln(w, "  dtfm ssh-config <host> [options]  Generate OpenSSH RemoteForward snippet")
	fmt.Fprintln(w, "  dtfm version                      Display version and exit")
	fmt.Fprintln(w, "  dtfm -h, --help                   Display help and exit")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Server options:")
	fmt.Fprintln(w, "  --socket <path>   Path to listen Unix domain socket (default: /run/user/<uid>/lmdtfy.sock or ~/.lmdtfy.sock)")
	fmt.Fprintln(w, "  --relay           Run in in-memory E2EE WebSocket relay mode")
	fmt.Fprintln(w, "  --relay-url <url> WebSocket relay endpoint (default: wss://relay.dtfm.dev/ws)")
	fmt.Fprintln(w, "  --hub-url <url>   Web hub base URL for Magic Links (default: https://dtfm.dev)")
	fmt.Fprintln(w, "  --session <id>    Explicit session ID (default: randomly generated)")
	fmt.Fprintln(w, "  -v, --version     Display version and exit")
	fmt.Fprintln(w, "  -h, --help        Display help and exit")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Helper command options (dtfm ssh-config):")
	fmt.Fprintln(w, "  -w, --write       Atomically append or update host entry in ~/.ssh/config")
	fmt.Fprintln(w, "  --socket <path>   Local socket path (default: DefaultSocketPath())")
	fmt.Fprintln(w, "  --config <path>   Target SSH config file (default: ~/.ssh/config)")
}

func main() {
	os.Exit(run(os.Args, os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) > 1 {
		switch args[1] {
		case "version", "-v", "--version", "-version":
			if len(args) > 2 {
				fmt.Fprintf(stderr, "dtfm: %q does not accept extra arguments: %q\n", args[1], args[2:])
				return 1
			}
			fmt.Fprintf(stdout, "dtfm %s\n", getVersion())
			return 0
		case "ssh-config", "sshconfig":
			return RunSSHConfig(args[2:], stdout, stderr, SSHConfigOptions{})
		case "help":
			if len(args) > 2 && (args[2] == "ssh-config" || args[2] == "sshconfig") {
				return RunSSHConfig([]string{"--help"}, stdout, stderr, SSHConfigOptions{})
			}
			printMainUsage(stdout)
			return 0
		case "-h", "--help", "-help":
			printMainUsage(stdout)
			return 0
		}
	}

	fs := flag.NewFlagSet("dtfm", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {}
	sockPath := fs.String("socket", protocol.DefaultSocketPath(), "Path to listen Unix domain socket")
	relayMode := fs.Bool("relay", false, "Start dtfm in public/private WebSocket relay mode")
	relayURL := fs.String("relay-url", e2ee.DefaultRelayWsURL, "WebSocket relay endpoint")
	hubURL := fs.String("hub-url", e2ee.DefaultHubURL, "Web hub base URL for Magic Links")
	sessionID := fs.String("session", "", "Explicit session ID (default: randomly generated)")
	showVersion := fs.Bool("version", false, "Display version and exit")
	showVersionShort := fs.Bool("v", false, "Display version and exit")
	showHelp := fs.Bool("help", false, "Display help and exit")
	showHelpShort := fs.Bool("h", false, "Display help and exit")

	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printMainUsage(stdout)
			return 0
		}
		printMainUsage(stderr)
		return 1
	}

	if *showHelp || *showHelpShort {
		printMainUsage(stdout)
		return 0
	}

	if *showVersion || *showVersionShort {
		if fs.NArg() > 0 {
			fmt.Fprintf(stderr, "dtfm: version flag does not accept extra arguments: %q\n", fs.Args())
			return 1
		}
		fmt.Fprintf(stdout, "dtfm %s\n", getVersion())
		return 0
	}

	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "dtfm: unknown command %q\n\n", fs.Arg(0))
		printMainUsage(stderr)
		return 1
	}

	if *relayMode {
		sID := strings.TrimSpace(*sessionID)
		if sID == "" {
			var err error
			sID, err = e2ee.GenerateSessionID()
			if err != nil {
				fmt.Fprintf(stderr, "Error generating session ID: %v\n", err)
				return 1
			}
		} else {
			if err := e2ee.ValidateSessionID(sID); err != nil {
				fmt.Fprintf(stderr, "Error: invalid --session ID: %v\n", err)
				return 1
			}
		}

		// If relay-url was specified and hub-url was not explicitly set, derive hub-url
		hubURLSet := false
		relayURLSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "hub-url" {
				hubURLSet = true
			}
			if f.Name == "relay-url" {
				relayURLSet = true
			}
		})

		effectiveHubURL := *hubURL
		if relayURLSet && !hubURLSet {
			u, err := url.Parse(*relayURL)
			if err == nil {
				scheme := "https"
				if u.Scheme == "ws" {
					scheme = "http"
				}
				basePath := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/ws")
				effectiveHubURL = fmt.Sprintf("%s://%s%s", scheme, u.Host, basePath)
			}
		}

		u, err := url.Parse(*relayURL)
		if err == nil && u.Scheme == "ws" && !isLoopbackHost(u.Hostname()) {
			fmt.Fprintf(stderr, "[warning: connecting over unencrypted ws:// to non-loopback relay host %s]\n", u.Hostname())
		}

		secretKey, keyHex, err := e2ee.GenerateSessionKey()
		if err != nil {
			fmt.Fprintf(stderr, "Error generating session key: %v\n", err)
			return 1
		}

		relayListener, err := DialRelayListener(*relayURL, sID, secretKey)
		if err != nil {
			fmt.Fprintf(stderr, "Error connecting to relay server: %v\n", err)
			return 1
		}
		defer relayListener.Close()

		prompter := NewTerminalPrompter()
		defer prompter.Close()

		server := NewServer(relayListener, prompter)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
		defer signal.Stop(sigChan)
		go func() {
			<-sigChan
			fmt.Fprintln(stdout, "\n🔴 Stopping dtfm relay session. Shutting down server and killing active child...")
			server.Shutdown()
		}()

		magicLink := e2ee.FormatMagicLink(effectiveHubURL, sID, keyHex)
		token := fmt.Sprintf("%s#%s", sID, keyHex)

		hostname, _ := os.Hostname()
		userName := protocol.CurrentUser()
		fmt.Fprintf(stdout, "🟢 dtfm relay session started.\n")
		fmt.Fprintf(stdout, "Relay: %s\n", *relayURL)
		fmt.Fprintf(stdout, "Session ID: %s\n", sID)
		fmt.Fprintf(stdout, "User: %s @ %s\n\n", userName, hostname)
		fmt.Fprintf(stdout, "Agent Magic Link:\n  %s\n\n", magicLink)
		fmt.Fprintf(stdout, "Pairing Token:\n  %s\n\n", token)
		fmt.Fprintf(stdout, "Waiting for agent requests... (Press Ctrl+C to exit)\n\n")

		if err := server.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(stderr, "dtfm relay server error: %v\n", err)
			return 1
		}
		return 0
	}

	// Ensure and validate socket directory security (ownership, non-symlink, mode 0700 for shared runtime paths)
	if err := protocol.EnsureSocketDir(*sockPath); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}

	// If path exists, verify it is actually a socket before touching or removing it
	if fi, err := os.Lstat(*sockPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			fmt.Fprintf(stderr, "Error: path %s already exists and is not a socket (mode %s)\n", *sockPath, fi.Mode())
			return 1
		}

		// Check if another dtfm instance is already actively listening on this socket
		conn, dialErr := net.DialTimeout("unix", *sockPath, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			fmt.Fprintf(stderr, "Error: another dtfm instance is already actively listening on socket %s\n", *sockPath)
			return 1
		}

		// Only unlink an existing socket when dial fails with ECONNREFUSED or ENOENT
		if errors.Is(dialErr, syscall.ECONNREFUSED) || errors.Is(dialErr, syscall.ENOENT) {
			if err := os.Remove(*sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(stderr, "Error removing stale socket %s: %v\n", *sockPath, err)
				return 1
			}
		} else {
			fmt.Fprintf(stderr, "Error probing socket %s: %v\n", *sockPath, dialErr)
			return 1
		}
	}

	// Note on remote forwarding: when using OpenSSH reverse socket forwarding (`ssh -R`),
	// the remote sshd creates the socket with permissions governed by `StreamLocalBindMask`
	// (default 0177) in sshd_config. Set `StreamLocalBindUnlink yes` to permit re-binding.
	//
	// Locally, set umask to 0077 before net.Listen so the socket file is created with 0600 permissions
	// atomically with zero permissions race window.
	oldUmask := syscall.Umask(0077)
	listener, err := net.Listen("unix", *sockPath)
	syscall.Umask(oldUmask)
	if err != nil {
		fmt.Fprintf(stderr, "Error listening on socket %s: %v\n", *sockPath, err)
		if len(*sockPath) > 100 {
			fmt.Fprintf(stderr, "Hint: Unix domain socket paths are limited to ~104 bytes on macOS/BSD and 108 bytes on Linux. Try using a shorter path via --socket (e.g. /tmp/lmdtfy-%d/lmdtfy.sock or ~/.lmdtfy.sock)\n", os.Getuid())
		}
		return 1
	}
	defer listener.Close()

	prompter := NewTerminalPrompter()
	defer prompter.Close()

	server := NewServer(listener, prompter)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		<-sigChan
		signal.Stop(sigChan)
		fmt.Println("\n🔴 Stopping dtfm session. Shutting down server and killing active child...")
		server.Shutdown()
	}()

	hostname, _ := os.Hostname()
	userName := protocol.CurrentUser()
	fmt.Fprintf(stdout, "🟢 dtfm session started.\nListening on: %s\nUser: %s @ %s\nWaiting for requests... (Press Ctrl+C to exit)\n\n", *sockPath, userName, hostname)

	if err := server.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintf(stderr, "dtfm server error: %v\n", err)
		return 1
	}
	return 0
}
