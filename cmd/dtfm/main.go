package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

func main() {
	fs := flag.NewFlagSet("dtfm", flag.ExitOnError)
	sockPath := fs.String("socket", protocol.DefaultSocketPath(), "Path to listen Unix domain socket")
	_ = fs.Parse(os.Args[1:])

	// Ensure and validate socket directory security (ownership, non-symlink, mode 0700 for shared runtime paths)
	if err := protocol.EnsureSocketDir(*sockPath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// If path exists, verify it is actually a socket before touching or removing it
	if fi, err := os.Lstat(*sockPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			fmt.Fprintf(os.Stderr, "Error: path %s already exists and is not a socket (mode %s)\n", *sockPath, fi.Mode())
			os.Exit(1)
		}

		// Check if another dtfm instance is already actively listening on this socket
		conn, dialErr := net.DialTimeout("unix", *sockPath, 200*time.Millisecond)
		if dialErr == nil {
			_ = conn.Close()
			fmt.Fprintf(os.Stderr, "Error: another dtfm instance is already actively listening on socket %s\n", *sockPath)
			os.Exit(1)
		}

		// Only unlink an existing socket when dial fails with ECONNREFUSED or ENOENT
		if errors.Is(dialErr, syscall.ECONNREFUSED) || errors.Is(dialErr, syscall.ENOENT) {
			if err := os.Remove(*sockPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(os.Stderr, "Error removing stale socket %s: %v\n", *sockPath, err)
				os.Exit(1)
			}
		} else {
			fmt.Fprintf(os.Stderr, "Error probing socket %s: %v\n", *sockPath, dialErr)
			os.Exit(1)
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
		fmt.Fprintf(os.Stderr, "Error listening on socket %s: %v\n", *sockPath, err)
		if len(*sockPath) > 100 {
			fmt.Fprintf(os.Stderr, "Hint: Unix domain socket paths are limited to ~104 bytes on macOS/BSD and 108 bytes on Linux. Try using a shorter path via --socket (e.g. /tmp/lmdtfy-%d/lmdtfy.sock or ~/.lmdtfy.sock)\n", os.Getuid())
		}
		os.Exit(1)
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
	fmt.Printf("🟢 dtfm session started.\nListening on: %s\nUser: %s @ %s\nWaiting for requests... (Press Ctrl+C to exit)\n\n", *sockPath, userName, hostname)

	if err := server.Serve(); err != nil && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintf(os.Stderr, "dtfm server error: %v\n", err)
	}
}
