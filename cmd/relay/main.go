// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
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

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `dtfm-relay — In-memory streaming WebSocket relay server for dtfm and lmdtfy

Usage:
  relay [options]

Options:
  --listen <addr>            HTTP/WebSocket listen address (default: :8088)
  --idle-timeout <dur>       Session idle timeout before automatic eviction (default: 10m)
  --max-sessions <count>     Maximum concurrent in-memory sessions (default: 10000)
  --max-sessions-per-ip <n>  Maximum concurrent sessions per IP (default: 64, 0 = disabled)
  --trusted-proxies <cidrs>  Comma-separated list of trusted proxy CIDRs/IPs (default: 127.0.0.0/8,::1/128)
  --verbose                  Enable verbose operational logging
  -v, --version              Display version and exit
  -h, --help                 Display help and exit
`)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	fs.SetOutput(stderr)

	listenAddr := fs.String("listen", ":8088", "HTTP/WebSocket listen address")
	idleTimeout := fs.Duration("idle-timeout", defaultIdleTimeout, "Session idle timeout before eviction")
	maxSessions := fs.Int("max-sessions", defaultMaxSessions, "Maximum concurrent sessions")
	maxSessionsPerIP := fs.Int("max-sessions-per-ip", defaultMaxSessionsPerIP, "Maximum concurrent sessions per IP (0 = disabled)")
	trustedProxiesStr := fs.String("trusted-proxies", "127.0.0.0/8,::1/128", "Comma-separated list of trusted proxy CIDRs/IPs for forwarded headers")
	verbose := fs.Bool("verbose", false, "Enable verbose operational logging")
	showVersion := fs.Bool("version", false, "Display version and exit")
	showVersionShort := fs.Bool("v", false, "Display version and exit")
	showHelp := fs.Bool("help", false, "Display help and exit")
	showHelpShort := fs.Bool("h", false, "Display help and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			printUsage(stdout)
			return 0
		}
		return 1
	}

	if *showHelp || *showHelpShort {
		printUsage(stdout)
		return 0
	}

	if *showVersion || *showVersionShort {
		fmt.Fprintf(stdout, "dtfm-relay %s\n", getVersion())
		return 0
	}

	explicitMaxPerIP := false
	explicitTrustedProxies := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "max-sessions-per-ip" {
			explicitMaxPerIP = true
		}
		if f.Name == "trusted-proxies" {
			explicitTrustedProxies = true
		}
	})

	var trustedProxies []*net.IPNet
	if explicitTrustedProxies && strings.TrimSpace(*trustedProxiesStr) == "" {
		trustedProxies = []*net.IPNet{}
	} else {
		var err error
		trustedProxies, err = ParseTrustedProxies(*trustedProxiesStr)
		if err != nil {
			fmt.Fprintf(stderr, "Error parsing --trusted-proxies: %v\n", err)
			return 1
		}
	}

	var logWriter io.Writer
	if *verbose {
		logWriter = stderr
	}

	hub := NewHubWithConfig(HubConfig{
		IdleTimeout:      *idleTimeout,
		MaxSessions:      *maxSessions,
		MaxSessionsPerIP: *maxSessionsPerIP,
		TrustedProxies:   trustedProxies,
		ExemptLoopback:   !explicitMaxPerIP,
		LogWriter:        logWriter,
	})
	defer hub.Close()

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           hub,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8192,
	}

	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, os.Interrupt, syscall.SIGTERM)

	serverErr := make(chan error, 1)
	go func() {
		fmt.Fprintf(stdout, "🟢 dtfm-relay %s listening on %s (idle timeout: %v, max sessions: %d)\n",
			getVersion(), *listenAddr, *idleTimeout, *maxSessions)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case sig := <-shutdownCh:
		fmt.Fprintf(stdout, "\n🔴 Caught signal %v, shutting down relay server gracefully...\n", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		return 0
	case err := <-serverErr:
		fmt.Fprintf(stderr, "Error starting relay server: %v\n", err)
		return 1
	}
}
