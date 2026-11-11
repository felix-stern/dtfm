// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRelayCLIFlags(t *testing.T) {
	// 1. --help exits 0 and prints usage
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	code := run([]string{"--help"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("expected code 0 for --help, got %d", code)
	}
	if !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("expected usage in stdout, got %q", stdout.String())
	}

	// 2. -v exits 0 and prints version
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-v"}, stdout, stderr)
	if code != 0 {
		t.Fatalf("expected code 0 for -v, got %d", code)
	}
	if !strings.Contains(stdout.String(), "dtfm-relay") {
		t.Fatalf("expected version in stdout, got %q", stdout.String())
	}

	// 3. Invalid --trusted-proxies exits 1
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"--trusted-proxies", "not-an-ip"}, stdout, stderr)
	if code != 1 {
		t.Fatalf("expected code 1 for invalid trusted proxies, got %d", code)
	}
	if !strings.Contains(stderr.String(), "Error parsing --trusted-proxies") {
		t.Fatalf("expected error in stderr, got %q", stderr.String())
	}
}
