// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

func TestApprovalEOFRejection(t *testing.T) {
	// Rejection when stdin is dead (e.g. dtfm </dev/null)
	stdin := strings.NewReader("")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-1",
		Reason:  "Automated test",
		Command: "touch",
		Args:    []string{"PWNED"},
	}

	decision, _, reason, err := prompter.Prompt(context.Background(), req)
	if decision != DecisionReject {
		t.Fatalf("SECURITY VIOLATION: Dead stdin resulted in decision %s; MUST be DecisionReject", decision)
	}
	if err == nil {
		t.Errorf("Expected EOF error from prompter")
	}
	if !strings.Contains(reason, "EOF") && !strings.Contains(reason, "closed") {
		t.Errorf("Unexpected reject reason: %s", reason)
	}
}

func TestApprovalEmptyEnterNotApproved(t *testing.T) {
	// Entering empty newline alone does NOT approve; only explicit 'y' or 'n'
	stdin := strings.NewReader("\n\nn\n")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-empty",
		Reason:  "Test empty enters",
		Command: "echo",
		Args:    []string{"hi"},
	}

	decision, _, _, _ := prompter.Prompt(context.Background(), req)
	if decision != DecisionReject {
		t.Fatalf("Empty enters followed by 'n' should have rejected, got %s", decision)
	}

	out := stdout.String()
	if !strings.Contains(out, "Empty response. Please explicitly type 'y', 'e', or 'n'") {
		t.Errorf("Expected prompt to warn about empty response, got output:\n%s", out)
	}
}

func TestApprovalExplicitYes(t *testing.T) {
	stdin := strings.NewReader("y\n")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-yes",
		Reason:  "Deploy",
		Command: "git",
		Args:    []string{"status"},
	}

	decision, _, _, err := prompter.Prompt(context.Background(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != DecisionApprove {
		t.Fatalf("Expected DecisionApprove, got %s", decision)
	}
}

func TestApprovalExplicitReject(t *testing.T) {
	stdin := strings.NewReader("n\nToo risky\n")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-no",
		Reason:  "Deploy",
		Command: "rm",
		Args:    []string{"-rf", "/"},
	}

	decision, _, reason, err := prompter.Prompt(context.Background(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != DecisionReject {
		t.Fatalf("Expected DecisionReject, got %s", decision)
	}
	if reason != "Too risky" {
		t.Errorf("Expected reject reason 'Too risky', got %q", reason)
	}
}

func TestApprovalEdit(t *testing.T) {
	stdin := strings.NewReader("e\necho modified\n")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-edit",
		Reason:  "Edit test",
		Command: "echo",
		Args:    []string{"original"},
	}

	decision, edited, _, err := prompter.Prompt(context.Background(), req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %s", decision)
	}
	if edited != "echo modified" {
		t.Errorf("Expected edited command 'echo modified', got %q", edited)
	}
}

func TestApprovalStaleKeystrokesDrainedNonVacuous(t *testing.T) {
	// Stale input of "y\n" must be drained so that real answer "n\n" rejects.
	// If draining were commented out, the prompt would consume "y\n" and approve.
	pr, pw := io.Pipe()
	defer pw.Close()

	prompter := NewStreamPrompter(pr, new(bytes.Buffer))
	defer prompter.Close()

	// Put stale partial "y" into partialLine timestamped before promptStartTime
	prompter.mu.Lock()
	prompter.partialLine = []byte("y")
	prompter.partialTime = time.Now().Add(-100 * time.Millisecond)
	prompter.mu.Unlock()

	// Now schedule the real answer "n\n" and reject reason "Declined\n"
	go func() {
		pw.Write([]byte("n\nDeclined\n"))
	}()

	req := protocol.CommandRequest{
		ID:      "test-drain-real",
		Reason:  "Stale keystroke test",
		Command: "echo",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	decision, _, reason, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if decision != DecisionReject {
		t.Fatalf("SECURITY FAILURE: Stale 'y' approved request; expected DecisionReject, got %s", decision)
	}
	if reason != "Declined" {
		t.Errorf("Expected reject reason 'Declined', got %q", reason)
	}
}

func TestApprovalEnvKeyTerminalEscapeSanitized(t *testing.T) {
	// Terminal-escape injection through env KEYS.
	// Repro: send exec with env key X\x1b[2K\r\x1b[1A\x1b[2K   Command: \x1b[1;32mls
	stdin := strings.NewReader("n\n")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	maliciousKey := "X\x1b[2K\r\x1b[1A\x1b[2K   Command: \x1b[1;32mls"
	req := protocol.CommandRequest{
		ID:      "test-esc-key",
		Reason:  "Test escape in env key",
		Command: "rm",
		Args:    []string{"-rf", "/important"},
		Env: map[string]string{
			maliciousKey: "value",
		},
	}

	_, _, _, _ = prompter.Prompt(context.Background(), req)

	promptOutput := stdout.String()
	// Assert no raw \x1b (0x1b byte) appears in the output
	if strings.Contains(promptOutput, "\x1b[2K") || strings.Contains(promptOutput, "\x1b[1A") {
		t.Fatalf("SECURITY VIOLATION: Raw ANSI escape sequence found in prompt output:\n%q", promptOutput)
	}
	// The literal string \x1b should be visible
	if !strings.Contains(promptOutput, `\x1b[2K`) {
		t.Errorf("Expected escaped \\x1b[2K in prompt output, got:\n%s", promptOutput)
	}
}

func TestApprovalDangerousEnvDisplayAndSanitization(t *testing.T) {
	// Dangerous env vars must be stripped and flagged, including '=' injection
	stdin := strings.NewReader("y\n")
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-env",
		Reason:  "Test env injection",
		Command: "echo",
		Args:    []string{"hello"},
		Env: map[string]string{
			"LD_PRELOAD":      "/evil.so",
			"BASH_ENV":        "/evil.sh",
			"PATH=/tmp/evil:": "/usr/bin",
			"SAFE_VAR":        "hello",
		},
	}

	decision, _, _, err := prompter.Prompt(context.Background(), req)
	if err != nil {
		t.Fatalf("Prompt error: %v", err)
	}
	if decision != DecisionApprove {
		t.Fatalf("Expected DecisionApprove, got %s", decision)
	}

	out := stdout.String()
	if !strings.Contains(out, "BLOCKED DANGEROUS") {
		t.Errorf("Expected prompt to display blocked dangerous env vars warning, got:\n%s", out)
	}
	if !strings.Contains(out, "PATH=/tmp/evil:") {
		t.Errorf("Expected '=' key injection to be reported in warning banner, got:\n%s", out)
	}
	if !strings.Contains(out, "SAFE_VAR=hello") {
		t.Errorf("Expected prompt to display safe environment variables, got:\n%s", out)
	}
}

func TestBackToBackTimeoutRace(t *testing.T) {
	// Two back-to-back requests where the first times out.
	// Must NOT trigger data race on bufio.Reader under -race,
	// and must NOT allow the second request to be stolen or corrupted.
	pr, pw := io.Pipe()
	defer pw.Close()

	var out bytes.Buffer

	prompter := NewStreamPrompter(pr, &out)
	defer prompter.Close()

	// Request 1 times out
	ctx1, cancel1 := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel1()

	req1 := protocol.CommandRequest{ID: "r1", Reason: "Req 1", Command: "echo"}
	dec1, _, _, err1 := prompter.Prompt(ctx1, req1)
	if dec1 != DecisionTimeout || err1 == nil {
		t.Fatalf("Expected DecisionTimeout for request 1, got %s (err: %v)", dec1, err1)
	}

	// User types response for Request 2 while prompt is presented
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = pw.Write([]byte("y\n"))
	}()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel2()

	req2 := protocol.CommandRequest{ID: "r2", Reason: "Req 2", Command: "echo"}
	dec2, _, _, err2 := prompter.Prompt(ctx2, req2)
	if err2 != nil {
		t.Fatalf("Unexpected error for request 2: %v", err2)
	}
	if dec2 != DecisionApprove {
		t.Fatalf("Expected DecisionApprove for request 2, got %s", dec2)
	}
}

func TestPTYStaleKeystrokesDiscarded(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("termios ioctls only supported on linux and darwin")
	}
	// A stale keystroke typed while idle must be flushed from
	// the kernel tty input queue via platform-specific ioctl (TCFLSH on Linux,
	// TIOCFLUSH on Darwin) so it does NOT approve a subsequent prompt.
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	var stdout bytes.Buffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// Write stale "y\n" to ptmx while idle (simulating user typing before prompt arrives)
	if _, err := ptmx.Write([]byte("y\n")); err != nil {
		t.Fatalf("Failed to write to PTY: %v", err)
	}

	// Small pause so the kernel PTY driver buffers the keystrokes
	time.Sleep(50 * time.Millisecond)

	req := protocol.CommandRequest{
		ID:      "test-pty-stale",
		Reason:  "PTY stale test",
		Command: "touch",
		Args:    []string{"PWNED"},
	}

	// Bound prompt wait to 200ms
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	decision, _, _, _ := prompter.Prompt(ctx, req)
	if decision == DecisionApprove {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Stale keystroke in kernel tty queue approved the command!")
	}
	if decision != DecisionTimeout {
		t.Fatalf("Expected DecisionTimeout waiting for real user input, got %s", decision)
	}
}

func TestTermiosSaveAndRestore(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("termios ioctls only supported on linux and darwin")
	}
	// Ensure termios state can be retrieved and restored
	// using platform-specific ioctl definitions (TCGETS/TCSETSF on Linux, TIOCGETA/TIOCSETAF on Darwin).
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	initial, err := getTermios(pts.Fd())
	if err != nil {
		t.Fatalf("Failed to get initial termios: %v", err)
	}

	// Restore termios settings
	if err := restoreTermios(pts.Fd(), initial); err != nil {
		t.Fatalf("Failed to restore termios: %v", err)
	}
}

func TestApprovalAgentDisconnectMessage(t *testing.T) {
	// Verify disconnect cause prints friendly message and rejects with ErrClientDisconnected
	stdin, stdinWriter := io.Pipe()
	defer stdinWriter.Close()
	var stdout bytes.Buffer

	prompter := NewStreamPrompter(stdin, &stdout)
	defer prompter.Close()

	ctx, cancel := context.WithCancelCause(context.Background())

	req := protocol.CommandRequest{
		ID:      "test-disconnect",
		Reason:  "Automated test",
		Command: "echo",
		Args:    []string{"hello"},
	}

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel(ErrClientDisconnected)
	}()

	decision, _, _, err := prompter.Prompt(ctx, req)
	if decision != DecisionReject {
		t.Fatalf("Expected DecisionReject on client disconnect, got %s", decision)
	}
	if !errors.Is(err, ErrClientDisconnected) {
		t.Errorf("Expected ErrClientDisconnected, got %v", err)
	}
	if !strings.Contains(stdout.String(), "Agent disconnected — request cancelled") {
		t.Errorf("Expected disconnect message in output, got: %s", stdout.String())
	}
}

func TestPTYPartialKeystrokeSurvivingTimeout(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("PTY tests only supported on linux and darwin")
	}
	// Regression test: Request 1 times out after partial 'y' (no newline) is written.
	// When Request 2 arrives, bare newline alone must NOT combine with stale 'y' to approve Request 2.
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	var stdout bytes.Buffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// Request 1 with 100ms timeout
	ctx1, cancel1 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel1()

	req1 := protocol.CommandRequest{ID: "r1", Reason: "Req 1", Command: "echo"}
	go func() {
		// Type partial 'y' without newline during Request 1
		time.Sleep(30 * time.Millisecond)
		_, _ = ptmx.Write([]byte("y"))
	}()

	dec1, _, _, _ := prompter.Prompt(ctx1, req1)
	if dec1 != DecisionTimeout {
		t.Fatalf("Expected Request 1 to time out, got %s", dec1)
	}

	// Request 2 with 300ms timeout
	ctx2, cancel2 := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel2()

	req2 := protocol.CommandRequest{ID: "r2", Reason: "Req 2", Command: "touch", Args: []string{"PWNED"}}
	go func() {
		// Bare newline entered on Request 2
		time.Sleep(50 * time.Millisecond)
		_, _ = ptmx.Write([]byte("\n"))
	}()

	dec2, _, _, _ := prompter.Prompt(ctx2, req2)
	if dec2 == DecisionApprove {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Stale partial 'y' from Request 1 combined with newline to auto-approve Request 2!")
	}
}

func TestMultiLinePrefetchNotAutoApproved(t *testing.T) {
	// Regression test: "y\ny\n" written in a single chunk during Request 1.
	// The second "y\n" must NOT be carried over in bufio.Reader to auto-approve Request 2.
	pr, pw := io.Pipe()
	defer pw.Close()

	var stdout bytes.Buffer
	prompter := NewStreamPrompter(pr, &stdout)
	defer prompter.Close()

	// Single chunk write containing multi-line input
	go func() {
		_, _ = pw.Write([]byte("y\ny\n"))
	}()

	ctx1, cancel1 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel1()

	req1 := protocol.CommandRequest{ID: "r1", Reason: "Req 1", Command: "echo"}
	dec1, _, _, err1 := prompter.Prompt(ctx1, req1)
	if err1 != nil || dec1 != DecisionApprove {
		t.Fatalf("Expected Request 1 to be approved, got %s (err: %v)", dec1, err1)
	}

	// Request 2 with 100ms timeout and NO more writes
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()

	req2 := protocol.CommandRequest{ID: "r2", Reason: "Req 2", Command: "touch", Args: []string{"PWNED"}}
	dec2, _, _, _ := prompter.Prompt(ctx2, req2)
	if dec2 == DecisionApprove {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Leftover 'y\\n' in bufio.Reader auto-approved Request 2!")
	}
	if dec2 != DecisionTimeout {
		t.Fatalf("Expected Request 2 to time out waiting for fresh input, got %s", dec2)
	}
}

func TestApprovalRejectTimeoutInReason(t *testing.T) {
	// Regression test: Operator enters 'n', then prompt for optional reason times out.
	// Decision must remain DecisionReject with "Declined by operator", NOT DecisionTimeout.
	pr, pw := io.Pipe()
	defer pw.Close()

	var stdout bytes.Buffer
	prompter := NewStreamPrompter(pr, &stdout)
	defer prompter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()

	go func() {
		// Type 'n' followed by newline, then pause so optional reason prompt times out
		_, _ = pw.Write([]byte("n\n"))
	}()

	req := protocol.CommandRequest{ID: "r-rej", Reason: "Reject test", Command: "rm"}
	dec, _, reason, err := prompter.Prompt(ctx, req)
	if dec != DecisionReject {
		t.Fatalf("Expected DecisionReject, got %s", dec)
	}
	if err != nil {
		t.Fatalf("Expected nil error on explicit reject, got %v", err)
	}
	if reason != "Declined by operator" {
		t.Fatalf("Expected 'Declined by operator', got %q", reason)
	}
}

func TestPTYPartialKeystrokeWithCtrlDSurvivingTimeout(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Skipf("PTY not available in this environment: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	var stdout bytes.Buffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// Request 1: Operator types 'y' followed by Ctrl+D (\x04), which flushes 'y' to read(2)
	// without a newline in canonical mode. Request 1 times out.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel1()

	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = ptmx.Write([]byte("y\x04"))
	}()

	req1 := protocol.CommandRequest{ID: "r1", Reason: "Req 1", Command: "echo"}
	dec1, _, _, _ := prompter.Prompt(ctx1, req1)
	if dec1 == DecisionApprove {
		t.Fatalf("Request 1 should not have been approved by partial input 'y'")
	}

	// Request 2: Operator presses bare Enter (\n). The stale 'y' must NOT combine with \n!
	ctx2, cancel2 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel2()

	req2 := protocol.CommandRequest{ID: "r2", Reason: "Req 2", Command: "rm", Args: []string{"-rf", "/"}}

	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = ptmx.Write([]byte("\n"))
	}()

	dec2, _, _, _ := prompter.Prompt(ctx2, req2)
	if dec2 == DecisionApprove {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Stale 'y' flushed via Ctrl+D combined with bare newline to auto-approve Request 2!")
	}
}

func TestStreamPartialKeystrokeSurvivingTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	var stdout bytes.Buffer
	prompter := NewStreamPrompter(pr, &stdout)
	defer prompter.Close()

	// Request 1: Partial byte 'y' written without newline. Request 1 times out.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel1()

	go func() {
		time.Sleep(10 * time.Millisecond)
		_, _ = pw.Write([]byte("y"))
	}()

	req1 := protocol.CommandRequest{ID: "r1", Reason: "Req 1", Command: "echo"}
	dec1, _, _, _ := prompter.Prompt(ctx1, req1)
	if dec1 == DecisionApprove {
		t.Fatalf("Request 1 should not have been approved by partial 'y'")
	}

	// Request 2: Bare Enter '\n' written. Stale 'y' must NOT combine with '\n'!
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()

	req2 := protocol.CommandRequest{ID: "r2", Reason: "Req 2", Command: "rm"}
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = pw.Write([]byte("\n"))
	}()

	dec2, _, _, _ := prompter.Prompt(ctx2, req2)
	if dec2 == DecisionApprove {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Stale stream 'y' combined with newline to auto-approve Request 2!")
	}
}

func TestPTYCtrlDDoesNotBrickSubsequentPrompts(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Skipf("PTY not available: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	var stdout bytes.Buffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// Request 1: Operator presses Ctrl+D on empty line
	ctx1, cancel1 := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel1()

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = ptmx.Write([]byte("\x04"))
	}()

	req1 := protocol.CommandRequest{ID: "r1", Reason: "Req 1", Command: "echo"}
	dec1, _, _, _ := prompter.Prompt(ctx1, req1)
	if dec1 == DecisionApprove {
		t.Fatalf("Request 1 should not be approved on Ctrl+D")
	}

	// Request 2: Operator types 'y\n'. Prompter must still be alive and accept approval!
	// Wait out the 300ms post-abort cooldown so DrainPendingInput does not discard Request 2's input
	time.Sleep(350 * time.Millisecond)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel2()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = ptmx.Write([]byte("y\n"))
	}()

	req2 := protocol.CommandRequest{ID: "r2", Reason: "Req 2", Command: "echo", Args: []string{"safe"}}
	dec2, _, _, err2 := prompter.Prompt(ctx2, req2)
	if err2 != nil || dec2 != DecisionApprove {
		t.Fatalf("Prompter was bricked by Ctrl+D: Request 2 failed with decision %s, err: %v", dec2, err2)
	}

	// Request 3: Times out while idle (no input)
	ctx3, cancel3 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel3()
	req3 := protocol.CommandRequest{ID: "r3", Reason: "Req 3", Command: "echo"}
	dec3, _, _, _ := prompter.Prompt(ctx3, req3)
	if dec3 == DecisionApprove {
		t.Fatalf("Request 3 should not be approved on timeout")
	}

	// While idle between prompts, operator presses Ctrl+D (\x04).
	// This pushes an EOF lineResult into linesChan that drainLinesChan must not latch into streamErr!
	time.Sleep(50 * time.Millisecond)
	_, _ = ptmx.Write([]byte("\x04"))
	// Wait out the 300ms post-abort cooldown before Request 4 so DrainPendingInput does not discard Request 4's input
	time.Sleep(300 * time.Millisecond)

	// Request 4: Operator approves with 'y\n'. Prompter must still be alive!
	ctx4, cancel4 := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel4()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = ptmx.Write([]byte("y\n"))
	}()

	req4 := protocol.CommandRequest{ID: "r4", Reason: "Req 4", Command: "echo", Args: []string{"still-working"}}
	dec4, _, _, err4 := prompter.Prompt(ctx4, req4)
	if err4 != nil || dec4 != DecisionApprove {
		t.Fatalf("Prompter was bricked by idle Ctrl+D: Request 4 failed with decision %s, err: %v", dec4, err4)
	}
}

func TestApprovalLongPromptViewportSummary(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	var stdout bytes.Buffer
	prompter := NewStreamPrompter(pr, &stdout)
	defer prompter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = pw.Write([]byte("n\nNo thanks\n"))
	}()

	longReason := strings.Repeat("A", 600)
	longCmd := "echo " + strings.Repeat("B", 350)
	req := protocol.CommandRequest{
		ID:      "long-req",
		Reason:  longReason,
		Command: longCmd,
		Cwd:     ".",
	}

	_, _, _, _ = prompter.Prompt(ctx, req)
	out := stdout.String()

	// Verify reason truncation in banner
	if !strings.Contains(out, "... [truncated]") {
		t.Errorf("Expected truncated reason in banner, got output: %s", out)
	}
	// Verify head + tail + truncation warning in Target preview
	if !strings.Contains(out, " ... [truncated] ... ") {
		t.Errorf("Expected head+tail truncated command in Target line, got: %s", out)
	}
	if !strings.Contains(out, "Full command exceeds viewport") {
		t.Errorf("Expected viewport command length warning, got: %s", out)
	}
	// Verify bottom Target preview line
	if !strings.Contains(out, "Target:") || !strings.Contains(out, "cwd: .") {
		t.Errorf("Expected Target preview summary before prompt, got: %s", out)
	}
	// Verify relative Cwd resolved
	if !strings.Contains(out, "(-> ") {
		t.Errorf("Expected relative cwd '.' to show resolved path (-> ...), got: %s", out)
	}
}

func TestApprovalLongCwdAndNonExistentIntermediate(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()

	var stdout bytes.Buffer
	prompter := NewStreamPrompter(pr, &stdout)
	defer prompter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = pw.Write([]byte("n\n"))
	}()

	// Path with nonexistent intermediate directory must be flagged as nonexistent
	nonexistentPath := "/tmp/dtfm_nonexistent_dir_99999/../tmp"
	req := protocol.CommandRequest{
		ID:      "nonexistent-cwd-req",
		Reason:  "Testing nonexistent cwd",
		Command: "ls",
		Cwd:     nonexistentPath,
	}

	_, _, _, _ = prompter.Prompt(ctx, req)
	out := stdout.String()

	if !strings.Contains(out, "Directory does not exist locally") {
		t.Errorf("Expected nonexistent warning for path with nonexistent intermediate component, got: %s", out)
	}
}

func TestApprovalContrastNoBrightCyan(t *testing.T) {
	// Verify that bright cyan (\033[1;36m) is NOT present in prompter output.
	// Bold blue (\033[1;34m) should be used instead for high contrast across light/dark themes.
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	var stdout bytes.Buffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-contrast",
		Reason:  "High contrast color check",
		Command: "ls",
		Args:    []string{"-la"},
		Cwd:     "/tmp",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_, _ = ptmx.Write([]byte("n\nDeclined\n"))
	}()

	_, _, _, _ = prompter.Prompt(ctx, req)
	output := stdout.String()

	if strings.Contains(output, "\033[1;36m") {
		t.Errorf("CRITICAL CONTRAST BUG: Found washed-out bright cyan \\033[1;36m in terminal output:\n%s", output)
	}
	if !strings.Contains(output, "\033[1;34m") {
		t.Errorf("Expected high-contrast bold blue \\033[1;34m in terminal output:\n%s", output)
	}
}

func TestWYSIWYGExecutionBannerForEditedCommand(t *testing.T) {
	var stdout bytes.Buffer
	executor := NewCommandExecutor(&stdout, &stdout)

	ctx := context.Background()
	resp := executor.ExecuteShell(ctx, "test-edit-banner", "echo 'hello from ivan'", "", time.Now())
	if resp.ExitCode != 0 {
		t.Fatalf("Expected exit code 0, got %d", resp.ExitCode)
	}

	out := stdout.String()
	if !strings.Contains(out, "⚡ Executing (edited): echo 'hello from ivan'") {
		t.Errorf("Expected WYSIWYG execution banner '⚡ Executing (edited): echo 'hello from ivan'', got:\n%s", out)
	}
	if strings.Contains(out, "/bash --noprofile") || strings.Contains(out, "/sh -c") {
		t.Errorf("Execution banner exposed internal shell wrapper:\n%s", out)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func waitForPromptOutput(buf *syncBuffer, substr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestPTYInteractiveEditPrepopulatedDefault(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-pty-edit-default",
		Reason:  "PTY edit test",
		Command: "echo",
		Args:    []string{"hello world"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Send "e\n" to enter edit mode, then "\r" to accept pre-populated command
	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("\r"))
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	expected := "echo 'hello world'"
	if edited != expected {
		t.Errorf("Expected pre-populated default command %q, got %q", expected, edited)
	}
}

func TestPTYInteractiveEditWithArrowAndBackspace(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-pty-edit-arrow",
		Reason:  "PTY edit arrow test",
		Command: "echo",
		Args:    []string{"cat"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pre-populated buffer is `echo cat`.
	// Operator types "e\n" to enter edit mode.
	// In edit mode:
	// Press Backspace 3 times (deleting 'cat') -> `echo `
	// Type 'dog' -> `echo dog`
	// Press Enter (\r)
	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("\x7f\x7f\x7fdog\r"))
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if edited != "echo dog" {
		t.Errorf("Expected edited command 'echo dog', got %q", edited)
	}
}

func TestPTYInteractiveEditLeftArrowInsertion(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-pty-edit-left",
		Reason:  "PTY edit left arrow",
		Command: "rm",
		Args:    []string{"file.txt"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pre-populated is `rm file.txt`. Length is 11.
	// Cursor starts at end (index 11).
	// Move left 8 times (over `file.txt` to right after `rm `).
	// Type `-i `
	// Buffer becomes `rm -i file.txt`.
	// Press Enter (\r).
	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		var seq []byte
		for i := 0; i < 8; i++ {
			seq = append(seq, []byte("\x1b[D")...)
		}
		seq = append(seq, []byte("-i \r")...)
		_, _ = ptmx.Write(seq)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if edited != "rm -i file.txt" {
		t.Errorf("Expected edited command 'rm -i file.txt', got %q", edited)
	}
}

func TestPTYInteractiveEditHomeEnd(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-pty-edit-home",
		Reason:  "PTY edit home test",
		Command: "ls",
		Args:    []string{"-l"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Pre-populated is `ls -l`.
	// Press Home (\x1b[H), type "sudo " -> `sudo ls -l`
	// Press End (\x1b[F), type " /tmp" -> `sudo ls -l /tmp`
	// Press Enter (\r)
	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		seq := []byte("\x1b[Hsudo \x1b[F /tmp\r")
		_, _ = ptmx.Write(seq)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if edited != "sudo ls -l /tmp" {
		t.Errorf("Expected edited command 'sudo ls -l /tmp', got %q", edited)
	}
}

func TestPTYInteractiveEditCtrlC(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-pty-edit-ctrlc",
		Reason:  "PTY edit ctrl-c test",
		Command: "rm",
		Args:    []string{"-rf", "/"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("\x03")) // Ctrl+C
	}()

	decision, _, reason, err := prompter.Prompt(ctx, req)
	if decision != DecisionReject {
		t.Fatalf("Expected DecisionReject on Ctrl+C, got %v (err: %v)", decision, err)
	}
	if !strings.Contains(reason, "Cancelled") && !strings.Contains(reason, "operator") {
		t.Errorf("Expected reject reason to mention cancellation, got %q", reason)
	}
}

func TestPTYEmptyEditRePromptDrainBypass(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-empty-edit-drain-bypass",
		Reason:  "Prevent empty edit auto-approval bypass",
		Command: "rm",
		Args:    []string{"-rf", "/"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		// Enter edit mode
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Clear line (\x15), press enter (\r), and immediately type-ahead "y\n"
		_, _ = ptmx.Write([]byte("\x15\r\ny\n"))

		// Wait for the re-prompt message "No command entered. Please choose again."
		if !waitForPromptOutput(&stdout, "No command entered", 2*time.Second) {
			return
		}
		// Give prompter 50ms to drain the queued "y\n"
		time.Sleep(50 * time.Millisecond)

		// Send explicit reject ("n\n")
		_, _ = ptmx.Write([]byte("n\nDeclined test\n"))
	}()

	decision, _, reason, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	// The buffered "y\n" MUST have been drained so the command was NOT auto-approved!
	if decision != DecisionReject {
		t.Fatalf("SECURITY VIOLATION: Empty edit allowed buffered 'y' to auto-approve! Decision was %v", decision)
	}
	if !strings.Contains(reason, "Declined") {
		t.Errorf("Expected reject reason to contain 'Declined', got %q", reason)
	}
}

func TestPTYECMA48CSIEscapesDropTilde(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-ecma48-tilde-drop",
		Reason:  "Ensure CSI sequence trailing tildes are not leaked into command",
		Command: "rm",
		Args:    []string{"-rf", "/build"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}

		// Move left 5 characters (to between -rf and /build)
		// Send Insert (\033[2~), PgUp (\033[5~), PgDn (\033[6~), F5 (\033[15~), SGR mouse (\033[<0;20;10M)
		// None of these should insert '~' or leak!
		seq := []byte("\033[D\033[D\033[D\033[D\033[D" +
			"\033[2~" +
			"\033[5~" +
			"\033[6~" +
			"\033[15~" +
			"\033[<0;20;10M" +
			"\r")
		_, _ = ptmx.Write(seq)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	// The original command was "rm -rf /build". If '~' leaked, it would be "rm -rf ~~~~.../build"
	expected := "rm -rf /build"
	if edited != expected {
		t.Fatalf("SECURITY VIOLATION: CSI sequence leaked trailing bytes into command! Expected %q, got %q", expected, edited)
	}
}

func TestPTYBracketedPasteNewlineHandling(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-bracketed-paste",
		Reason:  "Bracketed paste multiline safety",
		Command: "echo",
		Args:    []string{"init"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Clear line (\x15), send Bracketed Paste Start (\033[200~), multiline text with newlines, Bracketed Paste End (\033[201~), then Enter (\r)
		pasteSeq := []byte("\x15\033[200~echo line1\necho line2\r\n\033[201~\r")
		_, _ = ptmx.Write(pasteSeq)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	// In bracketed paste, newlines should be converted to space and not submit prematurely
	if !strings.Contains(edited, "echo line1") || !strings.Contains(edited, "echo line2") {
		t.Fatalf("Expected edited command to contain both pasted lines, got %q", edited)
	}
}

func TestPTYEditContextTimeoutNoHangOrStolenKeystroke(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req1 := protocol.CommandRequest{
		ID:      "test-timeout-req1",
		Reason:  "Timeout request 1",
		Command: "rm",
		Args:    []string{"-rf", "/"},
	}

	ctx1, cancel1 := context.WithCancel(context.Background())

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Simulate client disconnect / timeout while operator is in edit mode
		cancel1()
	}()

	decision1, _, _, _ := prompter.Prompt(ctx1, req1)
	if decision1 != DecisionTimeout && decision1 != DecisionReject {
		t.Fatalf("Expected DecisionTimeout or DecisionReject on cancelled context, got %v", decision1)
	}

	// Now immediately send second prompt on the same prompter
	req2 := protocol.CommandRequest{
		ID:      "test-timeout-req2",
		Reason:  "Followup request 2",
		Command: "echo",
		Args:    []string{"recovered"},
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	go func() {
		if !waitForPromptOutput(&stdout, "Followup request 2", 2*time.Second) {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = ptmx.Write([]byte("y\n"))
	}()

	decision2, _, _, err := prompter.Prompt(ctx2, req2)
	if err != nil {
		t.Fatalf("Unexpected prompt 2 error: %v", err)
	}
	if decision2 != DecisionApprove {
		t.Fatalf("Expected prompt 2 to succeed with DecisionApprove, got %v", decision2)
	}
}

func TestPrompterConcurrentCloseRace(t *testing.T) {
	var stdout syncBuffer
	r, w := io.Pipe()
	prompter := NewStreamPrompter(r, &stdout)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = prompter.Close()
		}()
	}
	wg.Wait()
	_ = w.Close()
}

func TestPTYLongCommandHorizontalScrolling(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// 150-char command that easily exceeds 80 columns
	longArg := strings.Repeat("A", 140)
	req := protocol.CommandRequest{
		ID:      "test-long-command-scroll",
		Reason:  "Horizontal scrolling test",
		Command: "echo",
		Args:    []string{longArg},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Press Enter to submit
		_, _ = ptmx.Write([]byte("\r"))
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if !strings.Contains(edited, longArg) {
		t.Fatalf("Expected edited command to contain full long argument")
	}

	// Verify that the redraw line contains horizontal scroll indicator '<'
	output := stdout.String()
	if !strings.Contains(output, "> <") {
		t.Errorf("Expected output to contain left-scroll indicator '> <', got: %s", output)
	}
}

func TestPromptCommandExceedsMaxEditRunesRefusesEdit(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// Command exceeding maxEditRunes (64 * 1024)
	giantArg := strings.Repeat("x", maxEditRunes+50)
	req := protocol.CommandRequest{
		ID:      "test-giant-command",
		Reason:  "Giant command edit refusal",
		Command: "echo",
		Args:    []string{giantArg},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		// Attempt to edit
		_, _ = ptmx.Write([]byte("e\n"))
		// Wait for refusal warning
		if !waitForPromptOutput(&stdout, "exceeds maximum interactive edit length", 2*time.Second) {
			return
		}
		time.Sleep(50 * time.Millisecond)
		// Now choose run 'y'
		_, _ = ptmx.Write([]byte("y\n"))
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionApprove {
		t.Fatalf("Expected DecisionApprove after edit was refused, got %v", decision)
	}
	if edited != "" {
		t.Errorf("Expected edited to be empty on direct approval, got %q", edited)
	}
}

func TestLineBufOverflowRejects(t *testing.T) {
	var stdout syncBuffer
	r, w := io.Pipe()
	prompter := NewStreamPrompter(r, &stdout)
	defer prompter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		// Write a 70 KB line without newline, followed by newline
		chunk := strings.Repeat("A", 70*1024)
		_, _ = w.Write([]byte(chunk + "\n"))
	}()

	req := protocol.CommandRequest{
		ID:      "test-line-overflow",
		Reason:  "Line overflow test",
		Command: "echo",
		Args:    []string{"hi"},
	}

	decision, _, reason, err := prompter.Prompt(ctx, req)
	if decision != DecisionReject {
		t.Fatalf("Expected DecisionReject for overflow line, got %v", decision)
	}
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum length") {
		t.Errorf("Expected 'exceeds maximum length' error, got %v (reason: %q)", err, reason)
	}
}

func TestPTYLoneUTF8LeadByteTimeoutNoRaceOrStolenKeystroke(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req1 := protocol.CommandRequest{
		ID:      "test-lone-utf8-req1",
		Reason:  "Lone UTF8 test 1",
		Command: "rm",
		Args:    []string{"-rf", "/"},
	}

	ctx1, cancel1 := context.WithCancel(context.Background())

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Write lone UTF-8 lead byte (0xC3) without continuation bytes
		_, _ = ptmx.Write([]byte{0xC3})
		time.Sleep(20 * time.Millisecond)
		// Cancel ctx1 while lone lead byte is pending
		cancel1()
	}()

	decision1, _, _, _ := prompter.Prompt(ctx1, req1)
	if decision1 != DecisionTimeout && decision1 != DecisionReject {
		t.Fatalf("Expected prompt 1 to terminate with Timeout/Reject, got %v", decision1)
	}

	// Immediately run prompt 2
	req2 := protocol.CommandRequest{
		ID:      "test-lone-utf8-req2",
		Reason:  "Lone UTF8 followup req2",
		Command: "echo",
		Args:    []string{"recovered"},
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()

	go func() {
		if !waitForPromptOutput(&stdout, "Lone UTF8 followup req2", 2*time.Second) {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_, _ = ptmx.Write([]byte("y\n"))
	}()

	decision2, _, _, err := prompter.Prompt(ctx2, req2)
	if err != nil {
		t.Fatalf("Unexpected prompt 2 error: %v", err)
	}
	if decision2 != DecisionApprove {
		t.Fatalf("Expected prompt 2 to approve cleanly, got %v", decision2)
	}
}

func TestClosedPipePOLLHUPImmediateRejectAndCloseUnblocks(t *testing.T) {
	// Part A: Closed pipe POLLHUP
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	var stdout syncBuffer
	prompter := newPrompter(r, &stdout, r)

	// Close write end immediately
	_ = w.Close()

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()

	req1 := protocol.CommandRequest{
		ID:      "test-pollhup-req",
		Reason:  "POLLHUP test",
		Command: "echo",
		Args:    []string{"eof"},
	}

	start := time.Now()
	decision, _, _, _ := prompter.Prompt(ctx1, req1)
	elapsed := time.Since(start)
	if decision != DecisionReject {
		t.Fatalf("Expected DecisionReject on closed pipe POLLHUP, got %v", decision)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("Prompt took %v to detect POLLHUP EOF, expected immediate return (<1s)", elapsed)
	}
	_ = prompter.Close()

	// Part B: prompter.Close() unblocks active Prompt()
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	defer w2.Close()

	var stdout2 syncBuffer
	prompter2 := newPrompter(r2, &stdout2, r2)

	doneCh := make(chan ApprovalDecision, 1)
	go func() {
		dec, _, _, _ := prompter2.Prompt(context.Background(), req1)
		doneCh <- dec
	}()

	time.Sleep(100 * time.Millisecond)
	_ = prompter2.Close()

	select {
	case dec := <-doneCh:
		if dec != DecisionReject {
			t.Fatalf("Expected DecisionReject on prompter.Close(), got %v", dec)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("prompter.Close() hung and failed to unblock active Prompt()")
	}
}

func TestPTYBracketedPasteEmitAndCRLFFilter(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-bracketed-paste-filter",
		Reason:  "Bracketed paste filter test",
		Command: "echo",
		Args:    []string{"init"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}

		// Clear line (\x15), send Bracketed Paste Start (\033[200~),
		// text with CRLF and ignored control bytes (\x07, \x04), Bracketed Paste End (\033[201~), then Enter (\r)
		pasteSeq := []byte("\x15\033[200~echo line1\r\necho line2\r\n\x07\x04\033[201~\r")
		_, _ = ptmx.Write(pasteSeq)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	expected := "echo line1 echo line2"
	if edited != expected {
		t.Fatalf("Expected edited command %q, got %q", expected, edited)
	}

	// Verify terminal output contains \033[?2004h and \033[?2004l
	out := stdout.String()
	if !strings.Contains(out, "\033[?2004h") {
		t.Errorf("Expected stdout to contain bracketed paste enable sequence \\033[?2004h")
	}
	if !strings.Contains(out, "\033[?2004l") {
		t.Errorf("Expected stdout to contain bracketed paste disable sequence \\033[?2004l")
	}
}

func TestPTYWideCJKRunesInRedraw(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// 60 CJK ideographs = 120 display columns
	cjkArg := strings.Repeat("中", 60)
	req := protocol.CommandRequest{
		ID:      "test-cjk-redraw",
		Reason:  "CJK redraw test",
		Command: "echo",
		Args:    []string{cjkArg},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Move cursor left 10 runes
		for i := 0; i < 10; i++ {
			_, _ = ptmx.Write([]byte("\033[D"))
		}
		time.Sleep(50 * time.Millisecond)
		// Submit
		_, _ = ptmx.Write([]byte("\r"))
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if !strings.Contains(edited, cjkArg) {
		t.Fatalf("Expected edited command to contain full CJK argument")
	}

	// Verify that redraw output contains horizontal scroll indicators '<' or '>'
	out := stdout.String()
	if !strings.Contains(out, "> <") && !strings.Contains(out, ">") {
		t.Errorf("Expected redraw output to contain horizontal scroll marker '<' or '>', got: %s", out)
	}
}

func TestPTYLargeCommandRedrawPerformanceAndBackspaceLeftPull(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// 60,000-rune command
	largeArg := strings.Repeat("a", 60000)
	req := protocol.CommandRequest{
		ID:      "test-large-redraw-perf",
		Reason:  "Large command redraw performance test",
		Command: "echo",
		Args:    []string{largeArg},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	doneCh := make(chan time.Duration, 1)

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		t0 := time.Now()
		// Enter edit mode
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Press Backspace 5 times at the end of the 60,000-char buffer and hit Enter
		_, _ = ptmx.Write([]byte("\x7f\x7f\x7f\x7f\x7f\r"))
		doneCh <- time.Since(t0)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	expectedLen := len("echo ") + 60000 - 5
	if len(edited) != expectedLen {
		t.Fatalf("Expected edited length %d, got %d", expectedLen, len(edited))
	}

	select {
	case dur := <-doneCh:
		if dur > 500*time.Millisecond {
			t.Errorf("Interactive edit on 60,000-rune command took %v (> 500ms), potential O(N^2) redraw freeze", dur)
		}
	default:
	}

	// Verify that the viewport after backspacing still has '<' left indicator and is populated
	out := stdout.String()
	if !strings.Contains(out, "> <") {
		t.Errorf("Expected stdout to retain left-scroll indicator '> <' after backspacing")
	}
}

func TestPTYEditCtrlCEnforcesLastAbortCooldownBeforeQueuedRequest(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req1 := protocol.CommandRequest{
		ID:      "test-req-1",
		Reason:  "Request 1",
		Command: "echo",
		Args:    []string{"first"},
	}

	ctx1, cancel1 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel1()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		// Enter edit mode then press Ctrl+C
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("\x03"))
	}()

	decision1, _, _, err1 := prompter.Prompt(ctx1, req1)
	if err1 != nil {
		t.Fatalf("Unexpected prompt 1 error: %v", err1)
	}
	if decision1 != DecisionReject {
		t.Fatalf("Expected DecisionReject for Ctrl+C, got %v", decision1)
	}

	prompter.mu.Lock()
	abortTime := prompter.lastAbortTime
	prompter.mu.Unlock()

	if abortTime.IsZero() || time.Since(abortTime) > 500*time.Millisecond {
		t.Fatalf("Expected lastAbortTime to be set recently upon edit Ctrl+C, got %v", abortTime)
	}

	req2 := protocol.CommandRequest{
		ID:      "test-req-2",
		Reason:  "Request 2",
		Command: "echo",
		Args:    []string{"second"},
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()

	// Write 'y\n' immediately into ptmx during the 300ms cooldown window.
	// DrainPendingInput in Prompt 2 MUST drain it and wait for cooldown.
	_, _ = ptmx.Write([]byte("y\n"))

	// Then after 350ms from abortTime, write 'n\n' which should be the actual decision.
	go func() {
		time.Sleep(350 * time.Millisecond)
		_, _ = ptmx.Write([]byte("n\n"))
	}()

	start2 := time.Now()
	decision2, _, _, _ := prompter.Prompt(ctx2, req2)
	elapsed2 := time.Since(start2)

	// Since 'y\n' was sent during cooldown, it must have been drained, so Prompt 2
	// should receive 'n\n' and reject rather than auto-approving with 'y\n'!
	if decision2 != DecisionReject {
		t.Fatalf("SECURITY VIOLATION: Stale keystrokes during edit abort cooldown auto-approved request 2 (got %v)", decision2)
	}
	if elapsed2 < 200*time.Millisecond {
		t.Errorf("Expected Prompt 2 to respect 300ms cooldown window, but completed in %v", elapsed2)
	}
}

func TestPTYMultiESCPasteSequenceRecognition(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	req := protocol.CommandRequest{
		ID:      "test-multiesc-paste",
		Reason:  "Multi ESC paste test",
		Command: "echo",
		Args:    []string{"initial"},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		// Send multiple ESC bytes before bracketed paste start and end
		pasteSeq := []byte("\x15\033\033\033[200~echo multiesc\033\033[201~\r")
		_, _ = ptmx.Write(pasteSeq)
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if edited != "echo multiesc" {
		t.Fatalf("Expected edited command %q, got %q", "echo multiesc", edited)
	}
}

func TestPTYWideSymbolColumnBounds(t *testing.T) {
	// Verify runeDisplayWidth classifies wide/narrow symbols accurately
	if runeDisplayWidth('✓') != 1 {
		t.Errorf("Expected '✓' (U+2713) to be 1 display column, got %d", runeDisplayWidth('✓'))
	}
	if runeDisplayWidth('⬛') != 2 {
		t.Errorf("Expected '⬛' (U+2B1B) to be 2 display columns, got %d", runeDisplayWidth('⬛'))
	}
	if runeDisplayWidth('⬜') != 2 {
		t.Errorf("Expected '⬜' (U+2B1C) to be 2 display columns, got %d", runeDisplayWidth('⬜'))
	}
	if runeDisplayWidth('⭐') != 2 {
		t.Errorf("Expected '⭐' (U+2B50) to be 2 display columns, got %d", runeDisplayWidth('⭐'))
	}
	if runeDisplayWidth('⭕') != 2 {
		t.Errorf("Expected '⭕' (U+2B55) to be 2 display columns, got %d", runeDisplayWidth('⭕'))
	}

	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	go func() {
		_, _ = io.Copy(io.Discard, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	// 60 wide black square symbols = 120 display columns
	wideArg := strings.Repeat("⬛", 60)
	req := protocol.CommandRequest{
		ID:      "test-wide-symbol-bounds",
		Reason:  "Wide symbol bounds test",
		Command: "echo",
		Args:    []string{wideArg},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "Approve execution?", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("e\n"))
		if !waitForPromptOutput(&stdout, "Edit command", 2*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("\r"))
	}()

	decision, edited, _, err := prompter.Prompt(ctx, req)
	if err != nil {
		t.Fatalf("Unexpected prompt error: %v", err)
	}
	if decision != DecisionEdit {
		t.Fatalf("Expected DecisionEdit, got %v", decision)
	}
	if !strings.Contains(edited, wideArg) {
		t.Fatalf("Expected edited command to contain full wide argument")
	}

	// Verify horizontal scroll indicator '<' is emitted for wide symbols
	out := stdout.String()
	if !strings.Contains(out, "> <") {
		t.Errorf("Expected redraw output to contain horizontal scroll marker '> <' for wide symbols")
	}
}

func TestCommandNeedsSudoAndPrepareSudoArgs(t *testing.T) {
	if !commandNeedsSudo("sudo", []string{"apt", "update"}, "") {
		t.Error("Expected direct sudo command to require sudo")
	}
	if !commandNeedsSudo("/usr/bin/sudo", []string{"id"}, "") {
		t.Error("Expected /usr/bin/sudo to require sudo")
	}
	if !commandNeedsSudo("bash", []string{"-c", "echo hi && sudo id"}, "") {
		t.Error("Expected bash -c with sudo to require sudo")
	}
	if commandNeedsSudo("echo", []string{"sudo"}, "") {
		t.Error("Expected 'echo sudo' not to require sudo")
	}
	if !commandNeedsSudo("echo", []string{"hi"}, "sudo whoami") {
		t.Error("Expected edited command containing sudo to require sudo")
	}
	if commandNeedsSudo("sudo", []string{"id"}, "id") {
		t.Error("Expected edited command removing sudo not to require sudo")
	}

	got := prepareSudoArgs("sudo", []string{"apt", "update"})
	want := []string{"-S", "-p", "", "apt", "update"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("prepareSudoArgs mismatch: got %v, want %v", got, want)
	}

	gotAlready := prepareSudoArgs("sudo", []string{"-S", "apt", "update"})
	if len(gotAlready) != 3 || gotAlready[0] != "-S" {
		t.Errorf("Expected existing -S not to be duplicated, got %v", gotAlready)
	}

	gotCombined := prepareSudoArgs("sudo", []string{"-kS", "id"})
	if len(gotCombined) != 2 || gotCombined[0] != "-kS" {
		t.Errorf("Expected combined -kS flag not to duplicate -S, got %v", gotCombined)
	}

	gotShell := prepareSudoArgs("bash", []string{"--noprofile", "--norc", "-c", "sudo id"})
	if len(gotShell) != 4 || !strings.Contains(gotShell[3], "command sudo -S -p ''") {
		t.Errorf("Expected shell -c sudo wrapper injection, got %v", gotShell)
	}
}

func TestMemclrScrubsPassword(t *testing.T) {
	pw := []byte("super-secret-sudo-password")
	memclr(pw)
	for i, b := range pw {
		if b != 0 {
			t.Fatalf("Expected byte %d to be 0 after memclr, got %d", i, b)
		}
	}
}

func TestPromptPasswordPTYNoEchoAndTimeout(t *testing.T) {
	ptmx, pts, err := pty.Open()
	if err != nil {
		t.Fatalf("Failed to open PTY: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()

	var ptyOut syncBuffer
	go func() {
		_, _ = io.Copy(&ptyOut, ptmx)
	}()

	var stdout syncBuffer
	prompter := newPrompter(pts, &stdout, pts)
	defer prompter.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		if !waitForPromptOutput(&stdout, "🔑 [sudo] Password:", 1*time.Second) {
			return
		}
		_, _ = ptmx.Write([]byte("hunter2-secret\n"))
	}()

	pw, err := prompter.PromptPassword(ctx)
	if err != nil {
		t.Fatalf("PromptPassword failed: %v", err)
	}
	if string(pw) != "hunter2-secret" {
		t.Fatalf("Expected password %q, got %q", "hunter2-secret", string(pw))
	}
	if strings.Contains(ptyOut.String(), "hunter2-secret") {
		t.Errorf("Password was echoed to PTY output: %q", ptyOut.String())
	}

	// Verify timeout when no password is entered
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer shortCancel()
	_, err = prompter.PromptPassword(shortCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected context.DeadlineExceeded on password timeout, got %v", err)
	}
}
