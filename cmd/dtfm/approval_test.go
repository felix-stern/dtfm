package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"strings"
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

	// Put stale "y\n" into linesChan timestamped before promptStartTime
	prompter.linesChan <- lineResult{
		line:      "y\n",
		timestamp: time.Now().Add(-100 * time.Millisecond),
	}

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

	prompter := newPrompter(pts, pts, pts)
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

	// Verify terminal flush works on the PTY
	if err := flushTTYInput(pts.Fd()); err != nil {
		t.Fatalf("Failed to flush TTY input on PTY: %v", err)
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

	prompter := newPrompter(pts, pts, pts)
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
	ctx2, cancel2 := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel2()

	go func() {
		time.Sleep(30 * time.Millisecond)
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
