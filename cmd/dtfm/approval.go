package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
	"golang.org/x/sys/unix"
)

type ApprovalDecision string

const (
	DecisionApprove ApprovalDecision = "approve"
	DecisionEdit    ApprovalDecision = "edit"
	DecisionReject  ApprovalDecision = "reject"
	DecisionTimeout ApprovalDecision = "timeout"
)

// ErrClientDisconnected is returned when the remote client closes its connection
// while waiting for human operator approval.
var ErrClientDisconnected = errors.New("client disconnected")

// Prompter provides a cancellable interface for interacting with the human operator.
type Prompter interface {
	Prompt(ctx context.Context, req protocol.CommandRequest) (decision ApprovalDecision, editedCmd string, rejectReason string, err error)
	Close() error
}

type lineResult struct {
	line      string
	err       error
	timestamp time.Time
}

// TerminalPrompter handles user interaction via a terminal or stream.
// It uses a demand-gated reader goroutine so reading occurs ONLY when Prompt()
// requests input. This guarantees zero concurrent reads on /dev/tty while
// approved commands (like sudo or ssh) run in CommandExecutor.Execute.
type TerminalPrompter struct {
	reader          *bufio.Reader
	writer          io.Writer
	file            *os.File // underlying file descriptor (if any)
	isTTY           bool     // true only if file is an actual character terminal device
	linesChan       chan lineResult
	wantLine        chan struct{} // demand-gate: signals readLoop to read exactly one line
	done            chan struct{}
	mu              sync.Mutex
	reading         bool      // true if readLoop is currently blocked in ReadString
	streamErr       error     // permanently tracks stream closure / EOF
	promptStartTime time.Time // timestamp when active prompt was presented
	lastAbortTime   time.Time // timestamp when previous prompt ended via timeout/disconnect
}

func (p *TerminalPrompter) useColor() bool {
	return p.isTTY && os.Getenv("NO_COLOR") == ""
}

func (p *TerminalPrompter) colorCyan(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;36m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorGreen(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;32m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorRed(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;31m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorBold(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

// NewTerminalPrompter creates a prompter reading from /dev/tty if available,
// falling back to os.Stdin/os.Stdout (e.g. for testing or headless environments).
func NewTerminalPrompter() *TerminalPrompter {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		return newPrompter(tty, tty, tty)
	}
	return newPrompter(os.Stdin, os.Stdout, os.Stdin)
}

// NewStreamPrompter creates a prompter using explicit reader and writer (ideal for tests).
func NewStreamPrompter(r io.Reader, w io.Writer) *TerminalPrompter {
	return newPrompter(r, w, nil)
}

func newPrompter(r io.Reader, w io.Writer, f *os.File) *TerminalPrompter {
	isTTY := false
	if f != nil {
		if fi, err := f.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice != 0) {
			isTTY = true
		}
	}

	p := &TerminalPrompter{
		reader:    bufio.NewReader(r),
		writer:    w,
		file:      f,
		isTTY:     isTTY,
		linesChan: make(chan lineResult, 32),
		wantLine:  make(chan struct{}, 1),
		done:      make(chan struct{}),
	}

	// Single dedicated demand-gated reader goroutine
	go p.readLoop()

	return p
}

func (p *TerminalPrompter) readLoop() {
	var lineBuf []byte
	var lineStartTime time.Time

	for {
		// Wait until Prompt() explicitly requests a line
		select {
		case <-p.wantLine:
		case <-p.done:
			return
		}

		for {
			b, err := p.reader.ReadByte()
			now := time.Now()

			if err != nil {
				p.mu.Lock()
				p.reading = false
				p.mu.Unlock()

				if p.isTTY && errors.Is(err, io.EOF) {
					// On a terminal, Ctrl+D delivers EOF without closing /dev/tty.
					// Discard partial line, send EOF to cancel active prompt, but keep readLoop alive.
					lineBuf = lineBuf[:0]
					select {
					case p.linesChan <- lineResult{err: io.EOF, timestamp: now}:
					case <-p.done:
						return
					}
					break
				}

				p.mu.Lock()
				p.streamErr = err
				p.mu.Unlock()

				select {
				case p.linesChan <- lineResult{line: string(lineBuf), err: err, timestamp: now}:
				case <-p.done:
				}
				return
			}

			p.mu.Lock()
			promptStart := p.promptStartTime
			p.mu.Unlock()

			if len(lineBuf) > 0 && !promptStart.IsZero() && lineStartTime.Before(promptStart) {
				// Partial keystrokes from an earlier cancelled/timed-out prompt must be discarded
				lineBuf = lineBuf[:0]
				lineStartTime = now
			}

			if len(lineBuf) == 0 {
				lineStartTime = now
			}

			if b == '\n' {
				p.mu.Lock()
				p.reading = false
				p.mu.Unlock()

				res := lineResult{line: string(lineBuf) + "\n", timestamp: lineStartTime}
				lineBuf = lineBuf[:0]

				select {
				case p.linesChan <- res:
				case <-p.done:
					return
				}
				break
			}

			lineBuf = append(lineBuf, b)
		}
	}
}

// requestLine signals readLoop to read exactly one line if not already reading.
func (p *TerminalPrompter) requestLine() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.reading || p.streamErr != nil {
		return
	}

	select {
	case p.wantLine <- struct{}{}:
		p.reading = true
	default:
	}
}

// Close terminates the background reader goroutine and closes /dev/tty if opened.
func (p *TerminalPrompter) Close() error {
	select {
	case <-p.done:
		return nil
	default:
		close(p.done)
	}
	if p.file != nil && p.file != os.Stdin {
		return p.file.Close()
	}
	return nil
}

func (p *TerminalPrompter) drainLinesChan() {
	for {
		select {
		case res := <-p.linesChan:
			if res.err != nil && !(p.isTTY && errors.Is(res.err, io.EOF)) {
				p.mu.Lock()
				p.streamErr = res.err
				p.mu.Unlock()
			}
		default:
			return
		}
	}
}

// DrainPendingInput clears any queued keystrokes from the lines channel, the user-space
// bufio.Reader buffer, and the OS kernel input queue.
func (p *TerminalPrompter) DrainPendingInput() error {
	// 1. Drain pending lines already in the Go channel, preserving any terminal error
	p.drainLinesChan()

	// 2. Unconditionally flush OS kernel terminal buffer whenever isTTY && file != nil.
	// (flushTTYInput is a driver ioctl that safely flushes the kernel queue even while read() is in flight)
	if p.isTTY && p.file != nil {
		signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		err := flushTTYInput(p.file.Fd())
		signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
		if err != nil {
			return fmt.Errorf("failed to flush terminal input queue: %w", err)
		}
	}

	// 3. Re-drain channel once after flushing kernel queue
	p.drainLinesChan()

	p.mu.Lock()
	if !p.reading && p.reader.Buffered() > 0 {
		_, _ = p.reader.Discard(p.reader.Buffered())
	}
	p.mu.Unlock()

	return nil
}

// readLineWithContext waits for a line of input or context cancellation.
// It discards any line entered before the current prompt was displayed.
func (p *TerminalPrompter) readLineWithContext(ctx context.Context) (string, error) {
	for {
		// First check if there is an already queued line in linesChan
		select {
		case res := <-p.linesChan:
			if res.err != nil {
				return "", res.err
			}
			p.mu.Lock()
			start := p.promptStartTime
			p.mu.Unlock()
			if !start.IsZero() && res.timestamp.Before(start) {
				// Discard stale keystroke entered before prompt was presented
				continue
			}
			return res.line, nil
		default:
		}

		p.mu.Lock()
		err := p.streamErr
		p.mu.Unlock()
		if err != nil {
			return "", err
		}

		// Request readLoop to read next line on demand
		p.requestLine()

		// Wait for line from readLoop or context cancellation
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case res := <-p.linesChan:
			if res.err != nil {
				return "", res.err
			}
			p.mu.Lock()
			start := p.promptStartTime
			p.mu.Unlock()
			if !start.IsZero() && res.timestamp.Before(start) {
				// Discard stale keystroke entered before prompt was presented
				continue
			}
			return res.line, nil
		}
	}
}

// handleContextErr prints and returns appropriate cancellation or timeout decisions.
func (p *TerminalPrompter) handleContextErr(ctx context.Context, timeoutMsg string) (ApprovalDecision, string, string, error) {
	p.mu.Lock()
	p.lastAbortTime = time.Now()
	p.mu.Unlock()

	if errors.Is(context.Cause(ctx), ErrClientDisconnected) {
		fmt.Fprintln(p.writer, "\n🔌 Agent disconnected — request cancelled.")
		return DecisionReject, "", "Agent disconnected — request cancelled", context.Cause(ctx)
	}
	if errors.Is(context.Cause(ctx), ErrServerShutdown) {
		fmt.Fprintln(p.writer, "\n🔴 Server shutting down — request cancelled.")
		return DecisionReject, "", "Server is shutting down", context.Cause(ctx)
	}
	fmt.Fprintf(p.writer, "\n⏳ %s\n", timeoutMsg)
	return DecisionTimeout, "", timeoutMsg, ctx.Err()
}

// Prompt presents the request to the human operator and collects an explicit decision.
func (p *TerminalPrompter) Prompt(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
	if p.isTTY && p.file != nil {
		if fg, err := unix.IoctlGetInt(int(p.file.Fd()), unix.TIOCGPGRP); err == nil && fg > 0 {
			if fg != syscall.Getpgrp() {
				fmt.Fprintln(p.writer, "\n❌ Server process is running in background. Request rejected.")
				return DecisionReject, "", "Server process is running in background", errors.New("terminal prompter not in foreground process group")
			}
		}
	}

	p.mu.Lock()
	lastAbort := p.lastAbortTime
	p.mu.Unlock()
	if p.isTTY && !lastAbort.IsZero() {
		if elapsed := time.Since(lastAbort); elapsed < 300*time.Millisecond {
			rem := 300*time.Millisecond - elapsed
			select {
			case <-time.After(rem):
			case <-ctx.Done():
				return p.handleContextErr(ctx, "Cancelled during cooldown")
			}
		}
	}

	p.mu.Lock()
	streamErr := p.streamErr
	p.mu.Unlock()

	if streamErr != nil {
		fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
		return DecisionReject, "", "Input stream closed or unavailable (EOF)", streamErr
	}

	// Drain stale keystrokes so Enter pressed while idle does NOT approve this request.
	// Fail closed if the terminal input queue cannot be flushed.
	if err := p.DrainPendingInput(); err != nil {
		fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
		return DecisionReject, "", "cannot flush terminal input", err
	}

	p.mu.Lock()
	streamErr = p.streamErr
	p.mu.Unlock()
	if streamErr != nil {
		fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
		return DecisionReject, "", "Input stream closed or unavailable (EOF)", streamErr
	}

	// Sanitize all untrusted agent inputs without deleting bytes
	cleanReason := protocol.SanitizeTerminalText(req.Reason)
	cleanCmd := protocol.FormatCommand(req.Command, req.Args)
	cleanCwd := protocol.SanitizeTerminalText(req.Cwd)
	displayCwd := cleanCwd
	if len([]rune(displayCwd)) > 240 {
		displayCwd = string([]rune(displayCwd)[:240]) + "... [truncated]"
	}
	targetCwd := cleanCwd
	if len([]rune(targetCwd)) > 80 {
		targetCwd = string([]rune(targetCwd)[:80]) + "... [truncated]"
	}

	// Sanitize and render environment variables as defense-in-depth for standalone Prompter callers
	// (note: Server rejects requests with non-empty Env upfront before prompting).
	cleanEnv, blockedKeys := protocol.SanitizeEnv(req.Env)

	displayReason := cleanReason
	if len([]rune(cleanReason)) > 500 {
		displayReason = string([]rune(cleanReason)[:500]) + "... [truncated]"
	}

	fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(p.writer, "🔔 LMDTFY Command Execution Request:")
	fmt.Fprintf(p.writer, "   Reason:  %s\n", p.colorCyan(displayReason))
	fmt.Fprintf(p.writer, "   Command: %s\n", p.colorGreen(cleanCmd))
	if cleanCwd != "" {
		cwdWarning := ""
		if st, err := os.Stat(req.Cwd); err != nil || !st.IsDir() {
			cwdWarning = " " + p.colorRed("(⚠️ Directory does not exist locally — execution will fail unless directory exists)")
		} else {
			if evalCwd, err := filepath.EvalSymlinks(req.Cwd); err == nil {
				if realCwd, err := filepath.Abs(evalCwd); err == nil && realCwd != req.Cwd {
					sanitizedReal := protocol.SanitizeTerminalText(realCwd)
					if len([]rune(sanitizedReal)) > 240 {
						sanitizedReal = string([]rune(sanitizedReal)[:240]) + "... [truncated]"
					}
					cwdWarning = " " + p.colorCyan(fmt.Sprintf("(-> %s)", sanitizedReal))
				}
			}
		}
		fmt.Fprintf(p.writer, "   Cwd:     %s%s\n", p.colorCyan(displayCwd), cwdWarning)
	}

	// Sanitize every blocked key so terminal escapes (CSI/OSC) cannot spoof output
	if len(blockedKeys) > 0 {
		sanitizedBlocked := make([]string, len(blockedKeys))
		for i, k := range blockedKeys {
			sanitizedBlocked[i] = protocol.SanitizeTerminalText(k)
		}
		fmt.Fprintf(p.writer, "   %s %s\n", p.colorRed("⚠️  BLOCKED DANGEROUS / MALFORMED ENV VARS:"), strings.Join(sanitizedBlocked, ", "))
	}

	// Display clean environment variables in deterministic sorted order
	if len(cleanEnv) > 0 {
		fmt.Fprintln(p.writer, "   Environment:")
		sortedKeys := make([]string, 0, len(cleanEnv))
		for k := range cleanEnv {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)
		for _, k := range sortedKeys {
			fmt.Fprintf(p.writer, "      %s=%s\n", protocol.SanitizeTerminalText(k), protocol.SanitizeTerminalText(cleanEnv[k]))
		}
	}
	fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	if len(cleanCmd) > 300 || len(cleanReason) > 300 || len(cleanCwd) > 200 {
		cmdRunes := []rune(cleanCmd)
		cmdPreview := cleanCmd
		if len(cmdRunes) > 160 {
			cmdPreview = string(cmdRunes[:100]) + " ... [truncated] ... " + string(cmdRunes[len(cmdRunes)-60:])
			fmt.Fprintf(p.writer, "   %s\n", p.colorRed(fmt.Sprintf("⚠️  Full command exceeds viewport (%d chars, %d args) — scroll up to inspect before approving", len(cmdRunes), len(req.Args))))
		}
		if cleanCwd != "" {
			fmt.Fprintf(p.writer, "   Target:  %s (cwd: %s)\n", cmdPreview, targetCwd)
		} else {
			fmt.Fprintf(p.writer, "   Target:  %s\n", cmdPreview)
		}
		fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	}

	// Set promptStartTime AFTER DrainPendingInput and after the banner is presented to the operator
	p.mu.Lock()
	p.promptStartTime = time.Now()
	p.mu.Unlock()

	for {
		fmt.Fprintf(p.writer, "Approve execution? [%s] Run  [%s] Edit  [%s] Reject: ", p.colorBold("y"), p.colorBold("e"), p.colorBold("n"))
		line, err := p.readLineWithContext(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return p.handleContextErr(ctx, "Timed out waiting for operator approval.")
			}
			// On EOF / dead stdin / read error, NEVER auto-approve! Always reject.
			fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
			return DecisionReject, "", "Input stream closed or unavailable (EOF)", err
		}

		choice := strings.TrimSpace(strings.ToLower(line))
		switch choice {
		case "y", "yes":
			return DecisionApprove, "", "", nil

		case "e", "edit":
			fmt.Fprintf(p.writer, "Edit command (press Enter to run):\n> ")
			edited, err := p.readLineWithContext(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return p.handleContextErr(ctx, "Timed out waiting for operator input during edit")
				}
				return DecisionReject, "", "Input stream closed during edit", err
			}
			edited = strings.TrimSpace(edited)
			if edited == "" {
				fmt.Fprintln(p.writer, "No command entered. Please choose again.")
				continue
			}
			return DecisionEdit, edited, "", nil

		case "n", "no":
			fmt.Fprintf(p.writer, "Reject reason (optional): ")
			reason, err := p.readLineWithContext(ctx)
			if err != nil {
				// Operator explicitly rejected; timeout/EOF during optional reason must NOT flip decision to Timeout
				fmt.Fprintln(p.writer)
				return DecisionReject, "", "Declined by operator", nil
			}
			reason = strings.TrimSpace(reason)
			if reason == "" {
				reason = "Declined by operator"
			}
			fmt.Fprintln(p.writer, "❌ Request rejected.")
			return DecisionReject, "", reason, nil

		case "":
			// Explicitly reject empty enter as approval
			fmt.Fprintln(p.writer, "Empty response. Please explicitly type 'y', 'e', or 'n'.")

		default:
			fmt.Fprintln(p.writer, "Invalid input. Please enter 'y', 'e', or 'n'.")
		}
	}
}
