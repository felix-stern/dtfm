// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

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

var (
	// ErrClientDisconnected is returned when the remote client closes its connection
	// while waiting for human operator approval.
	ErrClientDisconnected = errors.New("client disconnected")
	errEditCancelled      = errors.New("edit cancelled by operator")
	errPrompterBackground = errors.New("terminal prompter not in foreground process group")
	errPrompterClosed     = errors.New("prompter closed")
)

const (
	maxEditRunes = 64 * 1024
	maxLineBuf   = 64 * 1024
)

// Prompter provides a cancellable interface for interacting with the human operator.
type Prompter interface {
	Prompt(ctx context.Context, req protocol.CommandRequest) (decision ApprovalDecision, editedCmd string, rejectReason string, err error)
	Close() error
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
	wantLine        chan struct{}    // demand-gate: signals readLoop to read exactly one line
	wantEdit        chan editRequest // demand-gate: signals readLoop to run interactive edit
	done            chan struct{}
	loopDone        chan struct{} // closed when readLoop terminates
	closeOnce       sync.Once
	closeErr        error
	mu              sync.Mutex
	reading         bool      // true if readLoop is currently blocked in ReadString
	streamErr       error     // permanently tracks stream closure / EOF
	promptStartTime time.Time // timestamp when active prompt was presented
	lastAbortTime   time.Time // timestamp when previous prompt ended via timeout/disconnect
	editOrigTermios *termiosState
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
			if isTerminalFD(f.Fd()) {
				isTTY = true
				if wf, ok := w.(*os.File); ok {
					if !isTerminalFD(wf.Fd()) {
						isTTY = false
					}
				}
			}
		}
	}

	p := &TerminalPrompter{
		reader:    bufio.NewReader(r),
		writer:    &syncWriter{mu: &sync.Mutex{}, w: w},
		file:      f,
		isTTY:     isTTY,
		linesChan: make(chan lineResult, 32),
		wantLine:  make(chan struct{}, 1),
		wantEdit:  make(chan editRequest, 1),
		done:      make(chan struct{}),
		loopDone:  make(chan struct{}),
	}

	// Single dedicated demand-gated reader goroutine
	go p.readLoop()

	return p
}

// Close terminates the background reader goroutine and closes /dev/tty if opened.
func (p *TerminalPrompter) Close() error {
	p.closeOnce.Do(func() {
		close(p.done)
		select {
		case <-p.loopDone:
		case <-time.After(300 * time.Millisecond):
		}
		p.restoreEditMode()
		if p.file != nil && p.file != os.Stdin {
			p.closeErr = p.file.Close()
		}
	})
	return p.closeErr
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
	displayCmd, totalCmdLines, flatCmdPreview := p.formatCommandDisplay(req, cleanCmd)
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

	var banner strings.Builder
	fmt.Fprintln(&banner, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(&banner, "🔔 LMDTFY Command Execution Request:")
	fmt.Fprintf(&banner, "   Reason:  %s\n", p.colorBlue(displayReason))
	fmt.Fprintf(&banner, "   Command: %s\n", displayCmd)
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
					cwdWarning = " " + p.colorBlue(fmt.Sprintf("(-> %s)", sanitizedReal))
				}
			}
		}
		fmt.Fprintf(&banner, "   Cwd:     %s%s\n", p.colorBlue(displayCwd), cwdWarning)
	}

	// Sanitize every blocked key so terminal escapes (CSI/OSC) cannot spoof output
	if len(blockedKeys) > 0 {
		sanitizedBlocked := make([]string, len(blockedKeys))
		for i, k := range blockedKeys {
			sanitizedBlocked[i] = protocol.SanitizeTerminalText(k)
		}
		fmt.Fprintf(&banner, "   %s %s\n", p.colorRed("⚠️  BLOCKED DANGEROUS / MALFORMED ENV VARS:"), strings.Join(sanitizedBlocked, ", "))
	}

	// Display clean environment variables in deterministic sorted order
	if len(cleanEnv) > 0 {
		fmt.Fprintln(&banner, "   Environment:")
		sortedKeys := make([]string, 0, len(cleanEnv))
		for k := range cleanEnv {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)
		for _, k := range sortedKeys {
			fmt.Fprintf(&banner, "      %s=%s\n", protocol.SanitizeTerminalText(k), protocol.SanitizeTerminalText(cleanEnv[k]))
		}
	}
	fmt.Fprintln(&banner, "────────────────────────────────────────────────────────────")

	bannerStr := banner.String()
	fmt.Fprint(p.writer, bannerStr)

	termCols, termRows := p.getTerminalSize()
	renderedRows := countRenderedRows(bannerStr, termCols)
	viewportRowLimit := max(termRows-4, 10)
	cmdRunes := []rune(cleanCmd)
	previewRunes := []rune(flatCmdPreview)
	cmdExceedsViewport := renderedRows > viewportRowLimit || len(previewRunes) > 160 || len(cmdRunes) > 160

	if cmdExceedsViewport || len(cleanReason) > 300 || len(cleanCwd) > 200 {
		cmdPreview := flatCmdPreview
		if len(previewRunes) > 160 {
			cmdPreview = string(previewRunes[:100]) + " ... [truncated] ... " + string(previewRunes[len(previewRunes)-60:])
		}
		if cmdExceedsViewport {
			if totalCmdLines > 1 {
				fmt.Fprintf(p.writer, "   %s\n", p.colorRed(fmt.Sprintf("⚠️  Full command exceeds viewport (%d lines, %d chars, %d args) — scroll up to inspect before approving", totalCmdLines, len(cmdRunes), len(req.Args))))
			} else {
				fmt.Fprintf(p.writer, "   %s\n", p.colorRed(fmt.Sprintf("⚠️  Full command exceeds viewport (%d chars, %d args) — scroll up to inspect before approving", len(cmdRunes), len(req.Args))))
			}
		}
		if cleanCwd != "" {
			fmt.Fprintf(p.writer, "   Target:  %s (cwd: %s)\n", cmdPreview, targetCwd)
		} else {
			fmt.Fprintf(p.writer, "   Target:  %s\n", cmdPreview)
		}
		fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	}

	isMultiline := totalCmdLines > 1

	// Set promptStartTime AFTER DrainPendingInput and after the banner is presented to the operator
	p.mu.Lock()
	p.promptStartTime = time.Now()
	p.mu.Unlock()

	for {
		if isMultiline {
			fmt.Fprintf(p.writer, "Approve execution? [%s] Run  [%s] Reject: ", p.colorBold("y"), p.colorBold("n"))
		} else {
			fmt.Fprintf(p.writer, "Approve execution? [%s] Run  [%s] Edit  [%s] Reject: ", p.colorBold("y"), p.colorBold("e"), p.colorBold("n"))
		}
		line, err := p.readLineWithContext(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return p.handleContextErr(ctx, "Timed out waiting for operator approval.")
			}
			// On EOF / dead stdin / read error, NEVER auto-approve! Always reject.
			p.mu.Lock()
			p.lastAbortTime = time.Now()
			p.mu.Unlock()
			fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
			return DecisionReject, "", "Input stream closed or unavailable (EOF)", err
		}

		choice := strings.TrimSpace(strings.ToLower(line))
		switch choice {
		case "y", "yes":
			return DecisionApprove, "", "", nil

		case "e", "edit":
			if isMultiline {
				fmt.Fprintf(p.writer, "⚠️  Inline edit is disabled for multiline commands. Choose [%s] Run, or [%s] Reject with feedback so the agent can resend.\n", p.colorBold("y"), p.colorBold("n"))
				if err := p.DrainPendingInput(); err != nil {
					fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
					return DecisionReject, "", "cannot flush terminal input", err
				}
				p.mu.Lock()
				p.promptStartTime = time.Now()
				p.mu.Unlock()
				continue
			}
			if len([]rune(cleanCmd)) > maxEditRunes {
				fmt.Fprintf(p.writer, "⚠️  Command exceeds maximum interactive edit length (%d > %d chars). Please choose [%s] Run or [%s] Reject.\n", len([]rune(cleanCmd)), maxEditRunes, p.colorBold("y"), p.colorBold("n"))
				if err := p.DrainPendingInput(); err != nil {
					fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
					return DecisionReject, "", "cannot flush terminal input", err
				}
				p.mu.Lock()
				p.promptStartTime = time.Now()
				p.mu.Unlock()
				continue
			}

			edited, err := p.promptEdit(ctx, cleanCmd)
			if err != nil {
				if ctx.Err() != nil {
					return p.handleContextErr(ctx, "Timed out waiting for operator input during edit")
				}
				p.mu.Lock()
				p.lastAbortTime = time.Now()
				p.mu.Unlock()
				if errors.Is(err, errPrompterBackground) {
					fmt.Fprintln(p.writer, "\n❌ Server process is running in background. Request rejected.")
					return DecisionReject, "", "Server process is running in background", err
				}
				if errors.Is(err, errPrompterClosed) {
					fmt.Fprintln(p.writer, "\n🔴 Prompter closed — request cancelled.")
					return DecisionReject, "", "Prompter closed", err
				}
				if errors.Is(err, io.EOF) {
					fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
					return DecisionReject, "", "Input stream closed or unavailable (EOF)", err
				}
				fmt.Fprintln(p.writer, "❌ Request cancelled.")
				return DecisionReject, "", "Cancelled by operator", nil
			}
			edited = strings.TrimSpace(edited)
			if edited == "" {
				fmt.Fprintln(p.writer, "No command entered. Please choose again.")
				if err := p.DrainPendingInput(); err != nil {
					fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
					return DecisionReject, "", "cannot flush terminal input", err
				}
				p.mu.Lock()
				p.promptStartTime = time.Now()
				p.mu.Unlock()
				continue
			}
			return DecisionEdit, edited, "", nil

		case "n", "no":
			fmt.Fprintf(p.writer, "Reject reason (optional): ")
			reason, err := p.readLineWithContext(ctx)
			if err != nil {
				// Operator explicitly rejected; timeout/EOF during optional reason must NOT flip decision to Timeout
				p.mu.Lock()
				p.lastAbortTime = time.Now()
				p.mu.Unlock()
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
			if isMultiline {
				fmt.Fprintln(p.writer, "Empty response. Please explicitly type 'y' or 'n'.")
			} else {
				fmt.Fprintln(p.writer, "Empty response. Please explicitly type 'y', 'e', or 'n'.")
			}
			if err := p.DrainPendingInput(); err != nil {
				fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
				return DecisionReject, "", "cannot flush terminal input", err
			}
			p.mu.Lock()
			p.promptStartTime = time.Now()
			p.mu.Unlock()

		default:
			if isMultiline {
				fmt.Fprintln(p.writer, "Invalid input. Please enter 'y' or 'n'.")
			} else {
				fmt.Fprintln(p.writer, "Invalid input. Please enter 'y', 'e', or 'n'.")
			}
			if err := p.DrainPendingInput(); err != nil {
				fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
				return DecisionReject, "", "cannot flush terminal input", err
			}
			p.mu.Lock()
			p.promptStartTime = time.Now()
			p.mu.Unlock()
		}
	}
}

// getTerminalSize returns the current terminal width and height via TIOCGWINSZ when
// attached to a TTY, defaulting independently per dimension to 80x24 when unavailable.
func (p *TerminalPrompter) getTerminalSize() (cols, rows int) {
	cols, rows = 80, 24
	if p.isTTY && p.file != nil {
		if ws, err := unix.IoctlGetWinsize(int(p.file.Fd()), unix.TIOCGWINSZ); err == nil {
			if ws.Col > 0 {
				cols = int(ws.Col)
			}
			if ws.Row > 0 {
				rows = int(ws.Row)
			}
		}
	}
	return cols, rows
}

// visibleLineWidth returns the terminal column width of s after stripping ANSI CSI SGR sequences.
func visibleLineWidth(s string) int {
	width := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7E) {
				j++
			}
			if j < len(s) {
				i = j + 1
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		width += runeDisplayWidth(r)
	}
	return width
}

// countRenderedRows computes how many terminal rows banner occupies at width termCols,
// accounting for embedded newlines, banner chrome, block headers, and horizontal line wrapping.
func countRenderedRows(banner string, termCols int) int {
	if termCols <= 0 {
		termCols = 80
	}
	banner = strings.TrimSuffix(banner, "\n")
	if banner == "" {
		return 0
	}
	rows := 0
	for _, line := range strings.Split(banner, "\n") {
		w := visibleLineWidth(line)
		if w <= 0 {
			rows++
		} else {
			rows += (w + termCols - 1) / termCols
		}
	}
	return rows
}

// formatCommandDisplay renders single-line commands inline via FormatCommand, and renders
// multiline arguments inside a numbered left gutter ("   1 │ ...") so heredocs and scripts
// remain effortless to audit without compromising terminal-escape or prompt-spoofing defenses.
func (p *TerminalPrompter) formatCommandDisplay(req protocol.CommandRequest, cleanCmd string) (display string, totalLines int, flatPreview string) {
	tokens, multilineCount := protocol.InspectCommandTokens(req.Command, req.Args)
	if multilineCount == 0 {
		return p.colorGreen(cleanCmd), 1, strings.Join(strings.Fields(cleanCmd), " ")
	}

	headerParts := make([]string, len(tokens))
	for i, tok := range tokens {
		switch {
		case tok.Multiline && tok.Index == 0:
			headerParts[i] = p.colorRed(tok.Badge)
		case tok.Multiline:
			headerParts[i] = p.colorBlue(tok.Badge)
		default:
			headerParts[i] = p.colorGreen(tok.Quoted)
		}
	}

	var highlightFn func(string) string
	if p.useColor() {
		highlightFn = p.colorRed
	}

	var b strings.Builder
	b.WriteString(strings.Join(headerParts, " "))

	var previewSegments []string
	for _, tok := range tokens {
		if !tok.Multiline {
			continue
		}
		lines := strings.Split(tok.Raw, "\n")
		totalLines += len(lines)
		if tok.Index == 0 {
			fmt.Fprintf(&b, "\n     %s", p.colorRed(fmt.Sprintf("┌─ %s (%d lines):", tok.Label, len(lines))))
		} else if multilineCount > 1 {
			fmt.Fprintf(&b, "\n     %s", p.colorBlue(fmt.Sprintf("┌─ %s (%d lines):", tok.Label, len(lines))))
		}
		numWidth := max(len(fmt.Sprintf("%d", len(lines))), 4)
		for idx, line := range lines {
			styledLine, plainLine := protocol.SanitizeDisplayLinePair(line, highlightFn)
			gutter := p.colorDim(fmt.Sprintf("  %*d │ ", numWidth, idx+1))
			fmt.Fprintf(&b, "\n%s%s", gutter, styledLine)
			if collapsed := strings.Join(strings.Fields(plainLine), " "); collapsed != "" {
				previewSegments = append(previewSegments, collapsed)
			}
		}
	}

	flatPreview = strings.Join(strings.Fields(protocol.FormatCompactTokens(tokens)), " ")
	if len(previewSegments) > 0 {
		flatPreview += " — " + strings.Join(previewSegments, " ↵ ")
	}
	return b.String(), totalLines, flatPreview
}
