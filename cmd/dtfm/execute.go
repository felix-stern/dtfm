// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

// memclr zeroes out a byte slice in place and keeps it live past the loop
// so dead-store optimization cannot elide password scrubbing.
func memclr(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// commandNeedsSudo reports whether a direct command, arguments, or edited shell command invokes sudo.
func commandNeedsSudo(cmd string, args []string, editedCmd string) bool {
	if strings.TrimSpace(editedCmd) != "" {
		return shellStringHasSudo(editedCmd)
	}
	base := filepath.Base(strings.TrimSpace(cmd))
	if base == "sudo" {
		return true
	}
	if base == "sh" || base == "bash" || base == "zsh" || base == "dash" {
		for _, a := range args {
			if shellStringHasSudo(a) {
				return true
			}
		}
	}
	return false
}

func shellStringHasSudo(s string) bool {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '&', '|', '(', ')', '`', '"', '\'':
			return true
		default:
			return false
		}
	})
	for _, f := range fields {
		if f == "sudo" || strings.HasSuffix(f, "/sudo") {
			return true
		}
	}
	return false
}

// prepareSudoArgs ensures -S (read password from stdin) and -p "" (suppress password prompt banner)
// are passed when executing sudo directly or via a shell with a piped password.
func prepareSudoArgs(cmd string, args []string) []string {
	base := filepath.Base(strings.TrimSpace(cmd))
	if base == "sh" || base == "bash" || base == "zsh" || base == "dash" {
		out := make([]string, len(args))
		copy(out, args)
		for i := 0; i < len(out)-1; i++ {
			if out[i] == "-c" && shellStringHasSudo(out[i+1]) {
				out[i+1] = "sudo() { command sudo -S -p '' \"$@\"; }\n" + out[i+1]
				break
			}
		}
		return out
	}
	if base != "sudo" {
		return args
	}
	hasStdinFlag := false
	for _, a := range args {
		if a == "--" {
			break
		}
		if a == "-S" || a == "--stdin" {
			hasStdinFlag = true
			break
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") && strings.Contains(a[1:], "S") {
			hasStdinFlag = true
			break
		}
	}
	if hasStdinFlag {
		return args
	}
	out := make([]string, 0, len(args)+3)
	out = append(out, "-S", "-p", "")
	out = append(out, args...)
	return out
}

// LimitedBuffer prevents unbounded memory consumption from rogue command output.
type LimitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func NewLimitedBuffer(limit int) *LimitedBuffer {
	return &LimitedBuffer{limit: limit}
}

func (l *LimitedBuffer) Write(p []byte) (n int, err error) {
	remaining := l.limit - l.buf.Len()
	if remaining <= 0 {
		l.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		l.buf.Write(p[:remaining])
		l.truncated = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *LimitedBuffer) String() string {
	s := l.buf.String()
	if l.truncated {
		s += fmt.Sprintf("\n[output truncated: exceeded %d byte buffer limit]", l.limit)
	}
	return s
}

// ExecOptions groups parameters for command execution.
type ExecOptions struct {
	ID              string
	Command         string
	Args            []string
	Cwd             string
	ModifiedCommand string
	Password        []byte
	StartTime       time.Time
}

type syncWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// CommandExecutor manages subprocess execution, process-group isolation, and lifecycle signals.
type CommandExecutor struct {
	mu        sync.Mutex
	writeMu   sync.Mutex
	activePid int
	out       io.Writer
	errOut    io.Writer
}

func NewCommandExecutor(out, errOut io.Writer) *CommandExecutor {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	e := &CommandExecutor{}
	e.out = &syncWriter{mu: &e.writeMu, w: out}
	e.errOut = &syncWriter{mu: &e.writeMu, w: errOut}
	return e
}

func (e *CommandExecutor) SetActiveChild(pid int) {
	e.mu.Lock()
	e.activePid = pid
	e.mu.Unlock()
}

func (e *CommandExecutor) KillActiveChild() {
	e.mu.Lock()
	pid := e.activePid
	e.mu.Unlock()

	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func (e *CommandExecutor) ActiveChildPid() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.activePid
}

func cancelRejectReason(cause error) string {
	switch {
	case errors.Is(cause, ErrServerShutdown):
		return "Server is shutting down"
	case errors.Is(cause, ErrClientDisconnected):
		return "Client disconnected during command execution"
	default:
		return fmt.Sprintf("Command execution cancelled: %v", cause)
	}
}

func (e *CommandExecutor) cancelledResponse(ctx context.Context, opts ExecOptions, stdout, stderr string, duration int64) protocol.CommandResponse {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		fmt.Fprintf(e.out, "\n⏳ Command execution TIMED OUT (%d ms)\n\n", duration)
		return protocol.CommandResponse{
			ID:              opts.ID,
			Status:          protocol.StatusTimeout,
			ModifiedCommand: opts.ModifiedCommand,
			ExitCode:        protocol.ExitCodeTimeout,
			Stdout:          stdout,
			Stderr:          stderr,
			Error:           "Command execution timed out",
			DurationMs:      duration,
		}
	}
	cause := context.Cause(ctx)
	if cause == nil {
		cause = ctx.Err()
	}
	fmt.Fprintf(e.out, "\n🔌 Command execution cancelled (%v)\n\n", cause)
	return protocol.CommandResponse{
		ID:              opts.ID,
		Status:          protocol.StatusRejected,
		RejectReason:    cancelRejectReason(cause),
		ModifiedCommand: opts.ModifiedCommand,
		ExitCode:        protocol.ExitCodeRejected,
		Stdout:          stdout,
		Stderr:          stderr,
		Error:           fmt.Sprintf("Command execution cancelled: %v", cause),
		DurationMs:      duration,
	}
}

// Execute runs the approved binary directly with context timeout, process-group isolation,
// optional Model C sudo password piping (sudo -S), and safe environment inheritance.
func (e *CommandExecutor) Execute(ctx context.Context, opts ExecOptions) protocol.CommandResponse {
	defer func() {
		if len(opts.Password) > 0 {
			memclr(opts.Password)
		}
	}()

	if ctx.Err() != nil {
		duration := time.Since(opts.StartTime).Milliseconds()
		return e.cancelledResponse(ctx, opts, "", "", duration)
	}

	if opts.ModifiedCommand != "" {
		fmt.Fprintf(e.out, "⚡ Executing (edited): %s\n", protocol.SanitizeBannerCommand(opts.ModifiedCommand))
	} else {
		fmt.Fprintf(e.out, "⚡ Executing: %s\n", protocol.FormatCommand(opts.Command, opts.Args))
	}

	execArgs := opts.Args
	if opts.Password != nil {
		execArgs = prepareSudoArgs(opts.Command, opts.Args)
	}

	cmd := exec.CommandContext(ctx, opts.Command, execArgs...)
	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	var stdinPipe io.WriteCloser
	if opts.Password != nil {
		var pipeErr error
		stdinPipe, pipeErr = cmd.StdinPipe()
		if pipeErr != nil {
			duration := time.Since(opts.StartTime).Milliseconds()
			return protocol.CommandResponse{
				ID:              opts.ID,
				Status:          protocol.StatusError,
				ModifiedCommand: opts.ModifiedCommand,
				ExitCode:        protocol.ExitCodeError,
				Error:           pipeErr.Error(),
				DurationMs:      duration,
			}
		}
	} else if devNull, err := os.Open(os.DevNull); err == nil {
		cmd.Stdin = devNull
		defer devNull.Close()
	}

	cmd.Cancel = func() error {
		if cmd.Process != nil && cmd.Process.Pid > 0 {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
		}
		return nil
	}
	// Prevent hung pipes from wedging cmd.Run() indefinitely
	cmd.WaitDelay = 3 * time.Second

	// Child process inherits the clean server environment with BASH_ENV and ENV stripped
	childEnv := make([]string, 0, len(os.Environ()))
	for _, envVar := range os.Environ() {
		if strings.HasPrefix(envVar, "BASH_ENV=") || strings.HasPrefix(envVar, "ENV=") {
			continue
		}
		childEnv = append(childEnv, envVar)
	}
	cmd.Env = childEnv

	stdoutBuf := NewLimitedBuffer(protocol.MaxOutputBufferSize)
	stderrBuf := NewLimitedBuffer(protocol.MaxOutputBufferSize)

	cmd.Stdout = io.MultiWriter(e.out, stdoutBuf)
	cmd.Stderr = io.MultiWriter(e.errOut, stderrBuf)

	startErr := cmd.Start()
	if startErr != nil {
		if stdinPipe != nil {
			_ = stdinPipe.Close()
		}
		duration := time.Since(opts.StartTime).Milliseconds()
		if ctx.Err() != nil {
			return e.cancelledResponse(ctx, opts, stdoutBuf.String(), stderrBuf.String(), duration)
		}
		fmt.Fprintf(e.errOut, "Error starting command %s: %s\n",
			protocol.SanitizeTerminalText(opts.Command),
			protocol.SanitizeTerminalText(startErr.Error()))
		return protocol.CommandResponse{
			ID:              opts.ID,
			Status:          protocol.StatusError,
			ModifiedCommand: opts.ModifiedCommand,
			ExitCode:        protocol.ExitCodeError,
			Error:           startErr.Error(),
			DurationMs:      duration,
		}
	}

	if stdinPipe != nil {
		pwBuf := make([]byte, len(opts.Password)+1)
		copy(pwBuf, opts.Password)
		pwBuf[len(opts.Password)] = '\n'
		memclr(opts.Password)
		_, _ = stdinPipe.Write(pwBuf)
		memclr(pwBuf)
		_ = stdinPipe.Close()
	}

	e.SetActiveChild(cmd.Process.Pid)
	defer e.SetActiveChild(0)

	err := cmd.Wait()
	e.SetActiveChild(0)

	duration := time.Since(opts.StartTime).Milliseconds()

	// Check for context cancellation or timeout
	if ctx.Err() != nil {
		return e.cancelledResponse(ctx, opts, stdoutBuf.String(), stderrBuf.String(), duration)
	}

	exitCode := 0
	var errMsg string
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
			if exitCode == -1 {
				if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					exitCode = 128 + int(ws.Signal())
				}
			}
		} else {
			exitCode = 1
			errMsg = err.Error()
		}
		if errors.Is(err, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
			exitCode = 0
			errMsg = ""
		}
	}

	fmt.Fprintf(e.out, "\n✓ Finished with exit code %d (%d ms)\n\n", exitCode, duration)

	return protocol.CommandResponse{
		ID:              opts.ID,
		Status:          protocol.StatusApproved,
		ModifiedCommand: opts.ModifiedCommand,
		ExitCode:        exitCode,
		Stdout:          stdoutBuf.String(),
		Stderr:          stderrBuf.String(),
		Error:           errMsg,
		DurationMs:      duration,
	}
}

// ExecuteShell runs an operator-edited command via bash (or sh fallback) with profile/rc loading disabled.
func (e *CommandExecutor) ExecuteShell(ctx context.Context, id, shellCmd string, cwd string, start time.Time, password ...[]byte) protocol.CommandResponse {
	var pw []byte
	if len(password) > 0 {
		pw = password[0]
	}
	shellPath := "bash"
	shellArgs := []string{"--noprofile", "--norc", "-c", shellCmd}
	if p, err := exec.LookPath("bash"); err == nil && p != "" {
		shellPath = p
	} else if p, err := exec.LookPath("sh"); err == nil && p != "" {
		shellPath = p
		shellArgs = []string{"-c", shellCmd}
	} else {
		shellPath = "sh"
		shellArgs = []string{"-c", shellCmd}
	}

	return e.Execute(ctx, ExecOptions{
		ID:              id,
		Command:         shellPath,
		Args:            shellArgs,
		Cwd:             cwd,
		ModifiedCommand: shellCmd,
		Password:        pw,
		StartTime:       start,
	})
}
