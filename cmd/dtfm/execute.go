package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
	"golang.org/x/sys/unix"
)

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

// CommandExecutor manages subprocess execution, foreground terminal handover, and lifecycle signals.
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

// Execute runs the approved binary directly with context timeout, terminal foreground control,
// process group termination, and safe environment inheritance.
func (e *CommandExecutor) Execute(ctx context.Context, opts ExecOptions) protocol.CommandResponse {
	fmt.Fprintf(e.out, "⚡ Executing: %s\n", protocol.FormatCommand(opts.Command, opts.Args))

	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	if opts.Cwd != "" {
		cmd.Dir = opts.Cwd
	}

	// Check if dtfm is running on an interactive controlling terminal (/dev/tty).
	var ttyFile *os.File
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		if fi, err := tty.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice != 0) {
			ttyFile = tty
			defer ttyFile.Close()
		} else {
			_ = tty.Close()
		}
	}

	var isForeground bool
	var origPgrp int
	var origTermios *termiosState
	if ttyFile != nil {
		if fg, err := unix.IoctlGetInt(int(ttyFile.Fd()), unix.TIOCGPGRP); err == nil {
			if fg == syscall.Getpgrp() {
				isForeground = true
				origPgrp = fg
				// Save original termios state so child modifications (e.g. stty raw or stty -echo)
				// are cleanly restored when the child finishes or is killed.
				if t, err := getTermios(ttyFile.Fd()); err == nil {
					origTermios = t
					// Disable VSUSP (and VDSUSP on macOS) while dtfm is still the foreground process group,
					// BEFORE cmd.Start() is called. This prevents race conditions where child programs
					// (e.g. sudo or ssh) disable ECHO for password prompts and subsequent disableSusp calls
					// overwrite the child's termios back to +echo.
					disableSusp(ttyFile.Fd(), origTermios)
				}
			}
		}
	}

	var restoreOnce sync.Once
	restoreTTY := func() {
		restoreOnce.Do(func() {
			signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
			defer signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)

			// Restore original termios settings and flush pending input (TCSAFLUSH)
			if isForeground && ttyFile != nil {
				if origTermios != nil {
					_ = restoreTermios(ttyFile.Fd(), origTermios)
				}
				// Restore dtfm's process group as the foreground group on the controlling TTY.
				_ = unix.IoctlSetPointerInt(int(ttyFile.Fd()), unix.TIOCSPGRP, origPgrp)
			}
		})
	}
	defer restoreTTY()

	if isForeground {
		// Connected to an interactive terminal and dtfm is in the foreground:
		// Make the child the foreground process group on the controlling TTY so
		// commands like sudo, ssh, and stty can interact with the terminal without SIGTTOU/SIGTTIN.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Foreground: true,
			Ctty:       int(ttyFile.Fd()),
		}
	} else {
		// Non-interactive / headless environment or background process:
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setpgid: true,
		}
	}

	// Stdin is deliberately connected to /dev/null rather than the TTY.
	// Authenticators (sudo, ssh, pinentry) open /dev/tty directly and only need the foreground
	// process group. Connecting stdin to /dev/null ensures programs like 'cat' or 'python'
	// immediately receive EOF rather than hijacking the human operator's keyboard input.
	if devNull, err := os.Open(os.DevNull); err == nil {
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

	if err := cmd.Start(); err != nil {
		duration := time.Since(opts.StartTime).Milliseconds()
		fmt.Fprintf(e.errOut, "Error starting command %s: %s\n",
			protocol.SanitizeTerminalText(opts.Command),
			protocol.SanitizeTerminalText(err.Error()))
		return protocol.CommandResponse{
			ID:              opts.ID,
			Status:          protocol.StatusError,
			ModifiedCommand: opts.ModifiedCommand,
			ExitCode:        protocol.ExitCodeError,
			Error:           err.Error(),
			DurationMs:      duration,
		}
	}

	// In parent, ignore SIGTTOU / SIGTTIN while child runs so parent cannot be suspended
	// by terminal output or TTY state changes under stty tostop
	signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)

	e.SetActiveChild(cmd.Process.Pid)
	defer e.SetActiveChild(0)

	err := cmd.Wait()
	e.SetActiveChild(0)
	restoreTTY()
	signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)

	duration := time.Since(opts.StartTime).Milliseconds()

	// Check for context cancellation or timeout
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			fmt.Fprintf(e.out, "\n⏳ Command execution TIMED OUT (%d ms)\n\n", duration)
			return protocol.CommandResponse{
				ID:              opts.ID,
				Status:          protocol.StatusTimeout,
				ModifiedCommand: opts.ModifiedCommand,
				ExitCode:        protocol.ExitCodeTimeout,
				Stdout:          stdoutBuf.String(),
				Stderr:          stderrBuf.String(),
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
			ModifiedCommand: opts.ModifiedCommand,
			ExitCode:        protocol.ExitCodeRejected,
			Stdout:          stdoutBuf.String(),
			Stderr:          stderrBuf.String(),
			Error:           fmt.Sprintf("Command execution cancelled: %v", cause),
			DurationMs:      duration,
		}
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
func (e *CommandExecutor) ExecuteShell(ctx context.Context, id, shellCmd string, cwd string, start time.Time) protocol.CommandResponse {
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
		StartTime:       start,
	})
}
