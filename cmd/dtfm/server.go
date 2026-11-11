// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
	"golang.org/x/sys/unix"
)

const (
	defaultIdleReadTimeout = 10 * time.Minute
	defaultWriteTimeout    = 10 * time.Second
	defaultExecRespTimeout = 30 * time.Second
)

// countedReader wraps an io.Reader and enforces an upper bound on bytes read per frame,
// preventing memory exhaustion from unbounded decode buffering.
type countedReader struct {
	r         io.Reader
	remaining int64
}

func (c *countedReader) Read(p []byte) (n int, err error) {
	if c.remaining <= 0 {
		return 0, fmt.Errorf("request payload exceeded maximum size limit (%d bytes)", protocol.MaxMessageDataBytes)
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err = c.r.Read(p)
	c.remaining -= int64(n)
	return n, err
}

func (c *countedReader) Reset(limit int64) {
	c.remaining = limit
}

// ErrServerShutdown is returned or caused when the dtfm server is shut down.
var ErrServerShutdown = errors.New("server is shutting down")

// Server coordinates inbound client connections and serializes interactive terminal approvals.
type Server struct {
	listener       net.Listener
	prompter       Prompter
	executor       *CommandExecutor
	sem            chan struct{} // Capacity 1 semaphore serializing access to terminal prompt
	connSem        chan struct{} // Bounded concurrency limit (max 64 concurrent connections)
	wg             sync.WaitGroup
	shutdownCtx    context.Context
	shutdownCancel context.CancelCauseFunc
	connsMu        sync.Mutex
	conns          map[net.Conn]struct{}
	shutdownOnce   sync.Once
}

// NewServer creates a new dtfm server instance.
func NewServer(listener net.Listener, prompter Prompter) *Server {
	return NewServerWithExecutor(listener, prompter, NewCommandExecutor(os.Stdout, os.Stderr))
}

// NewServerWithExecutor creates a new dtfm server instance with a custom executor.
func NewServerWithExecutor(listener net.Listener, prompter Prompter, executor *CommandExecutor) *Server {
	if executor == nil {
		executor = NewCommandExecutor(os.Stdout, os.Stderr)
	}
	shutdownCtx, shutdownCancel := context.WithCancelCause(context.Background())
	return &Server{
		listener:       listener,
		prompter:       prompter,
		executor:       executor,
		sem:            make(chan struct{}, 1),
		connSem:        make(chan struct{}, 64),
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
		conns:          make(map[net.Conn]struct{}),
	}
}

// KillActiveChild terminates any running child process group spawned by this server.
func (s *Server) KillActiveChild() {
	if s.executor != nil {
		s.executor.KillActiveChild()
	}
}

// Shutdown initiates graceful server shutdown: cancels context, closes listener, kills child,
// and unblocks idle or active client connections immediately.
func (s *Server) Shutdown() {
	s.shutdownOnce.Do(func() {
		s.shutdownCancel(ErrServerShutdown)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.KillActiveChild()
		s.connsMu.Lock()
		for conn := range s.conns {
			_ = conn.SetReadDeadline(time.Now())
		}
		s.connsMu.Unlock()
	})
}

// Serve handles inbound connections concurrently with connection bounding and clean shutdown tracking.
func (s *Server) Serve() error {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Unblock all connections and queued/prompt contexts on listener closure
			s.Shutdown()
			// Wait for all active connection handlers to finish (including termios restoration)
			s.wg.Wait()
			return err
		}

		select {
		case s.connSem <- struct{}{}:
		default:
			// Connection limit exceeded, close connection immediately to prevent memory exhaustion
			_ = conn.Close()
			continue
		}

		s.wg.Add(1)
		go func() {
			defer func() {
				<-s.connSem
				s.wg.Done()
			}()
			s.handleConnection(conn)
		}()
	}
}

func writeEnvelope(conn net.Conn, enc *json.Encoder, msgType string, payload any, timeout time.Duration) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetWriteDeadline(time.Time{}) }()

	env, err := protocol.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}
	return enc.Encode(env)
}

func timeoutResp(id, msg string, start time.Time) protocol.CommandResponse {
	return protocol.CommandResponse{
		ID:         id,
		Status:     protocol.StatusTimeout,
		Error:      msg,
		ExitCode:   protocol.ExitCodeTimeout,
		DurationMs: time.Since(start).Milliseconds(),
	}
}

func rejectResp(id, reason string, start time.Time) protocol.CommandResponse {
	return protocol.CommandResponse{
		ID:           id,
		Status:       protocol.StatusRejected,
		RejectReason: reason,
		ExitCode:     protocol.ExitCodeRejected,
		DurationMs:   time.Since(start).Milliseconds(),
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	s.connsMu.Lock()
	if s.shutdownCtx.Err() != nil {
		s.connsMu.Unlock()
		_ = conn.Close()
		return
	}
	s.conns[conn] = struct{}{}
	s.connsMu.Unlock()
	defer func() {
		s.connsMu.Lock()
		delete(s.conns, conn)
		s.connsMu.Unlock()
		_ = conn.Close()
	}()

	br := bufio.NewReader(conn)
	cr := &countedReader{r: br, remaining: protocol.MaxMessageDataBytes + 64*1024}
	decoder := json.NewDecoder(cr)
	encoder := json.NewEncoder(conn)

	firstFrame := true
	for {
		s.connsMu.Lock()
		if s.shutdownCtx.Err() != nil {
			s.connsMu.Unlock()
			return
		}
		deadline := defaultIdleReadTimeout
		if firstFrame {
			deadline = 15 * time.Second
		}
		// Read deadline bounds waiting for incoming requests
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		s.connsMu.Unlock()

		cr.Reset(protocol.MaxMessageDataBytes + 64*1024)

		var env protocol.Envelope
		if err := decoder.Decode(&env); err != nil {
			if s.shutdownCtx.Err() != nil {
				return
			}
			if cr.remaining <= 0 {
				_ = writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
					Message: fmt.Sprintf("message exceeds maximum size limit (%d bytes)", protocol.MaxMessageDataBytes),
				}, defaultWriteTimeout)
			} else if !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "Decode error: %v\n", err)
			}
			return
		}

		firstFrame = false
		receivedAt := time.Now()

		// Clear read deadline while request is being processed
		_ = conn.SetReadDeadline(time.Time{})

		// Enforce maximum payload size to prevent memory exhaustion
		if len(env.Data) > protocol.MaxMessageDataBytes {
			_ = writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
				Message: fmt.Sprintf("request payload exceeded maximum size limit (%d bytes)", protocol.MaxMessageDataBytes),
			}, defaultWriteTimeout)
			return
		}

		if env.Version != protocol.ProtocolVersion {
			_ = writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
				Message: fmt.Sprintf("unsupported protocol version: %s (expected %s)", env.Version, protocol.ProtocolVersion),
			}, defaultWriteTimeout)
			return
		}

		switch env.Type {
		case protocol.TypePing:
			// Ping is handled immediately without acquiring approval lock
			hostname, _ := os.Hostname()
			resp := protocol.PingResponse{
				Active:    true,
				User:      protocol.CurrentUser(),
				Hostname:  hostname,
				Timestamp: time.Now(),
			}
			_ = writeEnvelope(conn, encoder, protocol.TypePingResp, resp, defaultWriteTimeout)

		case protocol.TypeExec:
			var req protocol.CommandRequest
			if err := json.Unmarshal(env.Data, &req); err != nil {
				_ = writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
					Message: fmt.Sprintf("invalid exec payload: %v", err),
				}, defaultWriteTimeout)
				continue
			}

			// Process exec with queue timeout, disconnect watcher, and semaphore
			resp := s.processExec(conn, br, req, receivedAt)

			if err := writeEnvelope(conn, encoder, protocol.TypeExecResp, resp, defaultExecRespTimeout); err != nil {
				fmt.Fprintf(os.Stderr, "dtfm: failed to send exec response to agent: %v\n", err)
			}

		default:
			_ = writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
				Message: fmt.Sprintf("unknown request type: %s", env.Type),
			}, defaultWriteTimeout)
		}
	}
}

// isSocketClosed checks if the socket has received a close event (POLLHUP/POLLRDHUP/POLLERR).
func isSocketClosed(conn net.Conn) bool {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return false
	}
	var closed bool
	_ = raw.Control(func(fd uintptr) {
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLPRI | pollCloseEvents}}
		n, err := unix.Poll(pfd, 0)
		if err == nil && n > 0 {
			if pfd[0].Revents&pollCloseEvents != 0 {
				closed = true
			}
		}
	})
	return closed
}

// watchDisconnect monitors a client connection for EOF / closure while operator prompt is active,
// using Peek so zero bytes are consumed from the stream.
func watchDisconnect(conn net.Conn, br *bufio.Reader, cancel context.CancelCauseFunc, shutdownCtx context.Context) (stop func(), disconnected <-chan struct{}) {
	disconnectCh := make(chan struct{})
	if conn == nil || br == nil {
		return func() {}, disconnectCh
	}

	stopCh := make(chan struct{})
	watcherDone := make(chan struct{})

	go func() {
		defer close(watcherDone)
		for {
			if br.Buffered() > 0 {
				if isSocketClosed(conn) {
					if shutdownCtx != nil && shutdownCtx.Err() != nil {
						return
					}
					close(disconnectCh)
					cancel(ErrClientDisconnected)
					return
				}
			}

			_, err := br.Peek(1)
			select {
			case <-stopCh:
				return
			default:
			}
			if err != nil {
				if shutdownCtx != nil && shutdownCtx.Err() != nil {
					return
				}
				close(disconnectCh)
				cancel(ErrClientDisconnected)
				return
			}

			select {
			case <-stopCh:
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}()

	var stopOnce sync.Once
	stop = func() {
		stopOnce.Do(func() {
			close(stopCh)
			_ = conn.SetReadDeadline(time.Now())
			<-watcherDone
			_ = conn.SetReadDeadline(time.Time{})
		})
	}

	return stop, disconnectCh
}

func (s *Server) processExec(conn net.Conn, br *bufio.Reader, req protocol.CommandRequest, receivedAt time.Time) protocol.CommandResponse {
	start := time.Now()

	// Validate non-empty command and execution reason upfront
	if strings.TrimSpace(req.Command) == "" {
		return rejectResp(req.ID, "Command cannot be empty", start)
	}
	if strings.TrimSpace(req.Reason) == "" {
		return rejectResp(req.ID, "Execution reason (--why) cannot be empty", start)
	}

	// For security, reject any request attempting to supply custom environment variables
	if len(req.Env) > 0 {
		return rejectResp(req.ID, "Custom environment variables are forbidden for security reasons", start)
	}

	timeoutSec := req.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = protocol.DefaultTimeoutSeconds
	}
	if timeoutSec > protocol.MaxTimeoutSeconds {
		timeoutSec = protocol.MaxTimeoutSeconds
	}
	totalTimeout := time.Duration(timeoutSec) * time.Second

	// Measure queue wait using monotonic receivedAt captured by the server upon arrival,
	// protecting against client clock skew and future/past spoofing
	queueWait := time.Since(receivedAt)
	if queueWait >= totalTimeout {
		return timeoutResp(req.ID, "Request timed out in queue before operator review", start)
	}

	remainingBudget := totalTimeout - queueWait
	parentCtx, parentCancel := context.WithCancelCause(s.shutdownCtx)
	defer parentCancel(nil)
	queueCtx, queueCancel := context.WithTimeout(parentCtx, remainingBudget)
	defer queueCancel()

	stopWatcher, disconnectCh := watchDisconnect(conn, br, parentCancel, s.shutdownCtx)
	defer stopWatcher()

	// Wait for terminal approval semaphore interruptibly.
	// Times out immediately if the request's timeout expires while queued,
	// or rejects immediately if the client disconnects while queued.
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-queueCtx.Done():
		if s.shutdownCtx.Err() != nil || errors.Is(context.Cause(queueCtx), ErrServerShutdown) {
			return rejectResp(req.ID, "Server is shutting down", start)
		}
		return timeoutResp(req.ID, "Request timed out in queue before operator review", start)
	case <-disconnectCh:
		if s.shutdownCtx.Err() != nil || errors.Is(context.Cause(queueCtx), ErrServerShutdown) {
			return rejectResp(req.ID, "Server is shutting down", start)
		}
		return rejectResp(req.ID, "Client disconnected while waiting in approval queue", start)
	}

	// Verify server is not shutting down and client is still connected right after acquiring prompt semaphore
	if s.shutdownCtx.Err() != nil || errors.Is(context.Cause(queueCtx), ErrServerShutdown) {
		return rejectResp(req.ID, "Server is shutting down", start)
	}
	select {
	case <-disconnectCh:
		return rejectResp(req.ID, "Client disconnected before operator approval", start)
	default:
	}

	// Prompt runs synchronously under s.sem, cancellable by queueCtx
	decision, edited, reason, err := s.prompter.Prompt(queueCtx, req)

	if err != nil {
		if s.shutdownCtx.Err() != nil || errors.Is(err, ErrServerShutdown) || errors.Is(context.Cause(queueCtx), ErrServerShutdown) {
			return rejectResp(req.ID, "Server is shutting down", start)
		}

		select {
		case <-disconnectCh:
			return rejectResp(req.ID, "Client disconnected before operator approval", start)
		default:
		}

		if errors.Is(err, ErrClientDisconnected) || errors.Is(context.Cause(queueCtx), ErrClientDisconnected) {
			return rejectResp(req.ID, "Client disconnected before operator approval", start)
		}

		if queueCtx.Err() != nil || decision == DecisionTimeout {
			return timeoutResp(req.ID, "Timed out waiting for operator approval", start)
		}
		if reason == "" {
			reason = "Declined by operator"
		}
		return rejectResp(req.ID, reason, start)
	}

	// Double-check shutdown and client connectivity before running approved command
	if s.shutdownCtx.Err() != nil || errors.Is(context.Cause(queueCtx), ErrServerShutdown) {
		return rejectResp(req.ID, "Server is shutting down", start)
	}
	select {
	case <-disconnectCh:
		return rejectResp(req.ID, "Client disconnected before operator approval", start)
	default:
	}

	if decision == DecisionReject {
		if reason == "" {
			reason = "Declined by operator"
		}
		return rejectResp(req.ID, reason, start)
	}

	// Dedicated execution context budget: operator deliberation does not truncate command runtime.
	// Derived from parentCtx so client disconnect or server shutdown cancels command execution immediately.
	execCtx, execCancel := context.WithTimeout(parentCtx, totalTimeout)
	defer execCancel()

	if decision == DecisionEdit {
		if edited == protocol.FormatCommand(req.Command, req.Args) {
			return s.executor.Execute(execCtx, ExecOptions{
				ID:              req.ID,
				Command:         req.Command,
				Args:            req.Args,
				Cwd:             req.Cwd,
				ModifiedCommand: "",
				StartTime:       start,
			})
		}
		return s.executor.ExecuteShell(execCtx, req.ID, edited, req.Cwd, start)
	}

	return s.executor.Execute(execCtx, ExecOptions{
		ID:              req.ID,
		Command:         req.Command,
		Args:            req.Args,
		Cwd:             req.Cwd,
		ModifiedCommand: "",
		StartTime:       start,
	})
}
