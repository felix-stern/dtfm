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
	shutdownWriteGrace     = 50 * time.Millisecond
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
		s.connsMu.Lock()
		s.shutdownCancel(ErrServerShutdown)
		now := time.Now()
		for conn := range s.conns {
			_ = conn.SetDeadline(now)
		}
		s.connsMu.Unlock()

		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.KillActiveChild()
	})
}

// Serve handles inbound connections concurrently with connection bounding and clean shutdown tracking.
func (s *Server) Serve() error {
	if s.listener == nil {
		s.Shutdown()
		return errors.New("server listener is nil")
	}
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

func (s *Server) writeEnvelope(conn net.Conn, enc *json.Encoder, msgType string, payload any, timeout time.Duration) error {
	env, err := protocol.NewEnvelope(msgType, payload)
	if err != nil {
		return err
	}

	s.connsMu.Lock()
	if s.shutdownCtx != nil && s.shutdownCtx.Err() != nil {
		// Never overwrite Shutdown()'s deadline with a long write timeout (e.g. 30s).
		// Skip non-exec responses during shutdown, and cap final exec rejection delivery
		// to a brief grace bound so Serve() never stalls on backpressured sockets.
		if msgType != protocol.TypeExecResp {
			s.connsMu.Unlock()
			return ErrServerShutdown
		}
		if timeout > shutdownWriteGrace {
			timeout = shutdownWriteGrace
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	s.connsMu.Unlock()

	defer func() {
		s.connsMu.Lock()
		if s.shutdownCtx == nil || s.shutdownCtx.Err() == nil {
			_ = conn.SetWriteDeadline(time.Time{})
		}
		s.connsMu.Unlock()
	}()

	return enc.Encode(env)
}

func isConnCloseOrTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) ||
		errors.Is(err, net.ErrClosed) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
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
				_ = s.writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
					Message: fmt.Sprintf("message exceeds maximum size limit (%d bytes)", protocol.MaxMessageDataBytes),
				}, defaultWriteTimeout)
			} else if !isConnCloseOrTimeoutErr(err) {
				_ = s.writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
					Message: "invalid request envelope",
				}, defaultWriteTimeout)
			}
			return
		}

		firstFrame = false
		receivedAt := time.Now()

		s.connsMu.Lock()
		if s.shutdownCtx.Err() == nil {
			// Clear read deadline while request is being processed
			_ = conn.SetReadDeadline(time.Time{})
		}
		s.connsMu.Unlock()

		// Enforce maximum payload size to prevent memory exhaustion
		if len(env.Data) > protocol.MaxMessageDataBytes {
			_ = s.writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
				Message: fmt.Sprintf("request payload exceeded maximum size limit (%d bytes)", protocol.MaxMessageDataBytes),
			}, defaultWriteTimeout)
			return
		}

		if env.Version != protocol.ProtocolVersion {
			_ = s.writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
				Message: fmt.Sprintf("unsupported protocol version: %s (expected %s)", env.Version, protocol.ProtocolVersion),
			}, defaultWriteTimeout)
			return
		}

		switch env.Type {
		case protocol.TypePing:
			var pingReq protocol.PingRequest
			_ = json.Unmarshal(env.Data, &pingReq)
			// Ping is handled immediately without acquiring approval lock
			hostname, _ := os.Hostname()
			resp := protocol.PingResponse{
				ID:        pingReq.ID,
				Active:    true,
				User:      protocol.CurrentUser(),
				Hostname:  hostname,
				Timestamp: time.Now(),
			}
			if err := s.writeEnvelope(conn, encoder, protocol.TypePingResp, resp, defaultWriteTimeout); err != nil {
				return
			}

		case protocol.TypeExec:
			var req protocol.CommandRequest
			if err := json.Unmarshal(env.Data, &req); err != nil {
				_ = s.writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
					Message: fmt.Sprintf("invalid exec payload: %v", err),
				}, defaultWriteTimeout)
				return
			}

			// Process exec with queue timeout, disconnect watcher, and semaphore
			resp, clientDisconnected := s.processExec(conn, br, req, receivedAt)
			if clientDisconnected {
				return
			}

			if err := s.writeEnvelope(conn, encoder, protocol.TypeExecResp, resp, defaultExecRespTimeout); err != nil {
				return
			}

		default:
			_ = s.writeEnvelope(conn, encoder, protocol.TypeError, protocol.ErrorPayload{
				Message: fmt.Sprintf("unknown request type: %s", env.Type),
			}, defaultWriteTimeout)
			return
		}
	}
}

// isSocketClosed checks if the underlying connection has been closed or received peer EOF/error
// without consuming any bytes from the socket receive queue.
func isSocketClosed(conn net.Conn) bool {
	if conn == nil {
		return true
	}
	if dc, ok := conn.(interface{ IsClosedOrEOF() bool }); ok {
		return dc.IsClosedOrEOF()
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return true
	}
	var closed bool
	ctrlErr := raw.Control(func(fd uintptr) {
		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLPRI | pollCloseEvents}}
		var n int
		var pollErr error
		for {
			n, pollErr = unix.Poll(pfd, 0)
			if !errors.Is(pollErr, syscall.EINTR) {
				break
			}
		}
		if pollErr != nil {
			if errors.Is(pollErr, syscall.EBADF) {
				closed = true
			}
			return
		}
		if n <= 0 {
			return
		}
		revents := pfd[0].Revents
		if revents&(pollCloseEvents|unix.POLLNVAL) != 0 {
			closed = true
			return
		}
		if revents&unix.POLLIN != 0 {
			var peek [1]byte
			var rn int
			var rerr error
			for {
				rn, _, rerr = unix.Recvfrom(int(fd), peek[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
				if !errors.Is(rerr, syscall.EINTR) {
					break
				}
			}
			if rn == 0 && rerr == nil {
				closed = true
			} else if rn > 0 && rerr == nil && hasQueuedPeerEOF(fd) {
				closed = true
			} else if errors.Is(rerr, syscall.ECONNRESET) ||
				errors.Is(rerr, syscall.EPIPE) ||
				errors.Is(rerr, syscall.ENOTCONN) ||
				errors.Is(rerr, syscall.ESHUTDOWN) ||
				errors.Is(rerr, syscall.EBADF) {
				closed = true
			}
		}
	})
	if ctrlErr != nil {
		return true
	}
	return closed
}

// watchDisconnect monitors a client connection for EOF or closure while a request
// is queued, awaiting operator approval, or executing, without consuming bytes from br.
func watchDisconnect(conn net.Conn, br *bufio.Reader, cancel context.CancelCauseFunc, shutdownCtx context.Context) (stop func(), disconnected <-chan struct{}) {
	disconnectCh := make(chan struct{})
	if conn == nil || br == nil {
		return func() {}, disconnectCh
	}

	stopCh := make(chan struct{})
	watcherDone := make(chan struct{})

	var disconnectOnce sync.Once
	signalDisconnect := func() {
		if shutdownCtx != nil && shutdownCtx.Err() != nil {
			return
		}
		disconnectOnce.Do(func() {
			if cancel != nil {
				cancel(ErrClientDisconnected)
			}
			close(disconnectCh)
		})
	}

	var deadlineMu sync.Mutex
	stopped := false
	_, hasCustomCloseCheck := conn.(interface{ IsClosedOrEOF() bool })

	go func() {
		defer close(watcherDone)
		for {
			select {
			case <-stopCh:
				return
			default:
			}
			if shutdownCtx != nil && shutdownCtx.Err() != nil {
				return
			}

			buffered := br.Buffered()
			if (buffered > 0 || hasCustomCloseCheck) && isSocketClosed(conn) {
				signalDisconnect()
				return
			}

			if buffered >= br.Size() {
				if isSocketClosed(conn) {
					signalDisconnect()
					return
				}
				select {
				case <-stopCh:
					return
				case <-time.After(50 * time.Millisecond):
				}
				continue
			}

			if hasCustomCloseCheck {
				deadlineMu.Lock()
				if stopped || (shutdownCtx != nil && shutdownCtx.Err() != nil) {
					deadlineMu.Unlock()
					return
				}
				_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
				deadlineMu.Unlock()
			}

			// Peek(buffered + 1) compacts unread buffered bytes to index 0 without discarding
			// any bytes and blocks in conn.Read until at least one new byte or EOF/error arrives.
			_, err := br.Peek(buffered + 1)
			select {
			case <-stopCh:
				return
			default:
			}
			if shutdownCtx != nil && shutdownCtx.Err() != nil {
				return
			}
			if err != nil {
				if hasCustomCloseCheck && errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				if errors.Is(err, bufio.ErrBufferFull) {
					continue
				}
				signalDisconnect()
				return
			}
		}
	}()

	var stopOnce sync.Once
	stop = func() {
		stopOnce.Do(func() {
			close(stopCh)
			deadlineMu.Lock()
			stopped = true
			_ = conn.SetReadDeadline(time.Now())
			deadlineMu.Unlock()
			<-watcherDone
			if shutdownCtx == nil || shutdownCtx.Err() == nil {
				_ = conn.SetReadDeadline(time.Time{})
			}
		})
	}

	return stop, disconnectCh
}

func (s *Server) isShuttingDown(ctxs ...context.Context) bool {
	if s.shutdownCtx != nil && s.shutdownCtx.Err() != nil {
		return true
	}
	for _, ctx := range ctxs {
		if ctx != nil && errors.Is(context.Cause(ctx), ErrServerShutdown) {
			return true
		}
	}
	return false
}

func isClientDisconnected(parentCtx, childCtx context.Context, disconnectCh <-chan struct{}) bool {
	if parentCtx != nil && errors.Is(context.Cause(parentCtx), ErrClientDisconnected) {
		return true
	}
	if childCtx != nil && errors.Is(context.Cause(childCtx), ErrClientDisconnected) {
		return true
	}
	select {
	case <-disconnectCh:
		return true
	default:
		return false
	}
}

func (s *Server) processExec(conn net.Conn, br *bufio.Reader, req protocol.CommandRequest, receivedAt time.Time) (protocol.CommandResponse, bool) {
	start := time.Now()

	// Validate non-empty command and execution reason upfront
	if strings.TrimSpace(req.Command) == "" {
		return rejectResp(req.ID, "Command cannot be empty", start), false
	}
	if strings.TrimSpace(req.Reason) == "" {
		return rejectResp(req.ID, "Execution reason (--why) cannot be empty", start), false
	}

	// For security, reject any request attempting to supply custom environment variables
	if len(req.Env) > 0 {
		return rejectResp(req.ID, "Custom environment variables are forbidden for security reasons", start), false
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
		return timeoutResp(req.ID, "Request timed out in queue before operator review", start), false
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
		if s.isShuttingDown(parentCtx, queueCtx) {
			return rejectResp(req.ID, "Server is shutting down", start), false
		}
		if isClientDisconnected(parentCtx, queueCtx, disconnectCh) {
			return rejectResp(req.ID, "Client disconnected while waiting in approval queue", start), true
		}
		return timeoutResp(req.ID, "Request timed out in queue before operator review", start), false
	case <-disconnectCh:
		if s.isShuttingDown(parentCtx, queueCtx) {
			return rejectResp(req.ID, "Server is shutting down", start), false
		}
		return rejectResp(req.ID, "Client disconnected while waiting in approval queue", start), true
	}

	// Re-check shutdown, client disconnect, and queue deadline right after acquiring s.sem
	// (guarding against Go select tie-breaks and cancel-vs-close(disconnectCh) scheduling).
	if s.isShuttingDown(parentCtx, queueCtx) {
		return rejectResp(req.ID, "Server is shutting down", start), false
	}
	if isClientDisconnected(parentCtx, queueCtx, disconnectCh) {
		return rejectResp(req.ID, "Client disconnected before operator approval", start), true
	}
	if queueCtx.Err() != nil {
		return timeoutResp(req.ID, "Request timed out in queue before operator review", start), false
	}
	if s.prompter == nil {
		return rejectResp(req.ID, "Approval prompter is not configured", start), false
	}

	// Prompt runs synchronously under s.sem, cancellable by queueCtx
	decision, edited, reason, err := s.prompter.Prompt(queueCtx, req)

	if err != nil {
		if s.isShuttingDown(parentCtx, queueCtx) || errors.Is(err, ErrServerShutdown) {
			return rejectResp(req.ID, "Server is shutting down", start), false
		}
		if isClientDisconnected(parentCtx, queueCtx, disconnectCh) || errors.Is(err, ErrClientDisconnected) {
			return rejectResp(req.ID, "Client disconnected before operator approval", start), true
		}
		if queueCtx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || decision == DecisionTimeout {
			return timeoutResp(req.ID, "Timed out waiting for operator approval", start), false
		}
		if reason == "" {
			reason = "Declined by operator"
		}
		return rejectResp(req.ID, reason, start), false
	}

	// Re-check shutdown, client disconnect, explicit rejection, and queue deadline before execution
	if s.isShuttingDown(parentCtx, queueCtx) {
		return rejectResp(req.ID, "Server is shutting down", start), false
	}
	if isClientDisconnected(parentCtx, queueCtx, disconnectCh) {
		return rejectResp(req.ID, "Client disconnected before operator approval", start), true
	}
	if decision == DecisionReject {
		if reason == "" {
			reason = "Declined by operator"
		}
		return rejectResp(req.ID, reason, start), false
	}
	if decision == DecisionTimeout || queueCtx.Err() != nil {
		return timeoutResp(req.ID, "Timed out waiting for operator approval", start), false
	}
	if s.executor == nil {
		return rejectResp(req.ID, "Command executor is not configured", start), false
	}

	var resp protocol.CommandResponse
	switch decision {
	case DecisionApprove:
		var password []byte
		if commandNeedsSudo(req.Command, req.Args, "") {
			if pp, ok := s.prompter.(PasswordPrompter); ok {
				pw, pwErr := pp.PromptPassword(queueCtx)
				if pwErr != nil {
					if s.isShuttingDown(parentCtx, queueCtx) || errors.Is(pwErr, ErrServerShutdown) {
						return rejectResp(req.ID, "Server is shutting down", start), false
					}
					if isClientDisconnected(parentCtx, queueCtx, disconnectCh) || errors.Is(pwErr, ErrClientDisconnected) {
						return rejectResp(req.ID, "Client disconnected before operator approval", start), true
					}
					if queueCtx.Err() != nil || errors.Is(pwErr, context.DeadlineExceeded) {
						return timeoutResp(req.ID, "Timed out waiting for operator password", start), false
					}
					return rejectResp(req.ID, "Password entry failed or cancelled", start), false
				}
				password = pw
				defer memclr(password)
			}
		}

		// Dedicated execution context budget: operator deliberation does not truncate command runtime.
		// Derived from parentCtx so client disconnect or server shutdown cancels command execution immediately.
		execCtx, execCancel := context.WithTimeout(parentCtx, totalTimeout)
		defer execCancel()
		resp = s.executor.Execute(execCtx, ExecOptions{
			ID:              req.ID,
			Command:         req.Command,
			Args:            req.Args,
			Cwd:             req.Cwd,
			ModifiedCommand: "",
			Password:        password,
			StartTime:       start,
		})

	case DecisionEdit:
		edited = strings.TrimSpace(edited)
		if edited == "" {
			return rejectResp(req.ID, "Edited command cannot be empty", start), false
		}
		var password []byte
		unchanged := edited == protocol.FormatCommand(req.Command, req.Args)
		needsSudo := false
		if unchanged {
			needsSudo = commandNeedsSudo(req.Command, req.Args, "")
		} else {
			needsSudo = commandNeedsSudo("", nil, edited)
		}
		if needsSudo {
			if pp, ok := s.prompter.(PasswordPrompter); ok {
				pw, pwErr := pp.PromptPassword(queueCtx)
				if pwErr != nil {
					if s.isShuttingDown(parentCtx, queueCtx) || errors.Is(pwErr, ErrServerShutdown) {
						return rejectResp(req.ID, "Server is shutting down", start), false
					}
					if isClientDisconnected(parentCtx, queueCtx, disconnectCh) || errors.Is(pwErr, ErrClientDisconnected) {
						return rejectResp(req.ID, "Client disconnected before operator approval", start), true
					}
					if queueCtx.Err() != nil || errors.Is(pwErr, context.DeadlineExceeded) {
						return timeoutResp(req.ID, "Timed out waiting for operator password", start), false
					}
					return rejectResp(req.ID, "Password entry failed or cancelled", start), false
				}
				password = pw
				defer memclr(password)
			}
		}

		execCtx, execCancel := context.WithTimeout(parentCtx, totalTimeout)
		defer execCancel()
		if unchanged {
			resp = s.executor.Execute(execCtx, ExecOptions{
				ID:              req.ID,
				Command:         req.Command,
				Args:            req.Args,
				Cwd:             req.Cwd,
				ModifiedCommand: "",
				Password:        password,
				StartTime:       start,
			})
		} else {
			resp = s.executor.ExecuteShell(execCtx, req.ID, edited, req.Cwd, start, password)
		}

	default:
		if reason == "" {
			reason = "Declined by operator"
		}
		return rejectResp(req.ID, reason, start), false
	}

	if s.isShuttingDown(parentCtx) {
		if resp.Status == protocol.StatusRejected && resp.RejectReason == "" {
			resp.RejectReason = "Server is shutting down"
		}
		return resp, false
	}
	if isClientDisconnected(parentCtx, nil, disconnectCh) {
		if resp.Status == protocol.StatusRejected && resp.RejectReason == "" {
			resp.RejectReason = "Client disconnected during command execution"
		}
		return resp, true
	}
	return resp, false
}
