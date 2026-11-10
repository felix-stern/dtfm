package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

type mockPrompter struct {
	mu           sync.Mutex
	decision     ApprovalDecision
	editedCmd    string
	rejectReason string
	err          error
	delay        time.Duration
	called       chan struct{}
	cancelled    chan error
	onPrompt     func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error)
}

func (m *mockPrompter) Prompt(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
	if m.called != nil {
		select {
		case m.called <- struct{}{}:
		default:
		}
	}
	if m.onPrompt != nil {
		return m.onPrompt(ctx, req)
	}
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			if m.cancelled != nil {
				select {
				case m.cancelled <- context.Cause(ctx):
				default:
				}
			}
			return DecisionTimeout, "", "Prompt timed out", ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.decision, m.editedCmd, m.rejectReason, m.err
}

func (m *mockPrompter) Close() error {
	return nil
}

func TestServerPingAndExecFlow(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{
		decision: DecisionApprove,
	}

	server := NewServer(listener, prompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// 1. Test Ping
	pingEnv, _ := protocol.NewEnvelope(protocol.TypePing, protocol.PingRequest{Timestamp: time.Now()})
	if err := encoder.Encode(pingEnv); err != nil {
		t.Fatalf("Send ping failed: %v", err)
	}

	var pingRespEnv protocol.Envelope
	if err := decoder.Decode(&pingRespEnv); err != nil {
		t.Fatalf("Decode ping response failed: %v", err)
	}
	if pingRespEnv.Type != protocol.TypePingResp {
		t.Fatalf("Expected ping_resp, got %s", pingRespEnv.Type)
	}

	var pingResp protocol.PingResponse
	if err := json.Unmarshal(pingRespEnv.Data, &pingResp); err != nil {
		t.Fatalf("Unmarshal ping data failed: %v", err)
	}
	if !pingResp.Active {
		t.Errorf("Expected ping active true")
	}

	// 2. Test Exec Approved
	execReq := protocol.CommandRequest{
		ID:             "exec-1",
		Reason:         "Test echo",
		Command:        "echo",
		Args:           []string{"hello from test"},
		TimeoutSeconds: 5,
		CreatedAt:      time.Now(),
	}
	execEnv, _ := protocol.NewEnvelope(protocol.TypeExec, execReq)
	if err := encoder.Encode(execEnv); err != nil {
		t.Fatalf("Send exec failed: %v", err)
	}

	var execRespEnv protocol.Envelope
	if err := decoder.Decode(&execRespEnv); err != nil {
		t.Fatalf("Decode exec response failed: %v", err)
	}
	if execRespEnv.Type != protocol.TypeExecResp {
		t.Fatalf("Expected exec_resp, got %s", execRespEnv.Type)
	}

	var execResp protocol.CommandResponse
	if err := json.Unmarshal(execRespEnv.Data, &execResp); err != nil {
		t.Fatalf("Unmarshal exec response failed: %v", err)
	}
	if execResp.Status != protocol.StatusApproved {
		t.Fatalf("Expected StatusApproved, got %s", execResp.Status)
	}
	if !strings.Contains(execResp.Stdout, "hello from test") {
		t.Errorf("Stdout missing output: %q", execResp.Stdout)
	}

	// 3. Test Ping AFTER Exec on the same persistent connection
	// Verifies that processExec's disconnect watcher stopped cleanly and did not steal
	// bytes or corrupt the stream for subsequent requests on the same connection.
	if err := encoder.Encode(pingEnv); err != nil {
		t.Fatalf("Send ping after exec failed: %v", err)
	}
	var pingRespEnv2 protocol.Envelope
	if err := decoder.Decode(&pingRespEnv2); err != nil {
		t.Fatalf("Decode ping response after exec failed (stream corruption / stolen bytes): %v", err)
	}
	if pingRespEnv2.Type != protocol.TypePingResp {
		t.Fatalf("Expected ping_resp after exec, got %s", pingRespEnv2.Type)
	}
}

func TestServerDeadStdinSecurityRepro(t *testing.T) {
	// A prompter connected to EOF stream must reject the execution request!
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	streamPrompter := NewStreamPrompter(strings.NewReader(""), new(bytes.Buffer))
	defer streamPrompter.Close()

	server := NewServer(listener, streamPrompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	execReq := protocol.CommandRequest{
		ID:             "exploit-1",
		Reason:         "Bypass attempt",
		Command:        "echo",
		Args:           []string{"PWNED"},
		TimeoutSeconds: 5,
		CreatedAt:      time.Now(),
	}
	execEnv, _ := protocol.NewEnvelope(protocol.TypeExec, execReq)
	if err := encoder.Encode(execEnv); err != nil {
		t.Fatalf("Send exec failed: %v", err)
	}

	var respEnv protocol.Envelope
	if err := decoder.Decode(&respEnv); err != nil {
		t.Fatalf("Decode exec response failed: %v", err)
	}

	var resp protocol.CommandResponse
	_ = json.Unmarshal(respEnv.Data, &resp)

	if resp.Status != protocol.StatusRejected {
		t.Fatalf("SECURITY FAILURE: Expected StatusRejected on dead stdin, got: %s", resp.Status)
	}
	if resp.ExitCode != protocol.ExitCodeRejected {
		t.Errorf("Expected reject exit code %d, got %d", protocol.ExitCodeRejected, resp.ExitCode)
	}
}

func TestServerConcurrentPingDuringApproval(t *testing.T) {
	// Verifies that a ping request is NOT blocked while an interactive approval is waiting for operator
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	called := make(chan struct{}, 1)
	prompter := &mockPrompter{
		decision: DecisionApprove,
		delay:    500 * time.Millisecond,
		called:   called,
	}

	server := NewServer(listener, prompter)
	go server.Serve()

	// Client 1 sends exec
	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn1 failed: %v", err)
	}
	defer conn1.Close()

	execReq := protocol.CommandRequest{
		ID:             "slow-exec",
		Reason:         "Slow command",
		Command:        "true",
		TimeoutSeconds: 5,
		CreatedAt:      time.Now(),
	}
	execEnv, _ := protocol.NewEnvelope(protocol.TypeExec, execReq)
	_ = json.NewEncoder(conn1).Encode(execEnv)

	// Wait until prompter is actively in Prompt()
	<-called

	// Client 2 connects and sends Ping while Client 1 is still waiting
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn2 failed: %v", err)
	}
	defer conn2.Close()

	pingStart := time.Now()
	pingEnv, _ := protocol.NewEnvelope(protocol.TypePing, protocol.PingRequest{Timestamp: time.Now()})
	_ = json.NewEncoder(conn2).Encode(pingEnv)

	var pingRespEnv protocol.Envelope
	if err := json.NewDecoder(conn2).Decode(&pingRespEnv); err != nil {
		t.Fatalf("Ping response decode failed: %v", err)
	}
	pingDuration := time.Since(pingStart)

	// Ping MUST return fast (< 200ms) without waiting for human deliberation
	if pingDuration > 300*time.Millisecond {
		t.Errorf("Ping was blocked by approval mutex! Duration: %v", pingDuration)
	}
	if pingRespEnv.Type != protocol.TypePingResp {
		t.Errorf("Expected ping_resp, got %s", pingRespEnv.Type)
	}
}

func TestServerExecTimeout(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{
		decision: DecisionApprove,
		delay:    2 * time.Second,
	}

	server := NewServer(listener, prompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	execReq := protocol.CommandRequest{
		ID:             "timeout-1",
		Reason:         "Test timeout",
		Command:        "echo",
		TimeoutSeconds: 1, // 1 second timeout
		CreatedAt:      time.Now(),
	}
	execEnv, _ := protocol.NewEnvelope(protocol.TypeExec, execReq)
	_ = json.NewEncoder(conn).Encode(execEnv)

	var respEnv protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&respEnv); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	var resp protocol.CommandResponse
	_ = json.Unmarshal(respEnv.Data, &resp)

	if resp.Status != protocol.StatusTimeout {
		t.Fatalf("Expected StatusTimeout, got %s", resp.Status)
	}
	if resp.ExitCode != protocol.ExitCodeTimeout {
		t.Errorf("Expected timeout exit code %d, got %d", protocol.ExitCodeTimeout, resp.ExitCode)
	}
}

func TestQueuedRequestExpiredBeforeReview(t *testing.T) {
	// Verifies that a queued request that waits longer than its TimeoutSeconds
	// behind an earlier slow request immediately fails with StatusTimeout
	// without prompting the operator.
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	req1Started := make(chan struct{}, 1)
	prompter := &mockPrompter{
		delay:    1100 * time.Millisecond,
		called:   req1Started,
		decision: DecisionApprove,
	}

	server := NewServer(listener, prompter)
	go server.Serve()

	// 1. Send Request 1 (holds s.mu for 1.1s)
	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial 1 failed: %v", err)
	}
	defer conn1.Close()

	req1 := protocol.CommandRequest{
		ID:             "req-slow",
		Reason:         "Slow request",
		Command:        "echo",
		TimeoutSeconds: 5,
	}
	env1, _ := protocol.NewEnvelope(protocol.TypeExec, req1)
	_ = json.NewEncoder(conn1).Encode(env1)

	// Wait for Request 1 to acquire s.mu
	<-req1Started

	// 2. Send Request 2 with 1s timeout while Request 1 is still holding s.mu
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial 2 failed: %v", err)
	}
	defer conn2.Close()

	req2 := protocol.CommandRequest{
		ID:             "req-queued",
		Reason:         "Queued request",
		Command:        "echo",
		TimeoutSeconds: 1,
	}
	env2, _ := protocol.NewEnvelope(protocol.TypeExec, req2)
	_ = json.NewEncoder(conn2).Encode(env2)

	// Read response for Request 2
	var respEnv protocol.Envelope
	_ = json.NewDecoder(conn2).Decode(&respEnv)

	var resp protocol.CommandResponse
	_ = json.Unmarshal(respEnv.Data, &resp)

	if resp.Status != protocol.StatusTimeout {
		t.Fatalf("Expected StatusTimeout on expired queued request, got: %s", resp.Status)
	}
	if !strings.Contains(resp.Error, "timed out in queue") {
		t.Errorf("Expected 'timed out in queue' error, got: %s", resp.Error)
	}
}

func TestSubprocessGrandchildTimeoutGroupKill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	executor := NewCommandExecutor(io.Discard, io.Discard)
	start := time.Now()
	resp := executor.Execute(ctx, ExecOptions{
		ID:        "subproc-1",
		Command:   "sh",
		Args:      []string{"-c", "(sleep 10 &); sleep 2"},
		StartTime: start,
	})

	if resp.Status != protocol.StatusTimeout {
		t.Fatalf("Expected StatusTimeout, got %s", resp.Status)
	}
	if resp.ExitCode != protocol.ExitCodeTimeout {
		t.Errorf("Expected exit code %d, got %d", protocol.ExitCodeTimeout, resp.ExitCode)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("Execution took too long (%v); grandchild process group was not terminated promptly", time.Since(start))
	}
}

func TestKillActiveChildSignalHandler(t *testing.T) {
	// Verify KillActiveChild terminates running child processes cleanly
	done := make(chan struct{})
	var pid int
	executor := NewCommandExecutor(io.Discard, io.Discard)

	go func() {
		// Run a long sleep
		start := time.Now()
		_ = executor.Execute(context.Background(), ExecOptions{
			ID:        "sleep-test",
			Command:   "sleep",
			Args:      []string{"60"},
			StartTime: start,
		})
		close(done)
	}()

	// Wait for process to spawn
	for i := 0; i < 50; i++ {
		pid = executor.ActiveChildPid()
		if pid > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if pid <= 0 {
		t.Fatalf("Failed to capture activeChildPid")
	}

	// Verify process is alive
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("Process %d is not running: %v", pid, err)
	}

	// Signal termination as dtfm would on SIGINT/SIGTERM
	executor.KillActiveChild()

	select {
	case <-done:
		// Succeeded: process terminated cleanly
	case <-time.After(2 * time.Second):
		t.Fatalf("KillActiveChild failed to terminate process %d within 2s", pid)
	}

	// Verify process is dead
	time.Sleep(50 * time.Millisecond)
	if err := syscall.Kill(pid, 0); err == nil {
		t.Errorf("Process %d is still alive after KillActiveChild", pid)
	}
}

func TestServerClientDisconnectDuringPrompt(t *testing.T) {
	// Client disconnect during operator prompt must immediately
	// cancel promptCtx and reject request rather than executing or lingering, and release s.mu.
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "disconnect.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	prompt1Started := make(chan struct{}, 1)
	cancelled := make(chan error, 1)
	req2Called := make(chan struct{}, 1)

	prompter := &mockPrompter{
		onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
			if req.ID == "disconnect-1" {
				prompt1Started <- struct{}{}
				select {
				case <-time.After(10 * time.Second):
					return DecisionTimeout, "", "Prompt timed out", ctx.Err()
				case <-ctx.Done():
					cancelled <- context.Cause(ctx)
					return DecisionReject, "", "Agent disconnected", context.Cause(ctx)
				}
			}
			if req.ID == "exec-2" {
				req2Called <- struct{}{}
				return DecisionApprove, "", "", nil
			}
			return DecisionReject, "", "Unknown request", nil
		},
	}
	server := NewServer(listener, prompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}

	req := protocol.CommandRequest{
		ID:             "disconnect-1",
		Reason:         "Disconnect test",
		Command:        "echo",
		TimeoutSeconds: 60,
	}
	env, _ := protocol.NewEnvelope(protocol.TypeExec, req)
	_ = json.NewEncoder(conn).Encode(env)

	// Wait for prompt to be active
	select {
	case <-prompt1Started:
	case <-time.After(1 * time.Second):
		t.Fatalf("Prompt was never started")
	}

	// Agent disconnects / process dies
	conn.Close()

	// Verify that prompter context was cancelled with ErrClientDisconnected within 300ms of disconnect
	select {
	case cause := <-cancelled:
		if !errors.Is(cause, ErrClientDisconnected) {
			t.Fatalf("Expected ErrClientDisconnected, got: %v", cause)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatalf("Prompter context was not cancelled within 300ms of client disconnect")
	}

	// Next client connection should immediately be able to acquire approval lock (s.mu) and execute
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial second connection failed: %v", err)
	}
	defer conn2.Close()

	req2 := protocol.CommandRequest{
		ID:             "exec-2",
		Reason:         "Second request after disconnect",
		Command:        "echo",
		Args:           []string{"recovered"},
		TimeoutSeconds: 5,
	}
	env2, _ := protocol.NewEnvelope(protocol.TypeExec, req2)
	if err := json.NewEncoder(conn2).Encode(env2); err != nil {
		t.Fatalf("Failed to encode req2: %v", err)
	}

	// Verify req2 was prompted without being blocked by lingering s.mu
	select {
	case <-req2Called:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Second exec request was blocked by lingering approval lock")
	}

	var respEnv protocol.Envelope
	_ = conn2.SetReadDeadline(time.Now().Add(1 * time.Second))
	if err := json.NewDecoder(conn2).Decode(&respEnv); err != nil {
		t.Fatalf("Failed to decode req2 response: %v", err)
	}
	var resp protocol.CommandResponse
	_ = json.Unmarshal(respEnv.Data, &resp)
	if resp.Status != protocol.StatusApproved {
		t.Errorf("Expected StatusApproved for req2, got: %s", resp.Status)
	}
}

func TestServerRejectsCustomEnvRequest(t *testing.T) {
	// Custom environment variables from the agent are rejected for security
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "reject_env.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServer(listener, prompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	req := protocol.CommandRequest{
		ID:             "env-injection-1",
		Reason:         "Env test",
		Command:        "echo",
		Args:           []string{"hi"},
		Env:            map[string]string{"EVIL": "1"},
		TimeoutSeconds: 5,
	}
	env, _ := protocol.NewEnvelope(protocol.TypeExec, req)
	if err := json.NewEncoder(conn).Encode(env); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	var respEnv protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&respEnv); err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	var resp protocol.CommandResponse
	_ = json.Unmarshal(respEnv.Data, &resp)
	if resp.Status != protocol.StatusRejected {
		t.Fatalf("Expected StatusRejected for request with custom env, got %s", resp.Status)
	}
	if resp.ExitCode != protocol.ExitCodeRejected {
		t.Errorf("Expected reject exit code 126, got %d", resp.ExitCode)
	}
	if !strings.Contains(resp.RejectReason, "forbidden") {
		t.Errorf("Expected 'forbidden' reject reason, got: %s", resp.RejectReason)
	}
}

func TestServerRejectsEmptyCommandAndReason(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServer(listener, prompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// 1. Empty command
	req1 := protocol.CommandRequest{
		ID:             "empty-cmd",
		Reason:         "Valid reason",
		Command:        "   ",
		TimeoutSeconds: 5,
	}
	env1, _ := protocol.NewEnvelope(protocol.TypeExec, req1)
	_ = json.NewEncoder(conn).Encode(env1)

	var respEnv1 protocol.Envelope
	_ = json.NewDecoder(conn).Decode(&respEnv1)
	var resp1 protocol.CommandResponse
	_ = json.Unmarshal(respEnv1.Data, &resp1)
	if resp1.Status != protocol.StatusRejected || resp1.ExitCode != protocol.ExitCodeRejected {
		t.Fatalf("Expected StatusRejected on empty command, got %s (exit %d)", resp1.Status, resp1.ExitCode)
	}

	// 2. Empty reason
	req2 := protocol.CommandRequest{
		ID:             "empty-reason",
		Reason:         "   ",
		Command:        "ls",
		TimeoutSeconds: 5,
	}
	env2, _ := protocol.NewEnvelope(protocol.TypeExec, req2)
	_ = json.NewEncoder(conn).Encode(env2)

	var respEnv2 protocol.Envelope
	_ = json.NewDecoder(conn).Decode(&respEnv2)
	var resp2 protocol.CommandResponse
	_ = json.Unmarshal(respEnv2.Data, &resp2)
	if resp2.Status != protocol.StatusRejected || resp2.ExitCode != protocol.ExitCodeRejected {
		t.Fatalf("Expected StatusRejected on empty reason, got %s (exit %d)", resp2.Status, resp2.ExitCode)
	}
}

func TestServerQueuedRequestTimesOutWhileWaiting(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	called := make(chan struct{}, 1)
	prompter := &mockPrompter{
		decision: DecisionApprove,
		delay:    1200 * time.Millisecond,
		called:   called,
	}
	server := NewServer(listener, prompter)
	go server.Serve()

	// Client 1 sends exec holding the prompt
	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn1 failed: %v", err)
	}
	defer conn1.Close()

	req1 := protocol.CommandRequest{
		ID:             "req-1",
		Reason:         "Slow req 1",
		Command:        "true",
		TimeoutSeconds: 5,
	}
	env1, _ := protocol.NewEnvelope(protocol.TypeExec, req1)
	_ = json.NewEncoder(conn1).Encode(env1)

	// Wait for Request 1 to be actively in Prompt
	<-called

	// Client 2 connects and queues Request 2 with 1s timeout
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn2 failed: %v", err)
	}
	defer conn2.Close()

	start2 := time.Now()
	req2 := protocol.CommandRequest{
		ID:             "req-2",
		Reason:         "Queued req 2",
		Command:        "true",
		TimeoutSeconds: 1, // 1 second timeout
	}
	env2, _ := protocol.NewEnvelope(protocol.TypeExec, req2)
	_ = json.NewEncoder(conn2).Encode(env2)

	var respEnv2 protocol.Envelope
	if err := json.NewDecoder(conn2).Decode(&respEnv2); err != nil {
		t.Fatalf("Failed to decode response for req2: %v", err)
	}
	dur2 := time.Since(start2)

	var resp2 protocol.CommandResponse
	_ = json.Unmarshal(respEnv2.Data, &resp2)

	if resp2.Status != protocol.StatusTimeout || resp2.ExitCode != protocol.ExitCodeTimeout {
		t.Fatalf("Expected StatusTimeout (124) for queued request, got %s (code: %d)", resp2.Status, resp2.ExitCode)
	}
	if dur2 > 1500*time.Millisecond {
		t.Errorf("Queued request took too long to time out: %v (expected ~1s)", dur2)
	}
}

func TestServerQueuedClientDisconnectBeforeTurn(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	promptCount := 0
	var promptMu sync.Mutex
	called := make(chan struct{}, 1)
	prompter := &mockPrompter{
		onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
			promptMu.Lock()
			promptCount++
			promptMu.Unlock()
			select {
			case called <- struct{}{}:
			default:
			}
			if req.ID == "req-1" {
				time.Sleep(300 * time.Millisecond)
				return DecisionApprove, "", "", nil
			}
			return DecisionApprove, "", "", nil
		},
	}
	server := NewServer(listener, prompter)
	go server.Serve()

	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn1 failed: %v", err)
	}
	defer conn1.Close()

	req1 := protocol.CommandRequest{
		ID:             "req-1",
		Reason:         "Req 1",
		Command:        "true",
		TimeoutSeconds: 5,
	}
	env1, _ := protocol.NewEnvelope(protocol.TypeExec, req1)
	_ = json.NewEncoder(conn1).Encode(env1)

	<-called

	// Client 2 connects and queues
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn2 failed: %v", err)
	}
	req2 := protocol.CommandRequest{
		ID:             "req-2",
		Reason:         "Req 2",
		Command:        "touch",
		Args:           []string{"PWNED"},
		TimeoutSeconds: 5,
	}
	env2, _ := protocol.NewEnvelope(protocol.TypeExec, req2)
	_ = json.NewEncoder(conn2).Encode(env2)

	// Client 2 closes connection while queued!
	time.Sleep(50 * time.Millisecond)
	_ = conn2.Close()

	// Wait for Request 1 response
	var respEnv1 protocol.Envelope
	_ = json.NewDecoder(conn1).Decode(&respEnv1)

	// Wait briefly for Server to process req2's turn
	time.Sleep(100 * time.Millisecond)

	promptMu.Lock()
	count := promptCount
	promptMu.Unlock()

	if count > 1 {
		t.Fatalf("Prompter was called %d times; disconnected queued request should NOT have prompted!", count)
	}
}

func TestServerOversizedMessageTypeError(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServer(listener, prompter)
	go server.Serve()

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// 1. Send frame larger than protocol.MaxMessageDataBytes (4MB)
	oversizedPayload := strings.Repeat("A", protocol.MaxMessageDataBytes+1000)
	rawMsg := fmt.Sprintf(`{"version":"1","type":"exec","data":%q}`+"\n", oversizedPayload)
	_, err = conn.Write([]byte(rawMsg))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var respEnv protocol.Envelope
	if err := json.NewDecoder(conn).Decode(&respEnv); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if respEnv.Type != protocol.TypeError {
		t.Fatalf("Expected TypeError for oversized message, got %s", respEnv.Type)
	}

	// 2. Test payload exceeding countedReader limit (MaxMessageDataBytes + 64*1024)
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn2.Close()

	hugePayload := strings.Repeat("B", protocol.MaxMessageDataBytes+70*1024)
	rawMsg2 := fmt.Sprintf(`{"version":"1","type":"exec","data":%q}`+"\n", hugePayload)
	_, err = conn2.Write([]byte(rawMsg2))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var respEnv2 protocol.Envelope
	if err := json.NewDecoder(conn2).Decode(&respEnv2); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if respEnv2.Type != protocol.TypeError {
		t.Fatalf("Expected TypeError for payload exceeding countedReader limit, got %s", respEnv2.Type)
	}
}

func TestServerShutdownDuringActivePromptAndIdleConn(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "dtfm.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	promptCalled := make(chan struct{})
	prompter := &mockPrompter{
		called: promptCalled,
		delay:  10 * time.Second,
	}

	server := NewServer(listener, prompter)

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve()
	}()

	// Client 1 sends an Exec request that blocks inside Prompter.Prompt
	conn1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn1 failed: %v", err)
	}
	defer conn1.Close()

	req := protocol.CommandRequest{
		ID:             "req-shutdown-test",
		Command:        "echo hello",
		Reason:         "Testing shutdown",
		TimeoutSeconds: 30,
	}
	env, err := protocol.NewEnvelope(protocol.TypeExec, req)
	if err != nil {
		t.Fatalf("NewEnvelope failed: %v", err)
	}
	if err := json.NewEncoder(conn1).Encode(env); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	// Wait until Prompter.Prompt is actively running for Client 1
	select {
	case <-promptCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("Timeout waiting for prompter to be called")
	}

	// Client 2 connects as an idle persistent connection
	conn2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial conn2 failed: %v", err)
	}
	defer conn2.Close()

	// Shutdown server
	shutdownStart := time.Now()
	server.Shutdown()

	// Serve() should return cleanly within 500ms (and definitely well before the 10s prompter delay)
	select {
	case <-serveDone:
		duration := time.Since(shutdownStart)
		if duration > 500*time.Millisecond {
			t.Fatalf("server.Serve took too long to shutdown: %v", duration)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server.Serve hung and did not unblock on Shutdown")
	}

	// Verify Client 1 got a response indicating server shutdown
	var respEnv protocol.Envelope
	_ = conn1.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if err := json.NewDecoder(conn1).Decode(&respEnv); err != nil {
		t.Fatalf("Failed to decode response from Client 1: %v", err)
	}
	var resp protocol.CommandResponse
	if err := json.Unmarshal(respEnv.Data, &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if resp.Status != protocol.StatusRejected || !strings.Contains(resp.RejectReason, "shutting down") {
		t.Errorf("Expected rejected response with 'shutting down', got: %+v", resp)
	}
}

func TestCommandExecutorContextCancellation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	executor := NewCommandExecutor(&stdout, &stderr)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(40 * time.Millisecond)
		cancel()
	}()

	resp := executor.Execute(ctx, ExecOptions{
		ID:        "cancel-test",
		Command:   "sleep",
		Args:      []string{"5"},
		StartTime: time.Now(),
	})

	if resp.Status != protocol.StatusRejected {
		t.Fatalf("Expected StatusRejected on cancelled context, got %s", resp.Status)
	}
	if resp.ExitCode != protocol.ExitCodeRejected {
		t.Fatalf("Expected ExitCodeRejected on cancelled context, got %d", resp.ExitCode)
	}
	if !strings.Contains(stdout.String(), "🔌 Command execution cancelled") {
		t.Fatalf("Expected '🔌 Command execution cancelled' banner, got: %s", stdout.String())
	}
}
