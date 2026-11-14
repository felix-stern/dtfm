// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func shortTempSockDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "s-*")
	if err != nil {
		dir, err = os.MkdirTemp("", "s-*")
		if err != nil {
			t.Fatalf("failed to create short temp socket dir: %v", err)
		}
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	_ = os.Chmod(dir, 0700)
	return dir
}

func startTestServer(t *testing.T, server *Server) <-chan struct{} {
	t.Helper()
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = server.Serve()
	}()
	t.Cleanup(func() {
		server.Shutdown()
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Errorf("server.Serve() did not exit within 3s after Shutdown()")
		}
	})
	return serveDone
}

func TestServerPingAndExecFlow(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{
		decision: DecisionApprove,
	}

	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	streamPrompter := NewStreamPrompter(strings.NewReader(""), new(bytes.Buffer))
	defer streamPrompter.Close()

	server := NewServerWithExecutor(listener, streamPrompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

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

	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	serveDone := startTestServer(t, server)

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

	server.Shutdown()
	<-serveDone
}

func TestServerExecTimeout(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{
		decision: DecisionApprove,
		delay:    2 * time.Second,
	}

	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

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

	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	serveDone := startTestServer(t, server)

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

	server.Shutdown()
	<-serveDone
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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

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
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

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
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	serveDone := startTestServer(t, server)

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

	server.Shutdown()
	<-serveDone
}

func TestServerQueuedClientDisconnectBeforeTurn(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	var promptCount atomic.Int32
	called := make(chan struct{}, 1)
	releaseReq1 := make(chan struct{})
	prompter := &mockPrompter{
		onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
			promptCount.Add(1)
			select {
			case called <- struct{}{}:
			default:
			}
			if req.ID == "req-1" {
				select {
				case <-releaseReq1:
					return DecisionApprove, "", "", nil
				case <-ctx.Done():
					return DecisionReject, "", "cancelled", context.Cause(ctx)
				}
			}
			return DecisionApprove, "", "", nil
		},
	}
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	serveDone := startTestServer(t, server)

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

	// 1. Verify processExec classifies queued client disconnect as StatusRejected (126),
	// NOT StatusTimeout (124), and unblocks immediately while req-1 still holds s.sem.
	pipeSrv, pipeCli := net.Pipe()
	defer pipeSrv.Close()
	type execResult struct {
		resp         protocol.CommandResponse
		disconnected bool
	}
	resCh := make(chan execResult, 1)
	go func() {
		resp, disconnected := server.processExec(pipeSrv, bufio.NewReader(pipeSrv), protocol.CommandRequest{
			ID:             "req-queued-direct",
			Reason:         "Queued direct check",
			Command:        "touch",
			Args:           []string{"PWNED"},
			TimeoutSeconds: 30,
		}, time.Now())
		resCh <- execResult{resp: resp, disconnected: disconnected}
	}()
	time.Sleep(25 * time.Millisecond)
	_ = pipeCli.Close()

	select {
	case res := <-resCh:
		if !res.disconnected {
			t.Fatalf("Expected processExec to report clientDisconnected=true on queued disconnect")
		}
		if res.resp.Status != protocol.StatusRejected || res.resp.ExitCode != protocol.ExitCodeRejected {
			t.Fatalf("Expected StatusRejected (126) for queued client disconnect, got status=%s exit=%d (err=%q reason=%q)",
				res.resp.Status, res.resp.ExitCode, res.resp.Error, res.resp.RejectReason)
		}
		if !strings.Contains(res.resp.RejectReason, "waiting in approval queue") {
			t.Errorf("Expected 'waiting in approval queue' RejectReason, got %q", res.resp.RejectReason)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("processExec did not unblock within 500ms when queued client disconnected")
	}

	// 2. End-to-end socket client queues behind req-1 and disconnects before its turn.
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

	time.Sleep(40 * time.Millisecond)
	_ = conn2.Close()

	// Release req-1 and read its response
	close(releaseReq1)
	var respEnv1 protocol.Envelope
	if err := json.NewDecoder(conn1).Decode(&respEnv1); err != nil {
		t.Fatalf("Decode req1 failed: %v", err)
	}

	_ = conn1.Close()
	server.Shutdown()
	<-serveDone

	if count := promptCount.Load(); count != 1 {
		t.Fatalf("Prompter was called %d times; disconnected queued requests must NOT prompt!", count)
	}
}

func TestServerOversizedMessageTypeError(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer listener.Close()

	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
	startTestServer(t, server)

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
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	promptCalled := make(chan struct{}, 1)
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

func TestCLIVersion(t *testing.T) {
	origVersion := version
	defer func() { version = origVersion }()

	version = "v1.2.3"

	for _, flag := range []string{"--version", "-v", "-version", "version"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"dtfm", flag}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("run(%q) returned code %d, stderr: %s", flag, code, stderr.String())
		}
		expected := "dtfm v1.2.3\n"
		if stdout.String() != expected {
			t.Errorf("run(%q) stdout = %q, expected %q", flag, stdout.String(), expected)
		}
		if stderr.Len() != 0 {
			t.Errorf("run(%q) stderr = %q, expected empty", flag, stderr.String())
		}
	}
}

func TestCLIVersionNoSocketSideEffects(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	nonExistentDir := filepath.Join(tmpDir, "do-not-create")
	sockPath := filepath.Join(nonExistentDir, "lmdtfy.sock")

	var stdout, stderr bytes.Buffer
	code := run([]string{"dtfm", "--socket", sockPath, "--version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run with --socket and --version returned %d, stderr: %s", code, stderr.String())
	}
	if _, err := os.Stat(nonExistentDir); !os.IsNotExist(err) {
		t.Fatalf("run with --version should NOT create socket directory %s", nonExistentDir)
	}
}

func TestCLIVersionExtraArgs(t *testing.T) {
	testCases := [][]string{
		{"dtfm", "version", "extra"},
		{"dtfm", "--version", "extra"},
		{"dtfm", "-v", "extra1", "extra2"},
	}

	for _, tc := range testCases {
		var stdout, stderr bytes.Buffer
		code := run(tc, &stdout, &stderr)
		if code != 1 {
			t.Errorf("run(%v) = %d, expected 1", tc, code)
		}
		if !strings.Contains(stderr.String(), "extra arguments") {
			t.Errorf("run(%v) stderr = %q, expected 'extra arguments' message", tc, stderr.String())
		}
	}
}

func TestCLIHelp(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "help"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{"dtfm", flag}, &stdout, &stderr)
		if code != 0 {
			t.Errorf("run(%q) returned code %d, stderr: %s", flag, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "Usage:") {
			t.Errorf("run(%q) stdout = %q, expected usage banner", flag, stdout.String())
		}
	}
}

func TestCLIUnknownArgs(t *testing.T) {
	testCases := [][]string{
		{"dtfm", "unknown-subcommand"},
		{"dtfm", "--socket", "/tmp/nonexistent.sock", "unexpected-trailing-arg"},
	}

	for _, tc := range testCases {
		var stdout, stderr bytes.Buffer
		code := run(tc, &stdout, &stderr)
		if code != 1 {
			t.Errorf("run(%v) = %d, expected 1", tc, code)
		}
		if !strings.Contains(stderr.String(), "unknown command") {
			t.Errorf("run(%v) stderr = %q, expected 'unknown command' message", tc, stderr.String())
		}
	}
}

func TestServerEnvRejectNoOutputBeforeSemaphore(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	var outBuf syncBuffer
	prompter := &mockPrompter{decision: DecisionApprove}
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(&outBuf, &outBuf))
	startTestServer(t, server)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	req := protocol.CommandRequest{
		ID:             "env-spoof-test",
		Reason:         "Spoof test",
		Command:        "echo",
		Args:           []string{"spoof"},
		Env:            map[string]string{"EVIL_VAR": "payload"},
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

	// Verify terminal output buffer was NEVER written to before acquiring semaphore
	if outBuf.String() != "" {
		t.Fatalf("SECURITY VIOLATION: server wrote to executor output before acquiring semaphore: %q", outBuf.String())
	}
}

func TestServerUnchangedEditDirectExecution(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	var outBuf syncBuffer
	// Operator selected DecisionEdit, but the edited string is identical to protocol.FormatCommand
	unchangedCmd := protocol.FormatCommand("echo", []string{"direct-exec-unchanged"})
	prompter := &mockPrompter{
		decision:  DecisionEdit,
		editedCmd: unchangedCmd,
	}
	server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(&outBuf, &outBuf))
	startTestServer(t, server)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	req := protocol.CommandRequest{
		ID:             "unchanged-edit-test",
		Reason:         "Unchanged edit fast path",
		Command:        "echo",
		Args:           []string{"direct-exec-unchanged"},
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
	if resp.Status != protocol.StatusApproved {
		t.Fatalf("Expected StatusApproved, got %s", resp.Status)
	}
	// Unchanged edit should NOT have ModifiedCommand set (direct execution)
	if resp.ModifiedCommand != "" {
		t.Errorf("Expected ModifiedCommand to be empty for unchanged edit, got %q", resp.ModifiedCommand)
	}
	// Execution banner should be "⚡ Executing: echo direct-exec-unchanged", NOT "⚡ Executing (edited):"
	if !strings.Contains(outBuf.String(), "⚡ Executing: echo direct-exec-unchanged") {
		t.Errorf("Expected direct execution banner, got: %s", outBuf.String())
	}
}

type mockRelayConn struct {
	net.Conn
	closed atomic.Bool
}

func (m *mockRelayConn) IsClosedOrEOF() bool {
	return m.closed.Load()
}

func TestWatchDisconnectRelayConnFailClosedWithBufferedData(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rc := &mockRelayConn{Conn: c1}

	// Write data to pipe so bufio.Reader has buffered bytes
	go func() {
		_, _ = c2.Write([]byte("buffered trailing byte\n"))
	}()

	br := bufio.NewReader(rc)
	// Peek so bytes are in br.Buffered()
	_, err := br.Peek(5)
	if err != nil {
		t.Fatalf("Peek failed: %v", err)
	}
	if br.Buffered() == 0 {
		t.Fatal("expected br.Buffered() > 0")
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	stop, disconnected := watchDisconnect(rc, br, cancel, context.Background())
	defer stop()

	// Simulate disconnect on RelayConn while buffer is full
	rc.closed.Store(true)

	select {
	case <-disconnected:
		// Success: watchDisconnect triggered fail-closed via IsClosedOrEOF()
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watchDisconnect failed to detect disconnect on RelayConn with buffered data")
	}

	if !errors.Is(context.Cause(ctx), ErrClientDisconnected) {
		t.Fatalf("expected ErrClientDisconnected, got: %v", context.Cause(ctx))
	}
}

type failWriteConn struct {
	net.Conn
	writes atomic.Int32
	closed atomic.Bool
}

func (c *failWriteConn) Write(p []byte) (n int, err error) {
	c.writes.Add(1)
	return 0, errors.New("simulated write failure")
}

func (c *failWriteConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

func TestServerWriteEnvelopeErrorImmediateDisconnect(t *testing.T) {
	t.Run("ping", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c2.Close()

		fwc := &failWriteConn{Conn: c1}
		defer fwc.Close()

		s := NewServerWithExecutor(nil, nil, NewCommandExecutor(io.Discard, io.Discard))

		go func() {
			env, err := protocol.NewEnvelope(protocol.TypePing, protocol.PingRequest{
				ID:        "test-ping-fail-write",
				Timestamp: time.Now(),
			})
			if err == nil {
				_ = json.NewEncoder(c2).Encode(env)
			}
		}()

		done := make(chan struct{})
		go func() {
			s.handleConnection(fwc)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("handleConnection blocked instead of immediately returning on ping writeEnvelope error")
		}

		if fwc.writes.Load() != 1 {
			t.Fatalf("expected exactly 1 write attempt on TypePing response, got %d", fwc.writes.Load())
		}
		if !fwc.closed.Load() {
			t.Fatal("expected conn.Close() to run immediately on writeEnvelope failure")
		}
	})

	t.Run("exec", func(t *testing.T) {
		c1, c2 := net.Pipe()
		defer c2.Close()

		fwc := &failWriteConn{Conn: c1}
		defer fwc.Close()

		prompted := atomic.Bool{}
		prompter := &mockPrompter{
			onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
				prompted.Store(true)
				return DecisionApprove, "", "", nil
			},
		}
		s := NewServerWithExecutor(nil, prompter, NewCommandExecutor(io.Discard, io.Discard))

		go func() {
			env, err := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
				ID:             "test-exec-fail-write",
				Command:        "true",
				Reason:         "test write failure on exec_resp",
				TimeoutSeconds: 5,
			})
			if err == nil {
				_ = json.NewEncoder(c2).Encode(env)
			}
		}()

		done := make(chan struct{})
		go func() {
			s.handleConnection(fwc)
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("handleConnection blocked instead of immediately returning on exec writeEnvelope error")
		}

		if !prompted.Load() {
			t.Fatal("expected request to reach TypeExec prompter with valid ProtocolVersion")
		}
		if fwc.writes.Load() != 1 {
			t.Fatalf("expected exactly 1 write attempt on TypeExec response, got %d", fwc.writes.Load())
		}
		if !fwc.closed.Load() {
			t.Fatal("expected conn.Close() to run immediately on writeEnvelope failure")
		}
	})
}

func TestIsSocketClosedAdversarial(t *testing.T) {
	if !isSocketClosed(nil) {
		t.Fatal("expected isSocketClosed(nil) to fail closed (true)")
	}

	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	// 1. Active open UnixConn -> false, then peer CloseWrite() half-close -> true
	acceptCh := make(chan net.Conn, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			acceptCh <- c
		}
	}()

	cli1, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial 1 failed: %v", err)
	}
	defer cli1.Close()
	srv1 := <-acceptCh
	defer srv1.Close()

	if isSocketClosed(srv1) {
		t.Fatal("expected open UnixConn to report isSocketClosed == false")
	}

	if err := cli1.(*net.UnixConn).CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for !isSocketClosed(srv1) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !isSocketClosed(srv1) {
		t.Fatal("expected isSocketClosed(srv1) == true after peer CloseWrite() half-close")
	}

	// 2. Locally closed UnixConn -> must fail closed (true)
	cli2, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial 2 failed: %v", err)
	}
	defer cli2.Close()
	srv2 := <-acceptCh
	_ = srv2.Close()

	if !isSocketClosed(srv2) {
		t.Fatal("expected locally closed UnixConn to fail closed (isSocketClosed == true)")
	}
}

func TestWatchDisconnectBufferedDataOnNetPipe(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	const payload = "pipelined unconsumed trailing data\n"
	writeDone := make(chan struct{})
	go func() {
		_, _ = c2.Write([]byte(payload))
		close(writeDone)
	}()

	br := bufio.NewReader(c1)
	if _, err := br.Peek(10); err != nil {
		t.Fatalf("Peek failed: %v", err)
	}
	<-writeDone
	if br.Buffered() == 0 || br.Buffered() >= br.Size() {
		t.Fatalf("expected 0 < br.Buffered() < br.Size(), got %d", br.Buffered())
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	stop, disconnected := watchDisconnect(c1, br, cancel, context.Background())
	defer stop()

	// Close remote end of net.Pipe (which does NOT implement syscall.Conn or IsClosedOrEOF)
	_ = c2.Close()

	select {
	case <-disconnected:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watchDisconnect failed to detect net.Pipe EOF when br.Buffered() > 0")
	}

	if !errors.Is(context.Cause(ctx), ErrClientDisconnected) {
		t.Fatalf("expected context cause ErrClientDisconnected immediately after <-disconnected, got %v", context.Cause(ctx))
	}

	// Verify zero buffered bytes were lost or corrupted
	stop()
	got, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("ReadAll buffered data failed: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("buffered stream corrupted: got %q, want %q", string(got), payload)
	}
}

func TestWatchDisconnectRelayConnFailClosedZeroBuffered(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	rc := &mockRelayConn{Conn: c1}
	br := bufio.NewReader(rc)
	if br.Buffered() != 0 {
		t.Fatalf("expected br.Buffered() == 0, got %d", br.Buffered())
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	stop, disconnected := watchDisconnect(rc, br, cancel, context.Background())
	defer stop()

	// Let watchDisconnect enter its first Peek iteration with br.Buffered() == 0,
	// then flip IsClosedOrEOF() without closing the underlying net.Pipe.
	time.Sleep(15 * time.Millisecond)
	rc.closed.Store(true)

	select {
	case <-disconnected:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watchDisconnect spun without detecting IsClosedOrEOF() when br.Buffered() == 0")
	}

	if !errors.Is(context.Cause(ctx), ErrClientDisconnected) {
		t.Fatalf("expected ErrClientDisconnected, got: %v", context.Cause(ctx))
	}
}

func TestWatchDisconnectFullBufferUnixConn(t *testing.T) {
	for _, tc := range []struct {
		name             string
		halfClose        bool
		extraKernelBytes int
	}{
		{name: "full_close", halfClose: false, extraKernelBytes: 0},
		{name: "half_close_write", halfClose: true, extraKernelBytes: 0},
		{name: "half_close_with_unread_kernel_bytes", halfClose: true, extraKernelBytes: 1024},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := shortTempSockDir(t)
			sockPath := filepath.Join(tmpDir, "s.sock")

			listener, err := net.Listen("unix", sockPath)
			if err != nil {
				t.Fatalf("Listen failed: %v", err)
			}
			defer listener.Close()

			acceptCh := make(chan net.Conn, 1)
			go func() {
				c, err := listener.Accept()
				if err == nil {
					acceptCh <- c
				}
			}()

			cli, err := net.Dial("unix", sockPath)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer cli.Close()
			srv := <-acceptCh
			defer srv.Close()

			const bufSize = 64
			br := bufio.NewReaderSize(srv, bufSize)
			expected := strings.Repeat("X", bufSize+tc.extraKernelBytes)
			if _, err := cli.Write([]byte(expected)); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
			if _, err := br.Peek(bufSize); err != nil {
				t.Fatalf("Peek(bufSize) failed: %v", err)
			}
			if br.Buffered() != br.Size() {
				t.Fatalf("expected full buffer (%d == %d), got %d", br.Buffered(), br.Size(), br.Buffered())
			}

			ctx, cancel := context.WithCancelCause(context.Background())
			stop, disconnected := watchDisconnect(srv, br, cancel, context.Background())
			defer stop()

			if tc.halfClose {
				_ = cli.(*net.UnixConn).CloseWrite()
			} else {
				_ = cli.Close()
			}

			select {
			case <-disconnected:
			case <-time.After(500 * time.Millisecond):
				t.Fatalf("watchDisconnect failed to detect %s when bufio.Reader buffer was full", tc.name)
			}

			if !errors.Is(context.Cause(ctx), ErrClientDisconnected) {
				t.Fatalf("expected ErrClientDisconnected, got %v", context.Cause(ctx))
			}

			stop()
			rest := make([]byte, len(expected))
			if _, err := io.ReadFull(br, rest); err != nil {
				t.Fatalf("ReadFull buffered+kernel bytes failed: %v", err)
			}
			if string(rest) != expected {
				t.Fatalf("stream bytes corrupted: len=%d, want len=%d", len(rest), len(expected))
			}
		})
	}
}

func TestWatchDisconnectNilCancelAndIdempotentStop(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	stop, disconnected := watchDisconnect(c1, bufio.NewReader(c1), nil, nil)
	_ = c2.Close()

	select {
	case <-disconnected:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("watchDisconnect with nil cancel did not close disconnected channel")
	}

	// Multiple stop() calls must be safe and non-panicking
	stop()
	stop()
}

func TestServerProcessExecFailClosedDecisions(t *testing.T) {
	cases := []struct {
		name     string
		prompter Prompter
	}{
		{
			name: "empty_decision_zero_value",
			prompter: &mockPrompter{
				decision: "",
			},
		},
		{
			name: "unknown_decision_string",
			prompter: &mockPrompter{
				decision: ApprovalDecision("auto-approve-bug"),
			},
		},
		{
			name: "whitespace_only_edit",
			prompter: &mockPrompter{
				decision:  DecisionEdit,
				editedCmd: "   \t\n  ",
			},
		},
		{
			name:     "nil_prompter",
			prompter: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf syncBuffer
			s := NewServerWithExecutor(nil, tc.prompter, NewCommandExecutor(&outBuf, &outBuf))
			c1, c2 := net.Pipe()
			defer c1.Close()
			defer c2.Close()

			resp, disconnected := s.processExec(c1, bufio.NewReader(c1), protocol.CommandRequest{
				ID:             "fail-closed-" + tc.name,
				Command:        "echo",
				Args:           []string{"MUST_NOT_EXECUTE"},
				Reason:         "adversarial decision test",
				TimeoutSeconds: 5,
			}, time.Now())

			if disconnected {
				t.Fatalf("expected disconnected=false, got true")
			}
			if resp.Status != protocol.StatusRejected || resp.ExitCode != protocol.ExitCodeRejected {
				t.Fatalf("SECURITY FAILURE (%s): expected StatusRejected (126), got status=%s exit=%d",
					tc.name, resp.Status, resp.ExitCode)
			}
			if strings.TrimSpace(resp.RejectReason) == "" {
				t.Errorf("expected non-empty RejectReason for %s", tc.name)
			}
			if strings.Contains(outBuf.String(), "MUST_NOT_EXECUTE") {
				t.Fatalf("SECURITY FAILURE (%s): command executed despite invalid approval state: %q", tc.name, outBuf.String())
			}
		})
	}
}

func TestServerClientDisconnectDuringActiveExecute(t *testing.T) {
	// 1. Direct executor check: pre-cancelled context before cmd.Start() must NOT return StatusError (127),
	// and must populate RejectReason according to cancellation cause.
	t.Run("cancelled_before_start", func(t *testing.T) {
		executor := NewCommandExecutor(io.Discard, io.Discard)

		for _, tc := range []struct {
			cause      error
			wantReason string
		}{
			{ErrServerShutdown, "Server is shutting down"},
			{ErrClientDisconnected, "Client disconnected during command execution"},
		} {
			ctx, cancel := context.WithCancelCause(context.Background())
			cancel(tc.cause)
			resp := executor.Execute(ctx, ExecOptions{
				ID:        "pre-cancel",
				Command:   "sleep",
				Args:      []string{"5"},
				StartTime: time.Now(),
			})
			if resp.Status != protocol.StatusRejected || resp.ExitCode != protocol.ExitCodeRejected {
				t.Fatalf("cause=%v: expected StatusRejected (126), got status=%s exit=%d", tc.cause, resp.Status, resp.ExitCode)
			}
			if resp.RejectReason != tc.wantReason {
				t.Fatalf("cause=%v: expected RejectReason %q, got %q", tc.cause, tc.wantReason, resp.RejectReason)
			}
		}
	})

	// 2. End-to-end disconnect during active Execute kills running child, skips response write, and releases s.sem.
	t.Run("active_child_killed_and_sem_released", func(t *testing.T) {
		tmpDir := shortTempSockDir(t)
		sockPath := filepath.Join(tmpDir, "s.sock")

		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}
		defer listener.Close()

		executor := NewCommandExecutor(io.Discard, io.Discard)
		prompter := &mockPrompter{decision: DecisionApprove}
		server := NewServerWithExecutor(listener, prompter, executor)
		startTestServer(t, server)

		// Also verify processExec response fields directly over net.Pipe
		pipeSrv, pipeCli := net.Pipe()
		defer pipeSrv.Close()
		type execResult struct {
			resp         protocol.CommandResponse
			disconnected bool
		}
		directResCh := make(chan execResult, 1)
		go func() {
			resp, disconnected := server.processExec(pipeSrv, bufio.NewReader(pipeSrv), protocol.CommandRequest{
				ID:             "exec-disconnect-direct",
				Command:        "sleep",
				Args:           []string{"30"},
				Reason:         "test disconnect during execute",
				TimeoutSeconds: 30,
			}, time.Now())
			directResCh <- execResult{resp: resp, disconnected: disconnected}
		}()

		var pid int
		for i := 0; i < 100; i++ {
			pid = executor.ActiveChildPid()
			if pid > 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if pid <= 0 {
			t.Fatal("timed out waiting for child process to start")
		}

		// Disconnect client while sleep 30 is actively running
		_ = pipeCli.Close()

		select {
		case res := <-directResCh:
			if !res.disconnected {
				t.Fatal("expected clientDisconnected=true when client disconnected during Execute")
			}
			if res.resp.Status != protocol.StatusRejected || res.resp.ExitCode != protocol.ExitCodeRejected {
				t.Fatalf("expected StatusRejected (126), got status=%s exit=%d", res.resp.Status, res.resp.ExitCode)
			}
			if res.resp.RejectReason != "Client disconnected during command execution" {
				t.Fatalf("expected RejectReason 'Client disconnected during command execution', got %q", res.resp.RejectReason)
			}
		case <-time.After(1 * time.Second):
			t.Fatal("processExec did not abort promptly when client disconnected during Execute")
		}

		// Subsequent socket client must immediately acquire s.sem and execute cleanly
		conn, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		env, _ := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
			ID:             "after-exec-disconnect",
			Command:        "echo",
			Args:           []string{"ok"},
			Reason:         "verify sem released",
			TimeoutSeconds: 5,
		})
		if err := json.NewEncoder(conn).Encode(env); err != nil {
			t.Fatalf("Encode failed: %v", err)
		}
		var respEnv protocol.Envelope
		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err := json.NewDecoder(conn).Decode(&respEnv); err != nil {
			t.Fatalf("Decode failed: %v", err)
		}
		var resp protocol.CommandResponse
		_ = json.Unmarshal(respEnv.Data, &resp)
		if resp.Status != protocol.StatusApproved {
			t.Fatalf("expected StatusApproved on follow-up request, got %s", resp.Status)
		}
	})
}

type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{
		ch:     make(chan net.Conn, 16),
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case <-l.closed:
		return nil, net.ErrClosed
	case c := <-l.ch:
		return c, nil
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr {
	return &net.UnixAddr{Name: "pipe-test", Net: "unix"}
}

func TestServerShutdownWithQueuedWaitersAndBackpressuredWrites(t *testing.T) {
	t.Run("active_exec_and_queued_waiter", func(t *testing.T) {
		tmpDir := shortTempSockDir(t)
		sockPath := filepath.Join(tmpDir, "s.sock")

		listener, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("Listen failed: %v", err)
		}

		executor := NewCommandExecutor(io.Discard, io.Discard)
		prompter := &mockPrompter{decision: DecisionApprove}
		server := NewServerWithExecutor(listener, prompter, executor)

		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve() }()

		// Client 1 enters active Execute ("sleep 30")
		conn1, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("Dial conn1 failed: %v", err)
		}
		defer conn1.Close()

		env1, _ := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
			ID:             "active-exec-shutdown",
			Command:        "sleep",
			Args:           []string{"30"},
			Reason:         "active exec during shutdown",
			TimeoutSeconds: 30,
		})
		if err := json.NewEncoder(conn1).Encode(env1); err != nil {
			t.Fatalf("Encode 1 failed: %v", err)
		}

		for i := 0; i < 100 && executor.ActiveChildPid() <= 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		if executor.ActiveChildPid() <= 0 {
			t.Fatal("timed out waiting for active child pid")
		}

		// Client 2 connects, completes a Ping roundtrip so handleConnection is guaranteed active,
		// and then queues an Exec request behind Client 1.
		conn2, err := net.Dial("unix", sockPath)
		if err != nil {
			t.Fatalf("Dial conn2 failed: %v", err)
		}
		defer conn2.Close()

		pingEnv, _ := protocol.NewEnvelope(protocol.TypePing, protocol.PingRequest{ID: "sync", Timestamp: time.Now()})
		if err := json.NewEncoder(conn2).Encode(pingEnv); err != nil {
			t.Fatalf("Encode ping on conn2 failed: %v", err)
		}
		var pingResp protocol.Envelope
		if err := json.NewDecoder(conn2).Decode(&pingResp); err != nil {
			t.Fatalf("Decode ping on conn2 failed: %v", err)
		}

		env2, _ := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
			ID:             "queued-waiter-shutdown",
			Command:        "echo",
			Args:           []string{"queued"},
			Reason:         "queued during shutdown",
			TimeoutSeconds: 30,
		})
		if err := json.NewEncoder(conn2).Encode(env2); err != nil {
			t.Fatalf("Encode 2 failed: %v", err)
		}
		time.Sleep(30 * time.Millisecond)

		shutdownStart := time.Now()
		server.Shutdown()

		select {
		case <-serveDone:
			if dur := time.Since(shutdownStart); dur > 500*time.Millisecond {
				t.Fatalf("Serve() took too long to exit on Shutdown: %v", dur)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve() hung during Shutdown with active Execute + queued waiter")
		}

		for idx, c := range []net.Conn{conn1, conn2} {
			var respEnv protocol.Envelope
			_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if err := json.NewDecoder(c).Decode(&respEnv); err != nil {
				t.Fatalf("client %d: failed to decode shutdown response: %v", idx+1, err)
			}
			var resp protocol.CommandResponse
			if err := json.Unmarshal(respEnv.Data, &resp); err != nil {
				t.Fatalf("client %d: unmarshal failed: %v", idx+1, err)
			}
			if resp.Status != protocol.StatusRejected || resp.ExitCode != protocol.ExitCodeRejected {
				t.Fatalf("client %d: expected StatusRejected (126), got status=%s exit=%d", idx+1, resp.Status, resp.ExitCode)
			}
			if resp.RejectReason != "Server is shutting down" {
				t.Fatalf("client %d: expected RejectReason 'Server is shutting down', got %q", idx+1, resp.RejectReason)
			}
		}
	})

	t.Run("backpressured_write_buffers", func(t *testing.T) {
		pl := newPipeListener()
		promptBStarted := make(chan struct{}, 1)
		execADone := make(chan struct{}, 1)

		prompter := &mockPrompter{
			onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
				if req.ID == "conn-a-blocked-write" {
					defer func() { execADone <- struct{}{} }()
					return DecisionApprove, "", "", nil
				}
				if req.ID == "conn-b-prompt" {
					promptBStarted <- struct{}{}
					<-ctx.Done()
					return DecisionReject, "", "Server is shutting down", context.Cause(ctx)
				}
				return DecisionReject, "", "unexpected", nil
			},
		}

		server := NewServerWithExecutor(pl, prompter, NewCommandExecutor(io.Discard, io.Discard))
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve() }()

		// Conn A: executes "true", then blocks inside writeEnvelope(30s) because peer aCli never reads!
		aSrv, aCli := net.Pipe()
		defer aCli.Close()
		pl.ch <- aSrv
		go func() {
			env, _ := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
				ID:             "conn-a-blocked-write",
				Command:        "true",
				Reason:         "backpressured write",
				TimeoutSeconds: 30,
			})
			_ = json.NewEncoder(aCli).Encode(env)
		}()
		<-execADone
		// Give Conn A 25ms after Prompt/Execute so it is blocked inside enc.Encode(env)
		time.Sleep(25 * time.Millisecond)

		// Conn B: active inside Prompt when Shutdown() fires; peer bCli never reads!
		bSrv, bCli := net.Pipe()
		defer bCli.Close()
		pl.ch <- bSrv
		go func() {
			env, _ := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
				ID:             "conn-b-prompt",
				Command:        "true",
				Reason:         "prompt then backpressured shutdown write",
				TimeoutSeconds: 30,
			})
			_ = json.NewEncoder(bCli).Encode(env)
		}()
		<-promptBStarted

		// Conn C: queued behind Conn B when Shutdown() fires; peer cCli never reads!
		cSrv, cCli := net.Pipe()
		defer cCli.Close()
		pl.ch <- cSrv
		go func() {
			env, _ := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
				ID:             "conn-c-queued",
				Command:        "true",
				Reason:         "queued then backpressured shutdown write",
				TimeoutSeconds: 30,
			})
			_ = json.NewEncoder(cCli).Encode(env)
		}()
		time.Sleep(25 * time.Millisecond)

		shutdownStart := time.Now()
		server.Shutdown()

		select {
		case <-serveDone:
			if dur := time.Since(shutdownStart); dur > 500*time.Millisecond {
				t.Fatalf("Serve() hung on backpressured write during Shutdown: %v (expected < 500ms)", dur)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Serve() hung on blocked conn.Write during Shutdown (up to 30s bug)")
		}
	})
}

func TestServerPostPromptDeadlineAndExplicitRejectPrecedence(t *testing.T) {
	// 1. If queueCtx deadline expires while Prompt returns DecisionApprove with nil err,
	// processExec must NOT execute the command and must return StatusTimeout (124).
	t.Run("approve_after_queue_deadline_times_out", func(t *testing.T) {
		var outBuf syncBuffer
		prompter := &mockPrompter{
			onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
				<-ctx.Done()
				// Simulate a prompter returning DecisionApprove right as queueCtx expires
				return DecisionApprove, "", "", nil
			},
		}
		s := NewServerWithExecutor(nil, prompter, NewCommandExecutor(&outBuf, &outBuf))
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		resp, _ := s.processExec(c1, bufio.NewReader(c1), protocol.CommandRequest{
			ID:             "late-approve",
			Command:        "echo",
			Args:           []string{"SHOULD_NOT_RUN"},
			Reason:         "deadline race",
			TimeoutSeconds: 1,
		}, time.Now().Add(-950*time.Millisecond))

		if resp.Status != protocol.StatusTimeout || resp.ExitCode != protocol.ExitCodeTimeout {
			t.Fatalf("expected StatusTimeout (124) when queueCtx expired before execution, got status=%s exit=%d", resp.Status, resp.ExitCode)
		}
		if strings.Contains(outBuf.String(), "SHOULD_NOT_RUN") {
			t.Fatalf("command ran after queueCtx deadline expired: %q", outBuf.String())
		}
	})

	// 2. If operator explicitly pressed 'n' (DecisionReject) and optional reject reason timed out on queueCtx,
	// processExec must preserve StatusRejected (126), NOT flip to StatusTimeout (124).
	t.Run("explicit_reject_with_expired_queue_ctx_stays_rejected", func(t *testing.T) {
		prompter := &mockPrompter{
			onPrompt: func(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
				<-ctx.Done()
				return DecisionReject, "", "Declined by operator", nil
			},
		}
		s := NewServerWithExecutor(nil, prompter, NewCommandExecutor(io.Discard, io.Discard))
		c1, c2 := net.Pipe()
		defer c1.Close()
		defer c2.Close()

		resp, _ := s.processExec(c1, bufio.NewReader(c1), protocol.CommandRequest{
			ID:             "explicit-reject-late",
			Command:        "echo",
			Args:           []string{"hi"},
			Reason:         "reject precedence",
			TimeoutSeconds: 1,
		}, time.Now().Add(-950*time.Millisecond))

		if resp.Status != protocol.StatusRejected || resp.ExitCode != protocol.ExitCodeRejected {
			t.Fatalf("expected StatusRejected (126) for explicit operator veto, got status=%s exit=%d", resp.Status, resp.ExitCode)
		}
	})
}

func TestServerMalformedJSONReturnsTypeErrorSilently(t *testing.T) {
	tmpDir := shortTempSockDir(t)
	sockPath := filepath.Join(tmpDir, "s.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	var outBuf syncBuffer
	server := NewServerWithExecutor(listener, &mockPrompter{decision: DecisionApprove}, NewCommandExecutor(&outBuf, &outBuf))
	startTestServer(t, server)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("{malformed json\n")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	var respEnv protocol.Envelope
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if err := json.NewDecoder(conn).Decode(&respEnv); err != nil {
		t.Fatalf("Decode TypeError response failed: %v", err)
	}
	if respEnv.Type != protocol.TypeError {
		t.Fatalf("expected TypeError for malformed JSON, got %s", respEnv.Type)
	}
	if outBuf.String() != "" {
		t.Fatalf("unexpected executor output on malformed wire frame: %q", outBuf.String())
	}
}

func TestServerPersistentConnectionPipelining(t *testing.T) {
	// Sends exec + exec + ping in a single conn.Write across < 512B, ~1.5KB, and > 4KB
	// payload sizes, verifying zero stolen/corrupted bytes and no false disconnects
	// across json.Decoder internal buffering, partial bufio.Reader compaction, and full 4KB+ buffers.
	for _, tc := range []struct {
		name    string
		padSize int
		minLen  int
		maxLen  int
	}{
		{name: "under_512B", padSize: 2, minLen: 1, maxLen: 500},
		{name: "around_1_5KB", padSize: 1100, minLen: 1200, maxLen: 2000},
		{name: "over_4KB", padSize: 5200, minLen: 5400, maxLen: 8000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := shortTempSockDir(t)
			sockPath := filepath.Join(tmpDir, "s.sock")

			listener, err := net.Listen("unix", sockPath)
			if err != nil {
				t.Fatalf("Listen failed: %v", err)
			}
			defer listener.Close()

			prompter := &mockPrompter{
				decision: DecisionApprove,
				delay:    65 * time.Millisecond,
			}
			server := NewServerWithExecutor(listener, prompter, NewCommandExecutor(io.Discard, io.Discard))
			startTestServer(t, server)

			conn, err := net.Dial("unix", sockPath)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer conn.Close()

			var batch bytes.Buffer
			enc := json.NewEncoder(&batch)

			id1 := "e1"
			env1, err := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
				ID:             id1,
				Command:        "echo",
				Args:           []string{"one"},
				Reason:         "p1",
				TimeoutSeconds: 5,
			})
			if err != nil {
				t.Fatalf("NewEnvelope 1 failed: %v", err)
			}
			if err := enc.Encode(env1); err != nil {
				t.Fatalf("Encode 1 failed: %v", err)
			}

			pad := strings.Repeat("p", tc.padSize)
			id2 := "e2"
			env2, err := protocol.NewEnvelope(protocol.TypeExec, protocol.CommandRequest{
				ID:             id2,
				Command:        "echo",
				Args:           []string{"2-" + pad},
				Reason:         "p2",
				TimeoutSeconds: 5,
			})
			if err != nil {
				t.Fatalf("NewEnvelope 2 failed: %v", err)
			}
			if err := enc.Encode(env2); err != nil {
				t.Fatalf("Encode 2 failed: %v", err)
			}

			pingID := "pg"
			env3, err := protocol.NewEnvelope(protocol.TypePing, protocol.PingRequest{
				ID:        pingID,
				Timestamp: time.Unix(1700000000, 0).UTC(),
			})
			if err != nil {
				t.Fatalf("NewEnvelope 3 failed: %v", err)
			}
			if err := enc.Encode(env3); err != nil {
				t.Fatalf("Encode 3 failed: %v", err)
			}

			payload := batch.Bytes()
			if len(payload) < tc.minLen || len(payload) > tc.maxLen {
				t.Fatalf("unexpected batch size %d (expected in [%d, %d])", len(payload), tc.minLen, tc.maxLen)
			}

			// Single write delivering all three pipelined frames back-to-back
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("conn.Write batch failed: %v", err)
			}

			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			dec := json.NewDecoder(conn)

			// 1. Read exec_resp 1
			var rEnv1 protocol.Envelope
			if err := dec.Decode(&rEnv1); err != nil {
				t.Fatalf("Decode resp 1 failed: %v", err)
			}
			if rEnv1.Type != protocol.TypeExecResp {
				t.Fatalf("resp 1: expected exec_resp, got %s", rEnv1.Type)
			}
			var r1 protocol.CommandResponse
			if err := json.Unmarshal(rEnv1.Data, &r1); err != nil {
				t.Fatalf("Unmarshal resp 1 failed: %v", err)
			}
			if r1.ID != id1 || r1.Status != protocol.StatusApproved {
				t.Fatalf("resp 1 mismatch: id=%q status=%s reason=%q", r1.ID, r1.Status, r1.RejectReason)
			}
			if !strings.Contains(r1.Stdout, "one") {
				t.Fatalf("resp 1 unexpected stdout: %q", r1.Stdout)
			}

			// 2. Read exec_resp 2
			var rEnv2 protocol.Envelope
			if err := dec.Decode(&rEnv2); err != nil {
				t.Fatalf("Decode resp 2 failed: %v", err)
			}
			if rEnv2.Type != protocol.TypeExecResp {
				t.Fatalf("resp 2: expected exec_resp, got %s", rEnv2.Type)
			}
			var r2 protocol.CommandResponse
			if err := json.Unmarshal(rEnv2.Data, &r2); err != nil {
				t.Fatalf("Unmarshal resp 2 failed: %v", err)
			}
			if r2.ID != id2 || r2.Status != protocol.StatusApproved {
				t.Fatalf("resp 2 mismatch: id=%q status=%s reason=%q", r2.ID, r2.Status, r2.RejectReason)
			}
			if !strings.Contains(r2.Stdout, "2-"+pad) {
				t.Fatalf("resp 2 missing padded stdout (len=%d)", len(r2.Stdout))
			}

			// 3. Read ping_resp 3
			var rEnv3 protocol.Envelope
			if err := dec.Decode(&rEnv3); err != nil {
				t.Fatalf("Decode resp 3 (ping) failed: %v", err)
			}
			if rEnv3.Type != protocol.TypePingResp {
				t.Fatalf("resp 3: expected ping_resp, got %s", rEnv3.Type)
			}
			var r3 protocol.PingResponse
			if err := json.Unmarshal(rEnv3.Data, &r3); err != nil {
				t.Fatalf("Unmarshal resp 3 failed: %v", err)
			}
			if r3.ID != pingID || !r3.Active {
				t.Fatalf("resp 3 ping mismatch: %+v", r3)
			}
		})
	}
}
