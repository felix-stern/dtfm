package main

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()
	if id1 == "" || id2 == "" {
		t.Fatalf("generateID returned empty string")
	}
	if id1 == id2 {
		t.Fatalf("generateID produced collisions: %s == %s", id1, id2)
	}
}

func TestExecutePing(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0700)
	sockPath := filepath.Join(tmpDir, "lmdtfy_ping.sock")

	// 1. Inactive socket returns code 2
	var stdout, stderr bytes.Buffer
	code := executePing(sockPath, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Expected exit code 2 on inactive socket, got %d, stderr: %s", code, stderr.String())
	}

	// 2. Active mock server
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		var env protocol.Envelope
		_ = json.NewDecoder(conn).Decode(&env)

		resp := protocol.PingResponse{
			Active:    true,
			User:      "test-operator",
			Hostname:  "test-box",
			Timestamp: time.Now(),
		}
		respEnv, _ := protocol.NewEnvelope(protocol.TypePingResp, resp)
		_ = json.NewEncoder(conn).Encode(respEnv)
	}()

	stdout.Reset()
	stderr.Reset()
	code = executePing(sockPath, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Expected exit code 0 on active socket, got %d (stderr: %s)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "test-operator") {
		t.Errorf("Expected username in stdout: %s", stdout.String())
	}
}

func TestExecuteExecFlows(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0700)
	sockPath := filepath.Join(tmpDir, "lmdtfy_exec.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	respChan := make(chan protocol.CommandResponse, 10)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			var env protocol.Envelope
			_ = json.NewDecoder(conn).Decode(&env)

			var req protocol.CommandRequest
			_ = json.Unmarshal(env.Data, &req)

			mockResp := <-respChan
			mockResp.ID = req.ID

			respEnv, _ := protocol.NewEnvelope(protocol.TypeExecResp, mockResp)
			_ = json.NewEncoder(conn).Encode(respEnv)
			conn.Close()
		}
	}()

	// Case 1: Approved execution
	respChan <- protocol.CommandResponse{
		Status:     protocol.StatusApproved,
		ExitCode:   0,
		Stdout:     "approved output\n",
		DurationMs: 10,
	}
	var stdout, stderr bytes.Buffer
	code := executeExec([]string{"echo", "hi"}, sockPath, 5, "Test reason", "", &stdout, &stderr)
	if code != 0 {
		t.Fatalf("Expected code 0, got %d", code)
	}
	if stdout.String() != "approved output\n" {
		t.Errorf("Unexpected stdout: %s", stdout.String())
	}

	// Case 2: Rejected execution -> exit 126
	respChan <- protocol.CommandResponse{
		Status:       protocol.StatusRejected,
		RejectReason: "Too risky",
		ExitCode:     protocol.ExitCodeRejected,
		DurationMs:   10,
	}
	stdout.Reset()
	stderr.Reset()
	code = executeExec([]string{"rm", "-rf", "/"}, sockPath, 5, "Danger", "", &stdout, &stderr)
	if code != protocol.ExitCodeRejected {
		t.Fatalf("Expected exit code %d on rejection, got %d", protocol.ExitCodeRejected, code)
	}

	// Case 3: Timeout execution -> exit 124
	respChan <- protocol.CommandResponse{
		Status:     protocol.StatusTimeout,
		ExitCode:   protocol.ExitCodeTimeout,
		Error:      "Command execution timed out",
		DurationMs: 10,
	}
	stdout.Reset()
	stderr.Reset()
	code = executeExec([]string{"sleep", "100"}, sockPath, 1, "Timeout test", "", &stdout, &stderr)
	if code != protocol.ExitCodeTimeout {
		t.Fatalf("Expected exit code %d on timeout, got %d", protocol.ExitCodeTimeout, code)
	}
	if !strings.Contains(stderr.String(), "Command execution timed out") {
		t.Errorf("Expected specific timeout error message in stderr: %s", stderr.String())
	}

	// Case 4: StatusError execution failure -> exit 127
	respChan <- protocol.CommandResponse{
		Status:     protocol.StatusError,
		ExitCode:   protocol.ExitCodeError,
		Error:      "executable file not found in $PATH",
		DurationMs: 5,
	}
	stdout.Reset()
	stderr.Reset()
	code = executeExec([]string{"nonexistent_cmd"}, sockPath, 5, "Error test", "", &stdout, &stderr)
	if code != protocol.ExitCodeError {
		t.Fatalf("Expected exit code %d on StatusError, got %d", protocol.ExitCodeError, code)
	}
	if !strings.Contains(stderr.String(), "executable file not found in $PATH") {
		t.Errorf("Expected error message in stderr: %s", stderr.String())
	}

	// Case 5: Client-side validation: empty why or invalid timeout
	stdout.Reset()
	stderr.Reset()
	if code := executeExec([]string{"ls"}, sockPath, 5, "   ", "", &stdout, &stderr); code != 1 {
		t.Fatalf("Expected exit code 1 on whitespace-only why, got %d", code)
	}
	stdout.Reset()
	stderr.Reset()
	if code := executeExec([]string{"ls"}, sockPath, 0, "why", "", &stdout, &stderr); code != 1 {
		t.Fatalf("Expected exit code 1 on timeout <= 0, got %d", code)
	}
}

func TestExecuteEnvelopeValidation(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0700)
	sockPath := filepath.Join(tmpDir, "lmdtfy_val.sock")

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer listener.Close()

	sendEnv := make(chan protocol.Envelope, 1)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var env protocol.Envelope
			_ = json.NewDecoder(conn).Decode(&env)

			outEnv := <-sendEnv
			_ = json.NewEncoder(conn).Encode(outEnv)
			conn.Close()
		}
	}()

	var stdout, stderr bytes.Buffer

	// 1. Ping with Active = false returns exit code 2
	pingResp, _ := protocol.NewEnvelope(protocol.TypePingResp, protocol.PingResponse{Active: false})
	sendEnv <- pingResp
	stdout.Reset()
	stderr.Reset()
	if code := executePing(sockPath, &stdout, &stderr); code != 2 {
		t.Fatalf("Expected exit code 2 when ping active is false, got %d", code)
	}

	// 2. Exec with mismatched ID returns exit code 1
	mismatchedResp, _ := protocol.NewEnvelope(protocol.TypeExecResp, protocol.CommandResponse{
		ID:     "wrong-id",
		Status: protocol.StatusApproved,
	})
	sendEnv <- mismatchedResp
	stdout.Reset()
	stderr.Reset()
	if code := executeExec([]string{"echo"}, sockPath, 5, "why", "", &stdout, &stderr); code != 1 {
		t.Fatalf("Expected exit code 1 on mismatched response ID, got %d", code)
	}
	if !strings.Contains(stderr.String(), "response ID mismatch") {
		t.Errorf("Expected ID mismatch error in stderr, got: %s", stderr.String())
	}

	// 3. Exec with wrong version returns exit code 1
	wrongVerEnv := protocol.Envelope{
		Version: "99.0",
		Type:    protocol.TypeExecResp,
		Data:    json.RawMessage(`{}`),
	}
	sendEnv <- wrongVerEnv
	stdout.Reset()
	stderr.Reset()
	if code := executeExec([]string{"echo"}, sockPath, 5, "why", "", &stdout, &stderr); code != 1 {
		t.Fatalf("Expected exit code 1 on wrong version, got %d", code)
	}
}

func TestClientNonExistentSocketDirReturnsCode2(t *testing.T) {
	td := t.TempDir()
	_ = os.Chmod(td, 0700)
	nonExistentDir := filepath.Join(td, "non-existent-subdir")
	sockPath := filepath.Join(nonExistentDir, "test.sock")

	var stdout, stderr bytes.Buffer
	code := executePing(sockPath, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Expected exit code 2 for non-existent socket dir, got %d (stderr: %s)", code, stderr.String())
	}
	if _, err := os.Lstat(nonExistentDir); !os.IsNotExist(err) {
		t.Fatalf("Directory %s should NOT have been created by executePing!", nonExistentDir)
	}

	stderr.Reset()
	code = executeExec([]string{"echo", "hi"}, sockPath, 10, "testing", "", &stdout, &stderr)
	if code != 2 {
		t.Fatalf("Expected exit code 2 for non-existent socket dir on executeExec, got %d (stderr: %s)", code, stderr.String())
	}
	if _, err := os.Lstat(nonExistentDir); !os.IsNotExist(err) {
		t.Fatalf("Directory %s should NOT have been created by executeExec!", nonExistentDir)
	}
}
