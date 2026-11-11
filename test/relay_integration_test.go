// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

func buildBinary(t *testing.T, pkg, name, binDir string) string {
	t.Helper()
	outPath := filepath.Join(binDir, name)
	cmd := exec.Command("go", "build", "-trimpath", "-o", outPath, "github.com/iinozemtsev-lab/dtfm/"+pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build %s: %v\nOutput:\n%s", pkg, err, string(out))
	}
	return outPath
}

func getFreePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForHTTP(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		res, err := http.Get(url)
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for HTTP endpoint %s", url)
}

func TestRelayCLIFlow(t *testing.T) {
	binDir := t.TempDir()

	// 1. Build binaries
	relayBin := buildBinary(t, "cmd/relay", "relay", binDir)
	dtfmBin := buildBinary(t, "cmd/dtfm", "dtfm", binDir)
	lmdtfyBin := buildBinary(t, "cmd/lmdtfy", "lmdtfy", binDir)

	// 2. Start relay server
	port := getFreePort(t)
	listenAddr := fmt.Sprintf("127.0.0.1:%d", port)
	relayURL := fmt.Sprintf("ws://%s/ws", listenAddr)
	healthURL := fmt.Sprintf("http://%s/healthz", listenAddr)

	relayCmd := exec.Command(relayBin, "--listen", listenAddr)
	relayCmd.Stdout = os.Stdout
	relayCmd.Stderr = os.Stderr
	if err := relayCmd.Start(); err != nil {
		t.Fatalf("failed to start relay server: %v", err)
	}
	defer func() {
		_ = relayCmd.Process.Kill()
		_ = relayCmd.Wait()
	}()

	waitForHTTP(t, healthURL, 5*time.Second)

	// 3. Start dtfm in relay mode with PTY attached
	sessionID := "integration-test-session-1"
	hubURL := fmt.Sprintf("http://%s", listenAddr)
	dtfmCmd := exec.Command(dtfmBin, "--relay", "--relay-url", relayURL, "--hub-url", hubURL, "--session", sessionID)
	dtfmPTY, err := pty.Start(dtfmCmd)
	if err != nil {
		t.Fatalf("failed to start dtfm under PTY: %v", err)
	}
	defer func() {
		_ = dtfmCmd.Process.Kill()
		_ = dtfmCmd.Wait()
		_ = dtfmPTY.Close()
	}()

	// Continuously read dtfm PTY output to extract credentials and drain output
	var ptyMu sync.Mutex
	var magicLink, pairingToken string
	readyCh := make(chan struct{})
	var readyOnce sync.Once

	go func() {
		buf := make([]byte, 64*1024)
		var pending bytes.Buffer
		for {
			n, err := dtfmPTY.Read(buf)
			if n > 0 {
				ptyMu.Lock()
				if magicLink == "" || pairingToken == "" {
					pending.Write(buf[:n])
					lines := strings.Split(pending.String(), "\n")
					if len(lines) > 1 {
						for i := 0; i < len(lines)-1; i++ {
							l := lines[i]
							if strings.Contains(l, "Agent Magic Link:") && i+1 < len(lines) {
								magicLink = strings.TrimSpace(lines[i+1])
							}
							if strings.Contains(l, "Pairing Token:") && i+1 < len(lines) {
								pairingToken = strings.TrimSpace(lines[i+1])
							}
						}
						pending.Reset()
						pending.WriteString(lines[len(lines)-1])
					}
					if magicLink != "" && pairingToken != "" {
						readyOnce.Do(func() {
							close(readyCh)
						})
					}
				}
				ptyMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-readyCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for dtfm pairing credentials")
	}

	// 4. Test lmdtfy ping over relay using Magic Link URL
	pingCmd := exec.Command(lmdtfyBin, "ping", "--relay", magicLink)
	var pingOut, pingErr bytes.Buffer
	pingCmd.Stdout = &pingOut
	pingCmd.Stderr = &pingErr
	if err := pingCmd.Run(); err != nil {
		t.Fatalf("lmdtfy ping failed: %v, stderr: %s", err, pingErr.String())
	}
	if !strings.Contains(pingOut.String(), "LMDTFY session is ACTIVE") {
		t.Fatalf("expected ping output to indicate active session, got: %s", pingOut.String())
	}

	// 5. Test lmdtfy exec (Approved flow) using Pairing Token + --relay-url
	execApprovedCmd := exec.Command(lmdtfyBin, "exec", "--relay", pairingToken, "--relay-url", relayURL, "--why", "integration test run", "echo", "e2ee-success-token")
	var execOut, execErr bytes.Buffer
	execApprovedCmd.Stdout = &execOut
	execApprovedCmd.Stderr = &execErr

	if err := execApprovedCmd.Start(); err != nil {
		t.Fatalf("failed to start lmdtfy exec: %v", err)
	}

	// Repeatedly send "y\n" until the prompter accepts it and execution completes
	stopApprove := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopApprove:
				return
			case <-time.After(200 * time.Millisecond):
				_, _ = dtfmPTY.Write([]byte("y\n"))
			}
		}
	}()

	err = execApprovedCmd.Wait()
	close(stopApprove)
	if err != nil {
		t.Fatalf("lmdtfy exec (approved) exited with error: %v, stderr: %s", err, execErr.String())
	}
	if !strings.Contains(execOut.String(), "e2ee-success-token") {
		t.Fatalf("expected output 'e2ee-success-token', got: %s", execOut.String())
	}

	// 6. Test lmdtfy exec (Rejected flow)
	execRejectCmd := exec.Command(lmdtfyBin, "exec", "--relay", magicLink, "--why", "integration test reject", "echo", "must-not-run")
	var rejOut, rejErr bytes.Buffer
	execRejectCmd.Stdout = &rejOut
	execRejectCmd.Stderr = &rejErr

	if err := execRejectCmd.Start(); err != nil {
		t.Fatalf("failed to start lmdtfy exec reject: %v", err)
	}

	// Repeatedly send "n\n" until the prompter accepts it and rejection completes
	stopReject := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopReject:
				return
			case <-time.After(200 * time.Millisecond):
				_, _ = dtfmPTY.Write([]byte("n\n"))
			}
		}
	}()

	err = execRejectCmd.Wait()
	close(stopReject)
	if err == nil {
		t.Fatal("expected lmdtfy exec reject to exit with non-zero code, but got 0")
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != protocol.ExitCodeRejected {
		t.Fatalf("expected exit code %d, got %v", protocol.ExitCodeRejected, err)
	}
	if !strings.Contains(rejErr.String(), "Command was REJECTED by user") {
		t.Fatalf("expected rejection reason in stderr, got: %s", rejErr.String())
	}

	// 7. Test large command output (1 MiB stdout '<' + 1 MiB stderr '\x1b' expanding to > 12 MiB JSON ExecResp)
	largeCmd := exec.Command(lmdtfyBin, "exec", "--relay", magicLink, "--why", "large payload execution test",
		"python3", "-c", "import sys; sys.stdout.write('<'*1024*1024); sys.stderr.write('\\x1b'*1024*1024)")
	var largeOut, largeErr bytes.Buffer
	largeCmd.Stdout = &largeOut
	largeCmd.Stderr = &largeErr

	if err := largeCmd.Start(); err != nil {
		t.Fatalf("failed to start lmdtfy exec large: %v", err)
	}

	stopLargeApprove := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopLargeApprove:
				return
			case <-time.After(200 * time.Millisecond):
				_, _ = dtfmPTY.Write([]byte("y\n"))
			}
		}
	}()

	err = largeCmd.Wait()
	close(stopLargeApprove)
	if err != nil {
		t.Fatalf("lmdtfy exec large exited with error: %v, stderr: %s", err, largeErr.String())
	}
	if largeOut.Len() != 1024*1024 {
		t.Fatalf("expected stdout len 1048576, got %d", largeOut.Len())
	}
	if largeErr.Len() != 1024*1024 {
		t.Fatalf("expected stderr len 1048576, got %d", largeErr.Len())
	}

	// 8. Test oversized agent frame isolation without killing RelayListener
	relayCfg, err := e2ee.ParseRelayToken(magicLink, relayURL)
	if err != nil {
		t.Fatalf("failed to parse magic link: %v", err)
	}
	_, agentAuth, _, err := e2ee.DeriveAuthTokens(relayCfg.SecretKey, relayCfg.SessionID)
	if err != nil {
		t.Fatalf("failed to derive auth tokens: %v", err)
	}
	handshakeKey, err := e2ee.HandshakeKey(relayCfg.SecretKey, relayCfg.SessionID)
	if err != nil {
		t.Fatalf("failed to derive handshake key: %v", err)
	}

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)
	agentWsURL := fmt.Sprintf("%s?session=%s&role=%s", relayURL, relayCfg.SessionID, e2ee.RoleAgent)

	badAgentConn, _, err := websocket.DefaultDialer.Dial(agentWsURL, agentHeader)
	if err != nil {
		t.Fatalf("failed to dial bad agent: %v", err)
	}
	defer badAgentConn.Close()

	agentNonce, agentHandshake, _ := e2ee.BuildAgentHandshake(handshakeKey, relayCfg.SessionID)
	_ = badAgentConn.WriteMessage(websocket.BinaryMessage, agentHandshake)
	_, opPacket, err := badAgentConn.ReadMessage()
	if err != nil {
		t.Fatalf("bad agent failed reading op handshake: %v", err)
	}
	opNonceRcv, _ := e2ee.VerifyOperatorHandshake(handshakeKey, relayCfg.SessionID, opPacket)
	agentCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, relayCfg.SessionID, relayCfg.SecretKey, opNonceRcv, agentNonce)

	// Send oversized 4.8 MiB frame (> 4.125 MiB cap, but < 5 MiB agent frame limit)
	bigPlaintext := bytes.Repeat([]byte("X"), 4800*1024)
	bigEncrypted, err := agentCipher.EncryptRecord(e2ee.RecordTypeData, bigPlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt big record: %v", err)
	}
	_ = badAgentConn.WriteMessage(websocket.BinaryMessage, bigEncrypted)

	// Bad agent must be kicked and connection closed
	_ = badAgentConn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, err = badAgentConn.ReadMessage()
	if err == nil {
		t.Fatal("expected bad agent connection to be closed after sending oversized frame, but read succeeded")
	}

	// Verify dtfm daemon is STILL RUNNING and accepts subsequent ping and exec
	pingAfterKickCmd := exec.Command(lmdtfyBin, "ping", "--relay", magicLink)
	if out, err := pingAfterKickCmd.CombinedOutput(); err != nil {
		t.Fatalf("lmdtfy ping failed after bad agent kick: %v, output: %s", err, string(out))
	}

	execAfterKickCmd := exec.Command(lmdtfyBin, "exec", "--relay", magicLink, "--why", "post-kick check", "echo", "still-alive-token")
	var postOut, postErr bytes.Buffer
	execAfterKickCmd.Stdout = &postOut
	execAfterKickCmd.Stderr = &postErr

	if err := execAfterKickCmd.Start(); err != nil {
		t.Fatalf("failed to start lmdtfy exec post-kick: %v", err)
	}

	stopPostApprove := make(chan struct{})
	go func() {
		for {
			select {
			case <-stopPostApprove:
				return
			case <-time.After(200 * time.Millisecond):
				_, _ = dtfmPTY.Write([]byte("y\n"))
			}
		}
	}()

	err = execAfterKickCmd.Wait()
	close(stopPostApprove)
	if err != nil {
		t.Fatalf("lmdtfy exec post-kick failed: %v, stderr: %s", err, postErr.String())
	}
	if !strings.Contains(postOut.String(), "still-alive-token") {
		t.Fatalf("expected output 'still-alive-token', got: %s", postOut.String())
	}
}
