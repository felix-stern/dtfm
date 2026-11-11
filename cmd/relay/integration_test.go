// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

type snoopReader struct {
	mu     sync.Mutex
	frames [][]byte
}

func (s *snoopReader) Record(frame []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := make([]byte, len(frame))
	copy(copied, frame)
	s.frames = append(s.frames, copied)
}

func (s *snoopReader) ContainsPlaintext(needle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := []byte(needle)
	for _, f := range s.frames {
		if bytes.Contains(f, b) {
			return true
		}
	}
	return false
}

// mockPrompter implements dtfm's Prompter interface for test automation.
type mockPrompter struct {
	decision string
	edited   string
	reason   string
}

func (m *mockPrompter) Prompt(ctx context.Context, req protocol.CommandRequest) (string, string, string, error) {
	return m.decision, m.edited, m.reason, nil
}

func (m *mockPrompter) Close() error {
	return nil
}

func TestEndToEndE2EERelayPingAndExecution(t *testing.T) {
	// 1. Start In-Memory WebSocket Relay Server
	snooper := &snoopReader{}
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	relayWsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	// 2. Generate ephemeral cryptographic credentials
	sessionID, err := e2ee.GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID error: %v", err)
	}
	secretKey, keyHex, err := e2ee.GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey error: %v", err)
	}

	opAuth, agentAuth, agentVerifier, err := e2ee.DeriveAuthTokens(secretKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveAuthTokens error: %v", err)
	}
	handshakeKey, err := e2ee.HandshakeKey(secretKey, sessionID)
	if err != nil {
		t.Fatalf("HandshakeKey error: %v", err)
	}

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)

	magicLink := e2ee.FormatMagicLink(ts.URL, sessionID, keyHex)

	// 3. Connect Operator to Relay with E2EE
	opURL := relayWsURL + "?session=" + sessionID + "&role=operator"
	opWsConn, _, err := websocket.DefaultDialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial error: %v", err)
	}
	defer opWsConn.Close()

	mockP := &mockPrompter{
		decision: "approved",
	}

	// Active connection state on operator side
	var opCipherMu sync.Mutex
	var activeConnID uint64
	var activeOpCipher *e2ee.ConnCipher
	var opNonce []byte

	go func() {
		for {
			msgType, msg, err := opWsConn.ReadMessage()
			if err != nil {
				return
			}
			if msgType != websocket.BinaryMessage || len(msg) < 9 {
				continue
			}

			snooper.Record(msg)

			ctrl := msg[0]
			connID := binary.BigEndian.Uint64(msg[1:9])

			if ctrl == e2ee.FrameAgentConnected {
				opCipherMu.Lock()
				activeConnID = connID
				var opPacket []byte
				opNonce, opPacket, _ = e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
				opCipherMu.Unlock()

				// Send operator handshake
				outFrame := make([]byte, 9+len(opPacket))
				outFrame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(outFrame[1:9], connID)
				copy(outFrame[9:], opPacket)
				snooper.Record(outFrame)
				_ = opWsConn.WriteMessage(websocket.BinaryMessage, outFrame)
				continue
			}
			if ctrl == e2ee.FrameAgentDisconnected {
				opCipherMu.Lock()
				if activeConnID == connID {
					activeConnID = 0
					activeOpCipher = nil
				}
				opCipherMu.Unlock()
				continue
			}
			if ctrl != e2ee.FrameData {
				continue
			}

			payload := msg[9:]

			opCipherMu.Lock()
			cipher := activeOpCipher
			savedOpNonce := opNonce
			opCipherMu.Unlock()

			if cipher == nil {
				// First incoming payload from agent is AgentHandshake
				agentNonce, err := e2ee.VerifyAgentHandshake(handshakeKey, sessionID, payload)
				if err != nil {
					t.Errorf("operator verify agent handshake error: %v", err)
					continue
				}
				newCipher, err := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, secretKey, savedOpNonce, agentNonce)
				if err != nil {
					t.Errorf("operator derive conn cipher error: %v", err)
					continue
				}
				opCipherMu.Lock()
				activeOpCipher = newCipher
				opCipherMu.Unlock()
				continue
			}

			// Decrypt incoming agent frame
			recType, plaintext, err := cipher.DecryptRecord(payload)
			if err != nil {
				t.Errorf("operator decrypt record error: %v", err)
				continue
			}
			if recType == e2ee.RecordTypeEOF {
				continue
			}

			var env protocol.Envelope
			if err := json.Unmarshal(plaintext, &env); err != nil {
				continue
			}

			if env.Type == protocol.TypePing {
				var pingReq protocol.PingRequest
				_ = json.Unmarshal(env.Data, &pingReq)

				resp := protocol.PingResponse{
					ID:        pingReq.ID,
					Active:    true,
					User:      "test-operator",
					Hostname:  "test-workstation",
					Timestamp: time.Now(),
				}
				respEnv, _ := protocol.NewEnvelope(protocol.TypePingResp, resp)
				respBytes, _ := json.Marshal(respEnv)
				encrypted, _ := cipher.EncryptRecord(e2ee.RecordTypeData, respBytes)

				frame := make([]byte, 9+len(encrypted))
				frame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(frame[1:9], connID)
				copy(frame[9:], encrypted)

				snooper.Record(frame)
				_ = opWsConn.WriteMessage(websocket.BinaryMessage, frame)

			} else if env.Type == protocol.TypeExec {
				var req protocol.CommandRequest
				_ = json.Unmarshal(env.Data, &req)

				var resp protocol.CommandResponse
				resp.ID = req.ID

				switch mockP.decision {
				case "approved":
					resp.Status = protocol.StatusApproved
					resp.ExitCode = 0
					resp.Stdout = "e2ee-hello-world\n"
				case "edit":
					resp.Status = protocol.StatusApproved
					resp.ModifiedCommand = mockP.edited
					resp.ExitCode = 0
					resp.Stdout = "modified-output\n"
				case "reject":
					resp.Status = protocol.StatusRejected
					resp.RejectReason = mockP.reason
					resp.ExitCode = protocol.ExitCodeRejected
				}

				respEnv, _ := protocol.NewEnvelope(protocol.TypeExecResp, resp)
				respBytes, _ := json.Marshal(respEnv)
				encrypted, _ := cipher.EncryptRecord(e2ee.RecordTypeData, respBytes)

				frame := make([]byte, 9+len(encrypted))
				frame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(frame[1:9], connID)
				copy(frame[9:], encrypted)

				snooper.Record(frame)
				_ = opWsConn.WriteMessage(websocket.BinaryMessage, frame)
			}
		}
	}()

	// Helper to connect an agent, complete handshake, and return ConnCipher
	connectAgent := func() (*websocket.Conn, *e2ee.ConnCipher) {
		agentWsURL := relayWsURL + "?session=" + sessionID + "&role=agent"
		agentConn, _, err := websocket.DefaultDialer.Dial(agentWsURL, agentHeader)
		if err != nil {
			t.Fatalf("agent dial error: %v", err)
		}

		// 1. Send agent handshake
		agentNonce, agentHandshake, err := e2ee.BuildAgentHandshake(handshakeKey, sessionID)
		if err != nil {
			t.Fatalf("build agent handshake error: %v", err)
		}
		snooper.Record(agentHandshake)
		if err := agentConn.WriteMessage(websocket.BinaryMessage, agentHandshake); err != nil {
			t.Fatalf("write agent handshake error: %v", err)
		}

		// 2. Read operator handshake
		_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, opPacket, err := agentConn.ReadMessage()
		if err != nil {
			t.Fatalf("read operator handshake error: %v", err)
		}
		snooper.Record(opPacket)

		opNonce, err := e2ee.VerifyOperatorHandshake(handshakeKey, sessionID, opPacket)
		if err != nil {
			t.Fatalf("verify operator handshake error: %v", err)
		}

		cipher, err := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonce, agentNonce)
		if err != nil {
			t.Fatalf("derive agent conn cipher error: %v", err)
		}
		return agentConn, cipher
	}

	// 4. Test Agent: lmdtfy ping over relay
	agentConn, agentCipher := connectAgent()

	pingReq := protocol.PingRequest{ID: "ping-1", Timestamp: time.Now()}
	pingEnv, _ := protocol.NewEnvelope(protocol.TypePing, pingReq)
	pingBytes, _ := json.Marshal(pingEnv)
	encryptedPing, _ := agentCipher.EncryptRecord(e2ee.RecordTypeData, pingBytes)

	snooper.Record(encryptedPing)
	err = agentConn.WriteMessage(websocket.BinaryMessage, encryptedPing)
	if err != nil {
		t.Fatalf("agent send ping error: %v", err)
	}

	_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, respEncrypted, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent read ping response error: %v", err)
	}

	snooper.Record(respEncrypted)
	_, respPlaintext, err := agentCipher.DecryptRecord(respEncrypted)
	if err != nil {
		t.Fatalf("agent decrypt ping response error: %v", err)
	}

	var respEnv protocol.Envelope
	if err := json.Unmarshal(respPlaintext, &respEnv); err != nil {
		t.Fatalf("agent decode ping envelope error: %v", err)
	}
	if respEnv.Type != protocol.TypePingResp {
		t.Fatalf("expected ping_resp, got %s", respEnv.Type)
	}
	agentConn.Close()

	// 5. Test Agent: lmdtfy exec (Approved)
	agentConn, agentCipher = connectAgent()

	execReq := protocol.CommandRequest{
		ID:        "exec-req-1",
		Reason:    "testing e2ee execution",
		Command:   "echo",
		Args:      []string{"e2ee-hello-world"},
		CreatedAt: time.Now(),
	}
	execEnv, _ := protocol.NewEnvelope(protocol.TypeExec, execReq)
	execBytes, _ := json.Marshal(execEnv)
	encryptedExec, _ := agentCipher.EncryptRecord(e2ee.RecordTypeData, execBytes)

	snooper.Record(encryptedExec)
	_ = agentConn.WriteMessage(websocket.BinaryMessage, encryptedExec)

	_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, execRespEnc, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent read exec resp error: %v", err)
	}

	snooper.Record(execRespEnc)
	_, execRespPlain, err := agentCipher.DecryptRecord(execRespEnc)
	if err != nil {
		t.Fatalf("agent decrypt exec resp error: %v", err)
	}

	var execRespEnv protocol.Envelope
	_ = json.Unmarshal(execRespPlain, &execRespEnv)
	var cmdResp protocol.CommandResponse
	_ = json.Unmarshal(execRespEnv.Data, &cmdResp)

	if cmdResp.Status != protocol.StatusApproved {
		t.Fatalf("expected status approved, got %s", cmdResp.Status)
	}
	if cmdResp.Stdout != "e2ee-hello-world\n" {
		t.Fatalf("expected stdout 'e2ee-hello-world\\n', got %q", cmdResp.Stdout)
	}
	agentConn.Close()

	// 6. Test Agent: lmdtfy exec (Rejected)
	mockP.decision = "reject"
	mockP.reason = "Security policy violation"

	agentConn, agentCipher = connectAgent()

	execReq.ID = "exec-req-2"
	execEnv, _ = protocol.NewEnvelope(protocol.TypeExec, execReq)
	execBytes, _ = json.Marshal(execEnv)
	encryptedExec, _ = agentCipher.EncryptRecord(e2ee.RecordTypeData, execBytes)

	_ = agentConn.WriteMessage(websocket.BinaryMessage, encryptedExec)

	_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, execRespEnc, err = agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent read exec reject resp error: %v", err)
	}

	_, execRespPlain, err = agentCipher.DecryptRecord(execRespEnc)
	if err != nil {
		t.Fatalf("agent decrypt exec reject error: %v", err)
	}

	_ = json.Unmarshal(execRespPlain, &execRespEnv)
	_ = json.Unmarshal(execRespEnv.Data, &cmdResp)

	if cmdResp.Status != protocol.StatusRejected {
		t.Fatalf("expected status rejected, got %s", cmdResp.Status)
	}
	if cmdResp.RejectReason != "Security policy violation" {
		t.Fatalf("expected reject reason 'Security policy violation', got %q", cmdResp.RejectReason)
	}
	agentConn.Close()

	// 7. Verify Zero-Knowledge Guarantee:
	plaintextsToCheck := []string{
		"e2ee-hello-world",
		"testing e2ee execution",
		"Security policy violation",
		"test-operator",
		"test-workstation",
	}

	for _, pt := range plaintextsToCheck {
		if snooper.ContainsPlaintext(pt) {
			t.Fatalf("ZERO-KNOWLEDGE VIOLATION: plaintext %q was found unencrypted in relay wire frames!", pt)
		}
	}

	// 8. Test Operator Disconnect:
	opWsConn.Close()
	time.Sleep(50 * time.Millisecond)

	agentWsURL := relayWsURL + "?session=" + sessionID + "&role=agent"
	_, _, err = websocket.DefaultDialer.Dial(agentWsURL, agentHeader)
	if err == nil {
		t.Fatal("expected agent dial to fail after operator disconnect, but succeeded")
	}

	_ = magicLink
}

func TestRelayLargeEscapedExecResp(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	relayWsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	sessionID, _ := e2ee.GenerateSessionID()
	secretKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, agentAuth, agentVerifier, _ := e2ee.DeriveAuthTokens(secretKey, sessionID)
	handshakeKey, _ := e2ee.HandshakeKey(secretKey, sessionID)

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)

	// 1. Connect Operator with 6 MiB read limit
	opURL := relayWsURL + "?session=" + sessionID + "&role=operator"
	dialer := *websocket.DefaultDialer
	opWsConn, _, err := dialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial error: %v", err)
	}
	defer opWsConn.Close()
	opWsConn.SetReadLimit(6 * 1024 * 1024)

	var opCipherMu sync.Mutex
	var activeOpCipher *e2ee.ConnCipher
	var opNonce []byte

	go func() {
		for {
			msgType, msg, err := opWsConn.ReadMessage()
			if err != nil {
				return
			}
			if msgType != websocket.BinaryMessage || len(msg) < 9 {
				continue
			}

			ctrl := msg[0]
			connID := binary.BigEndian.Uint64(msg[1:9])

			if ctrl == e2ee.FrameAgentConnected {
				opCipherMu.Lock()
				var opPacket []byte
				opNonce, opPacket, _ = e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
				opCipherMu.Unlock()

				outFrame := make([]byte, 9+len(opPacket))
				outFrame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(outFrame[1:9], connID)
				copy(outFrame[9:], opPacket)
				_ = opWsConn.WriteMessage(websocket.BinaryMessage, outFrame)
				continue
			}

			if ctrl != e2ee.FrameData {
				continue
			}

			payload := msg[9:]
			opCipherMu.Lock()
			cipher := activeOpCipher
			savedOpNonce := opNonce
			opCipherMu.Unlock()

			if cipher == nil {
				agentNonce, err := e2ee.VerifyAgentHandshake(handshakeKey, sessionID, payload)
				if err != nil {
					continue
				}
				newCipher, err := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, secretKey, savedOpNonce, agentNonce)
				if err != nil {
					continue
				}
				opCipherMu.Lock()
				activeOpCipher = newCipher
				opCipherMu.Unlock()
				continue
			}

			// Respond with huge escaped ExecResp (> 12 MiB JSON)
			var resp protocol.CommandResponse
			resp.ID = "large-exec-1"
			resp.Status = protocol.StatusApproved
			resp.ExitCode = 0
			resp.Stdout = string(bytes.Repeat([]byte("<"), 1024*1024))
			resp.Stderr = string(bytes.Repeat([]byte("\x1b"), 1024*1024))

			respEnv, _ := protocol.NewEnvelope(protocol.TypeExecResp, resp)
			respBytes, _ := json.Marshal(respEnv)
			if len(respBytes) < 12*1024*1024 {
				t.Errorf("expected JSON ExecResp to expand to > 12 MiB, got %d bytes", len(respBytes))
			}

			encrypted, err := cipher.EncryptRecord(e2ee.RecordTypeData, respBytes)
			if err != nil {
				t.Errorf("failed to encrypt large record: %v", err)
				return
			}

			frame := make([]byte, 9+len(encrypted))
			frame[0] = e2ee.FrameData
			binary.BigEndian.PutUint64(frame[1:9], connID)
			copy(frame[9:], encrypted)

			_ = opWsConn.SetWriteDeadline(time.Now().Add(writeWait))
			_ = opWsConn.WriteMessage(websocket.BinaryMessage, frame)
		}
	}()

	// 2. Connect Agent with 16.25 MiB read limit
	agentWsURL := relayWsURL + "?session=" + sessionID + "&role=agent"
	agentConn, _, err := dialer.Dial(agentWsURL, agentHeader)
	if err != nil {
		t.Fatalf("agent dial error: %v", err)
	}
	defer agentConn.Close()
	agentConn.SetReadLimit(protocol.MaxResponseEnvelopeBytes + 256*1024)

	// Send agent handshake
	agentNonce, agentHandshake, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)
	_ = agentConn.WriteMessage(websocket.BinaryMessage, agentHandshake)

	_, opPacket, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent read op handshake error: %v", err)
	}
	opNonceRcv, _ := e2ee.VerifyOperatorHandshake(handshakeKey, sessionID, opPacket)
	agentCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonceRcv, agentNonce)

	// Send exec request
	execReq := protocol.CommandRequest{ID: "large-exec-1", Command: "python3", CreatedAt: time.Now()}
	execEnv, _ := protocol.NewEnvelope(protocol.TypeExec, execReq)
	execBytes, _ := json.Marshal(execEnv)
	encryptedReq, _ := agentCipher.EncryptRecord(e2ee.RecordTypeData, execBytes)
	_ = agentConn.WriteMessage(websocket.BinaryMessage, encryptedReq)

	// Receive huge response frame (> 12 MiB)
	_ = agentConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, respEncrypted, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent failed to read large response frame (> 12 MiB): %v", err)
	}

	_, respPlain, err := agentCipher.DecryptRecord(respEncrypted)
	if err != nil {
		t.Fatalf("agent failed to decrypt large response: %v", err)
	}

	var parsedEnv protocol.Envelope
	if err := json.Unmarshal(respPlain, &parsedEnv); err != nil {
		t.Fatalf("agent failed to unmarshal JSON: %v", err)
	}
	var parsedResp protocol.CommandResponse
	if err := json.Unmarshal(parsedEnv.Data, &parsedResp); err != nil {
		t.Fatalf("agent failed to unmarshal CommandResponse: %v", err)
	}

	if len(parsedResp.Stdout) != 1024*1024 || len(parsedResp.Stderr) != 1024*1024 {
		t.Fatalf("output length mismatch: stdout=%d, stderr=%d", len(parsedResp.Stdout), len(parsedResp.Stderr))
	}
}

func TestRelayListenerOversizedAgentFrameIsolation(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	relayWsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	sessionID, _ := e2ee.GenerateSessionID()
	secretKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, agentAuth, agentVerifier, _ := e2ee.DeriveAuthTokens(secretKey, sessionID)
	handshakeKey, _ := e2ee.HandshakeKey(secretKey, sessionID)

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)

	// 1. Connect Operator with 6 MiB read limit (as in RelayListener)
	opURL := relayWsURL + "?session=" + sessionID + "&role=operator"
	dialer := *websocket.DefaultDialer
	opWsConn, _, err := dialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial error: %v", err)
	}
	defer opWsConn.Close()
	opWsConn.SetReadLimit(6 * 1024 * 1024)

	var opCipherMu sync.Mutex
	var activeOpCipher *e2ee.ConnCipher
	var opNonce []byte
	kickedCh := make(chan uint64, 1)

	go func() {
		for {
			msgType, msg, err := opWsConn.ReadMessage()
			if err != nil {
				return
			}
			if msgType != websocket.BinaryMessage || len(msg) < 9 {
				continue
			}

			ctrl := msg[0]
			connID := binary.BigEndian.Uint64(msg[1:9])

			if ctrl == e2ee.FrameAgentConnected {
				opCipherMu.Lock()
				var opPacket []byte
				opNonce, opPacket, _ = e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
				opCipherMu.Unlock()

				outFrame := make([]byte, 9+len(opPacket))
				outFrame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(outFrame[1:9], connID)
				copy(outFrame[9:], opPacket)
				_ = opWsConn.WriteMessage(websocket.BinaryMessage, outFrame)
				continue
			}

			if ctrl != e2ee.FrameData {
				continue
			}

			payload := msg[9:]
			opCipherMu.Lock()
			cipher := activeOpCipher
			savedOpNonce := opNonce
			opCipherMu.Unlock()

			if cipher == nil {
				agentNonce, err := e2ee.VerifyAgentHandshake(handshakeKey, sessionID, payload)
				if err != nil {
					continue
				}
				newCipher, err := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, secretKey, savedOpNonce, agentNonce)
				if err != nil {
					continue
				}
				opCipherMu.Lock()
				activeOpCipher = newCipher
				opCipherMu.Unlock()
				continue
			}

			recType, plaintext, err := cipher.DecryptRecord(payload)
			if err != nil {
				continue
			}

			// If plaintext exceeds 4.125 MiB cap, operator sends FrameKickAgent
			if len(plaintext) > protocol.MaxMessageDataBytes+128*1024 {
				kickFrame := make([]byte, 9)
				kickFrame[0] = e2ee.FrameKickAgent
				binary.BigEndian.PutUint64(kickFrame[1:9], connID)
				_ = opWsConn.WriteMessage(websocket.BinaryMessage, kickFrame)
				kickedCh <- connID
				continue
			}

			if recType == e2ee.RecordTypeData {
				var env protocol.Envelope
				if err := json.Unmarshal(plaintext, &env); err == nil && env.Type == protocol.TypePing {
					respEnv, _ := protocol.NewEnvelope(protocol.TypePingResp, protocol.PingResponse{Active: true})
					respBytes, _ := json.Marshal(respEnv)
					encrypted, _ := cipher.EncryptRecord(e2ee.RecordTypeData, respBytes)
					out := make([]byte, 9+len(encrypted))
					out[0] = e2ee.FrameData
					binary.BigEndian.PutUint64(out[1:9], connID)
					copy(out[9:], encrypted)
					_ = opWsConn.WriteMessage(websocket.BinaryMessage, out)
				}
			}
		}
	}()

	// 2. Bad Agent connects and sends 4.8 MiB frame
	agentWsURL := relayWsURL + "?session=" + sessionID + "&role=agent"
	agentConn1, _, err := dialer.Dial(agentWsURL, agentHeader)
	if err != nil {
		t.Fatalf("bad agent dial error: %v", err)
	}
	defer agentConn1.Close()

	agentNonce1, agentHandshake1, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)
	_ = agentConn1.WriteMessage(websocket.BinaryMessage, agentHandshake1)
	_, opPacket1, _ := agentConn1.ReadMessage()
	opNonceRcv1, _ := e2ee.VerifyOperatorHandshake(handshakeKey, sessionID, opPacket1)
	agentCipher1, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonceRcv1, agentNonce1)

	// Encrypt a 4.8 MiB payload (within agent 5 MiB limit, but > operator's 4.125 MiB cap)
	bigPlaintext := bytes.Repeat([]byte("A"), 4800*1024)
	bigEncrypted, err := agentCipher1.EncryptRecord(e2ee.RecordTypeData, bigPlaintext)
	if err != nil {
		t.Fatalf("failed to encrypt big record: %v", err)
	}

	// Write oversized frame
	if err := agentConn1.WriteMessage(websocket.BinaryMessage, bigEncrypted); err != nil {
		t.Fatalf("failed to write oversized frame from agent: %v", err)
	}

	// Verify operator receives it, kicks the bad agent, and bad agent is disconnected
	select {
	case connID := <-kickedCh:
		if connID == 0 {
			t.Fatal("expected non-zero connID kicked")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("operator timed out kicking oversized agent")
	}

	// Bad agent connection should receive CloseMessage or EOF
	_ = agentConn1.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _, err = agentConn1.ReadMessage()
	if err == nil {
		t.Fatal("expected bad agent connection to be closed after kick, but read succeeded")
	}

	// 3. Subsequent good agent connects to same session and pings successfully!
	agentConn2, _, err := dialer.Dial(agentWsURL, agentHeader)
	if err != nil {
		t.Fatalf("good agent dial failed after kick: %v", err)
	}
	defer agentConn2.Close()

	opCipherMu.Lock()
	activeOpCipher = nil
	opCipherMu.Unlock()

	agentNonce2, agentHandshake2, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)
	_ = agentConn2.WriteMessage(websocket.BinaryMessage, agentHandshake2)
	_, opPacket2, err := agentConn2.ReadMessage()
	if err != nil {
		t.Fatalf("good agent failed reading op handshake: %v", err)
	}
	opNonceRcv2, _ := e2ee.VerifyOperatorHandshake(handshakeKey, sessionID, opPacket2)
	agentCipher2, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonceRcv2, agentNonce2)

	pingEnv, _ := protocol.NewEnvelope(protocol.TypePing, protocol.PingRequest{ID: "p-alive"})
	pingBytes, _ := json.Marshal(pingEnv)
	encPing, _ := agentCipher2.EncryptRecord(e2ee.RecordTypeData, pingBytes)
	_ = agentConn2.WriteMessage(websocket.BinaryMessage, encPing)

	_ = agentConn2.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, respEnc, err := agentConn2.ReadMessage()
	if err != nil {
		t.Fatalf("good agent read ping response failed: %v", err)
	}
	_, respPlain, err := agentCipher2.DecryptRecord(respEnc)
	if err != nil {
		t.Fatalf("good agent decrypt response failed: %v", err)
	}
	var env protocol.Envelope
	_ = json.Unmarshal(respPlain, &env)
	if env.Type != protocol.TypePingResp {
		t.Fatalf("expected ping_resp, got %s", env.Type)
	}
}
