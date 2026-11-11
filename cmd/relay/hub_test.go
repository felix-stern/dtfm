// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

func TestHubHTTPStatusAndMagicLink(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	// 1. Root healthcheck
	res, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}
	body := make([]byte, 64)
	n, _ := res.Body.Read(body)
	if !strings.Contains(string(body[:n]), "dtfm-relay ok") {
		t.Fatalf("expected 'dtfm-relay ok', got %q", string(body[:n]))
	}
	// Verify active session count is not leaked
	if strings.Contains(string(body[:n]), "active sessions") {
		t.Fatalf("healthz should not leak active sessions, got %q", string(body[:n]))
	}

	// 2. Magic link HTTP page
	res, err = http.Get(ts.URL + "/c/test-session-42")
	if err != nil {
		t.Fatalf("GET /c/test-session-42 failed: %v", err)
	}
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.StatusCode)
	}

	// 3. Invalid magic link session ID
	res, err = http.Get(ts.URL + "/c/bad%20session")
	if err != nil {
		t.Fatalf("GET /c/bad session failed: %v", err)
	}
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for invalid session ID, got %d", res.StatusCode)
	}
}

func TestHubWebSocketPairingAndRelay(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	sessionID := "test-session-pairing"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, agentAuth, agentVerifier, err := e2ee.DeriveAuthTokens(rawKey, sessionID)
	if err != nil {
		t.Fatalf("DeriveAuthTokens failed: %v", err)
	}

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)

	// 1. Agent connects before operator -> should be rejected with 404
	agentURL := wsURL + "?session=" + sessionID + "&role=agent"
	_, resp, err := websocket.DefaultDialer.Dial(agentURL, agentHeader)
	if err == nil {
		t.Fatal("expected agent connect before operator to fail, but succeeded")
	}
	if resp != nil && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}

	// 2. Operator connects
	opURL := wsURL + "?session=" + sessionID + "&role=operator"
	opConn, _, err := websocket.DefaultDialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial failed: %v", err)
	}
	defer opConn.Close()

	// Wait for operator registration to complete
	deadline := time.Now().Add(2 * time.Second)
	for hub.ActiveSessionsCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	// 3. Agent connects now -> should succeed
	agentConn, _, err := websocket.DefaultDialer.Dial(agentURL, agentHeader)
	if err != nil {
		t.Fatalf("agent dial failed: %v", err)
	}
	defer agentConn.Close()

	// 4. Operator should receive FrameAgentConnected (0x02) with 8-byte connID
	_ = opConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err := opConn.ReadMessage()
	if err != nil {
		t.Fatalf("failed to read from operator conn: %v", err)
	}
	if msgType != websocket.BinaryMessage || len(msg) != 9 || msg[0] != e2ee.FrameAgentConnected {
		t.Fatalf("expected FrameAgentConnected with connID (9 bytes), got len=%d, bytes=%x", len(msg), msg)
	}
	connID := binary.BigEndian.Uint64(msg[1:9])
	if connID == 0 {
		t.Fatal("expected non-zero connID")
	}

	// 5. Agent sends binary payload to operator
	agentPayload := []byte("encrypted agent payload to operator")
	err = agentConn.WriteMessage(websocket.BinaryMessage, agentPayload)
	if err != nil {
		t.Fatalf("agent write failed: %v", err)
	}

	// Operator receives with FrameData (0x01) + connID (8B) prepended
	_ = opConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err = opConn.ReadMessage()
	if err != nil {
		t.Fatalf("operator read failed: %v", err)
	}
	if msgType != websocket.BinaryMessage || len(msg) < 9 || msg[0] != e2ee.FrameData {
		t.Fatalf("expected FrameData, got %x", msg)
	}
	recvConnID := binary.BigEndian.Uint64(msg[1:9])
	if recvConnID != connID {
		t.Fatalf("connID mismatch: got %d, expected %d", recvConnID, connID)
	}
	if !bytes.Equal(msg[9:], agentPayload) {
		t.Fatalf("payload mismatch: got %s, want %s", string(msg[9:]), string(agentPayload))
	}

	// 6. Operator responds with FrameData + connID + payload
	opPayload := []byte("encrypted operator response to agent")
	opFrame := make([]byte, 9+len(opPayload))
	opFrame[0] = e2ee.FrameData
	binary.BigEndian.PutUint64(opFrame[1:9], connID)
	copy(opFrame[9:], opPayload)

	err = opConn.WriteMessage(websocket.BinaryMessage, opFrame)
	if err != nil {
		t.Fatalf("operator write failed: %v", err)
	}

	// Agent receives raw payload (without 9-byte multiplex header)
	_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err = agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent read failed: %v", err)
	}
	if msgType != websocket.BinaryMessage || !bytes.Equal(msg, opPayload) {
		t.Fatalf("agent payload mismatch: got %s, want %s", string(msg), string(opPayload))
	}

	// 7. Agent disconnects -> operator receives FrameAgentDisconnected (0x03) with connID
	agentConn.Close()

	_ = opConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err = opConn.ReadMessage()
	if err != nil {
		t.Fatalf("operator read after agent disconnect failed: %v", err)
	}
	if msgType != websocket.BinaryMessage || len(msg) != 9 || msg[0] != e2ee.FrameAgentDisconnected {
		t.Fatalf("expected FrameAgentDisconnected with connID, got %x", msg)
	}
	if binary.BigEndian.Uint64(msg[1:9]) != connID {
		t.Fatalf("disconnect connID mismatch: got %d, expected %d", binary.BigEndian.Uint64(msg[1:9]), connID)
	}

	// 8. Another agent connects to same session -> operator receives FrameAgentConnected with connID+1
	agentConn2, _, err := websocket.DefaultDialer.Dial(agentURL, agentHeader)
	if err != nil {
		t.Fatalf("agent2 dial failed: %v", err)
	}
	defer agentConn2.Close()

	_ = opConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, msg, err = opConn.ReadMessage()
	if err != nil {
		t.Fatalf("operator read for agent2 connect failed: %v", err)
	}
	if msgType != websocket.BinaryMessage || len(msg) != 9 || msg[0] != e2ee.FrameAgentConnected {
		t.Fatalf("expected FrameAgentConnected for agent2, got %x", msg)
	}
	connID2 := binary.BigEndian.Uint64(msg[1:9])
	if connID2 <= connID {
		t.Fatalf("expected strictly incrementing connID: got %d, prior was %d", connID2, connID)
	}
}

func TestHubAuthentication(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	sessionID := "auth-test-session"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, agentAuth, agentVerifier, _ := e2ee.DeriveAuthTokens(rawKey, sessionID)

	opURL := wsURL + "?session=" + sessionID + "&role=operator"
	agentURL := wsURL + "?session=" + sessionID + "&role=agent"

	// 1. Operator without headers fails with 403
	_, resp, err := websocket.DefaultDialer.Dial(opURL, nil)
	if err == nil {
		t.Fatal("expected unauthenticated operator to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	// 2. Operator with valid headers succeeds
	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)
	opConn, _, err := websocket.DefaultDialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial failed: %v", err)
	}
	defer opConn.Close()

	// 3. Agent without headers fails with 403
	_, resp, err = websocket.DefaultDialer.Dial(agentURL, nil)
	if err == nil {
		t.Fatal("expected unauthenticated agent to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	// 4. Agent with wrong token fails with 403
	badHeader := make(http.Header)
	badHeader.Set("X-DTFM-Auth", strings.Repeat("0", 64))
	_, resp, err = websocket.DefaultDialer.Dial(agentURL, badHeader)
	if err == nil {
		t.Fatal("expected bad agent token to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	// 5. Agent with correct token succeeds
	goodHeader := make(http.Header)
	goodHeader.Set("X-DTFM-Auth", agentAuth)
	agentConn, _, err := websocket.DefaultDialer.Dial(agentURL, goodHeader)
	if err != nil {
		t.Fatalf("valid agent dial failed: %v", err)
	}
	defer agentConn.Close()
}

func TestHubFrameKickAgent(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	sessionID := "kick-test-session"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, agentAuth, agentVerifier, _ := e2ee.DeriveAuthTokens(rawKey, sessionID)

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)

	opURL := wsURL + "?session=" + sessionID + "&role=operator"
	agentURL := wsURL + "?session=" + sessionID + "&role=agent"

	opConn, _, err := websocket.DefaultDialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial failed: %v", err)
	}
	defer opConn.Close()

	agentConn1, _, err := websocket.DefaultDialer.Dial(agentURL, agentHeader)
	if err != nil {
		t.Fatalf("agent1 dial failed: %v", err)
	}
	defer agentConn1.Close()

	// Read agent connected frame on operator
	_ = opConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := opConn.ReadMessage()
	if err != nil || len(msg) != 9 || msg[0] != e2ee.FrameAgentConnected {
		t.Fatalf("failed to read FrameAgentConnected: %v", err)
	}
	connID1 := binary.BigEndian.Uint64(msg[1:9])

	// Operator kicks agent 1
	kickFrame := make([]byte, 9)
	kickFrame[0] = e2ee.FrameKickAgent
	binary.BigEndian.PutUint64(kickFrame[1:9], connID1)
	if err := opConn.WriteMessage(websocket.BinaryMessage, kickFrame); err != nil {
		t.Fatalf("failed to send FrameKickAgent: %v", err)
	}

	// Agent 1 should be disconnected
	_ = agentConn1.SetReadDeadline(time.Now().Add(time.Second))
	_, _, err = agentConn1.ReadMessage()
	if err == nil {
		t.Fatal("expected agent1 to be closed after kick")
	}

	// Immediately connect agent 2: should succeed (NOT 409 Conflict!)
	agentConn2, _, err := websocket.DefaultDialer.Dial(agentURL, agentHeader)
	if err != nil {
		t.Fatalf("agent2 dial failed after kick: %v (expected immediate availability)", err)
	}
	defer agentConn2.Close()
}

func TestHubOriginSecurity(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	sessionID := "origin-test-session"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, _, agentVerifier, _ := e2ee.DeriveAuthTokens(rawKey, sessionID)

	opURL := wsURL + "?session=" + sessionID + "&role=operator"
	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	// Cross-origin request from malicious site -> 403
	evilHeader := opHeader.Clone()
	evilHeader.Set("Origin", "https://evil-attacker-site.com")
	_, resp, err := websocket.DefaultDialer.Dial(opURL, evilHeader)
	if err == nil {
		t.Fatal("expected cross-origin request to fail")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", resp.StatusCode)
	}

	// Matching origin request -> success
	goodOriginHeader := opHeader.Clone()
	goodOriginHeader.Set("Origin", ts.URL)
	conn, _, err := websocket.DefaultDialer.Dial(opURL, goodOriginHeader)
	if err != nil {
		t.Fatalf("matching origin request failed: %v", err)
	}
	_ = conn.Close()
}

func TestHubIdleTimeoutEviction(t *testing.T) {
	hub := NewHub(100*time.Millisecond, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	sessionID := "test-idle-eviction"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, _, agentVerifier, _ := e2ee.DeriveAuthTokens(rawKey, sessionID)

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	opURL := wsURL + "?session=" + sessionID + "&role=operator"
	opConn, _, err := websocket.DefaultDialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial failed: %v", err)
	}
	defer opConn.Close()

	// Wait for operator registration to complete
	deadline := time.Now().Add(2 * time.Second)
	for hub.ActiveSessionsCount() != 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}

	if hub.ActiveSessionsCount() != 1 {
		t.Fatalf("expected 1 active session, got %d", hub.ActiveSessionsCount())
	}

	// Manually trigger sweep after idle period
	time.Sleep(150 * time.Millisecond)
	hub.sweepExpiredSessions(time.Now())

	if hub.ActiveSessionsCount() != 0 {
		t.Fatalf("expected 0 active sessions after sweep, got %d", hub.ActiveSessionsCount())
	}
}

func TestHubPerIPLimit(t *testing.T) {
	hub := NewHubWithConfig(HubConfig{
		IdleTimeout:      time.Minute,
		MaxSessions:      100,
		MaxSessionsPerIP: 2,
		ExemptLoopback:   false, // strictly enforce on test loopback
	})
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"

	connectOp := func(sessionID string) (*websocket.Conn, *http.Response, error) {
		rawKey, _, _ := e2ee.GenerateSessionKey()
		opAuth, _, agentVerifier, _ := e2ee.DeriveAuthTokens(rawKey, sessionID)
		h := make(http.Header)
		h.Set("X-DTFM-Auth", opAuth)
		h.Set("X-DTFM-Agent-Verifier", agentVerifier)
		return websocket.DefaultDialer.Dial(wsURL+"?session="+sessionID+"&role=operator", h)
	}

	conn1, _, err := connectOp("session-ip-1")
	if err != nil {
		t.Fatalf("operator 1 connect failed: %v", err)
	}
	defer conn1.Close()

	conn2, _, err := connectOp("session-ip-2")
	if err != nil {
		t.Fatalf("operator 2 connect failed: %v", err)
	}
	defer conn2.Close()

	// 3rd session from same IP must fail with 429
	conn3, resp, err := connectOp("session-ip-3")
	if err == nil {
		conn3.Close()
		t.Fatal("expected operator 3 to be rejected due to per-IP limit, but succeeded")
	}
	if resp != nil && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected HTTP 503 or 429, got %d", resp.StatusCode)
	}

	// Close conn1 and wait for cleanup
	conn1.Close()
	time.Sleep(50 * time.Millisecond)

	// Now session-ip-3 should succeed
	conn3, _, err = connectOp("session-ip-3")
	if err != nil {
		t.Fatalf("operator 3 connect failed after freeing slot: %v", err)
	}
	defer conn3.Close()
}

func TestHubTrustedProxiesAndForwardedHeaders(t *testing.T) {
	trusted, err := ParseTrustedProxies("127.0.0.0/8,::1/128,10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseTrustedProxies failed: %v", err)
	}

	hub := NewHubWithConfig(HubConfig{
		IdleTimeout:    time.Minute,
		MaxSessions:    100,
		TrustedProxies: trusted,
	})
	defer hub.Close()

	// 1. Untrusted peer sending spoofed headers: header must be ignored
	r1, _ := http.NewRequest("GET", "/ws", nil)
	r1.RemoteAddr = "198.51.100.5:4321"
	r1.Header.Set("X-Forwarded-For", "203.0.113.10")
	r1.Header.Set("X-Real-IP", "203.0.113.10")
	if ip, fwd := hub.getRemoteIP(r1); ip != "198.51.100.5" || fwd {
		t.Fatalf("expected untrusted peer IP 198.51.100.5 (fwd=false), got %s (fwd=%v)", ip, fwd)
	}

	// 2. Trusted proxy peer sending X-Real-IP
	r2, _ := http.NewRequest("GET", "/ws", nil)
	r2.RemoteAddr = "127.0.0.1:4321"
	r2.Header.Set("X-Real-IP", "203.0.113.50")
	if ip, fwd := hub.getRemoteIP(r2); ip != "203.0.113.50" || !fwd {
		t.Fatalf("expected forwarded X-Real-IP 203.0.113.50 (fwd=true), got %s (fwd=%v)", ip, fwd)
	}

	// 3. Trusted proxy peer sending X-Forwarded-For chain: client, intermediate-proxy
	r3, _ := http.NewRequest("GET", "/ws", nil)
	r3.RemoteAddr = "10.0.0.2:4321"
	r3.Header.Set("X-Forwarded-For", "198.51.100.99, 10.0.0.1")
	if ip, fwd := hub.getRemoteIP(r3); ip != "198.51.100.99" || !fwd {
		t.Fatalf("expected rightmost untrusted IP 198.51.100.99 (fwd=true), got %s (fwd=%v)", ip, fwd)
	}

	// 4. X-Forwarded-For precedence over X-Real-IP (prevents spoofed X-Real-IP injection)
	r4, _ := http.NewRequest("GET", "/ws", nil)
	r4.RemoteAddr = "127.0.0.1:4321"
	r4.Header.Set("X-Forwarded-For", "203.0.113.10")
	r4.Header.Set("X-Real-IP", "127.0.0.1")
	if ip, fwd := hub.getRemoteIP(r4); ip != "203.0.113.10" || !fwd {
		t.Fatalf("expected X-Forwarded-For precedence 203.0.113.10, got %s (fwd=%v)", ip, fwd)
	}

	// 5. Explicit empty slice disables proxy header trust entirely
	hubDisabled := NewHubWithConfig(HubConfig{
		IdleTimeout:    time.Minute,
		MaxSessions:    100,
		TrustedProxies: []*net.IPNet{},
	})
	defer hubDisabled.Close()

	r5, _ := http.NewRequest("GET", "/ws", nil)
	r5.RemoteAddr = "127.0.0.1:4321"
	r5.Header.Set("X-Forwarded-For", "203.0.113.10")
	r5.Header.Set("X-Real-IP", "203.0.113.50")
	if ip, fwd := hubDisabled.getRemoteIP(r5); ip != "127.0.0.1" || fwd {
		t.Fatalf("expected direct peer 127.0.0.1 when trusted proxies disabled, got %s (fwd=%v)", ip, fwd)
	}

	// 6. Forwarded loopback is NOT exempt from per-IP rate limits
	hubRateLimit := NewHubWithConfig(HubConfig{
		IdleTimeout:      time.Minute,
		MaxSessions:      100,
		MaxSessionsPerIP: 1,
		ExemptLoopback:   true,
		TrustedProxies:   trusted,
	})
	defer hubRateLimit.Close()

	hubRateLimit.sessionsPerIP["127.0.0.1"] = 1
	// Direct loopback peer is exempt
	if hubRateLimit.isIPRateLimited("127.0.0.1", false) {
		t.Fatalf("expected direct loopback to be exempt from rate limits")
	}
	// Forwarded loopback is NOT exempt
	if !hubRateLimit.isIPRateLimited("127.0.0.1", true) {
		t.Fatalf("expected forwarded loopback to NOT be exempt from rate limits")
	}

	// 7. Multi-header X-Forwarded-For coalescence
	r7, _ := http.NewRequest("GET", "/ws", nil)
	r7.RemoteAddr = "127.0.0.1:4321"
	r7.Header.Add("X-Forwarded-For", "1.2.3.4")
	r7.Header.Add("X-Forwarded-For", "203.0.113.9")
	if ip, fwd := hub.getRemoteIP(r7); ip != "203.0.113.9" || !fwd {
		t.Fatalf("expected multi-header rightmost untrusted IP 203.0.113.9, got %s (fwd=%v)", ip, fwd)
	}

	// 8. Malformed hop stops right-to-left traversal and falls back to rightmost valid trusted IP
	r8, _ := http.NewRequest("GET", "/ws", nil)
	r8.RemoteAddr = "127.0.0.1:4321"
	r8.Header.Set("X-Forwarded-For", "1.2.3.4, not-an-ip, 10.0.0.1")
	if ip, fwd := hub.getRemoteIP(r8); ip != "10.0.0.1" || !fwd {
		t.Fatalf("expected malformed hop fallback to rightmost trusted IP 10.0.0.1, got %s (fwd=%v)", ip, fwd)
	}
}

func TestHubKickDrainsQueuedData(t *testing.T) {
	hub := NewHub(time.Minute, 100, nil)
	defer hub.Close()

	ts := httptest.NewServer(hub)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	sessionID := "drain-kick-test"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	opAuth, agentAuth, agentVerifier, _ := e2ee.DeriveAuthTokens(rawKey, sessionID)

	opHeader := make(http.Header)
	opHeader.Set("X-DTFM-Auth", opAuth)
	opHeader.Set("X-DTFM-Agent-Verifier", agentVerifier)

	opURL := wsURL + "?session=" + sessionID + "&role=operator"
	opConn, _, err := websocket.DefaultDialer.Dial(opURL, opHeader)
	if err != nil {
		t.Fatalf("operator dial failed: %v", err)
	}
	defer opConn.Close()

	agentHeader := make(http.Header)
	agentHeader.Set("X-DTFM-Auth", agentAuth)
	agentURL := wsURL + "?session=" + sessionID + "&role=agent"
	agentConn, _, err := websocket.DefaultDialer.Dial(agentURL, agentHeader)
	if err != nil {
		t.Fatalf("agent dial failed: %v", err)
	}
	defer agentConn.Close()

	// Read operator notification about agent connected
	_, msg, err := opConn.ReadMessage()
	if err != nil || len(msg) < 9 || msg[0] != e2ee.FrameAgentConnected {
		t.Fatalf("expected FrameAgentConnected, got %v (%x)", err, msg)
	}
	connID := binary.BigEndian.Uint64(msg[1:9])

	// Operator enqueues FrameData followed immediately by FrameKickAgent
	dataPayload := []byte("final-error-response")
	dataMsg := make([]byte, 9+len(dataPayload))
	dataMsg[0] = e2ee.FrameData
	binary.BigEndian.PutUint64(dataMsg[1:9], connID)
	copy(dataMsg[9:], dataPayload)
	_ = opConn.WriteMessage(websocket.BinaryMessage, dataMsg)

	kickMsg := make([]byte, 9)
	kickMsg[0] = e2ee.FrameKickAgent
	binary.BigEndian.PutUint64(kickMsg[1:9], connID)
	_ = opConn.WriteMessage(websocket.BinaryMessage, kickMsg)

	// Agent should receive dataPayload cleanly before connection closes
	_ = agentConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	msgType, received, err := agentConn.ReadMessage()
	if err != nil {
		t.Fatalf("agent failed to read queued data before kick: %v", err)
	}
	if msgType != websocket.BinaryMessage || !bytes.Equal(received, dataPayload) {
		t.Fatalf("expected payload %q, got %q", string(dataPayload), string(received))
	}

	// Next read should return EOF / CloseMessage
	_, _, err = agentConn.ReadMessage()
	if err == nil {
		t.Fatal("expected agent connection to close after draining kick")
	}
}
