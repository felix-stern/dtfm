// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

func TestRelayClientConnDeadlinesAndConcurrentOps(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			_, _, err := ws.ReadMessage()
			if err != nil {
				return
			}
		}
	}))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer wsConn.Close()

	sessionID := "client-conn-test"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)
	opNonce, _, _ := e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
	agentNonce, _, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)

	cipher, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, rawKey, opNonce, agentNonce)

	clientConn := &RelayClientConn{
		wsConn:     wsConn,
		connCipher: cipher,
		sessionID:  sessionID,
		doneCh:     make(chan struct{}),
	}

	// 1. Read deadline expired returns os.ErrDeadlineExceeded
	_ = clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 16)
	_, err = clientConn.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded on read timeout, got: %v", err)
	}

	// 2. Write deadline expired returns os.ErrDeadlineExceeded
	_ = clientConn.SetWriteDeadline(time.Now().Add(-time.Second))
	_, err = clientConn.Write([]byte("expired write\n"))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded on expired write, got: %v", err)
	}

	// 3. Concurrent Writes under -race
	_ = clientConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = clientConn.Write([]byte("concurrent line\n"))
		}()
	}
	wg.Wait()

	// 4. Close
	_ = clientConn.Close()
}

func TestRelayHTTPErrorClassification(t *testing.T) {
	statusCode := http.StatusForbidden
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "status", statusCode)
	}))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	rawKey := bytes.Repeat([]byte{0x42}, e2ee.KeySize)

	// 1. 403 Forbidden -> Code 1
	statusCode = http.StatusForbidden
	_, err := DialRelay(wsURL, "session-test", rawKey)
	var rErr *RelayError
	if !errors.As(err, &rErr) || rErr.Code != 1 {
		t.Fatalf("expected RelayError with Code 1 on 403, got: %v", err)
	}

	// 2. 409 Conflict -> Code 1
	statusCode = http.StatusConflict
	_, err = DialRelay(wsURL, "session-test", rawKey)
	if !errors.As(err, &rErr) || rErr.Code != 1 {
		t.Fatalf("expected RelayError with Code 1 on 409, got: %v", err)
	}

	// 3. 404 Not Found -> Code 2
	statusCode = http.StatusNotFound
	_, err = DialRelay(wsURL, "session-test", rawKey)
	if !errors.As(err, &rErr) || rErr.Code != 2 {
		t.Fatalf("expected RelayError with Code 2 on 404, got: %v", err)
	}

	// 4. 503 Service Unavailable -> Code 2
	statusCode = http.StatusServiceUnavailable
	_, err = DialRelay(wsURL, "session-test", rawKey)
	if !errors.As(err, &rErr) || rErr.Code != 2 {
		t.Fatalf("expected RelayError with Code 2 on 503, got: %v", err)
	}
}

func TestRelayClientConnPongDuringReadNoDeadlock(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	sessionID := "pong-deadlock-test"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)
	opNonce, _, _ := e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
	agentNonce, _, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)

	opCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, rawKey, opNonce, agentNonce)
	agentCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, rawKey, opNonce, agentNonce)

	serverReady := make(chan *websocket.Conn, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverReady <- ws
	}))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	clientWs, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial error: %v", err)
	}
	defer clientWs.Close()

	serverWs := <-serverReady
	defer serverWs.Close()

	clientConn := &RelayClientConn{
		wsConn:     clientWs,
		connCipher: agentCipher,
		sessionID:  sessionID,
		doneCh:     make(chan struct{}),
	}
	defer clientConn.Close()

	clientWs.SetPongHandler(func(string) error {
		clientConn.updateSocketReadDeadline()
		return nil
	})

	// Start a goroutine that waits briefly, sends a Pong control message, then sends an encrypted data frame
	expectedPayload := []byte("payload-after-pong\n")
	go func() {
		time.Sleep(30 * time.Millisecond)
		// Send PongMessage
		_ = serverWs.WriteControl(websocket.PongMessage, []byte{}, time.Now().Add(time.Second))
		time.Sleep(20 * time.Millisecond)
		// Send Encrypted Data
		encrypted, err := opCipher.EncryptRecord(e2ee.RecordTypeData, expectedPayload)
		if err == nil {
			_ = serverWs.WriteMessage(websocket.BinaryMessage, encrypted)
		}
	}()

	// clientConn.Read should NOT deadlock when PongMessage arrives while blocked in ReadMessage
	buf := make([]byte, 64)
	readDone := make(chan error, 1)
	var n int
	go func() {
		var rErr error
		n, rErr = clientConn.Read(buf)
		readDone <- rErr
	}()

	select {
	case err := <-readDone:
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if !bytes.Equal(buf[:n], expectedPayload) {
			t.Fatalf("expected payload %q, got %q", string(expectedPayload), string(buf[:n]))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RelayClientConn.Read deadlocked on incoming PongMessage")
	}
}
