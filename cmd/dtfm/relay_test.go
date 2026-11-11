// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
)

func TestRelayConnConcurrentOperationsAndDeadlines(t *testing.T) {
	sessionID := "test-concurrent-ops"
	rawKey, _, _ := e2ee.GenerateSessionKey()

	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)
	opNonce, _, _ := e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
	agentNonce, _, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)

	opCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, rawKey, opNonce, agentNonce)
	agentCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, rawKey, opNonce, agentNonce)

	mockListener := &RelayListener{
		sessionID: sessionID,
		doneCh:    make(chan struct{}),
	}

	conn := newRelayConn(mockListener, 1)
	conn.connCipher.Store(opCipher)

	// 1. Read deadline expiration returns os.ErrDeadlineExceeded
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 16)
	_, err := conn.Read(buf)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expected os.ErrDeadlineExceeded on read timeout, got: %v", err)
	}

	// 2. Concurrent Read and Feed under -race
	var wg sync.WaitGroup
	var feedMu sync.Mutex
	for i := 0; i < 5; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			b := make([]byte, 32)
			_ = conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
			_, _ = conn.Read(b)
		}()

		go func() {
			defer wg.Done()
			feedMu.Lock()
			defer feedMu.Unlock()
			record, err := agentCipher.EncryptRecord(e2ee.RecordTypeData, []byte("data\n"))
			if err == nil {
				conn.feed(record)
			}
		}()
	}
	wg.Wait()

	// 3. Close unblocks all readers with net.ErrClosed
	_ = conn.Close()
	_, err = conn.Read(buf)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after Close(), got: %v", err)
	}
}

func TestRelayConnConcurrentWritesAndStaleConn(t *testing.T) {
	// Start a test HTTP server with WebSocket upgrade
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	serverReceivedFrames := make(chan []byte, 100)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			_, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			serverReceivedFrames <- msg
		}
	}))
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer wsConn.Close()

	sessionID := "stale-conn-test"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)
	opNonce, _, _ := e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
	agentNonce, _, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)

	cipher1, _ := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, rawKey, opNonce, agentNonce)
	cipher2, _ := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, rawKey, opNonce, agentNonce)

	listener := &RelayListener{
		wsConn:    wsConn,
		sessionID: sessionID,
		doneCh:    make(chan struct{}),
	}

	conn1 := newRelayConn(listener, 1)
	conn1.connCipher.Store(cipher1)

	conn2 := newRelayConn(listener, 2)
	conn2.connCipher.Store(cipher2)

	// Set conn1 as active
	listener.activeConn = conn1

	// Concurrent writes on conn1 must not panic gorilla/websocket
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = conn1.Write([]byte("message from conn1\n"))
		}()
	}
	wg.Wait()

	// Switch active connection to conn2
	listener.mu.Lock()
	listener.activeConn = conn2
	listener.mu.Unlock()

	// Stale write from conn1 must be refused with net.ErrClosed
	_, err = conn1.Write([]byte("stale write from old conn1\n"))
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed on stale connection write, got: %v", err)
	}

	// Writes from active conn2 must succeed
	_, err = conn2.Write([]byte("valid write from conn2\n"))
	if err != nil {
		t.Fatalf("expected active conn2 write to succeed, got: %v", err)
	}
}

func TestRelayConnFeedErrorNoDeadlock(t *testing.T) {
	sessionID := "test-feed-deadlock"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)

	listener := &RelayListener{
		sessionID:    sessionID,
		handshakeKey: handshakeKey,
		doneCh:       make(chan struct{}),
	}

	// 1. Corrupted handshake must not deadlock c.readMu
	conn1 := newRelayConn(listener, 1)
	done1 := make(chan struct{})
	go func() {
		conn1.feed([]byte("corrupted-short-handshake"))
		close(done1)
	}()

	select {
	case <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("feed with corrupted handshake deadlocked")
	}

	// Read on conn1 should unblock immediately with net.ErrClosed
	buf := make([]byte, 16)
	_, err := conn1.Read(buf)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after feed error, got: %v", err)
	}

	// 2. Tampered ciphertext after valid handshake must not deadlock
	opNonce, _, _ := e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
	agentNonce, _, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)
	opCipher, _ := e2ee.DeriveConnCipher(e2ee.RoleOperator, sessionID, rawKey, opNonce, agentNonce)

	conn2 := newRelayConn(listener, 2)
	conn2.connCipher.Store(opCipher)

	done2 := make(chan struct{})
	go func() {
		conn2.feed([]byte("tampered-encrypted-record"))
		close(done2)
	}()

	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("feed with tampered ciphertext deadlocked")
	}

	_, err = conn2.Read(buf)
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected net.ErrClosed after tampered record feed, got: %v", err)
	}
}

func TestRelayConnFeedConcurrentWithCloseAndWrite(t *testing.T) {
	sessionID := "test-feed-concurrent"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)
	opNonce, _, _ := e2ee.BuildOperatorHandshake(handshakeKey, sessionID)
	_, agentPacket, _ := e2ee.BuildAgentHandshake(handshakeKey, sessionID)

	listener := &RelayListener{
		sessionID:    sessionID,
		secretKey:    rawKey,
		handshakeKey: handshakeKey,
		doneCh:       make(chan struct{}),
	}

	for iter := 0; iter < 20; iter++ {
		conn := newRelayConn(listener, uint64(iter+1))
		conn.opNonce = opNonce
		listener.activeConn = conn

		var wg sync.WaitGroup
		wg.Add(3)

		// Goroutine 1: Feed handshake
		go func() {
			defer wg.Done()
			conn.feed(agentPacket)
		}()

		// Goroutine 2: Concurrent write
		go func() {
			defer wg.Done()
			_, _ = conn.Write([]byte("concurrent payload\n"))
		}()

		// Goroutine 3: Concurrent Close
		go func() {
			defer wg.Done()
			_ = conn.Close()
		}()

		wg.Wait()
	}
}

func TestEffectiveHubURLDerivation(t *testing.T) {
	derive := func(relayURL string) string {
		u, err := url.Parse(relayURL)
		if err != nil {
			return ""
		}
		scheme := "https"
		if u.Scheme == "ws" {
			scheme = "http"
		}
		basePath := strings.TrimSuffix(strings.TrimRight(u.Path, "/"), "/ws")
		return fmt.Sprintf("%s://%s%s", scheme, u.Host, basePath)
	}

	tests := []struct {
		input    string
		expected string
	}{
		{"wss://relay.dtfm.dev/ws", "https://relay.dtfm.dev"},
		{"ws://localhost:8088/ws", "http://localhost:8088"},
		{"wss://example.com/dtfm/ws", "https://example.com/dtfm"},
		{"ws://example.com/sub/path/ws", "http://example.com/sub/path"},
	}

	for _, tt := range tests {
		got := derive(tt.input)
		if got != tt.expected {
			t.Errorf("derive(%q) = %q, expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestRelayConnFeedConcurrentWithListenerClose(t *testing.T) {
	sessionID := "test-feed-listener-close"
	rawKey, _, _ := e2ee.GenerateSessionKey()
	handshakeKey, _ := e2ee.HandshakeKey(rawKey, sessionID)

	for iter := 0; iter < 20; iter++ {
		listener := &RelayListener{
			sessionID:    sessionID,
			secretKey:    rawKey,
			handshakeKey: handshakeKey,
			doneCh:       make(chan struct{}),
		}

		conn := newRelayConn(listener, uint64(iter+1))
		listener.activeConn = conn

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: Feed corrupted payload triggering kickAndClose
		go func() {
			defer wg.Done()
			conn.feed([]byte("corrupted-payload-triggering-kick"))
		}()

		// Goroutine 2: Concurrent listener.Close()
		go func() {
			defer wg.Done()
			_ = listener.Close()
		}()

		wg.Wait()
	}
}
