// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

const (
	writeWait         = 10 * time.Second
	pongWait          = 90 * time.Second
	pingPeriod        = 30 * time.Second
	maxWriteBufferCap = protocol.MaxMessageDataBytes + 128*1024
	maxReadBufferCap  = protocol.MaxResponseEnvelopeBytes + 64*1024
	handshakeWait     = 15 * time.Second
)

type relayAddr struct {
	network string
	str     string
}

func (a relayAddr) Network() string { return a.network }
func (a relayAddr) String() string  { return a.str }

// RelayClientConn implements net.Conn for the agent CLI communicating with dtfm via relay.
// RelayError encapsulates classified relay transport and protocol errors.
type RelayError struct {
	Code    int // POSIX exit code: 1 (bad request, auth failure, 409 busy) or 2 (inactive/unreachable)
	Message string
	Err     error
}

func (e *RelayError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *RelayError) Unwrap() error {
	return e.Err
}

type RelayClientConn struct {
	wsConn        *websocket.Conn
	wsWriteMu     sync.Mutex
	connCipher    *e2ee.ConnCipher
	sessionID     string
	readBuf       bytes.Buffer
	readMu        sync.Mutex
	deadlineMu    sync.Mutex
	readDeadline  time.Time
	writeMu       sync.Mutex
	writeBuf      bytes.Buffer
	writeDeadline time.Time
	closed        atomic.Bool
	remoteEOF     atomic.Bool
	doneCh        chan struct{}
}

// DialRelay establishes an authenticated, encrypted agent connection to the relay server.
func DialRelay(relayWsURL, sessionID string, secretKey []byte) (net.Conn, error) {
	if err := e2ee.ValidateSessionID(sessionID); err != nil {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid session ID: %v", err)}
	}
	if len(secretKey) != e2ee.KeySize {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid secret key length: expected %d bytes (256 bits), got %d", e2ee.KeySize, len(secretKey))}
	}

	_, agentAuthHex, _, err := e2ee.DeriveAuthTokens(secretKey, sessionID)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to derive agent auth tokens", Err: err}
	}

	handshakeKey, err := e2ee.HandshakeKey(secretKey, sessionID)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: "failed to derive handshake key", Err: err}
	}

	u, err := url.Parse(relayWsURL)
	if err != nil {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid relay websocket url: %v", err)}
	}
	if (u.Scheme != "ws" && u.Scheme != "wss") || u.Host == "" {
		return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid relay websocket url (must be ws:// or wss:// with host): %q", relayWsURL)}
	}

	q := u.Query()
	q.Set("session", sessionID)
	q.Set("role", e2ee.RoleAgent)
	u.RawQuery = q.Encode()

	headers := make(http.Header)
	headers.Set("X-DTFM-Auth", agentAuthHex)

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 5 * time.Second

	wsConn, httpResp, err := dialer.Dial(u.String(), headers)
	if err != nil {
		if httpResp != nil {
			switch httpResp.StatusCode {
			case http.StatusForbidden:
				return nil, &RelayError{Code: 1, Message: "relay authentication failed: invalid token or secret key (HTTP 403 Forbidden)"}
			case http.StatusNotFound:
				return nil, &RelayError{Code: 2, Message: fmt.Sprintf("🔴 LMDTFY session is inactive (relay session %q not found or operator is not connected)", sessionID)}
			case http.StatusConflict:
				return nil, &RelayError{Code: 1, Message: fmt.Sprintf("relay session %q is busy with another agent command (HTTP 409 Conflict)", sessionID)}
			case http.StatusBadRequest:
				return nil, &RelayError{Code: 1, Message: fmt.Sprintf("invalid relay request (HTTP 400 Bad Request): %v", err)}
			case http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
				return nil, &RelayError{Code: 2, Message: fmt.Sprintf("🔴 LMDTFY session is inactive (relay server unreachable: HTTP %d)", httpResp.StatusCode), Err: err}
			default:
				if httpResp.StatusCode >= 500 {
					return nil, &RelayError{Code: 2, Message: fmt.Sprintf("🔴 LMDTFY session is inactive (relay server error HTTP %d)", httpResp.StatusCode), Err: err}
				}
				return nil, &RelayError{Code: 1, Message: fmt.Sprintf("failed to connect to relay server (HTTP %d)", httpResp.StatusCode), Err: err}
			}
		}
		return nil, &RelayError{Code: 2, Message: fmt.Sprintf("🔴 LMDTFY session is inactive (cannot connect to relay at %s)", relayWsURL), Err: err}
	}

	wsConn.SetReadLimit(protocol.MaxResponseEnvelopeBytes + 256*1024)

	// Send agent handshake immediately
	agentNonce, agentHandshakePacket, err := e2ee.BuildAgentHandshake(handshakeKey, sessionID)
	if err != nil {
		_ = wsConn.Close()
		return nil, &RelayError{Code: 1, Message: "failed to build agent handshake", Err: err}
	}

	_ = wsConn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := wsConn.WriteMessage(websocket.BinaryMessage, agentHandshakePacket); err != nil {
		_ = wsConn.Close()
		return nil, &RelayError{Code: 1, Message: "failed to send agent handshake to relay", Err: err}
	}

	// Read operator handshake packet
	_ = wsConn.SetReadDeadline(time.Now().Add(handshakeWait))
	msgType, opPacket, err := wsConn.ReadMessage()
	if err != nil {
		_ = wsConn.Close()
		return nil, &RelayError{Code: 1, Message: "failed to read operator handshake from relay", Err: err}
	}
	if msgType != websocket.BinaryMessage {
		_ = wsConn.Close()
		return nil, &RelayError{Code: 1, Message: "unexpected non-binary operator handshake message"}
	}

	opNonce, err := e2ee.VerifyOperatorHandshake(handshakeKey, sessionID, opPacket)
	if err != nil {
		_ = wsConn.Close()
		return nil, &RelayError{Code: 1, Message: "operator handshake verification failed (tampered or mismatched key)", Err: err}
	}

	connCipher, err := e2ee.DeriveConnCipher(e2ee.RoleAgent, sessionID, secretKey, opNonce, agentNonce)
	if err != nil {
		_ = wsConn.Close()
		return nil, &RelayError{Code: 1, Message: "failed to derive connection cipher", Err: err}
	}

	rc := &RelayClientConn{
		wsConn:     wsConn,
		connCipher: connCipher,
		sessionID:  sessionID,
		doneCh:     make(chan struct{}),
	}

	wsConn.SetPongHandler(func(string) error {
		rc.updateSocketReadDeadline()
		return nil
	})

	rc.updateSocketReadDeadline()
	go rc.pingLoop()

	return rc, nil
}

func (c *RelayClientConn) updateSocketReadDeadline() {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()

	rd := c.readDeadline
	now := time.Now()
	pongDeadline := now.Add(pongWait)
	effective := pongDeadline
	if !rd.IsZero() && rd.Before(pongDeadline) {
		effective = rd
	}
	_ = c.wsConn.SetReadDeadline(effective)
}

func (c *RelayClientConn) pingLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-c.doneCh:
			return
		case <-ticker.C:
			c.wsWriteMu.Lock()
			if c.closed.Load() || c.wsConn == nil {
				c.wsWriteMu.Unlock()
				return
			}
			_ = c.wsConn.SetWriteDeadline(time.Now().Add(writeWait))
			err := c.wsConn.WriteMessage(websocket.PingMessage, nil)
			c.wsWriteMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (c *RelayClientConn) Read(p []byte) (n int, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if c.closed.Load() {
			return 0, net.ErrClosed
		}

		if c.readBuf.Len() > 0 {
			return c.readBuf.Read(p)
		}

		if c.remoteEOF.Load() {
			return 0, io.EOF
		}

		c.deadlineMu.Lock()
		rd := c.readDeadline
		now := time.Now()
		if !rd.IsZero() && !now.Before(rd) {
			c.deadlineMu.Unlock()
			return 0, os.ErrDeadlineExceeded
		}

		pongDeadline := now.Add(pongWait)
		effective := pongDeadline
		if !rd.IsZero() && rd.Before(pongDeadline) {
			effective = rd
		}
		_ = c.wsConn.SetReadDeadline(effective)
		c.deadlineMu.Unlock()

		msgType, msg, err := c.wsConn.ReadMessage()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.deadlineMu.Lock()
				curRd := c.readDeadline
				c.deadlineMu.Unlock()
				if !curRd.IsZero() && !time.Now().Before(curRd) {
					return 0, os.ErrDeadlineExceeded
				}
				// Pong wait timeout exceeded (dead connection)
				return 0, io.ErrUnexpectedEOF
			}
			return 0, err
		}

		if msgType != websocket.BinaryMessage {
			continue
		}

		recType, plaintext, err := c.connCipher.DecryptRecord(msg)
		if err != nil {
			return 0, fmt.Errorf("failed to decrypt incoming frame: %w", err)
		}

		switch recType {
		case e2ee.RecordTypeEOF:
			c.remoteEOF.Store(true)
			return 0, io.EOF
		case e2ee.RecordTypeData:
			// proceed to buffer plaintext
		default:
			return 0, fmt.Errorf("unexpected record type 0x%02x", recType)
		}

		if c.readBuf.Len()+len(plaintext) > maxReadBufferCap {
			return 0, errors.New("read buffer capacity exceeded")
		}

		c.readBuf.Write(plaintext)
		if !bytes.HasSuffix(plaintext, []byte("\n")) {
			c.readBuf.WriteByte('\n')
		}
	}
}

func (c *RelayClientConn) Write(p []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	if c.writeBuf.Len()+len(p) > maxWriteBufferCap {
		return 0, errors.New("write buffer capacity exceeded")
	}

	c.writeBuf.Write(p)

	// Flush when a newline is present
	if bytes.Contains(c.writeBuf.Bytes(), []byte("\n")) {
		if err := c.flushLocked(); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

func (c *RelayClientConn) flushLocked() error {
	data := c.writeBuf.Bytes()
	if len(data) == 0 {
		return nil
	}

	ciphertext, err := c.connCipher.EncryptRecord(e2ee.RecordTypeData, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt request frame: %w", err)
	}

	c.wsWriteMu.Lock()
	defer c.wsWriteMu.Unlock()

	if c.closed.Load() {
		return net.ErrClosed
	}

	if !c.writeDeadline.IsZero() {
		if time.Now().After(c.writeDeadline) {
			return os.ErrDeadlineExceeded
		}
		_ = c.wsConn.SetWriteDeadline(c.writeDeadline)
	} else {
		_ = c.wsConn.SetWriteDeadline(time.Now().Add(writeWait))
	}

	if err := c.wsConn.WriteMessage(websocket.BinaryMessage, ciphertext); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return os.ErrDeadlineExceeded
		}
		return fmt.Errorf("failed to send frame over websocket: %w", err)
	}

	c.writeBuf.Reset()
	return nil
}

func (c *RelayClientConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	close(c.doneCh)

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.wsWriteMu.Lock()
	defer c.wsWriteMu.Unlock()

	// If remote peer hasn't sent EOF yet, send authenticated RecordTypeEOF before closing
	if !c.remoteEOF.Load() && c.connCipher != nil {
		eofRecord, err := c.connCipher.EncryptRecord(e2ee.RecordTypeEOF, []byte{})
		if err == nil {
			_ = c.wsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			_ = c.wsConn.WriteMessage(websocket.BinaryMessage, eofRecord)
		}
	}

	_ = c.wsConn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, "agent client closed"),
		time.Now().Add(time.Second))

	return c.wsConn.Close()
}

func (c *RelayClientConn) LocalAddr() net.Addr {
	return relayAddr{network: "relay", str: "agent"}
}

func (c *RelayClientConn) RemoteAddr() net.Addr {
	return relayAddr{network: "relay", str: c.sessionID}
}

func (c *RelayClientConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *RelayClientConn) SetReadDeadline(t time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = t
	now := time.Now()
	pongDeadline := now.Add(pongWait)
	effective := pongDeadline
	if !t.IsZero() && t.Before(pongDeadline) {
		effective = t
	}
	_ = c.wsConn.SetReadDeadline(effective)
	c.deadlineMu.Unlock()
	return nil
}

func (c *RelayClientConn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	c.writeDeadline = t
	c.writeMu.Unlock()
	return nil
}
