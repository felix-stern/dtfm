// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
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
	pingPeriod        = (pongWait * 9) / 10
	maxReadBufferCap  = protocol.MaxMessageDataBytes + 128*1024
	maxWriteBufferCap = protocol.MaxResponseEnvelopeBytes
	handshakeWait     = 15 * time.Second
)

type relayAddr struct {
	network string
	str     string
}

func (a relayAddr) Network() string { return a.network }
func (a relayAddr) String() string  { return a.str }

// RelayListener implements net.Listener over a persistent WebSocket connection to the relay server.
type RelayListener struct {
	wsConn        *websocket.Conn
	wsWriteMu     sync.Mutex
	sessionID     string
	secretKey     []byte
	handshakeKey  []byte
	relayURL      string
	acceptCh      chan net.Conn
	doneCh        chan struct{}
	closeOnce     sync.Once
	mu            sync.Mutex
	activeConn    *RelayConn
	disconnectErr error
	closed        atomic.Bool
}

// DialRelayListener establishes an authenticated operator connection to the relay server and returns a net.Listener.
func DialRelayListener(relayWsURL, sessionID string, secretKey []byte) (*RelayListener, error) {
	if err := e2ee.ValidateSessionID(sessionID); err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}
	if len(secretKey) != e2ee.KeySize {
		return nil, fmt.Errorf("invalid secret key length: expected %d bytes (256 bits), got %d", e2ee.KeySize, len(secretKey))
	}

	opAuthHex, _, agentVerifierHex, err := e2ee.DeriveAuthTokens(secretKey, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive relay auth tokens: %w", err)
	}

	handshakeKey, err := e2ee.HandshakeKey(secretKey, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to derive handshake key: %w", err)
	}

	u, err := url.Parse(relayWsURL)
	if err != nil {
		return nil, fmt.Errorf("invalid relay websocket url: %w", err)
	}

	q := u.Query()
	q.Set("session", sessionID)
	q.Set("role", e2ee.RoleOperator)
	u.RawQuery = q.Encode()

	headers := make(http.Header)
	headers.Set("X-DTFM-Auth", opAuthHex)
	headers.Set("X-DTFM-Agent-Verifier", agentVerifierHex)

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second

	wsConn, resp, err := dialer.Dial(u.String(), headers)
	if err != nil {
		if resp != nil {
			switch resp.StatusCode {
			case http.StatusForbidden:
				return nil, fmt.Errorf("relay authentication failed: invalid token or session mismatch (HTTP 403 Forbidden)")
			case http.StatusServiceUnavailable:
				return nil, fmt.Errorf("relay server is at maximum session capacity (HTTP 503)")
			default:
				return nil, fmt.Errorf("relay connection failed (HTTP %d): %w", resp.StatusCode, err)
			}
		}
		return nil, fmt.Errorf("failed to connect to relay server at %s: %w", relayWsURL, err)
	}

	wsConn.SetReadLimit(6 * 1024 * 1024)

	rl := &RelayListener{
		wsConn:       wsConn,
		sessionID:    sessionID,
		secretKey:    secretKey,
		handshakeKey: handshakeKey,
		relayURL:     relayWsURL,
		acceptCh:     make(chan net.Conn, 16),
		doneCh:       make(chan struct{}),
	}

	// Ping keepalive loop
	go rl.pingLoop()

	// Read pump loop
	go rl.readPump()

	return rl, nil
}

func (l *RelayListener) pingLoop() {
	ticker := time.NewTicker(pingPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-l.doneCh:
			return
		case <-ticker.C:
			l.wsWriteMu.Lock()
			if l.closed.Load() {
				l.wsWriteMu.Unlock()
				return
			}
			_ = l.wsConn.SetWriteDeadline(time.Now().Add(writeWait))
			err := l.wsConn.WriteMessage(websocket.PingMessage, nil)
			l.wsWriteMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (l *RelayListener) sendKickAgent(connID uint64) {
	l.wsWriteMu.Lock()
	defer l.wsWriteMu.Unlock()
	if l.closed.Load() || l.wsConn == nil {
		return
	}

	hdr := make([]byte, 9)
	hdr[0] = e2ee.FrameKickAgent
	binary.BigEndian.PutUint64(hdr[1:9], connID)
	_ = l.wsConn.SetWriteDeadline(time.Now().Add(writeWait))
	_ = l.wsConn.WriteMessage(websocket.BinaryMessage, hdr)
}

func (l *RelayListener) readPump() {
	defer func() {
		_ = l.Close()
	}()

	_ = l.wsConn.SetReadDeadline(time.Now().Add(pongWait))
	l.wsConn.SetPongHandler(func(string) error {
		_ = l.wsConn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_ = l.wsConn.SetReadDeadline(time.Now().Add(pongWait))
		msgType, msg, err := l.wsConn.ReadMessage()
		if err != nil {
			l.mu.Lock()
			if !l.closed.Load() && l.disconnectErr == nil {
				l.disconnectErr = fmt.Errorf("relay connection dropped: %w", err)
			}
			prev := l.activeConn
			l.activeConn = nil
			l.mu.Unlock()
			if prev != nil {
				prev.signalEOF()
			}
			return
		}

		if msgType != websocket.BinaryMessage || len(msg) < 9 {
			continue
		}

		ctrlType := msg[0]
		connID := binary.BigEndian.Uint64(msg[1:9])

		switch ctrlType {
		case e2ee.FrameAgentConnected:
			l.mu.Lock()
			prev := l.activeConn
			conn := newRelayConn(l, connID)
			l.activeConn = conn
			l.mu.Unlock()
			if prev != nil {
				prev.signalEOF()
			}

			// Send operator handshake immediately to agent
			opNonce, opHandshakePacket, err := e2ee.BuildOperatorHandshake(l.handshakeKey, l.sessionID)
			if err != nil {
				conn.kickAndClose()
				continue
			}
			conn.opNonce = opNonce

			outFrame := make([]byte, 9+len(opHandshakePacket))
			outFrame[0] = e2ee.FrameData
			binary.BigEndian.PutUint64(outFrame[1:9], connID)
			copy(outFrame[9:], opHandshakePacket)

			l.wsWriteMu.Lock()
			_ = l.wsConn.SetWriteDeadline(time.Now().Add(writeWait))
			writeErr := l.wsConn.WriteMessage(websocket.BinaryMessage, outFrame)
			l.wsWriteMu.Unlock()

			if writeErr != nil {
				conn.kickAndClose()
				continue
			}

			select {
			case <-l.doneCh:
				return
			case l.acceptCh <- conn:
			default:
				conn.kickAndClose()
			}

		case e2ee.FrameAgentDisconnected:
			l.mu.Lock()
			var prev *RelayConn
			if l.activeConn != nil && l.activeConn.connID == connID {
				prev = l.activeConn
				l.activeConn = nil
			}
			l.mu.Unlock()
			if prev != nil {
				prev.signalEOF()
			}

		case e2ee.FrameData:
			payload := msg[9:]
			l.mu.Lock()
			conn := l.activeConn
			l.mu.Unlock()

			if conn != nil && conn.connID == connID {
				conn.feed(payload)
			}
		}
	}
}

func (l *RelayListener) Accept() (net.Conn, error) {
	select {
	case <-l.doneCh:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.disconnectErr != nil {
			return nil, l.disconnectErr
		}
		return nil, net.ErrClosed
	case conn, ok := <-l.acceptCh:
		if !ok {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.disconnectErr != nil {
				return nil, l.disconnectErr
			}
			return nil, net.ErrClosed
		}
		return conn, nil
	}
}

func (l *RelayListener) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.doneCh)

		l.wsWriteMu.Lock()
		if l.wsConn != nil {
			_ = l.wsConn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, "listener closed"),
				time.Now().Add(time.Second))
			_ = l.wsConn.Close()
		}
		l.wsWriteMu.Unlock()

		l.mu.Lock()
		prev := l.activeConn
		l.activeConn = nil
		l.mu.Unlock()
		if prev != nil {
			prev.signalEOF()
		}
	})
	return nil
}

func (l *RelayListener) Addr() net.Addr {
	return relayAddr{network: "relay", str: l.sessionID}
}

// RelayConn represents an active agent session bridged over the relay with E2EE.
type RelayConn struct {
	listener      *RelayListener
	connID        uint64
	opNonce       []byte
	connCipher    atomic.Pointer[e2ee.ConnCipher]
	readBuf       bytes.Buffer
	readMu        sync.Mutex
	readCond      *sync.Cond
	readDeadline  time.Time
	writeMu       sync.Mutex
	writeBuf      bytes.Buffer
	writeDeadline time.Time
	closed        atomic.Bool
	remoteEOF     atomic.Bool
}

func newRelayConn(l *RelayListener, connID uint64) *RelayConn {
	rc := &RelayConn{
		listener: l,
		connID:   connID,
	}
	rc.readCond = sync.NewCond(&rc.readMu)
	return rc
}

func (c *RelayConn) kickAndClose() {
	c.closed.Store(true)
	c.remoteEOF.Store(true)
	c.readMu.Lock()
	c.readCond.Broadcast()
	c.readMu.Unlock()

	c.listener.mu.Lock()
	if c.listener.activeConn == c {
		c.listener.activeConn = nil
	}
	c.listener.mu.Unlock()

	c.listener.sendKickAgent(c.connID)
}

func (c *RelayConn) feed(payload []byte) {
	c.readMu.Lock()
	kick := c.feedLocked(payload)
	c.readMu.Unlock()

	if kick {
		c.listener.mu.Lock()
		if c.listener.activeConn == c {
			c.listener.activeConn = nil
		}
		c.listener.mu.Unlock()
		c.listener.sendKickAgent(c.connID)
	}
}

func (c *RelayConn) feedLocked(payload []byte) bool {
	if c.closed.Load() || c.remoteEOF.Load() {
		return false
	}

	cipher := c.connCipher.Load()
	if cipher == nil {
		agentNonce, err := e2ee.VerifyAgentHandshake(c.listener.handshakeKey, c.listener.sessionID, payload)
		if err != nil {
			c.closed.Store(true)
			c.remoteEOF.Store(true)
			c.readCond.Broadcast()
			return true
		}

		newCipher, err := e2ee.DeriveConnCipher(e2ee.RoleOperator, c.listener.sessionID, c.listener.secretKey, c.opNonce, agentNonce)
		if err != nil {
			c.closed.Store(true)
			c.remoteEOF.Store(true)
			c.readCond.Broadcast()
			return true
		}

		c.connCipher.Store(newCipher)
		return false
	}

	recType, plaintext, err := cipher.DecryptRecord(payload)
	if err != nil {
		c.closed.Store(true)
		c.remoteEOF.Store(true)
		c.readCond.Broadcast()
		return true
	}

	switch recType {
	case e2ee.RecordTypeEOF:
		c.remoteEOF.Store(true)
		c.readCond.Broadcast()
		return false
	case e2ee.RecordTypeData:
		// proceed to buffer below
	default:
		c.closed.Store(true)
		c.remoteEOF.Store(true)
		c.readCond.Broadcast()
		return true
	}

	if c.readBuf.Len()+len(plaintext) > maxReadBufferCap {
		c.closed.Store(true)
		c.remoteEOF.Store(true)
		c.readCond.Broadcast()
		return true
	}

	c.readBuf.Write(plaintext)
	if !bytes.HasSuffix(plaintext, []byte("\n")) {
		c.readBuf.WriteByte('\n')
	}
	c.readCond.Broadcast()
	return false
}

func (c *RelayConn) signalEOF() {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	c.remoteEOF.Store(true)
	c.readCond.Broadcast()
}

func (c *RelayConn) IsClosedOrEOF() bool {
	return c.closed.Load() || c.remoteEOF.Load()
}

func (c *RelayConn) Read(p []byte) (n int, err error) {
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

		if !c.readDeadline.IsZero() && !time.Now().Before(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}

		var timer *time.Timer
		if !c.readDeadline.IsZero() {
			timeout := time.Until(c.readDeadline)
			if timeout <= 0 {
				return 0, os.ErrDeadlineExceeded
			}
			timer = time.AfterFunc(timeout, func() {
				c.readMu.Lock()
				c.readCond.Broadcast()
				c.readMu.Unlock()
			})
		}

		c.readCond.Wait()
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *RelayConn) Write(p []byte) (n int, err error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	if c.writeBuf.Len()+len(p) > maxWriteBufferCap {
		return 0, errors.New("write buffer capacity exceeded")
	}

	c.writeBuf.Write(p)

	// Flush frame when a newline is encountered
	if bytes.Contains(c.writeBuf.Bytes(), []byte("\n")) {
		if err := c.flushLocked(); err != nil {
			return 0, err
		}
	}

	return len(p), nil
}

func (c *RelayConn) flushLocked() error {
	data := c.writeBuf.Bytes()
	if len(data) == 0 {
		return nil
	}

	if !c.writeDeadline.IsZero() && !time.Now().Before(c.writeDeadline) {
		return os.ErrDeadlineExceeded
	}

	cipher := c.connCipher.Load()
	if cipher == nil {
		return errors.New("e2ee handshake not completed")
	}

	c.listener.mu.Lock()
	active := (c.listener.activeConn == c)
	c.listener.mu.Unlock()

	if !active || c.closed.Load() || c.remoteEOF.Load() {
		return net.ErrClosed
	}

	ciphertext, err := cipher.EncryptRecord(e2ee.RecordTypeData, data)
	if err != nil {
		return fmt.Errorf("failed to encrypt response frame: %w", err)
	}

	// Header: [ FrameData (0x01) | connID (8B) ] + ciphertext
	frame := make([]byte, 9+len(ciphertext))
	frame[0] = e2ee.FrameData
	binary.BigEndian.PutUint64(frame[1:9], c.connID)
	copy(frame[9:], ciphertext)

	c.listener.wsWriteMu.Lock()
	defer c.listener.wsWriteMu.Unlock()

	if c.listener.closed.Load() || c.listener.wsConn == nil {
		return net.ErrClosed
	}

	if !c.writeDeadline.IsZero() {
		_ = c.listener.wsConn.SetWriteDeadline(c.writeDeadline)
	} else {
		_ = c.listener.wsConn.SetWriteDeadline(time.Now().Add(writeWait))
	}

	if err := c.listener.wsConn.WriteMessage(websocket.BinaryMessage, frame); err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return os.ErrDeadlineExceeded
		}
		return fmt.Errorf("failed to send frame to relay: %w", err)
	}

	c.writeBuf.Reset()
	return nil
}

func (c *RelayConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}

	c.readMu.Lock()
	c.readCond.Broadcast()
	c.readMu.Unlock()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// If remote agent hasn't disconnected yet, send authenticated EOF if cipher available
	if !c.remoteEOF.Load() {
		if cipher := c.connCipher.Load(); cipher != nil {
			eofRecord, err := cipher.EncryptRecord(e2ee.RecordTypeEOF, []byte{})
			if err == nil {
				frame := make([]byte, 9+len(eofRecord))
				frame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(frame[1:9], c.connID)
				copy(frame[9:], eofRecord)

				c.listener.wsWriteMu.Lock()
				if !c.listener.closed.Load() && c.listener.wsConn != nil {
					_ = c.listener.wsConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
					_ = c.listener.wsConn.WriteMessage(websocket.BinaryMessage, frame)
				}
				c.listener.wsWriteMu.Unlock()
			}
		}

		// Unconditionally send kick frame even if cipher == nil
		c.listener.sendKickAgent(c.connID)
	}

	c.listener.mu.Lock()
	if c.listener.activeConn == c {
		c.listener.activeConn = nil
	}
	c.listener.mu.Unlock()

	c.writeBuf.Reset()
	return nil
}

func (c *RelayConn) LocalAddr() net.Addr {
	return relayAddr{network: "relay", str: c.listener.sessionID}
}

func (c *RelayConn) RemoteAddr() net.Addr {
	return relayAddr{network: "relay", str: fmt.Sprintf("agent-%d", c.connID)}
}

func (c *RelayConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	_ = c.SetWriteDeadline(t)
	return nil
}

func (c *RelayConn) SetReadDeadline(t time.Time) error {
	c.readMu.Lock()
	c.readDeadline = t
	c.readCond.Broadcast()
	c.readMu.Unlock()
	return nil
}

func (c *RelayConn) SetWriteDeadline(t time.Time) error {
	c.writeMu.Lock()
	c.writeDeadline = t
	c.writeMu.Unlock()
	return nil
}
