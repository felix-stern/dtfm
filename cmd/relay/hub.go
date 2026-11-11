// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/iinozemtsev-lab/dtfm/pkg/e2ee"
	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

const (
	defaultIdleTimeout            = 10 * time.Minute
	defaultSweepInterval          = 30 * time.Second
	defaultMaxSessions            = 10000
	defaultMaxSessionsPerIP       = 64
	defaultMaxAgentMessageSize    = 5 * 1024 * 1024                               // 5 MB frame limit for untrusted agents
	defaultMaxOperatorMessageSize = protocol.MaxResponseEnvelopeBytes + 256*1024  // 16 MB + 256 KB for operator ExecResp
	maxOperatorQueuedBytes        = 6 * 1024 * 1024                               // 6 MB backpressure queue cap when routing to operator
	maxAgentQueuedBytes           = protocol.MaxResponseEnvelopeBytes + 1024*1024 // 17 MB queue cap when routing ExecResp to agent
	clientChanCap                 = 16
	writeWait                     = 30 * time.Second // 30s matching defaultExecRespTimeout in cmd/dtfm/server.go
	pongWait                      = 90 * time.Second
	pingPeriod                    = (pongWait * 9) / 10
)

var (
	errSessionNotFound  = errors.New("session not found")
	errSessionBusy      = errors.New("session is busy with another agent")
	errMaxSessions      = errors.New("maximum concurrent sessions limit reached")
	errMaxSessionsPerIP = errors.New("maximum concurrent sessions per IP limit reached")
	errUnauthorized     = errors.New("unauthorized")
	errInvalidSessionID = errors.New("invalid session ID")
)

type Client struct {
	hub         *Hub
	session     *Session
	role        string
	connID      uint64 // monotonic ID for agent connections
	conn        *websocket.Conn
	send        chan []byte
	sendClosed  bool
	drainTimer  *time.Timer
	mu          sync.Mutex
	queuedBytes int
	closeOnce   sync.Once
	done        chan struct{}
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		if c.drainTimer != nil {
			c.drainTimer.Stop()
		}
		c.mu.Unlock()

		close(c.done)
		_ = c.conn.Close()
	})
}

func (c *Client) CloseAfterDrain() {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.done:
		return
	default:
	}

	if !c.sendClosed {
		c.sendClosed = true
		close(c.send)
		c.drainTimer = time.AfterFunc(writeWait, c.Close)
	}
}

func (c *Client) queueMessage(msg []byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	select {
	case <-c.done:
		return false
	default:
	}

	if c.sendClosed {
		return false
	}

	maxQueued := maxOperatorQueuedBytes
	if c.role == e2ee.RoleAgent {
		maxQueued = maxAgentQueuedBytes
	}

	if c.queuedBytes+len(msg) > maxQueued {
		c.hub.logf("lagging client buffer overflow (%d bytes), closing %s connID=%d", c.queuedBytes+len(msg), c.role, c.connID)
		go c.Close()
		return false
	}

	select {
	case c.send <- msg:
		c.queuedBytes += len(msg)
		return true
	default:
		c.hub.logf("lagging client channel full, closing %s connID=%d", c.role, c.connID)
		go c.Close()
		return false
	}
}

type Session struct {
	id            string
	ip            string
	opVerifier    [32]byte
	agentVerifier [32]byte
	hasAuth       bool
	createdAt     time.Time
	lastActive    time.Time
	operator      *Client
	agent         *Client
	nextConnID    uint64
	mu            sync.Mutex
	closed        bool
}

type HubConfig struct {
	IdleTimeout      time.Duration
	MaxSessions      int
	MaxSessionsPerIP int // default 64, 0 = disabled
	TrustedProxies   []*net.IPNet
	ExemptLoopback   bool
	LogWriter        io.Writer
}

func DefaultTrustedProxies() []*net.IPNet {
	_, v4Loopback, _ := net.ParseCIDR("127.0.0.0/8")
	_, v6Loopback, _ := net.ParseCIDR("::1/128")
	return []*net.IPNet{v4Loopback, v6Loopback}
}

func ParseTrustedProxies(s string) ([]*net.IPNet, error) {
	list := make([]*net.IPNet, 0)
	tokens := strings.Split(s, ",")
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "/") {
			_, ipNet, err := net.ParseCIDR(tok)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", tok, err)
			}
			list = append(list, ipNet)
		} else {
			ip := net.ParseIP(tok)
			if ip == nil {
				return nil, fmt.Errorf("invalid IP %q", tok)
			}
			if ip4 := ip.To4(); ip4 != nil {
				list = append(list, &net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)})
			} else {
				list = append(list, &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)})
			}
		}
	}
	return list, nil
}

type Hub struct {
	mu               sync.RWMutex
	sessions         map[string]*Session
	sessionsPerIP    map[string]int
	idleTimeout      time.Duration
	maxSessions      int
	maxSessionsPerIP int
	trustedProxies   []*net.IPNet
	exemptLoopback   bool
	upgrader         websocket.Upgrader
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	logWriter        io.Writer
}

func NewHubWithConfig(cfg HubConfig) *Hub {
	idleTimeout := cfg.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultIdleTimeout
	}
	maxSessions := cfg.MaxSessions
	if maxSessions <= 0 {
		maxSessions = defaultMaxSessions
	}
	trusted := cfg.TrustedProxies
	if trusted == nil {
		trusted = DefaultTrustedProxies()
	}

	ctx, cancel := context.WithCancel(context.Background())
	h := &Hub{
		sessions:         make(map[string]*Session),
		sessionsPerIP:    make(map[string]int),
		idleTimeout:      idleTimeout,
		maxSessions:      maxSessions,
		maxSessionsPerIP: cfg.MaxSessionsPerIP,
		trustedProxies:   trusted,
		exemptLoopback:   cfg.ExemptLoopback,
		ctx:              ctx,
		cancel:           cancel,
		logWriter:        cfg.LogWriter,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true // Allow CLI clients
				}
				u, err := url.Parse(origin)
				if err != nil {
					return false
				}
				return strings.EqualFold(u.Host, r.Host)
			},
		},
	}

	h.wg.Add(1)
	go h.sweepLoop()

	return h
}

func NewHub(idleTimeout time.Duration, maxSessions int, logWriter io.Writer) *Hub {
	return NewHubWithConfig(HubConfig{
		IdleTimeout:      idleTimeout,
		MaxSessions:      maxSessions,
		MaxSessionsPerIP: defaultMaxSessionsPerIP,
		TrustedProxies:   DefaultTrustedProxies(),
		ExemptLoopback:   true,
		LogWriter:        logWriter,
	})
}

func (h *Hub) logf(format string, args ...any) {
	if h.logWriter != nil {
		sanitizedArgs := make([]any, len(args))
		for i, a := range args {
			if s, ok := a.(string); ok {
				sanitizedArgs[i] = protocol.SanitizeTerminalText(s)
			} else {
				sanitizedArgs[i] = a
			}
		}
		fmt.Fprintf(h.logWriter, "[relay] "+format+"\n", sanitizedArgs...)
	}
}

func (h *Hub) Close() {
	h.cancel()
	h.mu.Lock()
	for id, s := range h.sessions {
		s.mu.Lock()
		s.closed = true
		if s.operator != nil {
			s.operator.Close()
		}
		if s.agent != nil {
			s.agent.Close()
		}
		s.mu.Unlock()
		delete(h.sessions, id)
	}
	h.sessionsPerIP = make(map[string]int)
	h.mu.Unlock()
	h.wg.Wait()
}

func (h *Hub) sweepLoop() {
	defer h.wg.Done()
	ticker := time.NewTicker(defaultSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-h.ctx.Done():
			return
		case now := <-ticker.C:
			h.sweepExpiredSessions(now)
		}
	}
}

func (h *Hub) sweepExpiredSessions(now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for id, s := range h.sessions {
		s.mu.Lock()
		idle := now.Sub(s.lastActive)
		if idle > h.idleTimeout {
			h.logf("evicting idle session %s (idle %v)", id, idle)
			s.closed = true
			if s.operator != nil {
				s.operator.Close()
			}
			if s.agent != nil {
				s.agent.Close()
			}
			delete(h.sessions, id)
			if h.sessionsPerIP[s.ip] > 0 {
				h.sessionsPerIP[s.ip]--
				if h.sessionsPerIP[s.ip] == 0 {
					delete(h.sessionsPerIP, s.ip)
				}
			}
		}
		s.mu.Unlock()
	}
}

func (h *Hub) ActiveSessionsCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.sessions)
}

func (h *Hub) isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, cidr := range h.trustedProxies {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func (h *Hub) getRemoteIP(r *http.Request) (string, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peerIP := net.ParseIP(host)
	if peerIP == nil {
		return host, false
	}

	if !h.isTrustedProxy(peerIP) {
		return peerIP.String(), false
	}

	// Peer is a trusted proxy. Check X-Forwarded-For first (parsing right-to-left
	// for the rightmost non-trusted IP). Reverse proxies append untrusted client IPs
	// to X-Forwarded-For while leaving client-sent X-Real-IP untouched, so checking
	// X-Forwarded-For first prevents attackers from spoofing X-Real-IP: 127.0.0.1.
	// Coalesce all X-Forwarded-For header lines in wire order per RFC 7230 §3.2.2.
	if xffValues := r.Header.Values("X-Forwarded-For"); len(xffValues) > 0 {
		xff := strings.Join(xffValues, ",")
		parts := strings.Split(xff, ",")
		var rightmostTrusted string
		for i := len(parts) - 1; i >= 0; i-- {
			part := strings.TrimSpace(parts[i])
			if part == "" {
				continue
			}
			ip := net.ParseIP(part)
			if ip == nil {
				// Malformed hop encountered! Stop right-to-left traversal immediately
				// rather than skipping over the untrusted hop into client-supplied entries to its left.
				break
			}
			if !h.isTrustedProxy(ip) {
				return ip.String(), true
			}
			if rightmostTrusted == "" {
				rightmostTrusted = ip.String()
			}
		}
		if rightmostTrusted != "" {
			return rightmostTrusted, true
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if ip := net.ParseIP(xri); ip != nil {
			return ip.String(), true
		}
	}

	return peerIP.String(), false
}

func (h *Hub) isIPRateLimited(ipStr string, fromForwarded bool) bool {
	if h.maxSessionsPerIP <= 0 {
		return false
	}
	ip := net.ParseIP(ipStr)
	if !fromForwarded && ip != nil && ip.IsLoopback() && h.exemptLoopback {
		return false
	}
	return h.sessionsPerIP[ipStr] >= h.maxSessionsPerIP
}

func (h *Hub) validatePreUpgrade(r *http.Request, sessionID, role string) error {
	if err := e2ee.ValidateSessionID(sessionID); err != nil {
		return errInvalidSessionID
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	s, exists := h.sessions[sessionID]
	ip, fromForwarded := h.getRemoteIP(r)

	authHex := r.Header.Get("X-DTFM-Auth")
	agentVerifierHex := r.Header.Get("X-DTFM-Agent-Verifier")

	if role == e2ee.RoleOperator {
		if !exists {
			if len(h.sessions) >= h.maxSessions {
				return errMaxSessions
			}
			if h.isIPRateLimited(ip, fromForwarded) {
				return errMaxSessionsPerIP
			}
			if len(authHex) != 64 || len(agentVerifierHex) != 64 {
				return errUnauthorized
			}
			return nil
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed {
			return errSessionNotFound
		}
		if s.hasAuth {
			rawAuth, err := hex.DecodeString(authHex)
			if err != nil || len(rawAuth) != 32 {
				return errUnauthorized
			}
			hash := sha256.Sum256(rawAuth)
			if subtle.ConstantTimeCompare(hash[:], s.opVerifier[:]) != 1 {
				return errUnauthorized
			}
		}
		return nil

	} else if role == e2ee.RoleAgent {
		if !exists {
			return errSessionNotFound
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.closed || s.operator == nil {
			return errSessionNotFound
		}
		if s.agent != nil {
			return errSessionBusy
		}
		if s.hasAuth {
			rawAuth, err := hex.DecodeString(authHex)
			if err != nil || len(rawAuth) != 32 {
				return errUnauthorized
			}
			hash := sha256.Sum256(rawAuth)
			if subtle.ConstantTimeCompare(hash[:], s.agentVerifier[:]) != 1 {
				return errUnauthorized
			}
		}
		return nil
	}

	return fmt.Errorf("unknown role: %q", role)
}

func (h *Hub) Register(r *http.Request, sessionID, role string, conn *websocket.Conn) (*Client, error) {
	if err := e2ee.ValidateSessionID(sessionID); err != nil {
		return nil, errInvalidSessionID
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	s, exists := h.sessions[sessionID]
	ip, fromForwarded := h.getRemoteIP(r)
	now := time.Now()

	authHex := r.Header.Get("X-DTFM-Auth")
	agentVerifierHex := r.Header.Get("X-DTFM-Agent-Verifier")

	if role == e2ee.RoleOperator {
		if !exists {
			if len(h.sessions) >= h.maxSessions {
				return nil, errMaxSessions
			}
			if h.isIPRateLimited(ip, fromForwarded) {
				return nil, errMaxSessionsPerIP
			}
			rawOpAuth, err := hex.DecodeString(authHex)
			if err != nil || len(rawOpAuth) != 32 {
				return nil, errUnauthorized
			}
			rawAgentVerifier, err := hex.DecodeString(agentVerifierHex)
			if err != nil || len(rawAgentVerifier) != 32 {
				return nil, errUnauthorized
			}

			s = &Session{
				id:         sessionID,
				ip:         ip,
				createdAt:  now,
				lastActive: now,
				hasAuth:    true,
				nextConnID: 1,
			}
			s.opVerifier = sha256.Sum256(rawOpAuth)
			copy(s.agentVerifier[:], rawAgentVerifier)

			h.sessions[sessionID] = s
			h.sessionsPerIP[ip]++
		}

		s.mu.Lock()
		defer s.mu.Unlock()

		if s.hasAuth {
			rawOpAuth, err := hex.DecodeString(authHex)
			if err != nil || len(rawOpAuth) != 32 {
				return nil, errUnauthorized
			}
			hash := sha256.Sum256(rawOpAuth)
			if subtle.ConstantTimeCompare(hash[:], s.opVerifier[:]) != 1 {
				return nil, errUnauthorized
			}
		}

		if s.operator != nil {
			h.logf("displacing prior operator connection on session %s", sessionID)
			s.operator.Close()
		}
		if s.agent != nil {
			h.logf("closing stale agent on session %s due to operator connect", sessionID)
			s.agent.Close()
			s.agent = nil
		}

		client := &Client{
			hub:     h,
			session: s,
			role:    role,
			conn:    conn,
			send:    make(chan []byte, clientChanCap),
			done:    make(chan struct{}),
		}
		s.operator = client
		s.lastActive = now
		h.logf("operator registered on session %s", sessionID)

		return client, nil

	} else if role == e2ee.RoleAgent {
		if !exists {
			return nil, errSessionNotFound
		}
		s.mu.Lock()
		defer s.mu.Unlock()

		if s.closed || s.operator == nil {
			return nil, errSessionNotFound
		}
		if s.agent != nil {
			return nil, errSessionBusy
		}

		if s.hasAuth {
			rawAuth, err := hex.DecodeString(authHex)
			if err != nil || len(rawAuth) != 32 {
				return nil, errUnauthorized
			}
			hash := sha256.Sum256(rawAuth)
			if subtle.ConstantTimeCompare(hash[:], s.agentVerifier[:]) != 1 {
				return nil, errUnauthorized
			}
		}

		connID := s.nextConnID
		s.nextConnID++

		client := &Client{
			hub:     h,
			session: s,
			role:    role,
			connID:  connID,
			conn:    conn,
			send:    make(chan []byte, clientChanCap),
			done:    make(chan struct{}),
		}
		s.agent = client
		s.lastActive = now
		h.logf("agent paired on session %s (connID=%d)", sessionID, connID)

		// Notify operator that agent connected: [FrameAgentConnected | connID(8B)]
		if s.operator != nil {
			hdr := make([]byte, 9)
			hdr[0] = e2ee.FrameAgentConnected
			binary.BigEndian.PutUint64(hdr[1:9], connID)
			s.operator.queueMessage(hdr)
		}

		return client, nil
	}

	return nil, fmt.Errorf("unknown role: %q", role)
}

func (h *Hub) Unregister(c *Client) {
	c.Close()

	h.mu.Lock()
	defer h.mu.Unlock()

	s := c.session
	s.mu.Lock()
	defer s.mu.Unlock()

	if c.role == e2ee.RoleOperator {
		if s.operator == c {
			s.operator = nil
			h.logf("operator disconnected from session %s", s.id)
			if s.agent != nil {
				s.agent.Close()
				s.agent = nil
			}
			delete(h.sessions, s.id)
			if h.sessionsPerIP[s.ip] > 0 {
				h.sessionsPerIP[s.ip]--
				if h.sessionsPerIP[s.ip] == 0 {
					delete(h.sessionsPerIP, s.ip)
				}
			}
		}
	} else if c.role == e2ee.RoleAgent {
		if s.agent == c {
			connID := c.connID
			s.agent = nil
			h.logf("agent disconnected from session %s (connID=%d)", s.id, connID)
			if s.operator != nil {
				hdr := make([]byte, 9)
				hdr[0] = e2ee.FrameAgentDisconnected
				binary.BigEndian.PutUint64(hdr[1:9], connID)
				s.operator.queueMessage(hdr)
			}
		}
	}
}

func (h *Hub) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	role := r.URL.Query().Get("role")

	if sessionID == "" {
		pathParts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(pathParts) >= 2 && pathParts[0] == "c" {
			sessionID = pathParts[1]
			if len(pathParts) >= 3 && role == "" {
				role = pathParts[2]
			}
		}
	}

	if role == "" {
		role = e2ee.RoleAgent
	}

	if err := e2ee.ValidateSessionID(sessionID); err != nil {
		http.Error(w, "invalid session ID", http.StatusBadRequest)
		return
	}

	if err := h.validatePreUpgrade(r, sessionID, role); err != nil {
		switch {
		case errors.Is(err, errSessionNotFound):
			http.Error(w, "session not found or operator not connected", http.StatusNotFound)
		case errors.Is(err, errSessionBusy):
			http.Error(w, "session is busy with another agent", http.StatusConflict)
		case errors.Is(err, errMaxSessions), errors.Is(err, errMaxSessionsPerIP):
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
		case errors.Is(err, errUnauthorized):
			http.Error(w, "unauthorized", http.StatusForbidden)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		return
	}

	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.logf("upgrade error: %v", err)
		return
	}

	client, err := h.Register(r, sessionID, role, conn)
	if err != nil {
		h.logf("register error for %s (%s): %v", sessionID, role, err)
		var closeCode int
		switch {
		case errors.Is(err, errSessionNotFound):
			closeCode = 4004
		case errors.Is(err, errSessionBusy):
			closeCode = 4009
		case errors.Is(err, errMaxSessions), errors.Is(err, errMaxSessionsPerIP):
			closeCode = 4029
		case errors.Is(err, errUnauthorized):
			closeCode = 4003
		default:
			closeCode = 4000
		}
		_ = conn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(closeCode, err.Error()),
			time.Now().Add(writeWait))
		_ = conn.Close()
		return
	}

	go client.writePump()
	client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.Unregister(c)
	}()

	if c.role == e2ee.RoleOperator {
		c.conn.SetReadLimit(defaultMaxOperatorMessageSize)
	} else {
		c.conn.SetReadLimit(defaultMaxAgentMessageSize)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		_ = c.conn.SetReadDeadline(time.Now().Add(pongWait))
		c.session.mu.Lock()
		c.session.lastActive = time.Now()
		c.session.mu.Unlock()
		return nil
	})

	for {
		messageType, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure, websocket.CloseNormalClosure) {
				c.hub.logf("%s read error: %v", c.role, err)
			}
			break
		}

		if messageType != websocket.BinaryMessage {
			continue
		}

		c.session.mu.Lock()
		c.session.lastActive = time.Now()

		if c.role == e2ee.RoleAgent {
			// Encapsulate with 9-byte header: [FrameData(0x01) | connID(8B) | payload]
			if c.session.operator != nil {
				frame := make([]byte, 9+len(message))
				frame[0] = e2ee.FrameData
				binary.BigEndian.PutUint64(frame[1:9], c.connID)
				copy(frame[9:], message)
				c.session.operator.queueMessage(frame)
			}
		} else if c.role == e2ee.RoleOperator {
			// Operator frames have 9-byte header: [ctrlByte(1B) | connID(8B)] + payload
			if len(message) >= 9 {
				ctrlByte := message[0]
				connID := binary.BigEndian.Uint64(message[1:9])
				payload := message[9:]

				switch ctrlByte {
				case e2ee.FrameData:
					if c.session.agent != nil && c.session.agent.connID == connID {
						c.session.agent.queueMessage(payload)
					} else {
						c.hub.logf("stale frame from operator for connID=%d dropped", connID)
					}
				case e2ee.FrameKickAgent:
					if c.session.agent != nil && c.session.agent.connID == connID {
						c.hub.logf("kicking agent on session %s (connID=%d) requested by operator", c.session.id, connID)
						agentToKick := c.session.agent
						c.session.agent = nil
						agentToKick.CloseAfterDrain()
					}
				}
			}
		}
		c.session.mu.Unlock()
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Close()
	}()

	for {
		select {
		case <-c.done:
			return
		case message, ok := <-c.send:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				_ = c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.mu.Lock()
			c.queuedBytes -= len(message)
			if c.queuedBytes < 0 {
				c.queuedBytes = 0
			}
			c.mu.Unlock()

			w, err := c.conn.NextWriter(websocket.BinaryMessage)
			if err != nil {
				return
			}
			if _, err := w.Write(message); err != nil {
				return
			}
			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			_ = c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// ServeHTTP handles HTTP status, landing pages, and routes WebSocket connections.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")

	if websocket.IsWebSocketUpgrade(r) {
		h.HandleWebSocket(w, r)
		return
	}

	path := strings.Trim(r.URL.Path, "/")
	switch {
	case path == "" || path == "healthz":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "dtfm-relay ok\n")
	case strings.HasPrefix(path, "c/"):
		sessionID := strings.TrimPrefix(path, "c/")
		if err := e2ee.ValidateSessionID(sessionID); err != nil {
			http.Error(w, "invalid session ID", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "dtfm Agent Magic Link Hub\nSession: %s\n\nRun 'lmdtfy --relay <URL> ping' to connect.\n", sessionID)
	default:
		http.NotFound(w, r)
	}
}
