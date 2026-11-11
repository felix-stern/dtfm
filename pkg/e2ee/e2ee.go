// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
)

const (
	RoleOperator = "operator"
	RoleAgent    = "agent"

	// KeySize is the symmetric key size for AES-256 in bytes.
	KeySize = 32

	// HexKeyLen is the hex-encoded string length of a 256-bit key.
	HexKeyLen = 64

	// NonceSize is the standard GCM nonce size in bytes.
	NonceSize = 12

	// HandshakeMagic is the fixed preamble for per-connection E2EE handshakes.
	HandshakeMagic = "DTFM1"

	// HandshakePacketSize is the byte size of a handshake packet: magic (5B) + nonce (32B) + hmac (32B).
	HandshakePacketSize = 5 + 32 + 32

	// DefaultRelayWsURL is the public WebSocket relay endpoint.
	DefaultRelayWsURL = "wss://relay.dtfm.dev/ws"

	// DefaultHubURL is the web hub base URL for Agent Magic Links.
	DefaultHubURL = "https://dtfm.dev"

	kdfSalt = "dtfm-e2ee-salt-v1"
)

// Relay framing control byte constants between Relay and Operator.
const (
	FrameData              byte = 0x01
	FrameAgentConnected    byte = 0x02
	FrameAgentDisconnected byte = 0x03
	FrameKickAgent         byte = 0x06
)

// Record types within encrypted E2EE stream payload.
const (
	RecordTypeData byte = 0x01
	RecordTypeEOF  byte = 0x02
)

// RelayConfig holds parsed connection and cryptographic credentials for a relay session.
type RelayConfig struct {
	SessionID string
	SecretKey []byte
	KeyHex    string
	RelayURL  string
	HubURL    string
}

// ValidateSessionID enforces length 1..64 and [a-zA-Z0-9_-] characters.
func ValidateSessionID(id string) error {
	if len(id) == 0 {
		return errors.New("session ID cannot be empty")
	}
	if len(id) > 64 {
		return fmt.Errorf("session ID %q exceeds maximum allowed length of 64 characters", id)
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return fmt.Errorf("invalid character %q in session ID %q: only [a-zA-Z0-9_-] allowed", c, id)
		}
	}
	return nil
}

// GenerateSessionID creates a cryptographically random 16-byte (32-character hex) session ID.
func GenerateSessionID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("failed to generate random session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// GenerateSessionKey creates a cryptographically random 32-byte (256-bit) symmetric key.
func GenerateSessionKey() ([]byte, string, error) {
	key := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, "", fmt.Errorf("failed to generate random session key: %w", err)
	}
	return key, hex.EncodeToString(key), nil
}

// hkdfExtract implements RFC 5869 Extract step with HMAC-SHA256.
func hkdfExtract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	h := hmac.New(sha256.New, salt)
	h.Write(ikm)
	return h.Sum(nil)
}

// hkdfExpand implements RFC 5869 Expand step with HMAC-SHA256.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length > 255*sha256.Size {
		return nil, errors.New("hkdf: requested length exceeds maximum allowed")
	}
	n := (length + sha256.Size - 1) / sha256.Size
	okm := make([]byte, 0, n*sha256.Size)
	var prev []byte
	for i := 1; i <= n; i++ {
		h := hmac.New(sha256.New, prk)
		h.Write(prev)
		h.Write(info)
		h.Write([]byte{byte(i)})
		prev = h.Sum(nil)
		okm = append(okm, prev...)
	}
	return okm[:length], nil
}

// DeriveSubkey derives a directional symmetric subkey using HKDF-SHA256.
func DeriveSubkey(secret []byte, sessionID string, info string) ([]byte, error) {
	salt := []byte(kdfSalt + ":" + sessionID)
	prk := hkdfExtract(salt, secret)
	return hkdfExpand(prk, []byte(info), KeySize)
}

// DeriveAuthTokens generates zero-knowledge auth tokens and verifier headers for relay HTTP registration.
func DeriveAuthTokens(secret []byte, sessionID string) (opAuthHex, agentAuthHex, agentVerifierHex string, err error) {
	if err := ValidateSessionID(sessionID); err != nil {
		return "", "", "", err
	}
	if len(secret) != KeySize {
		return "", "", "", fmt.Errorf("invalid secret key length: expected %d bytes, got %d", KeySize, len(secret))
	}

	opAuth, err := DeriveSubkey(secret, sessionID, "dtfm-relay-operator-auth-v1")
	if err != nil {
		return "", "", "", err
	}
	agentAuth, err := DeriveSubkey(secret, sessionID, "dtfm-relay-agent-auth-v1")
	if err != nil {
		return "", "", "", err
	}

	agentVerifier := sha256.Sum256(agentAuth)

	return hex.EncodeToString(opAuth), hex.EncodeToString(agentAuth), hex.EncodeToString(agentVerifier[:]), nil
}

// HandshakeKey derives the HMAC authentication key for per-connection sub-session handshakes.
func HandshakeKey(secret []byte, sessionID string) ([]byte, error) {
	return DeriveSubkey(secret, sessionID, "dtfm-handshake-v1")
}

// BuildAgentHandshake constructs the initial 69-byte handshake packet sent by the agent.
func BuildAgentHandshake(handshakeKey []byte, sessionID string) (agentNonce []byte, packet []byte, err error) {
	agentNonce = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, agentNonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate agent handshake nonce: %w", err)
	}

	mac := hmac.New(sha256.New, handshakeKey)
	mac.Write([]byte("agent"))
	mac.Write([]byte(sessionID))
	mac.Write(agentNonce)
	tag := mac.Sum(nil)

	packet = make([]byte, 0, HandshakePacketSize)
	packet = append(packet, []byte(HandshakeMagic)...)
	packet = append(packet, agentNonce...)
	packet = append(packet, tag...)

	return agentNonce, packet, nil
}

// VerifyAgentHandshake verifies and unpacks the 69-byte agent handshake packet.
func VerifyAgentHandshake(handshakeKey []byte, sessionID string, packet []byte) (agentNonce []byte, err error) {
	if len(packet) != HandshakePacketSize {
		return nil, fmt.Errorf("invalid agent handshake size: expected %d bytes, got %d", HandshakePacketSize, len(packet))
	}
	if string(packet[:5]) != HandshakeMagic {
		return nil, errors.New("invalid agent handshake magic header")
	}

	nonce := packet[5:37]
	tag := packet[37:69]

	mac := hmac.New(sha256.New, handshakeKey)
	mac.Write([]byte("agent"))
	mac.Write([]byte(sessionID))
	mac.Write(nonce)
	expectedTag := mac.Sum(nil)

	if !hmac.Equal(tag, expectedTag) {
		return nil, errors.New("agent handshake authentication failed: HMAC mismatch")
	}

	res := make([]byte, 32)
	copy(res, nonce)
	return res, nil
}

// BuildOperatorHandshake constructs the 69-byte handshake packet sent by the operator to the agent.
func BuildOperatorHandshake(handshakeKey []byte, sessionID string) (opNonce []byte, packet []byte, err error) {
	opNonce = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, opNonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate operator handshake nonce: %w", err)
	}

	mac := hmac.New(sha256.New, handshakeKey)
	mac.Write([]byte("operator"))
	mac.Write([]byte(sessionID))
	mac.Write(opNonce)
	tag := mac.Sum(nil)

	packet = make([]byte, 0, HandshakePacketSize)
	packet = append(packet, []byte(HandshakeMagic)...)
	packet = append(packet, opNonce...)
	packet = append(packet, tag...)

	return opNonce, packet, nil
}

// VerifyOperatorHandshake verifies and unpacks the 69-byte operator handshake packet.
func VerifyOperatorHandshake(handshakeKey []byte, sessionID string, packet []byte) (opNonce []byte, err error) {
	if len(packet) != HandshakePacketSize {
		return nil, fmt.Errorf("invalid operator handshake size: expected %d bytes, got %d", HandshakePacketSize, len(packet))
	}
	if string(packet[:5]) != HandshakeMagic {
		return nil, errors.New("invalid operator handshake magic header")
	}

	nonce := packet[5:37]
	tag := packet[37:69]

	mac := hmac.New(sha256.New, handshakeKey)
	mac.Write([]byte("operator"))
	mac.Write([]byte(sessionID))
	mac.Write(nonce)
	expectedTag := mac.Sum(nil)

	if !hmac.Equal(tag, expectedTag) {
		return nil, errors.New("operator handshake authentication failed: HMAC mismatch")
	}

	res := make([]byte, 32)
	copy(res, nonce)
	return res, nil
}

// ConnCipher provides authenticated end-to-end symmetric encryption for a specific paired connection
// using derived per-connection subkeys, monotonic 64-bit counter nonces, and anti-replay enforcement.
type ConnCipher struct {
	sessionID string
	role      string
	sendAead  cipher.AEAD
	recvAead  cipher.AEAD
	sendSeq   uint64
	recvSeq   uint64
	sendMu    sync.Mutex
	recvMu    sync.Mutex
}

// DeriveConnCipher derives fresh per-connection subkeys via HKDF using peer nonces.
func DeriveConnCipher(role, sessionID string, secretKey, opNonce, agentNonce []byte) (*ConnCipher, error) {
	if role != RoleOperator && role != RoleAgent {
		return nil, fmt.Errorf("invalid e2ee role: %q", role)
	}
	if err := ValidateSessionID(sessionID); err != nil {
		return nil, err
	}
	if len(secretKey) != KeySize {
		return nil, fmt.Errorf("invalid secret key length: expected %d bytes", KeySize)
	}
	if len(opNonce) != 32 || len(agentNonce) != 32 {
		return nil, errors.New("invalid nonces for conn cipher derivation")
	}

	salt := "dtfm-e2ee-v1:" + sessionID + ":" + hex.EncodeToString(opNonce) + ":" + hex.EncodeToString(agentNonce)
	prk := hkdfExtract([]byte(salt), secretKey)

	opKey, err := hkdfExpand(prk, []byte("operator-to-agent"), KeySize)
	if err != nil {
		return nil, err
	}
	agentKey, err := hkdfExpand(prk, []byte("agent-to-operator"), KeySize)
	if err != nil {
		return nil, err
	}

	opBlock, err := aes.NewCipher(opKey)
	if err != nil {
		return nil, err
	}
	opGCM, err := cipher.NewGCM(opBlock)
	if err != nil {
		return nil, err
	}

	agentBlock, err := aes.NewCipher(agentKey)
	if err != nil {
		return nil, err
	}
	agentGCM, err := cipher.NewGCM(agentBlock)
	if err != nil {
		return nil, err
	}

	cc := &ConnCipher{
		sessionID: sessionID,
		role:      role,
	}
	if role == RoleOperator {
		cc.sendAead = opGCM
		cc.recvAead = agentGCM
	} else {
		cc.sendAead = agentGCM
		cc.recvAead = opGCM
	}
	return cc, nil
}

// EncryptRecord seals plaintext into [ seq(8B) | Ciphertext+Tag ] with deterministic counter nonces.
func (c *ConnCipher) EncryptRecord(recordType byte, plaintext []byte) ([]byte, error) {
	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	seq := c.sendSeq
	c.sendSeq++

	var nonce [NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)

	var roleByte byte = 0x01
	if c.role == RoleAgent {
		roleByte = 0x02
	}

	aad := make([]byte, len(c.sessionID)+1+8)
	copy(aad, c.sessionID)
	aad[len(c.sessionID)] = roleByte
	binary.BigEndian.PutUint64(aad[len(c.sessionID)+1:], seq)

	payload := make([]byte, 1+len(plaintext))
	payload[0] = recordType
	copy(payload[1:], plaintext)

	frame := make([]byte, 8, 8+len(payload)+c.sendAead.Overhead())
	binary.BigEndian.PutUint64(frame[:8], seq)
	return c.sendAead.Seal(frame, nonce[:], payload, aad), nil
}

// DecryptRecord opens an authenticated record, validating monotonic sequence counter and AAD binding.
func (c *ConnCipher) DecryptRecord(frame []byte) (byte, []byte, error) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	if len(frame) < 8+1+c.recvAead.Overhead() {
		return 0, nil, errors.New("frame is too short to be a valid authenticated record")
	}

	seq := binary.BigEndian.Uint64(frame[:8])
	if seq != c.recvSeq {
		return 0, nil, fmt.Errorf("out-of-order or replayed frame: expected seq %d, got %d", c.recvSeq, seq)
	}

	var nonce [NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)

	var peerRoleByte byte = 0x02
	if c.role == RoleAgent {
		peerRoleByte = 0x01
	}

	aad := make([]byte, len(c.sessionID)+1+8)
	copy(aad, c.sessionID)
	aad[len(c.sessionID)] = peerRoleByte
	binary.BigEndian.PutUint64(aad[len(c.sessionID)+1:], seq)

	decrypted, err := c.recvAead.Open(nil, nonce[:], frame[8:], aad)
	if err != nil {
		return 0, nil, fmt.Errorf("e2ee record authentication failed: %w", err)
	}

	c.recvSeq++
	recordType := decrypted[0]
	plaintext := decrypted[1:]
	return recordType, plaintext, nil
}

// ParseRelayToken parses an input string which may be:
// 1. Full Agent Magic Link: https://dtfm.dev/c/<sessionID>#<keyHex>
// 2. Direct WebSocket URL: wss://relay.dtfm.dev/ws?session=<sessionID>#<keyHex>
// 3. Compact Token: <sessionID>#<keyHex>
// 4. Colon-separated Token: <sessionID>:<keyHex>
func ParseRelayToken(input, defaultRelayURL string) (*RelayConfig, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil, errors.New("relay token cannot be empty")
	}

	if defaultRelayURL == "" {
		defaultRelayURL = DefaultRelayWsURL
	}

	var sessionID, keyHex, relayWsURL, hubURL string

	lowerInput := strings.ToLower(trimmed)
	if strings.HasPrefix(lowerInput, "http://") || strings.HasPrefix(lowerInput, "https://") ||
		strings.HasPrefix(lowerInput, "ws://") || strings.HasPrefix(lowerInput, "wss://") {

		u, err := url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("failed to parse relay url: %w", err)
		}

		if strings.TrimSpace(u.Host) == "" {
			return nil, errors.New("relay url must have a valid host")
		}

		keyHex = u.Fragment
		if keyHex == "" {
			return nil, errors.New("missing secret key in url fragment (expected #<key>)")
		}

		// Check for /c/<session-id> path format
		path := strings.Trim(u.Path, "/")
		parts := strings.Split(path, "/")
		var prefix string
		for i, part := range parts {
			if part == "c" && i+1 < len(parts) {
				sessionID = parts[i+1]
				if i > 0 {
					prefix = "/" + strings.Join(parts[:i], "/")
				}
				break
			}
		}

		if sessionID == "" {
			if qSession := u.Query().Get("session"); qSession != "" {
				sessionID = qSession
			} else if len(parts) == 1 && parts[0] != "" && parts[0] != "ws" && parts[0] != "relay" {
				sessionID = parts[0]
			}
		}

		if sessionID == "" {
			return nil, errors.New("failed to extract session ID from relay url")
		}

		scheme := strings.ToLower(u.Scheme)
		switch scheme {
		case "https":
			if strings.EqualFold(u.Hostname(), "dtfm.dev") {
				relayWsURL = DefaultRelayWsURL
				hubURL = fmt.Sprintf("https://%s%s", u.Host, prefix)
			} else {
				relayWsURL = fmt.Sprintf("wss://%s%s/ws", u.Host, prefix)
				hubURL = fmt.Sprintf("https://%s%s", u.Host, prefix)
			}
		case "http":
			relayWsURL = fmt.Sprintf("ws://%s%s/ws", u.Host, prefix)
			hubURL = fmt.Sprintf("http://%s%s", u.Host, prefix)
		case "wss", "ws":
			uClean := *u
			uClean.Fragment = ""
			uClean.RawQuery = ""
			if uClean.Path == "" || uClean.Path == "/" || strings.Contains(uClean.Path, "/c/") {
				uClean.Path = prefix + "/ws"
			}
			relayWsURL = uClean.String()
			if scheme == "wss" {
				hubURL = fmt.Sprintf("https://%s%s", u.Host, prefix)
			} else {
				hubURL = fmt.Sprintf("http://%s%s", u.Host, prefix)
			}
		}

	} else {
		// Non-URL format: <sessionID>#<keyHex> or <sessionID>:<keyHex>
		var sep string
		if strings.Contains(trimmed, "#") {
			sep = "#"
		} else if strings.Contains(trimmed, ":") {
			sep = ":"
		} else {
			return nil, errors.New("invalid relay token format: expected <session-id>#<key> or magic link URL")
		}

		parts := strings.SplitN(trimmed, sep, 2)
		sessionID = strings.TrimSpace(parts[0])
		keyHex = strings.TrimSpace(parts[1])

		if sessionID == "" || keyHex == "" {
			return nil, errors.New("invalid relay token: session ID and secret key cannot be empty")
		}

		relayWsURL = defaultRelayURL
		hubURL = DefaultHubURL
	}

	if err := ValidateSessionID(sessionID); err != nil {
		return nil, fmt.Errorf("invalid session ID: %w", err)
	}

	secretKey, err := decodeSecretKey(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid secret key: %w", err)
	}

	return &RelayConfig{
		SessionID: sessionID,
		SecretKey: secretKey,
		KeyHex:    keyHex,
		RelayURL:  relayWsURL,
		HubURL:    hubURL,
	}, nil
}

// decodeSecretKey decodes a hex string strictly requiring 64 hex characters (32 bytes).
func decodeSecretKey(keyStr string) ([]byte, error) {
	keyStr = strings.TrimSpace(keyStr)
	if len(keyStr) != HexKeyLen {
		return nil, fmt.Errorf("secret key must be exactly %d hex characters (%d bytes), got length %d", HexKeyLen, KeySize, len(keyStr))
	}
	b, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex encoding in secret key: %w", err)
	}
	if len(b) != KeySize {
		return nil, fmt.Errorf("secret key must decode to exactly %d bytes, got %d", KeySize, len(b))
	}
	return b, nil
}

// FormatMagicLink constructs the public Agent Magic Link.
func FormatMagicLink(hubURL, sessionID, keyHex string) string {
	hubURL = strings.TrimRight(hubURL, "/")
	return fmt.Sprintf("%s/c/%s#%s", hubURL, sessionID, keyHex)
}
