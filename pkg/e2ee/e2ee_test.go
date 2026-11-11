// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package e2ee

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestSessionIDAndKeyGeneration(t *testing.T) {
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error: %v", err)
	}
	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected unique session IDs, got identical: %s", id1)
	}
	if len(id1) != 32 {
		t.Fatalf("expected 32 hex chars for 16-byte session ID, got %d", len(id1))
	}
	if err := ValidateSessionID(id1); err != nil {
		t.Fatalf("generated session ID should be valid: %v", err)
	}

	rawKey, hexKey, err := GenerateSessionKey()
	if err != nil {
		t.Fatalf("GenerateSessionKey() error: %v", err)
	}
	if len(rawKey) != KeySize {
		t.Fatalf("expected raw key length %d, got %d", KeySize, len(rawKey))
	}
	if len(hexKey) != KeySize*2 {
		t.Fatalf("expected hex key length %d, got %d", KeySize*2, len(hexKey))
	}
}

func TestValidateSessionID(t *testing.T) {
	validIDs := []string{
		"a",
		"session-123",
		"session_456",
		"SESSION-ABC-xyz_09",
		strings.Repeat("a", 64),
	}
	for _, id := range validIDs {
		if err := ValidateSessionID(id); err != nil {
			t.Errorf("expected valid session ID %q, got error: %v", id, err)
		}
	}

	invalidIDs := []string{
		"",
		" ",
		" valid ",
		" valid",
		"valid ",
		"\tsession",
		strings.Repeat("b", 65),
		"sess ion",
		"sess/ion",
		"sess.ion",
		"sess%20ion",
		"sess\nion",
		"sess:ion",
		"sess#ion",
	}
	for _, id := range invalidIDs {
		if err := ValidateSessionID(id); err == nil {
			t.Errorf("expected invalid session ID %q to fail, but succeeded", id)
		}
	}
}

func TestStrictSecretKeyDecoding(t *testing.T) {
	validKeyHex := hex.EncodeToString(bytes.Repeat([]byte{0x55}, KeySize))
	key, err := decodeSecretKey(validKeyHex)
	if err != nil {
		t.Fatalf("expected valid key to decode, got: %v", err)
	}
	if len(key) != KeySize {
		t.Fatalf("expected %d bytes, got %d", KeySize, len(key))
	}

	invalidKeys := []string{
		"",
		"my-human-passphrase",
		"short",
		strings.Repeat("a", 63), // odd length / short
		strings.Repeat("a", 65), // too long
		strings.Repeat("z", 64), // invalid hex
		"0123456789abcdef",      // 16 hex chars (8 bytes)
	}

	for _, k := range invalidKeys {
		if _, err := decodeSecretKey(k); err == nil {
			t.Errorf("expected secret key %q to fail validation, but succeeded", k)
		}
	}
}

func TestDeriveAuthTokens(t *testing.T) {
	key := bytes.Repeat([]byte{0x77}, KeySize)
	sessionID := "test-auth-session-1"

	opAuth, agentAuth, agentVerifier, err := DeriveAuthTokens(key, sessionID)
	if err != nil {
		t.Fatalf("DeriveAuthTokens error: %v", err)
	}
	if len(opAuth) != 64 || len(agentAuth) != 64 || len(agentVerifier) != 64 {
		t.Fatalf("expected 64 hex characters for all tokens, got %d, %d, %d", len(opAuth), len(agentAuth), len(agentVerifier))
	}
	if opAuth == agentAuth {
		t.Fatal("opAuth and agentAuth must be domain-separated and distinct")
	}

	// Different session yields different tokens
	opAuth2, _, _, _ := DeriveAuthTokens(key, "test-auth-session-2")
	if opAuth == opAuth2 {
		t.Fatal("different sessions must yield different auth tokens")
	}
}

func TestHandshakePackets(t *testing.T) {
	rawKey, _, _ := GenerateSessionKey()
	sessionID := "handshake-session-test"

	handshakeKey, err := HandshakeKey(rawKey, sessionID)
	if err != nil {
		t.Fatalf("HandshakeKey error: %v", err)
	}

	// Agent Handshake
	agentNonce, agentPacket, err := BuildAgentHandshake(handshakeKey, sessionID)
	if err != nil {
		t.Fatalf("BuildAgentHandshake error: %v", err)
	}
	if len(agentPacket) != HandshakePacketSize {
		t.Fatalf("expected agent packet size %d, got %d", HandshakePacketSize, len(agentPacket))
	}

	verifiedAgentNonce, err := VerifyAgentHandshake(handshakeKey, sessionID, agentPacket)
	if err != nil {
		t.Fatalf("VerifyAgentHandshake error: %v", err)
	}
	if !bytes.Equal(agentNonce, verifiedAgentNonce) {
		t.Fatal("agent nonce mismatch")
	}

	// Operator Handshake
	opNonce, opPacket, err := BuildOperatorHandshake(handshakeKey, sessionID)
	if err != nil {
		t.Fatalf("BuildOperatorHandshake error: %v", err)
	}
	verifiedOpNonce, err := VerifyOperatorHandshake(handshakeKey, sessionID, opPacket)
	if err != nil {
		t.Fatalf("VerifyOperatorHandshake error: %v", err)
	}
	if !bytes.Equal(opNonce, verifiedOpNonce) {
		t.Fatal("operator nonce mismatch")
	}

	// Tampered packet fails
	tampered := make([]byte, len(agentPacket))
	copy(tampered, agentPacket)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := VerifyAgentHandshake(handshakeKey, sessionID, tampered); err == nil {
		t.Fatal("expected tampered agent handshake to fail")
	}

	// Cross-role verification fails
	if _, err := VerifyAgentHandshake(handshakeKey, sessionID, opPacket); err == nil {
		t.Fatal("verifying operator packet as agent packet must fail")
	}
	if _, err := VerifyOperatorHandshake(handshakeKey, sessionID, agentPacket); err == nil {
		t.Fatal("verifying agent packet as operator packet must fail")
	}
}

func TestConnCipherEncryptionAndAntiReplay(t *testing.T) {
	sessionID := "conn-cipher-test-session"
	rawKey, _, _ := GenerateSessionKey()
	handshakeKey, _ := HandshakeKey(rawKey, sessionID)

	opNonce, _, _ := BuildOperatorHandshake(handshakeKey, sessionID)
	agentNonce, _, _ := BuildAgentHandshake(handshakeKey, sessionID)

	opCipher, err := DeriveConnCipher(RoleOperator, sessionID, rawKey, opNonce, agentNonce)
	if err != nil {
		t.Fatalf("DeriveConnCipher(operator) error: %v", err)
	}
	agentCipher, err := DeriveConnCipher(RoleAgent, sessionID, rawKey, opNonce, agentNonce)
	if err != nil {
		t.Fatalf("DeriveConnCipher(agent) error: %v", err)
	}

	// Frame 0: Agent -> Operator
	payload0 := []byte("exec request 0")
	frame0, err := agentCipher.EncryptRecord(RecordTypeData, payload0)
	if err != nil {
		t.Fatalf("EncryptRecord error: %v", err)
	}

	recType, dec0, err := opCipher.DecryptRecord(frame0)
	if err != nil {
		t.Fatalf("DecryptRecord error: %v", err)
	}
	if recType != RecordTypeData || !bytes.Equal(dec0, payload0) {
		t.Fatalf("payload mismatch: got %s, want %s", string(dec0), string(payload0))
	}

	// Replay attack: decrypting frame0 again must fail immediately
	if _, _, err := opCipher.DecryptRecord(frame0); err == nil {
		t.Fatal("expected replayed frame0 to fail, but succeeded")
	}

	// Frame 1: Agent -> Operator
	payload1 := []byte("exec request 1")
	frame1, err := agentCipher.EncryptRecord(RecordTypeData, payload1)
	if err != nil {
		t.Fatalf("EncryptRecord error: %v", err)
	}

	recType1, dec1, err := opCipher.DecryptRecord(frame1)
	if err != nil {
		t.Fatalf("DecryptRecord error: %v", err)
	}
	if recType1 != RecordTypeData || !bytes.Equal(dec1, payload1) {
		t.Fatalf("payload mismatch: got %s, want %s", string(dec1), string(payload1))
	}

	// Frame 2: EOF from Agent -> Operator
	frameEOF, err := agentCipher.EncryptRecord(RecordTypeEOF, []byte{})
	if err != nil {
		t.Fatalf("EncryptRecord(EOF) error: %v", err)
	}
	recTypeEOF, _, err := opCipher.DecryptRecord(frameEOF)
	if err != nil {
		t.Fatalf("DecryptRecord(EOF) error: %v", err)
	}
	if recTypeEOF != RecordTypeEOF {
		t.Fatalf("expected RecordTypeEOF (0x02), got 0x%02x", recTypeEOF)
	}

	// Operator -> Agent response
	opResp := []byte("exec response payload")
	opFrame, err := opCipher.EncryptRecord(RecordTypeData, opResp)
	if err != nil {
		t.Fatalf("opCipher EncryptRecord error: %v", err)
	}
	agentRecType, agentDec, err := agentCipher.DecryptRecord(opFrame)
	if err != nil {
		t.Fatalf("agentCipher DecryptRecord error: %v", err)
	}
	if agentRecType != RecordTypeData || !bytes.Equal(agentDec, opResp) {
		t.Fatalf("expected %s, got %s", string(opResp), string(agentDec))
	}
}

func TestConnCipherBidirectionalEncryption(t *testing.T) {
	sessionID, _ := GenerateSessionID()
	rawKey, _, _ := GenerateSessionKey()
	opNonce := bytes.Repeat([]byte{0x01}, 32)
	agentNonce := bytes.Repeat([]byte{0x02}, 32)

	opCipher, err := DeriveConnCipher(RoleOperator, sessionID, rawKey, opNonce, agentNonce)
	if err != nil {
		t.Fatalf("failed to create operator cipher: %v", err)
	}
	agentCipher, err := DeriveConnCipher(RoleAgent, sessionID, rawKey, opNonce, agentNonce)
	if err != nil {
		t.Fatalf("failed to create agent cipher: %v", err)
	}

	// 1. Operator -> Agent
	opMsg := []byte(`{"version":"1","type":"exec_resp","data":"hello agent"}`)
	encryptedForAgent, err := opCipher.EncryptRecord(RecordTypeData, opMsg)
	if err != nil {
		t.Fatalf("opCipher.EncryptRecord() error: %v", err)
	}
	if bytes.Equal(encryptedForAgent, opMsg) {
		t.Fatal("encrypted payload must not match plaintext")
	}

	recType, decryptedByAgent, err := agentCipher.DecryptRecord(encryptedForAgent)
	if err != nil {
		t.Fatalf("agentCipher.DecryptRecord() error: %v", err)
	}
	if recType != RecordTypeData {
		t.Fatalf("expected recType %d, got %d", RecordTypeData, recType)
	}
	if !bytes.Equal(decryptedByAgent, opMsg) {
		t.Fatalf("expected %s, got %s", string(opMsg), string(decryptedByAgent))
	}

	// Replay on ConnCipher should fail
	if _, _, err := agentCipher.DecryptRecord(encryptedForAgent); err == nil {
		t.Fatal("expected replayed frame to fail on ConnCipher, but succeeded")
	}

	// 2. Agent -> Operator
	agentMsg := []byte(`{"version":"1","type":"exec","data":"hello operator"}`)
	encryptedForOp, err := agentCipher.EncryptRecord(RecordTypeData, agentMsg)
	if err != nil {
		t.Fatalf("agentCipher.EncryptRecord() error: %v", err)
	}

	recType, decryptedByOp, err := opCipher.DecryptRecord(encryptedForOp)
	if err != nil {
		t.Fatalf("opCipher.DecryptRecord() error: %v", err)
	}
	if recType != RecordTypeData {
		t.Fatalf("expected recType %d, got %d", RecordTypeData, recType)
	}
	if !bytes.Equal(decryptedByOp, agentMsg) {
		t.Fatalf("expected %s, got %s", string(agentMsg), string(decryptedByOp))
	}
}

func TestConnCipherTamperingDetection(t *testing.T) {
	sessionID, _ := GenerateSessionID()
	rawKey, _, _ := GenerateSessionKey()
	opNonce := bytes.Repeat([]byte{0x01}, 32)
	agentNonce := bytes.Repeat([]byte{0x02}, 32)

	opCipher, _ := DeriveConnCipher(RoleOperator, sessionID, rawKey, opNonce, agentNonce)
	agentCipher, _ := DeriveConnCipher(RoleAgent, sessionID, rawKey, opNonce, agentNonce)

	msg := []byte("important payload")
	ciphertext, err := opCipher.EncryptRecord(RecordTypeData, msg)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Corrupt ciphertext body
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[len(corrupted)-1] ^= 0x42

	if _, _, err := agentCipher.DecryptRecord(corrupted); err == nil {
		t.Fatal("expected decryption to fail on tampered ciphertext, but succeeded")
	}

	// Truncated frame
	truncated := ciphertext[:NonceSize]
	if _, _, err := agentCipher.DecryptRecord(truncated); err == nil {
		t.Fatal("expected decryption to fail on truncated frame, but succeeded")
	}
}

func TestConnCipherCrossSessionReplayProtection(t *testing.T) {
	sessionID1, _ := GenerateSessionID()
	sessionID2, _ := GenerateSessionID()
	rawKey, _, _ := GenerateSessionKey()
	opNonce := bytes.Repeat([]byte{0x01}, 32)
	agentNonce := bytes.Repeat([]byte{0x02}, 32)

	opCipher1, _ := DeriveConnCipher(RoleOperator, sessionID1, rawKey, opNonce, agentNonce)
	agentCipher2, _ := DeriveConnCipher(RoleAgent, sessionID2, rawKey, opNonce, agentNonce)

	msg := []byte("secret command")
	ciphertext, err := opCipher1.EncryptRecord(RecordTypeData, msg)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Try to decrypt frame from session1 inside session2 (even though they share the same key)
	if _, _, err := agentCipher2.DecryptRecord(ciphertext); err == nil {
		t.Fatal("expected decryption to fail due to AAD session mismatch, but succeeded")
	}
}

func TestConnCipherDirectionalProtection(t *testing.T) {
	sessionID, _ := GenerateSessionID()
	rawKey, _, _ := GenerateSessionKey()
	opNonce := bytes.Repeat([]byte{0x01}, 32)
	agentNonce := bytes.Repeat([]byte{0x02}, 32)

	opCipher, _ := DeriveConnCipher(RoleOperator, sessionID, rawKey, opNonce, agentNonce)

	msg := []byte("self reflected frame")
	ciphertext, err := opCipher.EncryptRecord(RecordTypeData, msg)
	if err != nil {
		t.Fatalf("Encrypt error: %v", err)
	}

	// Reflection attack: operator receives its own frame back
	if _, _, err := opCipher.DecryptRecord(ciphertext); err == nil {
		t.Fatal("expected operator to fail decrypting its own outgoing frame, but succeeded")
	}
}

func TestParseRelayToken(t *testing.T) {
	keyHex := hex.EncodeToString(bytes.Repeat([]byte{0x42}, KeySize))

	tests := []struct {
		name              string
		input             string
		defaultRelayURL   string
		expectedSessionID string
		expectedRelayURL  string
		expectedHubURL    string
		expectErr         bool
	}{
		{
			name:              "Agent Magic Link HTTPS dtfm.dev",
			input:             "https://dtfm.dev/c/session-fox-42#" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "session-fox-42",
			expectedRelayURL:  "wss://relay.dtfm.dev/ws",
			expectedHubURL:    "https://dtfm.dev",
			expectErr:         false,
		},
		{
			name:              "URL with subpath prefix preserves prefix in hubURL",
			input:             "https://custom.example.com/sub/path/c/session-prefixed#" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "session-prefixed",
			expectedRelayURL:  "wss://custom.example.com/sub/path/ws",
			expectedHubURL:    "https://custom.example.com/sub/path",
			expectErr:         false,
		},
		{
			name:              "HTTP URL with subpath prefix preserves prefix in hubURL",
			input:             "http://127.0.0.1:8088/custom/c/session-sub#" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "session-sub",
			expectedRelayURL:  "ws://127.0.0.1:8088/custom/ws",
			expectedHubURL:    "http://127.0.0.1:8088/custom",
			expectErr:         false,
		},
		{
			name:              "WSS URL with subpath prefix preserves prefix in hubURL",
			input:             "wss://relay.example.com/custom/c/session-wss#" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "session-wss",
			expectedRelayURL:  "wss://relay.example.com/custom/ws",
			expectedHubURL:    "https://relay.example.com/custom",
			expectErr:         false,
		},
		{
			name:              "Local HTTP Relay URL",
			input:             "http://127.0.0.1:8088/c/test-session#" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "test-session",
			expectedRelayURL:  "ws://127.0.0.1:8088/ws",
			expectedHubURL:    "http://127.0.0.1:8088",
			expectErr:         false,
		},
		{
			name:              "WebSocket URL with query session",
			input:             "wss://relay.dtfm.dev/ws?session=my-session#" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "my-session",
			expectedRelayURL:  "wss://relay.dtfm.dev/ws",
			expectedHubURL:    "https://relay.dtfm.dev",
			expectErr:         false,
		},
		{
			name:              "Compact Token with hash",
			input:             "session-abc-123#" + keyHex,
			defaultRelayURL:   "wss://relay.custom.io/ws",
			expectedSessionID: "session-abc-123",
			expectedRelayURL:  "wss://relay.custom.io/ws",
			expectedHubURL:    "https://dtfm.dev",
			expectErr:         false,
		},
		{
			name:              "Colon Separated Token with valid hex",
			input:             "session-xyz:" + keyHex,
			defaultRelayURL:   DefaultRelayWsURL,
			expectedSessionID: "session-xyz",
			expectedRelayURL:  DefaultRelayWsURL,
			expectedHubURL:    "https://dtfm.dev",
			expectErr:         false,
		},
		{
			name:      "Passphrase key rejected",
			input:     "session-xyz:my-custom-passphrase",
			expectErr: true,
		},
		{
			name:      "Empty input",
			input:     "",
			expectErr: true,
		},
		{
			name:      "Missing key fragment in URL",
			input:     "https://dtfm.dev/c/session-only",
			expectErr: true,
		},
		{
			name:      "Missing separator",
			input:     "plainstringwithnoseparator",
			expectErr: true,
		},
		{
			name:      "Invalid session characters",
			input:     "session/invalid#" + keyHex,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseRelayToken(tt.input, tt.defaultRelayURL)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for input %q, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for input %q: %v", tt.input, err)
			}
			if cfg.SessionID != tt.expectedSessionID {
				t.Errorf("session ID mismatch: got %q, expected %q", cfg.SessionID, tt.expectedSessionID)
			}
			if cfg.RelayURL != tt.expectedRelayURL {
				t.Errorf("relay URL mismatch: got %q, expected %q", cfg.RelayURL, tt.expectedRelayURL)
			}
			if cfg.HubURL != tt.expectedHubURL {
				t.Errorf("hub URL mismatch: got %q, expected %q", cfg.HubURL, tt.expectedHubURL)
			}
		})
	}
}

func TestFormatMagicLink(t *testing.T) {
	link := FormatMagicLink("https://dtfm.dev", "session-123", "secret-key")
	expected := "https://dtfm.dev/c/session-123#secret-key"
	if link != expected {
		t.Fatalf("expected %q, got %q", expected, link)
	}

	// Test trailing slash removal
	link2 := FormatMagicLink("https://dtfm.dev/", "session-123", "secret-key")
	if link2 != expected {
		t.Fatalf("expected %q, got %q", expected, link2)
	}
}

func TestConnCipherInvalidParams(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x42}, KeySize)
	validNonce := bytes.Repeat([]byte{0x01}, 32)
	_, err := DeriveConnCipher("invalid_role", "session", validKey, validNonce, validNonce)
	if err == nil || !strings.Contains(err.Error(), "invalid e2ee role") {
		t.Fatalf("expected invalid role error, got: %v", err)
	}

	_, err = DeriveConnCipher(RoleOperator, "", validKey, validNonce, validNonce)
	if err == nil || !strings.Contains(err.Error(), "session ID cannot be empty") {
		t.Fatalf("expected empty sessionID error, got: %v", err)
	}

	_, err = DeriveConnCipher(RoleOperator, "session", nil, validNonce, validNonce)
	if err == nil || !strings.Contains(err.Error(), "invalid secret key length") {
		t.Fatalf("expected invalid secret key error, got: %v", err)
	}

	_, err = DeriveConnCipher(RoleOperator, "session", []byte("short"), validNonce, validNonce)
	if err == nil || !strings.Contains(err.Error(), "invalid secret key length") {
		t.Fatalf("expected short secret key error, got: %v", err)
	}

	_, err = DeriveConnCipher(RoleOperator, "session", validKey, []byte("short"), validNonce)
	if err == nil || !strings.Contains(err.Error(), "invalid nonces") {
		t.Fatalf("expected short op nonce error, got: %v", err)
	}

	_, err = DeriveConnCipher(RoleOperator, "session", validKey, validNonce, []byte("short"))
	if err == nil || !strings.Contains(err.Error(), "invalid nonces") {
		t.Fatalf("expected short agent nonce error, got: %v", err)
	}
}

func TestHKDFRFC5869TestVector(t *testing.T) {
	// RFC 5869 Test Case 1 (SHA-256)
	ikm, _ := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	expectedOKM, _ := hex.DecodeString("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

	prk := hkdfExtract(salt, ikm)
	okm, err := hkdfExpand(prk, info, 42)
	if err != nil {
		t.Fatalf("hkdfExpand error: %v", err)
	}
	if !bytes.Equal(okm, expectedOKM) {
		t.Fatalf("HKDF output mismatch:\ngot:  %x\nwant: %x", okm, expectedOKM)
	}
}
