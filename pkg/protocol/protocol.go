// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"time"
)

const (
	ProtocolVersion = "1"

	TypePing     = "ping"
	TypePingResp = "ping_resp"
	TypeExec     = "exec"
	TypeExecResp = "exec_resp"
	TypeError    = "error"

	// DefaultTimeoutSeconds is the default timeout for execution requests (5 minutes).
	DefaultTimeoutSeconds = 300
	// MaxTimeoutSeconds is the upper bound on execution requests (24 hours).
	MaxTimeoutSeconds = 86400

	// MaxMessageDataBytes is the maximum JSON payload allowed in an Envelope frame (4 MB).
	MaxMessageDataBytes = 4 * 1024 * 1024

	// MaxOutputBufferSize is the maximum stdout/stderr captured per stream (1 MB).
	MaxOutputBufferSize = 1024 * 1024

	// MaxResponseEnvelopeBytes is the upper bound on serialized response envelopes
	// accounting for 6x JSON escaping expansion of binary/ANSI output (16 MB).
	MaxResponseEnvelopeBytes = 16 * 1024 * 1024

	// Standard process exit codes returned in CommandResponse
	ExitCodeTimeout  = 124
	ExitCodeRejected = 126
	ExitCodeError    = 127
)

// CurrentUser returns the username from $USER, falling back to os/user.Current().
func CurrentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if curr, err := user.Current(); err == nil && curr.Username != "" {
		return curr.Username
	}
	return "unknown"
}

// Envelope wraps all messages exchanged over the streaming connection.
type Envelope struct {
	Version string          `json:"version"`
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
}

// ErrorPayload represents a generic protocol error response.
type ErrorPayload struct {
	Message string `json:"message"`
}

// NewEnvelope wraps a payload inside an Envelope with ProtocolVersion.
func NewEnvelope(msgType string, payload any) (Envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("failed to marshal envelope data: %w", err)
	}
	return Envelope{
		Version: ProtocolVersion,
		Type:    msgType,
		Data:    data,
	}, nil
}

// CommandRequest represents an execution request from the remote agent to the local human operator.
type CommandRequest struct {
	ID      string   `json:"id"`
	Reason  string   `json:"reason"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Cwd     string   `json:"cwd,omitempty"`
	// Env is retained on the wire protocol struct so dtfm can explicitly detect and reject
	// agent attempts to supply custom environment variables, while preventing unknown-field bypasses.
	Env            map[string]string `json:"env,omitempty"`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty"`
	CreatedAt      time.Time         `json:"created_at"`
}

// ApprovalStatus represents the user's decision on the prompt.
type ApprovalStatus string

const (
	StatusApproved ApprovalStatus = "approved"
	StatusRejected ApprovalStatus = "rejected"
	StatusTimeout  ApprovalStatus = "timeout"
	StatusError    ApprovalStatus = "error"
)

// CommandResponse represents the execution result sent back to the agent.
type CommandResponse struct {
	ID              string         `json:"id"`
	Status          ApprovalStatus `json:"status"`
	RejectReason    string         `json:"reject_reason,omitempty"`
	ModifiedCommand string         `json:"modified_command,omitempty"`
	ExitCode        int            `json:"exit_code"`
	Stdout          string         `json:"stdout"`
	Stderr          string         `json:"stderr"`
	Error           string         `json:"error,omitempty"`
	DurationMs      int64          `json:"duration_ms"`
}

// PingRequest is sent to check if the user is connected and accepting requests.
type PingRequest struct {
	ID        string    `json:"id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// PingResponse is returned when the user session is active.
type PingResponse struct {
	ID        string    `json:"id,omitempty"`
	Active    bool      `json:"active"`
	User      string    `json:"user,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}
