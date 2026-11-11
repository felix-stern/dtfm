// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package protocol_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
)

func TestEnvelopeRoundTrip(t *testing.T) {
	req := protocol.CommandRequest{
		ID:             "cmd-1",
		Reason:         "Fix bug",
		Command:        "make",
		Args:           []string{"test"},
		TimeoutSeconds: 60,
		CreatedAt:      time.Now(),
	}

	env, err := protocol.NewEnvelope(protocol.TypeExec, req)
	if err != nil {
		t.Fatalf("Failed to create envelope: %v", err)
	}

	if env.Version != protocol.ProtocolVersion || env.Type != protocol.TypeExec {
		t.Fatalf("Unexpected envelope header: %+v", env)
	}

	data, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decodedEnv protocol.Envelope
	if err := json.Unmarshal(data, &decodedEnv); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	var decodedReq protocol.CommandRequest
	if err := json.Unmarshal(decodedEnv.Data, &decodedReq); err != nil {
		t.Fatalf("Unmarshal data failed: %v", err)
	}

	if decodedReq.ID != req.ID || decodedReq.Command != req.Command {
		t.Errorf("Mismatch in payload: expected %+v, got %+v", req, decodedReq)
	}
}

func TestSanitizeTerminalTextLossless(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "plain text unchanged",
			input:    "git status",
			expected: "git status",
		},
		{
			name:     "escape ANSI color codes visibly without deleting",
			input:    "\033[31mrm -rf /\033[0m",
			expected: `\x1b[31mrm -rf /\x1b[0m`,
		},
		{
			name:     "escape ANSI OSC exploit without deleting malicious payload",
			input:    "echo \x1b]; rm -rf /important; #\x07 hello",
			expected: `echo \x1b]; rm -rf /important; #\a hello`,
		},
		{
			name:     "escape carriage return",
			input:    "malicious\roverwrite",
			expected: `malicious\roverwrite`,
		},
		{
			name:     "escape newlines",
			input:    "line1\nline2",
			expected: `line1\nline2`,
		},
		{
			name:     "escape bell and control characters",
			input:    "ring\x07bell",
			expected: `ring\abell`,
		},
		{
			name:     "escape bidirectional Trojan Source characters",
			input:    "safe\u202Ereversed",
			expected: `safe\u202ereversed`,
		},
		{
			name:     "escape NBSP and supplementary non-BMP characters with \\U8",
			input:    "hello\u00a0world\U000e0061",
			expected: `hello\u00a0world\U000e0061`,
		},
		{
			name:     "escape invisible Unicode variation selectors and blank fillers",
			input:    "invisible\ufe0f\u115f\u3164rune",
			expected: `invisible\ufe0f\u115f\u3164rune`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := protocol.SanitizeTerminalText(tc.input)
			if result != tc.expected {
				t.Errorf("SanitizeTerminalText(%q) = %q; expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestShellQuotingAndFormatCommand(t *testing.T) {
	// Verify that multi-word single argument is distinguished from separate args
	cmd1 := protocol.FormatCommand("rm", []string{"-rf ~"})
	cmd2 := protocol.FormatCommand("rm", []string{"-rf", "~"})

	if cmd1 == cmd2 {
		t.Fatalf("FormatCommand failed to distinguish multi-word single argument from separate args: %q vs %q", cmd1, cmd2)
	}

	expectedCmd1 := "rm '-rf ~'"
	if cmd1 != expectedCmd1 {
		t.Errorf("Expected %q, got %q", expectedCmd1, cmd1)
	}

	// Verify that arguments containing ANSI escapes are ANSI-C quoted ($'...') with escapes visible
	exploitArg := "echo \x1b]; rm -rf /important; #\x07 hello"
	formatted := protocol.FormatCommand("bash", []string{"-c", exploitArg})
	if strings.Contains(formatted, "echo  hello") {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: ANSI sequence was stripped! Result: %s", formatted)
	}
	if !strings.Contains(formatted, `\x1b`) || !strings.Contains(formatted, "rm -rf /important") {
		t.Fatalf("Expected escape code and payload to be visible: %s", formatted)
	}
	if !strings.HasPrefix(strings.Split(formatted, " ")[2], "$'") {
		t.Fatalf("Expected ANSI-C quoting $'...' for argument with escapes: %s", formatted)
	}

	// Verify quoting with single quotes in argument
	quoted := protocol.ShellQuote("it's dangerous")
	expectedQuoted := `'it'\''s dangerous'`
	if quoted != expectedQuoted {
		t.Errorf("ShellQuote mismatch: expected %s, got %s", expectedQuoted, quoted)
	}

	// Verify empty string quoted
	if protocol.ShellQuote("") != "''" {
		t.Errorf("Expected '', got %s", protocol.ShellQuote(""))
	}

	// Verify command with '=' is quoted
	cmdWithEquals := protocol.FormatCommand("DRY_RUN=1", []string{"rm", "-rf", "/"})
	if !strings.HasPrefix(cmdWithEquals, "'DRY_RUN=1'") {
		t.Errorf("Expected command with '=' to be quoted, got %s", cmdWithEquals)
	}

	// Verify leading '=' is quoted in ShellQuote
	if protocol.ShellQuote("=rm") != "'=rm'" {
		t.Errorf("Expected leading '=' to be quoted, got %s", protocol.ShellQuote("=rm"))
	}
}

func TestSanitizeEnvSecurity(t *testing.T) {
	inputEnv := map[string]string{
		"LD_PRELOAD":              "/evil.so",
		"ld_library_path":         "/tmp",
		"DYLD_INSERT":             "/evil.dylib",
		"BASH_ENV":                "/tmp/evil_rc",
		"BASHOPTS":                "evil_opts",
		"BASH_FUNC_evil%%":        "() { echo evil; }",
		"GIT_SSH_COMMAND":         "curl http://evil",
		"HOME":                    "/tmp/attacker",
		"PATH=/tmp/evil:":         "/usr/bin", // '=' key injection attack attempt
		"PATH":                    "/tmp/bin:/usr/bin",
		"PYTHONPATH":              "/tmp/py",
		"OPENSSL_CONF":            "/evil.cnf",
		"SUDO_ASKPASS":            "/evil_askpass",
		"SSH_ASKPASS":             "/evil_ssh_askpass",
		"PERLLIB":                 "/evil_perl",
		"NODE_PATH":               "/evil_node",
		"VISUAL":                  "/evil_editor",
		"GOFLAGS":                 "-toolexec=/evil",
		"SSL_CERT_FILE":           "/evil_ca.pem",
		"KUBECONFIG":              "/evil_kube",
		"DOCKER_HOST":             "tcp://evil:2375",
		"SAFE_VAR":                "value1",
		"ANOTHER_SAFE":            "value2",
		"INVALID-KEY-WITH-DASHES": "val",
	}

	clean, blocked := protocol.SanitizeEnv(inputEnv)

	// Blocked dangerous variables
	blockedChecks := []string{
		"LD_PRELOAD",
		"ld_library_path",
		"DYLD_INSERT",
		"BASH_ENV",
		"BASHOPTS",
		"BASH_FUNC_evil%%",
		"GIT_SSH_COMMAND",
		"HOME",
		"PATH=/tmp/evil:", // '=' key injection caught
		"PATH",
		"PYTHONPATH",
		"OPENSSL_CONF",
		"SUDO_ASKPASS",
		"SSH_ASKPASS",
		"PERLLIB",
		"NODE_PATH",
		"VISUAL",
		"GOFLAGS",
		"SSL_CERT_FILE",
		"KUBECONFIG",
		"DOCKER_HOST",
		"INVALID-KEY-WITH-DASHES",
	}

	for _, k := range blockedChecks {
		if _, ok := clean[k]; ok {
			t.Errorf("Security failure: %q should have been blocked by SanitizeEnv", k)
		}
	}

	// Safe variables preserved
	if clean["SAFE_VAR"] != "value1" || clean["ANOTHER_SAFE"] != "value2" {
		t.Errorf("Safe env vars missing or modified: %+v", clean)
	}

	if len(blocked) != len(blockedChecks) {
		t.Errorf("Expected %d blocked env vars, got %d: %v", len(blockedChecks), len(blocked), blocked)
	}
}

func TestValidateSocketPath(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.Chmod(tmpDir, 0700)

	// 1. Valid directory succeeds
	validSock := filepath.Join(tmpDir, "valid", "lmdtfy.sock")
	if err := protocol.EnsureSocketDir(validSock); err != nil {
		t.Fatalf("Expected EnsureSocketDir to succeed on valid dir, got %v", err)
	}

	// 2. Symlinked directory fails closed
	realDir := filepath.Join(tmpDir, "real")
	_ = os.Mkdir(realDir, 0700)
	symDir := filepath.Join(tmpDir, "symlink")
	if err := os.Symlink(realDir, symDir); err == nil {
		symSock := filepath.Join(symDir, "lmdtfy.sock")
		if err := protocol.EnsureSocketDir(symSock); err == nil {
			t.Fatalf("SECURITY VIOLATION: Expected error on symlinked socket directory %s", symDir)
		}
	}

	// 3. File parent fails closed
	filePath := filepath.Join(tmpDir, "regular_file")
	_ = os.WriteFile(filePath, []byte("data"), 0600)
	fileSock := filepath.Join(filePath, "lmdtfy.sock")
	if err := protocol.EnsureSocketDir(fileSock); err == nil {
		t.Fatalf("Expected error when socket parent is a file, got nil")
	}

	// 4. Mode 0755 directory outside /tmp (e.g. $HOME) is accepted without chmod 0700 mutation
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		homeSubdir := filepath.Join(home, fmt.Sprintf(".test-dtfm-perm-%d", time.Now().UnixNano()))
		if err := os.Mkdir(homeSubdir, 0755); err == nil {
			defer os.RemoveAll(homeSubdir)
			homeSock := filepath.Join(homeSubdir, "lmdtfy.sock")
			if err := protocol.EnsureSocketDir(homeSock); err != nil {
				t.Fatalf("Expected 0755 directory in home to be accepted, got: %v", err)
			}
			st, err := os.Lstat(homeSubdir)
			if err != nil {
				t.Fatalf("Failed to stat homeSubdir: %v", err)
			}
			if st.Mode().Perm() != 0755 {
				t.Fatalf("Expected permissions to remain 0755, but was mutated to %04o", st.Mode().Perm())
			}
		}
	}

	// 5. Mode 0755 subdirectory inside /tmp MUST be rejected
	tmpSubdir := filepath.Join("/tmp", fmt.Sprintf("test-lmdtfy-%d-perm-%d", os.Getuid(), time.Now().UnixNano()))
	if err := os.Mkdir(tmpSubdir, 0755); err == nil {
		defer os.RemoveAll(tmpSubdir)
		tmpSock := filepath.Join(tmpSubdir, "lmdtfy.sock")
		if err := protocol.EnsureSocketDir(tmpSock); err == nil {
			t.Fatalf("SECURITY VIOLATION: Expected 0755 directory inside /tmp to be rejected, but got nil")
		}
	}

	// 6. ValidateClientSocketPath on non-existent directory does NOT create directory and returns nil
	nonExistentDir := filepath.Join(tmpDir, "does-not-exist")
	clientSock := filepath.Join(nonExistentDir, "client.sock")
	if err := protocol.ValidateClientSocketPath(clientSock); err != nil {
		t.Fatalf("Expected ValidateClientSocketPath to return nil for non-existent dir, got: %v", err)
	}
	if _, err := os.Lstat(nonExistentDir); !os.IsNotExist(err) {
		t.Fatalf("ValidateClientSocketPath should not create nonExistentDir %s", nonExistentDir)
	}

	// 7. Relative path resolving inside /tmp with mode 0755 fails closed
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmpSubdir); err == nil {
		defer os.Chdir(origWd)
		if err := protocol.EnsureSocketDir("lmdtfy.sock"); err == nil {
			t.Fatalf("SECURITY VIOLATION: Relative path in /tmp with mode 0755 must be rejected!")
		}
		_ = os.Chdir(origWd)
	}

	// 8. Root-owned directory outside /tmp is accepted by ValidateClientSocketPath for container compatibility
	if err := protocol.ValidateClientSocketPath("/lmdtfy.sock"); err != nil {
		t.Fatalf("Expected ValidateClientSocketPath on root-owned / to succeed, got: %v", err)
	}

	// 9. Root-owned OS system symlinks (such as /var/run -> /run with mode 0777 on Linux) must not be rejected by checkAncestors
	if fi, err := os.Lstat("/var/run"); err == nil && (fi.Mode()&os.ModeSymlink != 0) {
		runUserDir := fmt.Sprintf("/var/run/user/%d", os.Getuid())
		if ufi, err := os.Lstat(runUserDir); err == nil && ufi.IsDir() {
			if err := protocol.ValidateClientSocketPath(filepath.Join(runUserDir, "lmdtfy.sock")); err != nil {
				t.Fatalf("Expected ValidateClientSocketPath to accept root-owned system symlink /var/run, got: %v", err)
			}
		}
	}

	// 10. Untrusted intermediate symlink prefix before non-existent socket dir: EnsureSocketDir must fail before creating dir
	untrustedSymlink := filepath.Join(tmpDir, "untrusted_sym")
	_ = os.Symlink(tmpDir, untrustedSymlink)
	targetDir := filepath.Join(untrustedSymlink, "child", "lmdtfy.sock")
	if err := protocol.EnsureSocketDir(targetDir); err == nil {
		t.Fatalf("SECURITY VIOLATION: EnsureSocketDir must reject untrusted intermediate symlink prefix")
	}
	if _, err := os.Lstat(filepath.Join(tmpDir, "child")); !os.IsNotExist(err) {
		t.Fatalf("EnsureSocketDir created directory despite untrusted symlink prefix!")
	}

	// 11. Insecure 0777 non-sticky directory prefix: EnsureSocketDir must reject before MkdirAll
	insecurePrefix := filepath.Join(tmpDir, "insecure_0777_dir")
	_ = os.Mkdir(insecurePrefix, 0777)
	_ = os.Chmod(insecurePrefix, 0777) // Ensure non-sticky 0777
	insecureTarget := filepath.Join(insecurePrefix, "new_child", "lmdtfy.sock")
	if err := protocol.EnsureSocketDir(insecureTarget); err == nil {
		t.Fatalf("SECURITY VIOLATION: EnsureSocketDir must reject insecure 0777 non-sticky prefix before MkdirAll")
	}
	if _, err := os.Lstat(filepath.Join(insecurePrefix, "new_child")); !os.IsNotExist(err) {
		t.Fatalf("EnsureSocketDir created directory inside insecure 0777 prefix!")
	}
}
