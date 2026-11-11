package main

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func init() {
	switch os.Getenv("TEST_UID_QUERIER_HELPER") {
	case "leader_bg":
		// Session leader spawned by pty.Start. Spawns child worker in new process group.
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), "TEST_UID_QUERIER_HELPER=worker_bg")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)

	case "worker_bg":
		// Worker running in background process group on controlling terminal
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		uid, err := DefaultUIDQuerier(ctx, "bg-target")
		if err != nil {
			fmt.Fprintf(os.Stderr, "worker_bg error: %v\n", err)
			os.Exit(1)
		}
		if uid != 1000 {
			fmt.Fprintf(os.Stderr, "worker_bg expected uid 1000, got %d\n", uid)
			os.Exit(1)
		}
		os.Exit(0)

	case "fg_worker":
		// Foreground session leader. DefaultUIDQuerier must restore ECHO modified by child ssh.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		uid, err := DefaultUIDQuerier(ctx, "fg-target")
		if err != nil {
			fmt.Fprintf(os.Stderr, "fg_worker error: %v\n", err)
			os.Exit(1)
		}
		if uid != 1000 {
			fmt.Fprintf(os.Stderr, "fg_worker expected uid 1000, got %d\n", uid)
			os.Exit(1)
		}

		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "fg_worker cannot open /dev/tty: %v\n", err)
			os.Exit(1)
		}
		defer tty.Close()

		tstate, err := getTermios(tty.Fd())
		if err != nil {
			fmt.Fprintf(os.Stderr, "fg_worker failed getTermios: %v\n", err)
			os.Exit(1)
		}
		if tstate.Lflag&syscall.ECHO == 0 {
			fmt.Fprintf(os.Stderr, "ECHO is not restored on /dev/tty!\n")
			os.Exit(2)
		}
		os.Exit(0)
	}
}

func TestGenerateSnippet(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		user        string
		uid         uint32
		socket      string
		expected    string
		expectError bool
	}{
		{
			name:   "standard user uid 1000",
			host:   "prod-vm",
			uid:    1000,
			socket: "/home/ivan/.lmdtfy.sock",
			expected: "# Added by dtfm ssh-config\n" +
				"Host prod-vm\n" +
				"    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n" +
				"    StreamLocalBindUnlink yes\n",
		},
		{
			name:   "with user",
			host:   "prod-vm",
			user:   "ubuntu",
			uid:    1000,
			socket: "/home/ivan/.lmdtfy.sock",
			expected: "# Added by dtfm ssh-config\n" +
				"Host prod-vm\n" +
				"    User ubuntu\n" +
				"    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n" +
				"    StreamLocalBindUnlink yes\n",
		},
		{
			name:   "socket with spaces is quoted",
			host:   "prod-vm",
			uid:    1000,
			socket: "/Users/John Doe/.lmdtfy.sock",
			expected: "# Added by dtfm ssh-config\n" +
				"Host prod-vm\n" +
				"    RemoteForward /run/user/1000/lmdtfy.sock \"/Users/John Doe/.lmdtfy.sock\"\n" +
				"    StreamLocalBindUnlink yes\n",
		},
		{
			name:   "socket with percent is escaped as %%",
			host:   "prod-vm",
			uid:    1000,
			socket: "/tmp/sock%test/.lmdtfy.sock",
			expected: "# Added by dtfm ssh-config\n" +
				"Host prod-vm\n" +
				"    RemoteForward /run/user/1000/lmdtfy.sock /tmp/sock%%test/.lmdtfy.sock\n" +
				"    StreamLocalBindUnlink yes\n",
		},
		{
			name:        "uid MaxUint32 rejected",
			host:        "prod-vm",
			uid:         math.MaxUint32,
			socket:      "/home/ivan/.lmdtfy.sock",
			expectError: true,
		},
		{
			name:        "socket with colon rejected",
			host:        "prod-vm",
			uid:         1000,
			socket:      "127.0.0.1:9222",
			expectError: true,
		},
		{
			name:        "empty socket rejected",
			host:        "prod-vm",
			uid:         1000,
			socket:      "",
			expectError: true,
		},
		{
			name:        "socket length > 103 rejected",
			host:        "prod-vm",
			uid:         1000,
			socket:      "/" + strings.Repeat("a", 103),
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GenerateSnippet(tc.host, tc.user, tc.uid, tc.socket)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error, got nil (result: %q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.expected {
				t.Fatalf("expected:\n%s\ngot:\n%s", tc.expected, got)
			}
		})
	}
}

func TestValidateSSHTarget(t *testing.T) {
	valid := []struct {
		target   string
		wantHost string
		wantUser string
	}{
		{"my-host", "my-host", ""},
		{"ubuntu@192.168.1.10", "192.168.1.10", "ubuntu"},
		{"dev.example.com", "dev.example.com", ""},
		{"user_name@host-123.internal", "host-123.internal", "user_name"},
	}
	for _, tc := range valid {
		h, u, err := validateSSHTarget(tc.target)
		if err != nil {
			t.Errorf("expected valid target %q, got err: %v", tc.target, err)
		}
		if h != tc.wantHost || u != tc.wantUser {
			t.Errorf("for %q expected host=%q user=%q, got host=%q user=%q", tc.target, tc.wantHost, tc.wantUser, h, u)
		}
	}

	invalid := []struct {
		target string
		errMsg string
	}{
		{"", "cannot be empty"},
		{"   ", "whitespace and control characters"},
		{"host\nwithnewline", "whitespace and control characters"},
		{"host\twithtab", "whitespace and control characters"},
		{"host withspace", "whitespace and control characters"},
		{"-oProxyCommand=calc", "must not start with a dash"},
		{"--help", "must not start with a dash"},
		{"user@-host", "host must not start with a dash"},
		{"-user@host", "user must not start with a dash"},
		{"user@", "empty host after '@'"},
		{"@host", "empty user before '@'"},
		{"user@sub@domain.com", "multiple '@' symbols"},
		{"ssh://host", "':' is not permitted"},
		{"host:22", "':' is not permitted"},
		{"host#comment", "characters '\"'"},
		{"host=val", "characters '\"'"},
		{"host*wildcard", "characters '\"'"},
		{"host?wildcard", "characters '\"'"},
		{"!host", "characters '\"'"},
		{"\"host\"", "characters '\"'"},
	}
	for _, tc := range invalid {
		_, _, err := validateSSHTarget(tc.target)
		if err == nil {
			t.Errorf("expected error for %q, got nil", tc.target)
			continue
		}
		if !strings.Contains(err.Error(), tc.errMsg) {
			t.Errorf("expected %q in error for %q, got %v", tc.errMsg, tc.target, err)
		}
	}
}

func TestResolveHostAndUser(t *testing.T) {
	tests := []struct {
		name      string
		host      string
		user      string
		wantHost  string
		wantUser  string
		expectErr string
	}{
		{
			name:     "valid host only",
			host:     "my-vm",
			user:     "",
			wantHost: "my-vm",
			wantUser: "",
		},
		{
			name:     "valid user in host",
			host:     "ubuntu@my-vm",
			user:     "",
			wantHost: "my-vm",
			wantUser: "ubuntu",
		},
		{
			name:     "valid user in user arg",
			host:     "my-vm",
			user:     "ubuntu",
			wantHost: "my-vm",
			wantUser: "ubuntu",
		},
		{
			name:     "matching user in both",
			host:     "ubuntu@my-vm",
			user:     "ubuntu",
			wantHost: "my-vm",
			wantUser: "ubuntu",
		},
		{
			name:      "conflicting user in host and user arg",
			host:      "alice@my-vm",
			user:      "bob",
			expectErr: "conflicting user specifications",
		},
		{
			name:      "invalid user starting with dash",
			host:      "my-vm",
			user:      "-admin",
			expectErr: "invalid user",
		},
		{
			name:      "invalid host starting with dash",
			host:      "-oProxyCommand=calc",
			user:      "",
			expectErr: "must not start with a dash",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h, u, err := resolveHostAndUser(tc.host, tc.user)
			if tc.expectErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil (h=%q, u=%q)", tc.expectErr, h, u)
				}
				if !strings.Contains(err.Error(), tc.expectErr) {
					t.Fatalf("expected error containing %q, got %v", tc.expectErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if h != tc.wantHost || u != tc.wantUser {
				t.Fatalf("expected host=%q user=%q, got host=%q user=%q", tc.wantHost, tc.wantUser, h, u)
			}
		})
	}
}

func TestValidateAndCanonicalizeLocalSocket(t *testing.T) {
	t.Run("valid absolute path", func(t *testing.T) {
		got, err := validateAndCanonicalizeLocalSocket("/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "/home/ivan/.lmdtfy.sock" {
			t.Fatalf("unexpected result: %q", got)
		}
	})

	t.Run("relative path resolves to absolute", func(t *testing.T) {
		got, err := validateAndCanonicalizeLocalSocket(".lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(got, "/") || !strings.HasSuffix(got, ".lmdtfy.sock") {
			t.Fatalf("expected absolute path, got %q", got)
		}
	})

	t.Run("tilde expansion", func(t *testing.T) {
		got, err := validateAndCanonicalizeLocalSocket("~/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.HasPrefix(got, "~") || !strings.HasPrefix(got, "/") {
			t.Fatalf("expected expanded absolute path, got %q", got)
		}
	})

	t.Run("rejects empty or whitespace", func(t *testing.T) {
		for _, s := range []string{"", "   ", "\t"} {
			if _, err := validateAndCanonicalizeLocalSocket(s); err == nil {
				t.Fatalf("expected error for empty socket %q, got nil", s)
			}
		}
	})

	t.Run("rejects control characters", func(t *testing.T) {
		for _, s := range []string{"/tmp/sock\n", "/tmp/sock\r", "/tmp/sock\x00"} {
			if _, err := validateAndCanonicalizeLocalSocket(s); err == nil {
				t.Fatalf("expected error for control char in %q, got nil", s)
			}
		}
	})

	t.Run("rejects colons and quotes", func(t *testing.T) {
		for _, s := range []string{"localhost:9222", "/tmp/\"sock\"", "/tmp/'sock'"} {
			if _, err := validateAndCanonicalizeLocalSocket(s); err == nil {
				t.Fatalf("expected error for %q, got nil", s)
			}
		}
	})

	t.Run("rejects length over 103", func(t *testing.T) {
		longPath := "/" + strings.Repeat("x", 103)
		if _, err := validateAndCanonicalizeLocalSocket(longPath); err == nil {
			t.Fatalf("expected error for path of length %d, got nil", len(longPath))
		}
	})

	t.Run("rejects HOME with colons after expansion", func(t *testing.T) {
		t.Setenv("HOME", "/tmp/path:with:colon")
		if _, err := validateAndCanonicalizeLocalSocket("~/sock.sock"); err == nil {
			t.Fatalf("expected error when expanded HOME contains colon, got nil")
		} else if !strings.Contains(err.Error(), "must not contain ':'") {
			t.Fatalf("expected colon error, got %v", err)
		}
	})

	t.Run("rejects HOME with quotes after expansion", func(t *testing.T) {
		t.Setenv("HOME", "/tmp/path\"quote")
		if _, err := validateAndCanonicalizeLocalSocket("~/sock.sock"); err == nil {
			t.Fatalf("expected error when expanded HOME contains quotes, got nil")
		} else if !strings.Contains(err.Error(), "must not contain quotes") {
			t.Fatalf("expected quote error, got %v", err)
		}
	})
}

func TestParseSSHDirective(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantKw   string
		wantArgs []string
		wantOk   bool
	}{
		{
			name:     "standard whitespace host",
			line:     "Host dev-box",
			wantKw:   "Host",
			wantArgs: []string{"dev-box"},
			wantOk:   true,
		},
		{
			name:     "key=value without spaces",
			line:     "Match=all",
			wantKw:   "Match",
			wantArgs: []string{"all"},
			wantOk:   true,
		},
		{
			name:     "key = value with spaces",
			line:     "StreamLocalBindUnlink = no",
			wantKw:   "StreamLocalBindUnlink",
			wantArgs: []string{"no"},
			wantOk:   true,
		},
		{
			name:     "inline comment stripped",
			line:     "Host staging # mirrors prod-vm",
			wantKw:   "Host",
			wantArgs: []string{"staging"},
			wantOk:   true,
		},
		{
			name:     "quoted argument preserved",
			line:     "RemoteForward /run/user/1000/lmdtfy.sock \"/Users/John Doe/.lmdtfy.sock\"",
			wantKw:   "RemoteForward",
			wantArgs: []string{"/run/user/1000/lmdtfy.sock", "/Users/John Doe/.lmdtfy.sock"},
			wantOk:   true,
		},
		{
			name:     "unrelated forward with comment mentioning lmdtfy",
			line:     "RemoteForward 5432 127.0.0.1:5432 # keep separate from lmdtfy.sock",
			wantKw:   "RemoteForward",
			wantArgs: []string{"5432", "127.0.0.1:5432"},
			wantOk:   true,
		},
		{
			name:   "comment only line",
			line:   "# This is a comment",
			wantOk: false,
		},
		{
			name:   "empty line",
			line:   "   \t  ",
			wantOk: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kw, args, ok := parseSSHDirective(tc.line)
			if ok != tc.wantOk {
				t.Fatalf("expected ok=%v, got %v", tc.wantOk, ok)
			}
			if !tc.wantOk {
				return
			}
			if kw != tc.wantKw {
				t.Errorf("expected kw=%q, got %q", tc.wantKw, kw)
			}
			if len(args) != len(tc.wantArgs) {
				t.Fatalf("expected %d args (%v), got %d (%v)", len(tc.wantArgs), tc.wantArgs, len(args), args)
			}
			for i := range args {
				if args[i] != tc.wantArgs[i] {
					t.Errorf("arg %d: expected %q, got %q", i, tc.wantArgs[i], args[i])
				}
			}
		})
	}
}

func TestUpdateSSHConfig(t *testing.T) {
	t.Run("empty original content produces clean host block", func(t *testing.T) {
		got, err := UpdateSSHConfig("", "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "# Added by dtfm ssh-config\nHost my-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("insert with user directive", func(t *testing.T) {
		got, err := UpdateSSHConfig("", "my-vm", "ubuntu", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "# Added by dtfm ssh-config\nHost my-vm\n    User ubuntu\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("insert before Host * catch-all section", func(t *testing.T) {
		orig := "# Global defaults\nHost *\n    StreamLocalBindUnlink no\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "# Added by dtfm ssh-config\nHost my-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n\n# Global defaults\nHost *\n    StreamLocalBindUnlink no\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("catch-all section comments stay attached to Host *", func(t *testing.T) {
		orig := "Host prod-host\n    HostName 10.1.1.1\n\n# -------------------------\n# Global catch-all settings\n# -------------------------\nHost *\n    StreamLocalBindUnlink no\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host prod-host\n    HostName 10.1.1.1\n\n# Added by dtfm ssh-config\nHost my-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n\n# -------------------------\n# Global catch-all settings\n# -------------------------\nHost *\n    StreamLocalBindUnlink no\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("insert before Match all catch-all section", func(t *testing.T) {
		orig := "Match all\n    StreamLocalBindUnlink no\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "# Added by dtfm ssh-config\nHost my-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n\nMatch all\n    StreamLocalBindUnlink no\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("multi-host block containing target is not modified in-place but inserted before", func(t *testing.T) {
		orig := "Host primary my-vm *.prod\n    HostName 10.0.0.1\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "# Added by dtfm ssh-config\nHost my-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n\nHost primary my-vm *.prod\n    HostName 10.0.0.1\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("updates exact host block with StreamLocalBindUnlink=no Key=Value syntax", func(t *testing.T) {
		orig := "Host my-vm\n    HostName 10.0.0.1\n    StreamLocalBindUnlink=no\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n    HostName 10.0.0.1\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("preserves unrelated RemoteForward with lmdtfy in comment", func(t *testing.T) {
		orig := "Host my-vm\n    RemoteForward 5432 127.0.0.1:5432 # lmdtfy.sock comment\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n    RemoteForward 5432 127.0.0.1:5432 # lmdtfy.sock comment\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("duplicate exact Host blocks: updates first and strips stale from second", func(t *testing.T) {
		orig := "Host my-vm\n    HostName 10.0.0.1\n    RemoteForward /run/user/999/lmdtfy.sock /old.sock\n\nHost my-vm\n    RemoteForward /run/user/888/lmdtfy.sock /stale.sock\n    User admin\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n    HostName 10.0.0.1\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n\nHost my-vm\n    User admin\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("updates existing host block preserving existing user when user arg empty", func(t *testing.T) {
		orig := "Host my-vm\n    HostName 10.0.0.1\n    User existing-user\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n    HostName 10.0.0.1\n    User existing-user\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("updates existing host block replacing existing user when explicit user provided", func(t *testing.T) {
		orig := "Host my-vm\n    HostName 10.0.0.1\n    User existing-user\n    User duplicate-user\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "ubuntu", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n    HostName 10.0.0.1\n    User ubuntu\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("inserts user directive when updating existing host block without user", func(t *testing.T) {
		orig := "Host my-vm\n    HostName 10.0.0.1\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "ubuntu", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n    User ubuntu\n    HostName 10.0.0.1\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("preserves two-space indentation if present in block", func(t *testing.T) {
		orig := "Host my-vm\n  HostName 192.168.1.50\n  User admin\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\n  HostName 192.168.1.50\n  User admin\n  # Added by dtfm ssh-config\n  RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n  StreamLocalBindUnlink yes\n"
		if got != expected {
			t.Fatalf("expected:\n%q\ngot:\n%q", expected, got)
		}
	})

	t.Run("idempotent update when snippet already present", func(t *testing.T) {
		orig := "Host my-vm\n    HostName 192.168.1.50\n    User admin\n    # Added by dtfm ssh-config\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != orig {
			t.Fatalf("expected idempotent result identical to original, got:\n%s", got)
		}

		origWithHeader := "# Added by dtfm ssh-config\nHost my-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		gotWithHeader, err := UpdateSSHConfig(origWithHeader, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotWithHeader != origWithHeader {
			t.Fatalf("expected idempotent result with header identical to original, got:\n%s", gotWithHeader)
		}
	})

	t.Run("preserves CRLF line endings", func(t *testing.T) {
		orig := "Host my-vm\r\n    HostName 192.168.1.50\r\n"
		got, err := UpdateSSHConfig(orig, "my-vm", "", 1000, "/home/ivan/.lmdtfy.sock")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "Host my-vm\r\n    HostName 192.168.1.50\r\n    # Added by dtfm ssh-config\r\n    RemoteForward /run/user/1000/lmdtfy.sock /home/ivan/.lmdtfy.sock\r\n    StreamLocalBindUnlink yes\r\n"
		if got != expected {
			t.Fatalf("expected CRLF output:\n%q\ngot:\n%q", expected, got)
		}
	})
}

func TestWriteSSHConfigFile(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "subdir", "config")
	content := "Host test-host\n    RemoteForward /run/user/1000/lmdtfy.sock /local.sock\n    StreamLocalBindUnlink yes\n"

	// 1. Initial write to non-existent directory
	if err := WriteSSHConfigFile(configPath, content); err != nil {
		t.Fatalf("WriteSSHConfigFile failed: %v", err)
	}

	fi, err := os.Stat(configPath)
	if err != nil {
		t.Fatalf("stat failed on created config: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected permissions 0600, got %04o", perm)
	}

	parentDir := filepath.Dir(configPath)
	dirFi, err := os.Stat(parentDir)
	if err != nil {
		t.Fatalf("stat failed on parent directory: %v", err)
	}
	if perm := dirFi.Mode().Perm(); perm != 0700 {
		t.Fatalf("expected parent dir permissions 0700, got %04o", perm)
	}

	// 2. Symlink preservation
	dotfilesTarget := filepath.Join(tempDir, "dotfiles", "ssh-config")
	_ = os.MkdirAll(filepath.Dir(dotfilesTarget), 0700)
	if err := os.WriteFile(dotfilesTarget, []byte("# dotfile content\n"), 0600); err != nil {
		t.Fatalf("failed to write dotfile target: %v", err)
	}
	symlinkPath := filepath.Join(tempDir, "symlink-config")
	if err := os.Symlink(dotfilesTarget, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	newSymContent := "# updated dotfile\nHost sym-host\n"
	if err := WriteSSHConfigFile(symlinkPath, newSymContent); err != nil {
		t.Fatalf("failed to write through symlink: %v", err)
	}

	lfi, err := os.Lstat(symlinkPath)
	if err != nil || lfi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink was destroyed and replaced with regular file: %v", err)
	}

	data, err := os.ReadFile(dotfilesTarget)
	if err != nil || string(data) != newSymContent {
		t.Fatalf("dotfiles target content mismatch: %q, err: %v", string(data), err)
	}

	// 3. Dangling symlink returns error
	danglingPath := filepath.Join(tempDir, "dangling-symlink")
	_ = os.Symlink(filepath.Join(tempDir, "nonexistent-target"), danglingPath)
	if err := WriteSSHConfigFile(danglingPath, content); err == nil {
		t.Fatalf("expected error when writing to dangling symlink, got nil")
	}

	// 4. Directory target rejected
	dirTarget := filepath.Join(tempDir, "target-is-dir")
	if err := os.MkdirAll(dirTarget, 0700); err != nil {
		t.Fatalf("failed to create dir target: %v", err)
	}
	if err := WriteSSHConfigFile(dirTarget, content); err == nil {
		t.Fatalf("expected error when writing to directory target, got nil")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected not a regular file error, got %v", err)
	}

	// 5. Symlink to directory rejected
	symlinkToDir := filepath.Join(tempDir, "symlink-to-dir")
	if err := os.Symlink(dirTarget, symlinkToDir); err != nil {
		t.Fatalf("failed to create symlink to dir: %v", err)
	}
	if err := WriteSSHConfigFile(symlinkToDir, content); err == nil {
		t.Fatalf("expected error when writing to symlink pointing to dir, got nil")
	} else if !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected not a regular file error, got %v", err)
	}
}

func TestRunSSHConfig(t *testing.T) {
	mockQuerier := func(uid uint32, err error) UIDQuerier {
		return func(ctx context.Context, target string) (uint32, error) {
			return uid, err
		}
	}

	t.Run("missing host argument returns 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunSSHConfig([]string{}, &stdout, &stderr, SSHConfigOptions{Querier: mockQuerier(1000, nil)})
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
		if !strings.Contains(stderr.String(), "host argument is required") {
			t.Fatalf("expected missing host error in stderr, got: %s", stderr.String())
		}
	})

	t.Run("help flag returns 0 and prints usage", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunSSHConfig([]string{"--help"}, &stdout, &stderr, SSHConfigOptions{})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Usage: dtfm ssh-config <host>") {
			t.Fatalf("expected usage in stdout, got: %s", stdout.String())
		}
	})

	t.Run("invalid host starting with dash returns 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunSSHConfig([]string{"-oProxyCommand=touch /tmp/evil"}, &stdout, &stderr, SSHConfigOptions{})
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
	})

	t.Run("empty --socket or --config returns 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := RunSSHConfig([]string{"my-vm", "--socket", "  "}, &stdout, &stderr, SSHConfigOptions{})
		if code != 1 {
			t.Fatalf("expected exit code 1 for empty socket, got %d", code)
		}

		stdout.Reset()
		stderr.Reset()
		code = RunSSHConfig([]string{"my-vm", "--config="}, &stdout, &stderr, SSHConfigOptions{})
		if code != 1 {
			t.Fatalf("expected exit code 1 for empty config, got %d", code)
		}
	})

	t.Run("querier connection error reports clear message and returns 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		querier := mockQuerier(0, fmt.Errorf("ssh: connect to host bad-host.example port 22: Connection timed out"))
		code := RunSSHConfig([]string{"bad-host.example"}, &stdout, &stderr, SSHConfigOptions{Querier: querier})
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
		if !strings.Contains(stderr.String(), "Connection timed out") {
			t.Fatalf("expected connection timeout message in stderr, got: %s", stderr.String())
		}
	})

	t.Run("success without write prints snippet to stdout without touching file", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "config")

		code := RunSSHConfig([]string{"prod-vm", "--socket", "/custom/sock.sock"}, &stdout, &stderr, SSHConfigOptions{
			Querier:    mockQuerier(1000, nil),
			ConfigPath: configFile,
		})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
		}

		expectedSnippet := "# Added by dtfm ssh-config\nHost prod-vm\n    RemoteForward /run/user/1000/lmdtfy.sock /custom/sock.sock\n    StreamLocalBindUnlink yes\n"
		if stdout.String() != expectedSnippet {
			t.Fatalf("expected snippet:\n%q\ngot:\n%q", expectedSnippet, stdout.String())
		}

		if _, err := os.Stat(configFile); !os.IsNotExist(err) {
			t.Fatalf("config file should not have been created without --write")
		}
	})

	t.Run("success with --write updates file with strict 0600", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "config")

		code := RunSSHConfig([]string{"prod-vm", "--write", "--socket", "/home/user/.lmdtfy.sock", "--config", configFile}, &stdout, &stderr, SSHConfigOptions{
			Querier: mockQuerier(1001, nil),
		})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
		}

		expectedSnippet := "# Added by dtfm ssh-config\nHost prod-vm\n    RemoteForward /run/user/1001/lmdtfy.sock /home/user/.lmdtfy.sock\n    StreamLocalBindUnlink yes\n"
		if stdout.String() != expectedSnippet {
			t.Fatalf("expected snippet in stdout:\n%q\ngot:\n%q", expectedSnippet, stdout.String())
		}

		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("failed to read updated config file: %v", err)
		}
		if string(data) != expectedSnippet {
			t.Fatalf("file content mismatch: expected %q, got %q", expectedSnippet, string(data))
		}

		fi, err := os.Stat(configFile)
		if err != nil {
			t.Fatalf("failed to stat config file: %v", err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Fatalf("expected file permission 0600, got %04o", fi.Mode().Perm())
		}

		if !strings.Contains(stderr.String(), "Configuration written to") {
			t.Fatalf("expected confirmation in stderr, got: %s", stderr.String())
		}
	})

	t.Run("handles -w flag positioned after host", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "config")

		code := RunSSHConfig([]string{"server1", "-w", "--config", configFile, "--socket", "/s.sock"}, &stdout, &stderr, SSHConfigOptions{
			Querier: mockQuerier(1000, nil),
		})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
		}

		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("failed to read file: %v", err)
		}
		if !strings.Contains(string(data), "Host server1") {
			t.Fatalf("expected 'Host server1' in file, got: %s", string(data))
		}
	})

	t.Run("handles user@host syntax: queries user@host and writes User directive", func(t *testing.T) {
		var queriedTarget string
		spyQuerier := func(ctx context.Context, target string) (uint32, error) {
			queriedTarget = target
			return 1000, nil
		}

		var stdout, stderr bytes.Buffer
		tempDir := t.TempDir()
		configFile := filepath.Join(tempDir, "config")

		code := RunSSHConfig([]string{"ubuntu@remote-server", "--write", "--config", configFile, "--socket", "/s.sock"}, &stdout, &stderr, SSHConfigOptions{
			Querier: spyQuerier,
		})
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d. stderr: %s", code, stderr.String())
		}

		if queriedTarget != "ubuntu@remote-server" {
			t.Fatalf("expected querier to be called with 'ubuntu@remote-server', got %q", queriedTarget)
		}

		data, err := os.ReadFile(configFile)
		if err != nil {
			t.Fatalf("failed to read config: %v", err)
		}
		if !strings.Contains(string(data), "Host remote-server\n") {
			t.Fatalf("expected 'Host remote-server' in config, got:\n%s", string(data))
		}
		if !strings.Contains(string(data), "User ubuntu\n") {
			t.Fatalf("expected 'User ubuntu' in config, got:\n%s", string(data))
		}
	})
}

func TestParseRemoteUID(t *testing.T) {
	tests := []struct {
		name      string
		rawOutput string
		expectUID uint32
		expectErr bool
	}{
		{"standard uid", "1000\n", 1000, false},
		{"root uid", "0", 0, false},
		{"ldap uid with whitespace", "  50012 \r\n", 50012, false},
		{"motd banner preceding uid", "Welcome to Ubuntu 24.04 LTS\nLast login: Mon Nov 11 08:00:00 2026\n1000\n", 1000, false},
		{"empty output", "", 0, true},
		{"whitespace only", "   \n\t  ", 0, true},
		{"non-numeric error message", "bash: id: command not found", 0, true},
		{"negative number", "-1", 0, true},
		{"max uint32 minus 1 is valid", fmt.Sprintf("%d\n", uint64(math.MaxUint32-1)), math.MaxUint32 - 1, false},
		{"max uint32 rejected", fmt.Sprintf("%d\n", uint64(math.MaxUint32)), 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid, err := parseRemoteUID("test-target", tc.rawOutput)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for %q, got uid %d", tc.rawOutput, uid)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %q: %v", tc.rawOutput, err)
				}
				if uid != tc.expectUID {
					t.Fatalf("expected UID %d, got %d", tc.expectUID, uid)
				}
			}
		})
	}
}

func TestDefaultUIDQuerier_FakeSSH(t *testing.T) {
	tempDir := t.TempDir()
	recordFile := filepath.Join(tempDir, "record.txt")
	fakeSSHPath := filepath.Join(tempDir, "ssh")

	script := fmt.Sprintf(`#!/bin/sh
echo "$@" > %q
if [ "$SSH_SIM_EXIT" != "" ]; then
    printf "%%b" "$SSH_SIM_STDERR" >&2
    exit "$SSH_SIM_EXIT"
fi
if [ "$SSH_SIM_SLEEP" != "" ]; then
    sleep "$SSH_SIM_SLEEP"
fi
if [ "$SSH_SIM_STDOUT" != "" ]; then
    printf "%%b" "$SSH_SIM_STDOUT"
else
    echo "1000"
fi
`, recordFile)

	if err := os.WriteFile(fakeSSHPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create fake ssh script: %v", err)
	}

	// Prepend tempDir to PATH
	origPath := os.Getenv("PATH")
	t.Setenv("PATH", tempDir+string(filepath.ListSeparator)+origPath)

	t.Run("verifies flags passed to ssh", func(t *testing.T) {
		_ = os.Remove(recordFile)
		ctx := context.Background()
		uid, err := DefaultUIDQuerier(ctx, "dev-target")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if uid != 1000 {
			t.Fatalf("expected uid 1000, got %d", uid)
		}

		recorded, err := os.ReadFile(recordFile)
		if err != nil {
			t.Fatalf("failed to read recorded args: %v", err)
		}
		rec := string(recorded)
		for _, required := range []string{
			"-T",
			"-o ConnectTimeout=15",
			"-o ClearAllForwardings=yes",
			"-o ControlMaster=no",
			"-o ControlPersist=no",
			"-- dev-target id -u",
		} {
			if !strings.Contains(rec, required) {
				t.Errorf("missing expected flag/arg %q in ssh invocation: %s", required, rec)
			}
		}
	})

	t.Run("sanitizes ANSI escapes in remote stderr", func(t *testing.T) {
		t.Setenv("SSH_SIM_EXIT", "255")
		t.Setenv("SSH_SIM_STDERR", "\x1b[31mHost down\x1b[0m\x1b]0;hacked\x07")

		ctx := context.Background()
		_, err := DefaultUIDQuerier(ctx, "dev-target")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		errMsg := err.Error()
		if strings.Contains(errMsg, "\x1b[31m") || strings.Contains(errMsg, "\x1b]0;") {
			t.Fatalf("raw ANSI escapes were not sanitized in error: %q", errMsg)
		}
		if !strings.Contains(errMsg, "Host down") {
			t.Fatalf("expected sanitized error message, got: %q", errMsg)
		}
	})

	t.Run("timeout handling", func(t *testing.T) {
		t.Setenv("SSH_SIM_SLEEP", "5")
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()

		_, err := DefaultUIDQuerier(ctx, "dev-target")
		if err == nil {
			t.Fatal("expected timeout error, got nil")
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected timeout in error, got: %v", err)
		}
	})
}

func TestMain_Run(t *testing.T) {
	t.Run("-help and --help exit 0 and print usage to stdout", func(t *testing.T) {
		for _, flag := range []string{"-help", "--help", "-h", "help"} {
			var stdout, stderr bytes.Buffer
			code := run([]string{"dtfm", flag}, &stdout, &stderr)
			if code != 0 {
				t.Errorf("flag %q: expected exit code 0, got %d", flag, code)
			}
			if !strings.Contains(stdout.String(), "Usage:") {
				t.Errorf("flag %q: expected usage in stdout, got %q", flag, stdout.String())
			}
		}
	})

	t.Run("unknown subcommand reports error and exits 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"dtfm", "unknown-subcommand"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
		if !strings.Contains(stderr.String(), "unknown command \"unknown-subcommand\"") {
			t.Fatalf("expected unknown command error in stderr, got: %s", stderr.String())
		}
	})

	t.Run("ssh-config -help exits 0", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"dtfm", "ssh-config", "-help"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}
		if !strings.Contains(stdout.String(), "Usage: dtfm ssh-config <host>") {
			t.Fatalf("expected ssh-config usage in stdout, got: %s", stdout.String())
		}
	})

	t.Run("-h flag prints usage to stdout once without duplicate on stderr", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"dtfm", "--socket", "/tmp/s.sock", "-h"}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("expected exit code 0, got %d", code)
		}
		if stderr.String() != "" {
			t.Fatalf("expected empty stderr, got: %q", stderr.String())
		}
		if count := strings.Count(stdout.String(), "Start dtfm operator server"); count != 1 {
			t.Fatalf("expected usage exactly once in stdout, got %d times:\n%s", count, stdout.String())
		}
	})

	t.Run("invalid flag prints usage to stderr and exits 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"dtfm", "--invalid-nonexistent-flag"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("expected exit code 1, got %d", code)
		}
		if stdout.String() != "" {
			t.Fatalf("expected empty stdout, got: %q", stdout.String())
		}
		if !strings.Contains(stderr.String(), "Start dtfm operator server") {
			t.Fatalf("expected usage in stderr, got: %q", stderr.String())
		}
	})
}

func TestSSHConfig_GrammarValidationWithSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh binary not available on PATH; skipping grammar validation")
	}

	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config")

	origContent := "Host other-host\n    HostName 10.0.0.1\n"
	updated, err := UpdateSSHConfig(origContent, "my-vm", "ubuntu", 1000, "/tmp/John Doe/%%test%%/.lmdtfy.sock")
	if err != nil {
		t.Fatalf("UpdateSSHConfig failed: %v", err)
	}

	if err := os.WriteFile(configPath, []byte(updated), 0600); err != nil {
		t.Fatalf("failed to write config: %v", err)
	}

	cmd := exec.Command("ssh", "-F", configPath, "-G", "my-vm")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("OpenSSH failed to parse generated config (exit: %v): %s\nGenerated content:\n%s", err, string(out), updated)
	}

	outStr := string(out)
	if !strings.Contains(outStr, "remoteforward /run/user/1000/lmdtfy.sock /tmp/John Doe/%%test%%/.lmdtfy.sock") {
		t.Fatalf("expected remoteforward in ssh -G output, got:\n%s", outStr)
	}
	if !strings.Contains(outStr, "user ubuntu") {
		t.Fatalf("expected user ubuntu in ssh -G output, got:\n%s", outStr)
	}
}

func TestDefaultUIDQuerier_PTYBackground(t *testing.T) {
	tempDir := t.TempDir()
	fakeSSHPath := filepath.Join(tempDir, "ssh")
	script := "#!/bin/sh\necho 1000\n"
	if err := os.WriteFile(fakeSSHPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create fake ssh: %v", err)
	}

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"TEST_UID_QUERIER_HELPER=leader_bg",
		"PATH="+tempDir+string(filepath.ListSeparator)+os.Getenv("PATH"),
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("PTY start failed (environment may not support PTY): %v", err)
	}
	defer ptmx.Close()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("background child process exited with error: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("background child hung (SIGTTOU deadlock regression!)")
	}
}

func TestDefaultUIDQuerier_PTYForegroundRestore(t *testing.T) {
	tempDir := t.TempDir()
	fakeSSHPath := filepath.Join(tempDir, "ssh")
	// Fake ssh disables echo on /dev/tty then outputs 1000
	script := "#!/bin/sh\nstty -F /dev/tty -echo 2>/dev/null || stty -echo 2>/dev/null\necho 1000\n"
	if err := os.WriteFile(fakeSSHPath, []byte(script), 0755); err != nil {
		t.Fatalf("failed to create fake ssh: %v", err)
	}

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		"TEST_UID_QUERIER_HELPER=fg_worker",
		"PATH="+tempDir+string(filepath.ListSeparator)+os.Getenv("PATH"),
	)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		t.Skipf("PTY start failed (environment may not support PTY): %v", err)
	}
	defer ptmx.Close()

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("foreground child process failed (ECHO was not restored): %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("foreground child hung")
	}
}
