package protocol

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	// Regex for characters safe without shell quoting in POSIX shells.
	// Disallows leading '=' to avoid expansion ambiguity in shells like zsh (=rm).
	safeShellArg = regexp.MustCompile(`^[a-zA-Z0-9_./@:-][a-zA-Z0-9_./@:=-]*$`)

	// Valid POSIX environment variable identifier (no '=', NUL, or whitespace).
	validEnvKey = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

	// Exact blocked environment variables (case-insensitive).
	blockedEnvExact = map[string]bool{
		"BASH_ENV":           true,
		"ENV":                true,
		"SHELLOPTS":          true,
		"BASHOPTS":           true,
		"BASH_OPTS":          true,
		"PROMPT_COMMAND":     true,
		"PATH":               true,
		"IFS":                true,
		"PYTHONPATH":         true,
		"PYTHONSTARTUP":      true,
		"PYTHONHOME":         true,
		"JAVA_TOOL_OPTIONS":  true,
		"_JAVA_OPTIONS":      true,
		"PERL5LIB":           true,
		"PERL5OPT":           true,
		"PERLLIB":            true,
		"RUBYLIB":            true,
		"RUBYOPT":            true,
		"NODE_OPTIONS":       true,
		"NODE_PATH":          true,
		"GCONV_PATH":         true,
		"CDPATH":             true,
		"ZDOTDIR":            true,
		"HOME":               true,
		"LESSOPEN":           true,
		"EDITOR":             true,
		"VISUAL":             true,
		"PAGER":              true,
		"OPENSSL_CONF":       true,
		"SUDO_ASKPASS":       true,
		"SSH_ASKPASS":        true,
		"GOFLAGS":            true,
		"SSL_CERT_FILE":      true,
		"CURL_CA_BUNDLE":     true,
		"REQUESTS_CA_BUNDLE": true,
		"KUBECONFIG":         true,
		"DOCKER_HOST":        true,
		"HTTP_PROXY":         true,
		"HTTPS_PROXY":        true,
		"ALL_PROXY":          true,
		"NO_PROXY":           true,
	}

	// Blocked environment variable prefixes (case-insensitive).
	blockedEnvPrefixes = []string{
		"LD_",
		"DYLD_",
		"BASH_FUNC_", // Shellshock-style bash function export
		"GIT_",       // GIT_SSH_COMMAND, GIT_ASKPASS, GIT_EXEC_PATH, GIT_CONFIG_*
		"NPM_CONFIG_",
		"DOCKER_",
		"AWS_",
	}
)

func escapeRune(b *strings.Builder, r rune) {
	switch {
	case r == '\x1b':
		b.WriteString(`\x1b`)
	case r == '\n':
		b.WriteString(`\n`)
	case r == '\r':
		b.WriteString(`\r`)
	case r == '\t':
		b.WriteString(`\t`)
	case r == '\a':
		b.WriteString(`\a`)
	case r == '\b':
		b.WriteString(`\b`)
	case r == '\v':
		b.WriteString(`\v`)
	case r == '\f':
		b.WriteString(`\f`)
	case r == '\\':
		b.WriteString(`\\`)
	case r < 32 || r == 127:
		fmt.Fprintf(b, `\x%02x`, r)
	case r > 0xFFFF:
		// Bash ANSI-C $'...' requires \U followed by 8 hex digits for non-BMP runes
		fmt.Fprintf(b, `\U%08x`, r)
	default:
		// BMP runes (including NBSP U+00A0, bidi overrides, etc.)
		fmt.Fprintf(b, `\u%04x`, r)
	}
}

// isBidiOverride checks for Unicode bidirectional override characters.
func isBidiOverride(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

// needsEscape returns true if rune r requires escaping to be safely displayed on a terminal.
// Explicit checks for control codes, NBSP, bidirectional overrides, combining marks,
// formatting/variation selectors, and invisible blank fillers prevent visual spoofing.
func needsEscape(r rune) bool {
	return r < 32 || r == 127 || r == 0x00A0 || isBidiOverride(r) || !unicode.IsPrint(r) ||
		unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) ||
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) ||
		r == 0x034F || r == 0x115F || r == 0x1160 || r == 0x2800 || r == 0x3164 || r == 0xFFA0
}

// SanitizeTerminalText makes arbitrary text safe to print to an operator's terminal
// WITHOUT DELETING ANY BYTES (WYSIWYG preservation). Escape codes (\x1b) are visibly
// escaped so an agent cannot hide commands or spoof the prompt.
func SanitizeTerminalText(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid UTF-8 byte
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		i += size

		switch {
		case r == '\x1b' || r == '\n' || r == '\r' || r == '\t' || r == '\a' || r == '\b' || r == '\v' || r == '\f' || r == '\\':
			escapeRune(&b, r)
		case needsEscape(r):
			escapeRune(&b, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// needsAnsiCQuote returns true if string contains control characters, newlines,
// escapes, or non-printable/bidi runes (like NBSP) that require bash/zsh ANSI-C $'...' quoting.
func needsAnsiCQuote(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return true
		}
		i += size
		if r == '\x1b' || needsEscape(r) {
			return true
		}
	}
	return false
}

// ShellQuote quotes an argument so it is unambiguously displayed and valid copy-pasteable shell syntax.
// - Safe alphanumeric strings are printed directly.
// - Normal strings needing quoting use POSIX single-quotes: '...'
// - Strings with control characters, escapes, newlines, or non-printable runes use ANSI-C quoting: $'...'
// Crucially, NO BYTES ARE EVER DELETED.
func ShellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if safeShellArg.MatchString(arg) {
		return arg
	}

	if needsAnsiCQuote(arg) {
		var b strings.Builder
		b.WriteString("$'")
		for i := 0; i < len(arg); {
			r, size := utf8.DecodeRuneInString(arg[i:])
			if r == utf8.RuneError && size == 1 {
				fmt.Fprintf(&b, `\x%02x`, arg[i])
				i++
				continue
			}
			i += size

			if r == '\'' {
				b.WriteString(`\'`)
			} else if r == '\\' {
				b.WriteString(`\\`)
			} else if r == '\x1b' || r == '\n' || r == '\r' || r == '\t' || r == '\a' || r == '\b' || r == '\v' || r == '\f' {
				escapeRune(&b, r)
			} else if needsEscape(r) {
				escapeRune(&b, r)
			} else {
				b.WriteRune(r)
			}
		}
		b.WriteString("'")
		return b.String()
	}

	// Standard POSIX single-quote format
	return "'" + strings.ReplaceAll(arg, "'", `'\''`) + "'"
}

// FormatCommand formats a command and its arguments into an unambiguous, lossless shell string.
// If the command contains '=' (e.g. DRY_RUN=1), it is always quoted to avoid looking like a shell assignment prefix.
// No bytes from the arguments are ever deleted or stripped.
func FormatCommand(command string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	cmdQuoted := ShellQuote(command)
	if strings.Contains(command, "=") && !strings.HasPrefix(cmdQuoted, "'") && !strings.HasPrefix(cmdQuoted, "$'") {
		cmdQuoted = "'" + strings.ReplaceAll(command, "'", `'\''`) + "'"
	}
	parts = append(parts, cmdQuoted)
	for _, arg := range args {
		parts = append(parts, ShellQuote(arg))
	}
	return strings.Join(parts, " ")
}

// IsDangerousEnv returns true if the environment variable name poses a security risk
// or is not a valid POSIX environment identifier.
func IsDangerousEnv(key string) bool {
	if !validEnvKey.MatchString(key) {
		// Reject any keys with '=', NUL, dashes, or non-identifier characters
		return true
	}

	upper := strings.ToUpper(key)
	if blockedEnvExact[upper] {
		return true
	}
	for _, prefix := range blockedEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// SanitizeEnv classifies and sanitizes environment variables for display purposes only.
// It MUST NOT be used as an allowlist to pass untrusted environment variables to subprocesses.
func SanitizeEnv(env map[string]string) (clean map[string]string, blocked []string) {
	clean = make(map[string]string, len(env))
	var blockedList []string

	for k, v := range env {
		if IsDangerousEnv(k) {
			blockedList = append(blockedList, k)
		} else {
			clean[k] = v
		}
	}

	sort.Strings(blockedList)
	return clean, blockedList
}
