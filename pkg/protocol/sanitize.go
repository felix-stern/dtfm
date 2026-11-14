// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

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

// IsBidiOverride checks for Unicode bidirectional override characters.
func IsBidiOverride(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

// NeedsEscape returns true if rune r requires escaping to be safely displayed on a terminal.
// Explicit checks for control codes, NBSP, bidirectional overrides, combining marks,
// formatting/variation selectors, and invisible blank fillers prevent visual spoofing.
func NeedsEscape(r rune) bool {
	return r < 32 || r == 127 || r == 0x00A0 || IsBidiOverride(r) || !unicode.IsPrint(r) ||
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
		case NeedsEscape(r):
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
		if r == '\x1b' || NeedsEscape(r) {
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
			} else if NeedsEscape(r) {
				if r >= 0x80 {
					var buf [utf8.UTFMax]byte
					n := utf8.EncodeRune(buf[:], r)
					for j := 0; j < n; j++ {
						fmt.Fprintf(&b, `\x%02x`, buf[j])
					}
				} else {
					escapeRune(&b, r)
				}
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

// SanitizeBannerCommand sanitizes text printed in the execution banner (e.g. opts.ModifiedCommand)
// by escaping control characters, bidi overrides, C1 controls, invisible runes, and formatting characters
// to prevent terminal manipulation, while preserving normal backslashes and printable characters.
func SanitizeBannerCommand(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, s[i])
			i++
			continue
		}
		i += size

		switch {
		case r == '\\':
			b.WriteRune('\\')
		case r == '\x1b' || r == '\n' || r == '\r' || r == '\t' || r == '\a' || r == '\b' || r == '\v' || r == '\f':
			escapeRune(&b, r)
		case NeedsEscape(r):
			escapeRune(&b, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// QuoteCommandName quotes argv[0] so that a binary name containing '=' (e.g. DRY_RUN=1)
// is always quoted and never resembles a shell environment assignment prefix.
func QuoteCommandName(command string) string {
	cmdQuoted := ShellQuote(command)
	if strings.Contains(command, "=") && !strings.HasPrefix(cmdQuoted, "'") && !strings.HasPrefix(cmdQuoted, "$'") {
		cmdQuoted = "'" + strings.ReplaceAll(command, "'", `'\''`) + "'"
	}
	return cmdQuoted
}

// FormatCommand formats a command and its arguments into an unambiguous, lossless shell string.
// If the command contains '=' (e.g. DRY_RUN=1), it is always quoted to avoid looking like a shell assignment prefix.
// No bytes from the arguments are ever deleted or stripped.
func FormatCommand(command string, args []string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, QuoteCommandName(command))
	for _, arg := range args {
		parts = append(parts, ShellQuote(arg))
	}
	return strings.Join(parts, " ")
}

// CommandToken describes a single argv element (Index 0 for Command, Index >= 1 for Args)
// classified in a single pass for header badges and multiline gutter rendering.
type CommandToken struct {
	Index     int    // 0 for Command, 1..len(Args) for Args
	Label     string // "cmd" for Index 0, "arg[i]" for Index >= 1
	Raw       string // Original unquoted token string
	Quoted    string // Single-line shell-quoted token (populated when !Multiline)
	Badge     string // Compact multiline placeholder e.g. "‹arg[2]: 37 lines›" (populated when Multiline)
	LineCount int    // Number of '\n'-delimited lines (>= 2 when Multiline, 1 otherwise)
	Multiline bool   // True iff Raw contains '\n'
}

// InspectCommandTokens classifies command and args into display tokens in a single pass,
// sharing badge formatting between FormatCompactCommand and TerminalPrompter.
// Note that a literal single-line argument containing "‹arg[2]: 4 lines›" is quoted via
// ShellQuote ("'‹arg[2]: 4 lines›'"), keeping it strictly distinct from an unquoted Badge.
func InspectCommandTokens(command string, args []string) (tokens []CommandToken, multilineCount int) {
	tokens = make([]CommandToken, 0, len(args)+1)
	addToken := func(idx int, raw string) {
		label := "cmd"
		if idx > 0 {
			label = fmt.Sprintf("arg[%d]", idx)
		}
		if nl := strings.Count(raw, "\n"); nl > 0 {
			multilineCount++
			lines := nl + 1
			tokens = append(tokens, CommandToken{
				Index:     idx,
				Label:     label,
				Raw:       raw,
				Badge:     fmt.Sprintf("‹%s: %d lines›", label, lines),
				LineCount: lines,
				Multiline: true,
			})
			return
		}
		quoted := ShellQuote(raw)
		if idx == 0 {
			quoted = QuoteCommandName(raw)
		}
		tokens = append(tokens, CommandToken{
			Index:     idx,
			Label:     label,
			Raw:       raw,
			Quoted:    quoted,
			LineCount: 1,
		})
	}

	addToken(0, command)
	for i, arg := range args {
		addToken(i+1, arg)
	}
	return tokens, multilineCount
}

// HasMultilineArgs reports whether command or any element of args contains a newline ('\n').
func HasMultilineArgs(command string, args []string) bool {
	if strings.Contains(command, "\n") {
		return true
	}
	for _, arg := range args {
		if strings.Contains(arg, "\n") {
			return true
		}
	}
	return false
}

// FormatCompactTokens joins pre-inspected CommandTokens into a compact single-line summary,
// replacing any multiline token with its line-count badge while shell-quoting single-line tokens.
func FormatCompactTokens(tokens []CommandToken) string {
	parts := make([]string, len(tokens))
	for i, tok := range tokens {
		if tok.Multiline {
			parts[i] = tok.Badge
		} else {
			parts[i] = tok.Quoted
		}
	}
	return strings.Join(parts, " ")
}

// FormatCompactCommand formats single-line invocations identically to FormatCommand,
// while replacing any multiline command/argument token with a concise line-count badge
// (e.g. "bash -c ‹arg[2]: 37 lines›") suitable for compact headers and execution banners.
func FormatCompactCommand(command string, args []string) string {
	tokens, _ := InspectCommandTokens(command, args)
	return FormatCompactTokens(tokens)
}

// SanitizeDisplayLine sanitizes a single line of a multiline argument for gutter-boxed terminal display.
// Because this output is used strictly for human review display (while [e] inline edit uses lossless
// FormatCommand $'...' quoting and direct execution passes the original req.Command / req.Args slice to execvp),
// printable characters — including single/double quotes and literal backslashes — render naturally without
// $'...' quoting noise, and tabs expand to 4 spaces to avoid right-margin VT100 tab truncation.
// Every control code, carriage return, ANSI escape, invalid UTF-8 byte, and Trojan Source bidi/invisible rune
// matched by NeedsEscape is visibly escaped (optionally wrapped by highlightEscape, e.g. bold red on TTYs).
func SanitizeDisplayLine(line string, highlightEscape func(string) string) string {
	styled, _ := SanitizeDisplayLinePair(line, highlightEscape)
	return styled
}

// SanitizeDisplayLinePair performs a single-pass sanitization of line, returning both the styled line
// (with escaped sequences wrapped by highlightEscape when non-nil) and the plain unstyled sanitized line.
func SanitizeDisplayLinePair(line string, highlightEscape func(string) string) (styled string, plain string) {
	var styledBuf strings.Builder
	var plainBuf strings.Builder
	var escBuf strings.Builder
	hasStyledEscape := false

	writePlainText := func(s string) {
		styledBuf.WriteString(s)
		if hasStyledEscape {
			plainBuf.WriteString(s)
		}
	}
	writePlainRune := func(r rune) {
		styledBuf.WriteRune(r)
		if hasStyledEscape {
			plainBuf.WriteRune(r)
		}
	}
	writeEsc := func(esc string) {
		if highlightEscape != nil {
			wrapped := highlightEscape(esc)
			if wrapped != esc {
				if !hasStyledEscape {
					hasStyledEscape = true
					plainBuf.WriteString(styledBuf.String())
				}
				styledBuf.WriteString(wrapped)
				plainBuf.WriteString(esc)
				return
			}
		}
		writePlainText(esc)
	}

	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		if r == utf8.RuneError && size == 1 {
			writeEsc(fmt.Sprintf(`\x%02x`, line[i]))
			i++
			continue
		}
		i += size

		switch {
		case r == '\t':
			writePlainText("    ")
		case NeedsEscape(r):
			escBuf.Reset()
			escapeRune(&escBuf, r)
			writeEsc(escBuf.String())
		default:
			writePlainRune(r)
		}
	}

	styled = styledBuf.String()
	if hasStyledEscape {
		return styled, plainBuf.String()
	}
	return styled, styled
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
