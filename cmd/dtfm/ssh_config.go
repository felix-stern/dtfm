// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
	"golang.org/x/sys/unix"
)

// UIDQuerier resolves the remote numeric UID of an SSH target.
type UIDQuerier func(ctx context.Context, sshTarget string) (uint32, error)

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func newLimitedBuffer(limit int) *limitedBuffer {
	return &limitedBuffer{limit: limit}
}

func (lb *limitedBuffer) Write(p []byte) (n int, err error) {
	if lb.buf.Len() >= lb.limit {
		return len(p), nil
	}
	remaining := lb.limit - lb.buf.Len()
	if len(p) > remaining {
		n, _ = lb.buf.Write(p[:remaining])
		return len(p), nil
	}
	return lb.buf.Write(p)
}

func (lb *limitedBuffer) String() string {
	return lb.buf.String()
}

// DefaultUIDQuerier executes `ssh -T -o ConnectTimeout=15 -o ClearAllForwardings=yes -o ControlMaster=no -o ControlPersist=no -- <target> id -u`
// to determine the remote numeric UID.
func DefaultUIDQuerier(ctx context.Context, sshTarget string) (uint32, error) {
	if _, _, err := validateSSHTarget(sshTarget); err != nil {
		return 0, err
	}

	if _, err := exec.LookPath("ssh"); err != nil {
		return 0, fmt.Errorf("ssh executable not found in PATH: %w", err)
	}

	cmd := exec.CommandContext(ctx, "ssh",
		"-T",
		"-o", "ConnectTimeout=15",
		"-o", "ClearAllForwardings=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPersist=no",
		"--", sshTarget, "id -u")
	cmd.Stdin = os.Stdin
	cmd.Cancel = func() error {
		if cmd.Process != nil {
			return cmd.Process.Signal(syscall.SIGTERM)
		}
		return nil
	}
	cmd.WaitDelay = 3 * time.Second

	stdoutBuf := newLimitedBuffer(64 * 1024)
	stderrBuf := newLimitedBuffer(64 * 1024)
	cmd.Stdout = stdoutBuf
	cmd.Stderr = stderrBuf

	// Save and restore /dev/tty termios settings only if /dev/tty is available and dtfm is in the foreground
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		var origTermios *termiosState
		if fg, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP); err == nil && fg == syscall.Getpgrp() {
			if t, err := getTermios(tty.Fd()); err == nil {
				origTermios = t
			}
		}
		if origTermios != nil {
			defer func() {
				fgNow, err := unix.IoctlGetInt(int(tty.Fd()), unix.TIOCGPGRP)
				if err == nil && fgNow == syscall.Getpgrp() {
					if cur, err := getTermios(tty.Fd()); err == nil && cur != nil && *cur != *origTermios {
						signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
						defer signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
						_ = restoreTermios(tty.Fd(), origTermios)
					}
				}
			}()
		}
	}

	runErr := cmd.Run()
	errMsg := protocol.SanitizeTerminalText(strings.TrimSpace(stderrBuf.String()))

	if ctx.Err() != nil {
		if errMsg != "" {
			return 0, fmt.Errorf("ssh connection to %s timed out: %w (stderr: %s)", sshTarget, ctx.Err(), errMsg)
		}
		return 0, fmt.Errorf("ssh connection to %s timed out: %w", sshTarget, ctx.Err())
	}

	if runErr != nil {
		if errMsg != "" {
			return 0, fmt.Errorf("ssh command failed for %s: %s", sshTarget, errMsg)
		}
		return 0, fmt.Errorf("ssh command failed for %s: %w", sshTarget, runErr)
	}

	return parseRemoteUID(sshTarget, stdoutBuf.String())
}

func parseRemoteUID(sshTarget string, rawOutput string) (uint32, error) {
	out := strings.TrimSpace(rawOutput)
	if out == "" {
		return 0, fmt.Errorf("empty output from remote id -u on %s", sshTarget)
	}

	lines := strings.Split(out, "\n")
	lastLine := strings.TrimSpace(lines[len(lines)-1])

	uidVal, err := strconv.ParseUint(lastLine, 10, 32)
	if err != nil || uidVal >= math.MaxUint32 {
		return 0, fmt.Errorf("invalid numeric UID returned from %s: %q", sshTarget, protocol.SanitizeTerminalText(out))
	}

	return uint32(uidVal), nil
}

func validateSSHTarget(target string) (host string, user string, err error) {
	if target == "" {
		return "", "", fmt.Errorf("host argument cannot be empty")
	}

	for _, r := range target {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r < 32 || r == 127 {
			return "", "", fmt.Errorf("invalid host name %q: whitespace and control characters are not permitted", target)
		}
	}

	if strings.Contains(target, ":") {
		return "", "", fmt.Errorf("invalid host name %q: ':' is not permitted (do not use 'ssh://' URLs or 'host:port' syntax)", target)
	}

	if strings.Count(target, "@") > 1 {
		return "", "", fmt.Errorf("invalid host name %q: multiple '@' symbols not permitted", target)
	}

	if strings.Contains(target, "@") {
		parts := strings.Split(target, "@")
		userPart := parts[0]
		hostPart := parts[1]
		if userPart == "" {
			return "", "", fmt.Errorf("invalid host name %q: empty user before '@'", target)
		}
		if hostPart == "" {
			return "", "", fmt.Errorf("invalid host name %q: empty host after '@'", target)
		}
		if strings.HasPrefix(userPart, "-") {
			return "", "", fmt.Errorf("invalid host name %q: user must not start with a dash", target)
		}
		if strings.HasPrefix(hostPart, "-") {
			return "", "", fmt.Errorf("invalid host name %q: host must not start with a dash", target)
		}
		if strings.ContainsAny(target, "\"'#=*?!") {
			return "", "", fmt.Errorf("invalid host name %q: characters '\"', ''', '#', '=', '*', '?', '!' are not permitted", target)
		}
		return hostPart, userPart, nil
	}

	if strings.HasPrefix(target, "-") {
		return "", "", fmt.Errorf("invalid host name %q: must not start with a dash", target)
	}

	if strings.ContainsAny(target, "\"'#=*?!") {
		return "", "", fmt.Errorf("invalid host name %q: characters '\"', ''', '#', '=', '*', '?', '!' are not permitted", target)
	}

	return target, "", nil
}

func resolveHostAndUser(host string, user string) (cleanHost string, cleanUser string, err error) {
	h, u, err := validateSSHTarget(host)
	if err != nil {
		return "", "", err
	}
	cleanHost = h
	if u != "" && user != "" && u != user {
		return "", "", fmt.Errorf("conflicting user specifications: %q in host and %q in user argument", u, user)
	}
	if u != "" {
		cleanUser = u
	} else if user != "" {
		_, validUser, userErr := validateSSHTarget(user + "@" + cleanHost)
		if userErr != nil {
			return "", "", fmt.Errorf("invalid user %q: %w", user, userErr)
		}
		cleanUser = validUser
	}
	return cleanHost, cleanUser, nil
}

func resolveHomeDir() (string, error) {
	home, err := os.UserHomeDir()
	if err == nil && home != "" && filepath.IsAbs(home) {
		return filepath.Clean(home), nil
	}
	u, uErr := user.Current()
	if uErr == nil && u.HomeDir != "" && filepath.IsAbs(u.HomeDir) {
		return filepath.Clean(u.HomeDir), nil
	}
	if envHome := os.Getenv("HOME"); envHome != "" && filepath.IsAbs(envHome) {
		return filepath.Clean(envHome), nil
	}
	if err != nil {
		return "", fmt.Errorf("cannot determine user home directory: %w", err)
	}
	return "", fmt.Errorf("user home directory is not set or not an absolute path")
}

func expandHomePath(p string) (string, error) {
	if p == "~" {
		return resolveHomeDir()
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~\\") {
		home, err := resolveHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, p[2:]), nil
	}
	return p, nil
}

func validateSocketCharacters(path string, label string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	for _, r := range path {
		if r < 32 || r == 127 || unicode.IsControl(r) {
			return fmt.Errorf("%s contains forbidden control character", label)
		}
	}
	if strings.ContainsAny(path, "\"'") {
		return fmt.Errorf("%s must not contain quotes", label)
	}
	if strings.Contains(path, ":") {
		return fmt.Errorf("%s must not contain ':' (Unix domain sockets only)", label)
	}
	return nil
}

// validateAndCanonicalizeLocalSocket checks socket path invariants and resolves it to a canonical absolute path.
func validateAndCanonicalizeLocalSocket(raw string) (string, error) {
	if err := validateSocketCharacters(raw, "local socket path"); err != nil {
		return "", err
	}

	expanded, err := expandHomePath(raw)
	if err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(expanded)
	if err != nil {
		return "", fmt.Errorf("failed to determine absolute path for socket %q: %w", raw, err)
	}
	absPath = filepath.Clean(absPath)

	if !strings.HasPrefix(absPath, "/") {
		return "", fmt.Errorf("socket path must be an absolute path starting with '/'")
	}

	// Re-validate resolved path in case HOME or CWD contained colons, quotes, or control characters
	if err := validateSocketCharacters(absPath, "canonical socket path"); err != nil {
		return "", err
	}

	// Portable Unix domain socket sockaddr_un length bound (Darwin: 104 bytes, Linux: 108 bytes).
	// Limit to 103 characters to accommodate null terminator portably.
	if len(absPath) > 103 {
		return "", fmt.Errorf("socket path %q length (%d bytes) exceeds portable Unix domain socket limit of 103 bytes", absPath, len(absPath))
	}

	return absPath, nil
}

func formatSSHPathArg(path string) string {
	// OpenSSH percent_expand replaces % with directive values; escape literal % as %%
	escaped := strings.ReplaceAll(path, "%", "%%")
	// If path contains whitespace or '#', quote with double quotes
	if strings.ContainsAny(escaped, " \t#") {
		return `"` + escaped + `"`
	}
	return escaped
}

// parseSSHDirective parses a single line of OpenSSH configuration.
// It strips unquoted comments, extracts keyword and arguments (supporting whitespace and '=' delimiters),
// and unquotes double-quoted arguments and keywords.
func parseSSHDirective(line string) (keyword string, args []string, ok bool) {
	inQuotes := false
	commentIdx := -1
	runes := []rune(line)
	for i, r := range runes {
		if r == '"' {
			inQuotes = !inQuotes
		} else if r == '#' && !inQuotes {
			commentIdx = i
			break
		}
	}
	if commentIdx != -1 {
		runes = runes[:commentIdx]
	}

	start := 0
	for start < len(runes) && (runes[start] == ' ' || runes[start] == '\t' || runes[start] == '\r' || runes[start] == '\n') {
		start++
	}
	end := len(runes)
	for end > start && (runes[end-1] == ' ' || runes[end-1] == '\t' || runes[end-1] == '\r' || runes[end-1] == '\n') {
		end--
	}
	if start >= end {
		return "", nil, false
	}
	runes = runes[start:end]

	i := 0
	if runes[0] == '"' {
		i++
		kwStart := i
		for i < len(runes) && runes[i] != '"' {
			i++
		}
		keyword = string(runes[kwStart:i])
		if i < len(runes) && runes[i] == '"' {
			i++
		}
	} else {
		for i < len(runes) && runes[i] != ' ' && runes[i] != '\t' && runes[i] != '=' {
			i++
		}
		keyword = string(runes[:i])
	}
	if keyword == "" {
		return "", nil, false
	}

	for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t') {
		i++
	}
	if i < len(runes) && runes[i] == '=' {
		i++
		for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
	}

	for i < len(runes) {
		for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
		if i >= len(runes) {
			break
		}

		if runes[i] == '"' {
			i++ // skip opening quote
			argStart := i
			for i < len(runes) && runes[i] != '"' {
				i++
			}
			args = append(args, string(runes[argStart:i]))
			if i < len(runes) && runes[i] == '"' {
				i++ // skip closing quote
			}
		} else {
			argStart := i
			for i < len(runes) && runes[i] != ' ' && runes[i] != '\t' {
				i++
			}
			args = append(args, string(runes[argStart:i]))
		}
	}

	return keyword, args, true
}

func isLmdtfyRemoteForward(keyword string, args []string) bool {
	if !strings.EqualFold(keyword, "RemoteForward") || len(args) == 0 {
		return false
	}
	remoteArg := args[0]
	return remoteArg == "lmdtfy.sock" || strings.HasSuffix(remoteArg, "/lmdtfy.sock")
}

const dtfmHeaderComment = "# Added by dtfm ssh-config"

// GenerateSnippet formats the canonical OpenSSH configuration block.
func GenerateSnippet(host string, user string, remoteUID uint32, localSocket string) (string, error) {
	cleanHost, cleanUser, err := resolveHostAndUser(host, user)
	if err != nil {
		return "", err
	}
	if remoteUID >= math.MaxUint32 {
		return "", fmt.Errorf("remoteUID cannot be %d ((uid_t)-1)", remoteUID)
	}

	canonSocket, err := validateAndCanonicalizeLocalSocket(localSocket)
	if err != nil {
		return "", err
	}

	formattedSocket := formatSSHPathArg(canonSocket)

	var b strings.Builder
	b.WriteString(dtfmHeaderComment + "\n")
	b.WriteString(fmt.Sprintf("Host %s\n", cleanHost))
	if cleanUser != "" {
		b.WriteString(fmt.Sprintf("    User %s\n", cleanUser))
	}
	b.WriteString(fmt.Sprintf("    RemoteForward /run/user/%d/lmdtfy.sock %s\n", remoteUID, formattedSocket))
	b.WriteString("    StreamLocalBindUnlink yes\n")
	return b.String(), nil
}

// UpdateSSHConfig parses existing ssh_config content, updating the matching Host block
// or inserting a new one before any catch-all section.
func UpdateSSHConfig(originalContent string, host string, user string, remoteUID uint32, localSocket string) (string, error) {
	cleanHost, cleanUser, err := resolveHostAndUser(host, user)
	if err != nil {
		return "", err
	}
	if remoteUID >= math.MaxUint32 {
		return "", fmt.Errorf("remoteUID cannot be %d ((uid_t)-1)", remoteUID)
	}

	canonSocket, err := validateAndCanonicalizeLocalSocket(localSocket)
	if err != nil {
		return "", err
	}
	formattedSocket := formatSSHPathArg(canonSocket)

	useCRLF := strings.Contains(originalContent, "\r\n")
	eol := "\n"
	if useCRLF {
		eol = "\r\n"
	}

	rawLines := strings.Split(strings.ReplaceAll(originalContent, "\r\n", "\n"), "\n")
	hasTrailingNewline := len(rawLines) > 0 && rawLines[len(rawLines)-1] == ""
	if hasTrailingNewline {
		rawLines = rawLines[:len(rawLines)-1]
	}

	type section struct {
		startIdx    int
		endIdx      int
		isHost      bool
		isExactHost bool
		isCatchAll  bool
	}

	var sections []section
	var currentSec *section

	for i, line := range rawLines {
		kw, args, ok := parseSSHDirective(line)
		if !ok {
			continue
		}

		if strings.EqualFold(kw, "Host") {
			if currentSec != nil {
				currentSec.endIdx = i
				sections = append(sections, *currentSec)
			}
			isExact := len(args) == 1 && args[0] == cleanHost && !strings.ContainsAny(args[0], "*?!")
			isCatchAll := false
			for _, pat := range args {
				if strings.ContainsAny(pat, "*?") {
					isCatchAll = true
					break
				}
			}
			if len(args) > 1 {
				for _, pat := range args {
					if pat == cleanHost {
						isCatchAll = true
						break
					}
				}
			}
			currentSec = &section{
				startIdx:    i,
				endIdx:      len(rawLines),
				isHost:      true,
				isExactHost: isExact,
				isCatchAll:  isCatchAll,
			}
		} else if strings.EqualFold(kw, "Match") {
			if currentSec != nil {
				currentSec.endIdx = i
				sections = append(sections, *currentSec)
			}
			isCatchAll := true
			currentSec = &section{
				startIdx:    i,
				endIdx:      len(rawLines),
				isHost:      false,
				isExactHost: false,
				isCatchAll:  isCatchAll,
			}
		}
	}
	if currentSec != nil {
		currentSec.endIdx = len(rawLines)
		sections = append(sections, *currentSec)
	}

	var exactHostSecIndices []int
	for idx, s := range sections {
		if s.isExactHost {
			exactHostSecIndices = append(exactHostSecIndices, idx)
		}
	}

	// Case 1: No exact single-host Host block exists -> insert before first catch-all or append at EOF
	if len(exactHostSecIndices) == 0 {
		snippet, err := GenerateSnippet(cleanHost, cleanUser, remoteUID, canonSocket)
		if err != nil {
			return "", err
		}
		if useCRLF {
			snippet = strings.ReplaceAll(snippet, "\n", "\r\n")
		}

		firstCatchAllLine := -1
		for _, s := range sections {
			if s.isCatchAll {
				firstCatchAllLine = s.startIdx
				break
			}
		}

		if firstCatchAllLine != -1 {
			// Walk back across contiguous comments immediately above the catch-all header
			insertLine := firstCatchAllLine
			for insertLine > 0 {
				prevLine := strings.TrimSpace(rawLines[insertLine-1])
				if strings.HasPrefix(prevLine, "#") {
					insertLine--
				} else {
					break
				}
			}
			firstCatchAllLine = insertLine

			var resultLines []string
			resultLines = append(resultLines, rawLines[:firstCatchAllLine]...)

			if len(resultLines) > 0 && strings.TrimSpace(resultLines[len(resultLines)-1]) != "" {
				resultLines = append(resultLines, "")
			}

			snippetLines := strings.Split(strings.TrimRight(snippet, "\r\n"), "\n")
			for _, sl := range snippetLines {
				resultLines = append(resultLines, strings.TrimRight(sl, "\r"))
			}

			resultLines = append(resultLines, "")
			resultLines = append(resultLines, rawLines[firstCatchAllLine:]...)

			res := strings.Join(resultLines, eol) + eol
			return res, nil
		}

		// Append at EOF
		trimmedOriginal := strings.TrimRight(originalContent, "\r\n")
		if trimmedOriginal == "" {
			return snippet, nil
		}
		return trimmedOriginal + eol + eol + snippet, nil
	}

	// Case 2: One or more exact single-host Host blocks exist.
	// Update the first exact Host block in-place, and strip any stale lmdtfy RemoteForwards from subsequent exact blocks.
	primarySec := sections[exactHostSecIndices[0]]
	blockLines := rawLines[primarySec.startIdx:primarySec.endIdx]

	hasDtfmComment := false
	if primarySec.startIdx > 0 && strings.TrimSpace(rawLines[primarySec.startIdx-1]) == dtfmHeaderComment {
		hasDtfmComment = true
	}
	for _, bLine := range blockLines {
		if strings.TrimSpace(bLine) == dtfmHeaderComment {
			hasDtfmComment = true
			break
		}
	}

	indent := "    "
	var rfRelativeIndices []int
	var slbuRelativeIndices []int
	var userRelativeIndices []int

	for rIdx := 1; rIdx < len(blockLines); rIdx++ {
		bLine := blockLines[rIdx]
		trimmed := strings.TrimSpace(bLine)
		if trimmed == "" {
			continue
		}
		kw, args, ok := parseSSHDirective(bLine)
		if !strings.HasPrefix(trimmed, "#") {
			prefix := ""
			for _, ch := range bLine {
				if ch == ' ' || ch == '\t' {
					prefix += string(ch)
				} else {
					break
				}
			}
			if prefix != "" {
				indent = prefix
			}
		}

		if ok {
			if isLmdtfyRemoteForward(kw, args) {
				rfRelativeIndices = append(rfRelativeIndices, rIdx)
			} else if strings.EqualFold(kw, "StreamLocalBindUnlink") {
				slbuRelativeIndices = append(slbuRelativeIndices, rIdx)
			} else if strings.EqualFold(kw, "User") {
				userRelativeIndices = append(userRelativeIndices, rIdx)
			}
		}
	}

	desiredComment := indent + dtfmHeaderComment
	desiredRF := fmt.Sprintf("%sRemoteForward /run/user/%d/lmdtfy.sock %s", indent, remoteUID, formattedSocket)
	desiredSLBU := fmt.Sprintf("%sStreamLocalBindUnlink yes", indent)
	desiredUser := ""
	if cleanUser != "" {
		desiredUser = fmt.Sprintf("%sUser %s", indent, cleanUser)
	}

	var newBlockLines []string
	rfPlaced := false
	slbuPlaced := false
	userPlaced := desiredUser == ""

	for rIdx, bLine := range blockLines {
		if rIdx == 0 {
			newBlockLines = append(newBlockLines, bLine)
			if desiredUser != "" && len(userRelativeIndices) == 0 && !userPlaced {
				newBlockLines = append(newBlockLines, desiredUser)
				userPlaced = true
			}
			continue
		}

		kw, args, ok := parseSSHDirective(bLine)
		isLmdtfyRF := ok && isLmdtfyRemoteForward(kw, args)
		isSLBU := ok && strings.EqualFold(kw, "StreamLocalBindUnlink")
		isUser := ok && strings.EqualFold(kw, "User")

		if isUser && desiredUser != "" {
			if !userPlaced {
				newBlockLines = append(newBlockLines, desiredUser)
				userPlaced = true
			}
			// Drops any duplicate User lines in this block
			continue
		}

		if isLmdtfyRF {
			if !rfPlaced {
				if !hasDtfmComment {
					newBlockLines = append(newBlockLines, desiredComment)
					hasDtfmComment = true
				}
				newBlockLines = append(newBlockLines, desiredRF)
				rfPlaced = true
				if len(slbuRelativeIndices) == 0 && !slbuPlaced {
					newBlockLines = append(newBlockLines, desiredSLBU)
					slbuPlaced = true
				}
			}
			continue
		}

		if isSLBU {
			if !rfPlaced && len(rfRelativeIndices) == 0 {
				if !hasDtfmComment {
					newBlockLines = append(newBlockLines, desiredComment)
					hasDtfmComment = true
				}
				newBlockLines = append(newBlockLines, desiredRF)
				rfPlaced = true
			}
			if !slbuPlaced {
				newBlockLines = append(newBlockLines, desiredSLBU)
				slbuPlaced = true
			}
			continue
		}

		newBlockLines = append(newBlockLines, bLine)
	}

	if !rfPlaced || !slbuPlaced {
		insertIdx := 0
		for idx := 1; idx < len(newBlockLines); idx++ {
			trimmed := strings.TrimSpace(newBlockLines[idx])
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				insertIdx = idx
			}
		}

		var finalBlock []string
		for idx, line := range newBlockLines {
			finalBlock = append(finalBlock, line)
			if idx == insertIdx {
				if !rfPlaced {
					if !hasDtfmComment {
						finalBlock = append(finalBlock, desiredComment)
						hasDtfmComment = true
					}
					finalBlock = append(finalBlock, desiredRF)
					rfPlaced = true
				}
				if !slbuPlaced {
					finalBlock = append(finalBlock, desiredSLBU)
					slbuPlaced = true
				}
			}
		}
		newBlockLines = finalBlock
	}

	// Recompose the file, stripping any stale lmdtfy RemoteForwards from subsequent exact host blocks
	var resultLines []string
	resultLines = append(resultLines, rawLines[:primarySec.startIdx]...)
	resultLines = append(resultLines, newBlockLines...)

	subsequentExactSet := make(map[int]bool)
	for _, secIdx := range exactHostSecIndices[1:] {
		subsequentExactSet[secIdx] = true
	}

	for secIdx := 1; secIdx < len(sections); secIdx++ {
		sec := sections[secIdx]
		if sec.startIdx < primarySec.endIdx {
			continue
		}
		secLines := rawLines[sec.startIdx:sec.endIdx]
		if subsequentExactSet[secIdx] {
			for _, line := range secLines {
				kw, args, ok := parseSSHDirective(line)
				if ok && isLmdtfyRemoteForward(kw, args) {
					continue
				}
				resultLines = append(resultLines, line)
			}
		} else {
			resultLines = append(resultLines, secLines...)
		}
	}

	res := strings.Join(resultLines, eol) + eol
	return res, nil
}

// WriteSSHConfigFile writes content to targetPath atomically with strict 0600 permissions,
// preserving existing symlinks and verifying inode ownership and file regular mode.
func WriteSSHConfigFile(configPath string, content string) error {
	fi, err := os.Lstat(configPath)
	var writePath string
	if err == nil && fi.Mode()&os.ModeSymlink != 0 {
		if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
			curUID := uint32(os.Getuid())
			if stat.Uid != curUID && stat.Uid != 0 {
				return fmt.Errorf("insecure symlink %s: owned by UID %d, expected UID %d or root (0)", configPath, stat.Uid, curUID)
			}
		}
		resolved, evalErr := filepath.EvalSymlinks(configPath)
		if evalErr != nil {
			return fmt.Errorf("cannot resolve symlink %s: %w", configPath, evalErr)
		}
		writePath = resolved
	} else if err == nil {
		writePath = configPath
	} else if os.IsNotExist(err) {
		writePath = configPath
	} else {
		return fmt.Errorf("failed to stat %s: %w", configPath, err)
	}

	if wfi, err := os.Lstat(writePath); err == nil {
		if !wfi.Mode().IsRegular() {
			return fmt.Errorf("target config %s is not a regular file (mode %s)", writePath, wfi.Mode())
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to stat target config %s: %w", writePath, err)
	}

	dir := filepath.Dir(writePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".config.tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %s: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to set 0600 permissions on %s: %w", tmpPath, err)
	}

	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write content to %s: %w", tmpPath, err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync content to %s: %w", tmpPath, err)
	}

	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close %s: %w", tmpPath, err)
	}

	if err := os.Rename(tmpPath, writePath); err != nil {
		return fmt.Errorf("failed to atomically replace %s with %s: %w", writePath, tmpPath, err)
	}
	tmpPath = "" // Disarm defer removal

	return nil
}

// SSHConfigOptions parameterizes the ssh-config subcommand execution.
type SSHConfigOptions struct {
	Querier    UIDQuerier
	ConfigPath string
}

func parseSSHConfigArgs(args []string) (host string, write bool, socketPath string, socketSet bool, configPath string, configSet bool, showHelp bool, err error) {
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-h" || arg == "--help" || arg == "-help":
			showHelp = true
			return
		case arg == "-w" || arg == "--write" || arg == "-write":
			write = true
		case strings.HasPrefix(arg, "--write=") || strings.HasPrefix(arg, "-write="):
			val := strings.TrimPrefix(strings.TrimPrefix(arg, "--write="), "-write=")
			b, parseErr := strconv.ParseBool(val)
			if parseErr != nil {
				err = fmt.Errorf("invalid boolean value %q for --write", val)
				return
			}
			write = b
		case arg == "--socket" || arg == "-socket":
			if i+1 >= len(args) {
				err = fmt.Errorf("flag %s requires an argument", arg)
				return
			}
			i++
			val := args[i]
			if strings.TrimSpace(val) == "" {
				err = fmt.Errorf("flag %s requires a non-empty value", arg)
				return
			}
			socketPath = val
			socketSet = true
		case strings.HasPrefix(arg, "--socket=") || strings.HasPrefix(arg, "-socket="):
			val := strings.TrimPrefix(strings.TrimPrefix(arg, "--socket="), "-socket=")
			if strings.TrimSpace(val) == "" {
				err = fmt.Errorf("flag --socket requires a non-empty value")
				return
			}
			socketPath = val
			socketSet = true
		case arg == "--config" || arg == "-config":
			if i+1 >= len(args) {
				err = fmt.Errorf("flag %s requires an argument", arg)
				return
			}
			i++
			val := args[i]
			if strings.TrimSpace(val) == "" {
				err = fmt.Errorf("flag %s requires a non-empty value", arg)
				return
			}
			configPath = val
			configSet = true
		case strings.HasPrefix(arg, "--config=") || strings.HasPrefix(arg, "-config="):
			val := strings.TrimPrefix(strings.TrimPrefix(arg, "--config="), "-config=")
			if strings.TrimSpace(val) == "" {
				err = fmt.Errorf("flag --config requires a non-empty value")
				return
			}
			configPath = val
			configSet = true
		case arg == "--":
			positional = append(positional, args[i+1:]...)
			i = len(args)
		case strings.HasPrefix(arg, "-"):
			err = fmt.Errorf("unknown flag: %s", arg)
			return
		default:
			positional = append(positional, arg)
		}
	}

	if !socketSet {
		socketPath = protocol.DefaultSocketPath()
	}

	if len(positional) > 0 {
		host = positional[0]
	}
	if len(positional) > 1 {
		err = fmt.Errorf("unexpected extra arguments: %v", positional[1:])
		return
	}
	return
}

func printSSHConfigUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: dtfm ssh-config <host> [options]")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Queries the remote host's numeric UID via SSH and outputs the exact OpenSSH")
	fmt.Fprintln(w, "RemoteForward configuration snippet required for lmdtfy forwarding.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "Options:")
	fmt.Fprintln(w, "  -w, --write       Atomically append/update snippet in ~/.ssh/config (mode 0600)")
	fmt.Fprintln(w, "  --socket <path>   Local Unix domain socket path (default: DefaultSocketPath())")
	fmt.Fprintln(w, "  --config <path>   Target SSH config file (default: ~/.ssh/config)")
	fmt.Fprintln(w, "  -h, --help        Show this help message")
}

// RunSSHConfig executes the `dtfm ssh-config` subcommand.
func RunSSHConfig(args []string, stdout io.Writer, stderr io.Writer, opts SSHConfigOptions) int {
	host, write, socketPath, _, configPath, _, showHelp, err := parseSSHConfigArgs(args)
	if showHelp {
		printSSHConfigUsage(stdout)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
		fmt.Fprintln(stderr, "Usage: dtfm ssh-config <host> [--write|-w] [--socket <path>] [--config <path>]")
		return 1
	}

	if host == "" {
		fmt.Fprintln(stderr, "dtfm ssh-config: host argument is required")
		fmt.Fprintln(stderr, "Usage: dtfm ssh-config <host> [--write|-w] [--socket <path>] [--config <path>]")
		return 1
	}

	hostPart, userPart, err := validateSSHTarget(host)
	if err != nil {
		fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
		return 1
	}

	canonSocket, err := validateAndCanonicalizeLocalSocket(socketPath)
	if err != nil {
		fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
		return 1
	}

	targetFile := configPath
	if targetFile == "" {
		targetFile = opts.ConfigPath
	}
	if targetFile == "" {
		home, err := resolveHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
			return 1
		}
		targetFile = filepath.Join(home, ".ssh", "config")
	} else {
		expanded, err := expandHomePath(targetFile)
		if err != nil {
			fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
			return 1
		}
		targetFile = expanded
	}

	// Pre-flight validation for --write before making network calls
	if write {
		fi, err := os.Lstat(targetFile)
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok {
				curUID := uint32(os.Getuid())
				if stat.Uid != curUID && stat.Uid != 0 {
					fmt.Fprintf(stderr, "dtfm ssh-config: insecure symlink %s: owned by UID %d, expected UID %d or root (0)\n", targetFile, stat.Uid, curUID)
					return 1
				}
			}
			resolved, evalErr := filepath.EvalSymlinks(targetFile)
			if evalErr != nil {
				fmt.Fprintf(stderr, "dtfm ssh-config: cannot resolve symlink %s: %v\n", targetFile, evalErr)
				return 1
			}
			if wfi, err := os.Lstat(resolved); err == nil && !wfi.Mode().IsRegular() {
				fmt.Fprintf(stderr, "dtfm ssh-config: target config %s is not a regular file (mode %s)\n", resolved, wfi.Mode())
				return 1
			}
		} else if err == nil && !fi.Mode().IsRegular() {
			fmt.Fprintf(stderr, "dtfm ssh-config: target config %s is not a regular file (mode %s)\n", targetFile, fi.Mode())
			return 1
		}
		if _, err := os.ReadFile(targetFile); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "dtfm ssh-config: cannot read %s: %v\n", targetFile, err)
			return 1
		}
	}

	querier := opts.Querier
	if querier == nil {
		querier = DefaultUIDQuerier
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	remoteUID, err := querier(ctx, host)
	if err != nil {
		fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
		return 1
	}

	snippet, err := GenerateSnippet(hostPart, userPart, remoteUID, canonSocket)
	if err != nil {
		fmt.Fprintf(stderr, "dtfm ssh-config: %v\n", err)
		return 1
	}

	if write {
		// Re-read targetFile freshly after querier succeeds to avoid clobbering concurrent edits
		freshContent := ""
		if data, err := os.ReadFile(targetFile); err == nil {
			freshContent = string(data)
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(stderr, "dtfm ssh-config: cannot read %s: %v\n", targetFile, err)
			return 1
		}

		updatedContent, err := UpdateSSHConfig(freshContent, hostPart, userPart, remoteUID, canonSocket)
		if err != nil {
			fmt.Fprintf(stderr, "dtfm ssh-config: cannot update config: %v\n", err)
			return 1
		}

		if err := WriteSSHConfigFile(targetFile, updatedContent); err != nil {
			fmt.Fprintf(stderr, "dtfm ssh-config: failed to write %s: %v\n", targetFile, err)
			return 1
		}

		fmt.Fprint(stdout, snippet)
		fmt.Fprintf(stderr, "✓ Configuration written to %s\n", targetFile)
	} else {
		fmt.Fprint(stdout, snippet)
	}

	return 0
}
