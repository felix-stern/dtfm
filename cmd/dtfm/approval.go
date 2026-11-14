// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/iinozemtsev-lab/dtfm/pkg/protocol"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type ApprovalDecision string

const (
	DecisionApprove ApprovalDecision = "approve"
	DecisionEdit    ApprovalDecision = "edit"
	DecisionReject  ApprovalDecision = "reject"
	DecisionTimeout ApprovalDecision = "timeout"
)

var (
	// ErrClientDisconnected is returned when the remote client closes its connection
	// while waiting for human operator approval.
	ErrClientDisconnected = errors.New("client disconnected")
	errEditCancelled      = errors.New("edit cancelled by operator")
	errPrompterBackground = errors.New("terminal prompter not in foreground process group")
	errPrompterClosed     = errors.New("prompter closed")
)

const (
	maxEditRunes = 64 * 1024
	maxLineBuf   = 64 * 1024
)

// Prompter provides a cancellable interface for interacting with the human operator.
type Prompter interface {
	Prompt(ctx context.Context, req protocol.CommandRequest) (decision ApprovalDecision, editedCmd string, rejectReason string, err error)
	Close() error
}

// PasswordPrompter is an optional interface implemented by prompters that can collect
// an operator password (e.g. via term.ReadPassword) when sudo elevation is required.
type PasswordPrompter interface {
	PromptPassword(ctx context.Context) ([]byte, error)
}

type lineResult struct {
	line      string
	err       error
	timestamp time.Time
}

type streamByte struct {
	b   byte
	err error
	at  time.Time
}

type editRequest struct {
	initial string
	ctx     context.Context
}

// TerminalPrompter handles user interaction via a terminal or stream.
type TerminalPrompter struct {
	reader          *bufio.Reader
	writer          io.Writer
	file            *os.File // underlying file descriptor (if any)
	isTTY           bool     // true only if file is an actual character terminal device
	done            chan struct{}
	closeOnce       sync.Once
	closeErr        error
	activeWG        sync.WaitGroup
	mu              sync.Mutex
	streamErr       error           // permanently tracks stream closure / EOF
	streamReadCh    chan streamByte // in-flight ReadByte when file == nil
	promptStartTime time.Time       // timestamp when active prompt was presented
	lastAbortTime   time.Time       // timestamp when previous prompt ended via timeout/disconnect
	editOrigTermios *termiosState
	partialLine     []byte
	partialTime     time.Time
	partialOverflow bool
	readPasswordFn  func(fd int) ([]byte, error) // optional override for term.ReadPassword
}

func (p *TerminalPrompter) useColor() bool {
	return p.isTTY && os.Getenv("NO_COLOR") == ""
}

func (p *TerminalPrompter) colorBlue(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;34m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorGreen(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;32m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorRed(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;31m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorBold(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}

// NewTerminalPrompter creates a prompter reading from /dev/tty if available,
// falling back to os.Stdin/os.Stdout (e.g. for testing or headless environments).
func NewTerminalPrompter() *TerminalPrompter {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		return newPrompter(tty, tty, tty)
	}
	return newPrompter(os.Stdin, os.Stdout, os.Stdin)
}

// NewStreamPrompter creates a prompter using explicit reader and writer (ideal for tests).
func NewStreamPrompter(r io.Reader, w io.Writer) *TerminalPrompter {
	return newPrompter(r, w, nil)
}

func newPrompter(r io.Reader, w io.Writer, f *os.File) *TerminalPrompter {
	isTTY := false
	if f != nil {
		if fi, err := f.Stat(); err == nil && (fi.Mode()&os.ModeCharDevice != 0) {
			if isTerminalFD(f.Fd()) {
				isTTY = true
				if wf, ok := w.(*os.File); ok {
					if !isTerminalFD(wf.Fd()) {
						isTTY = false
					}
				}
			}
		}
	}

	p := &TerminalPrompter{
		reader:         bufio.NewReader(r),
		writer:         &syncWriter{mu: &sync.Mutex{}, w: w},
		file:           f,
		isTTY:          isTTY,
		done:           make(chan struct{}),
		readPasswordFn: term.ReadPassword,
	}

	return p
}

// Close closes the prompter and /dev/tty if opened.
func (p *TerminalPrompter) Close() error {
	p.closeOnce.Do(func() {
		p.mu.Lock()
		close(p.done)
		p.mu.Unlock()
		p.activeWG.Wait()
		p.restoreEditMode()
		if p.file != nil && p.file != os.Stdin {
			p.closeErr = p.file.Close()
		}
	})
	return p.closeErr
}

func (p *TerminalPrompter) enterOp() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	select {
	case <-p.done:
		return false
	default:
		p.activeWG.Add(1)
		return true
	}
}

func (p *TerminalPrompter) leaveOp() {
	p.activeWG.Done()
}

func (p *TerminalPrompter) hasPendingInput(timeoutMs int) bool {
	if p.reader.Buffered() > 0 {
		return true
	}
	if p.file == nil {
		return false
	}
	pfd := []unix.PollFd{{Fd: int32(p.file.Fd()), Events: unix.POLLIN}}
	n, err := unix.Poll(pfd, timeoutMs)
	if err != nil && !errors.Is(err, syscall.EINTR) {
		return true
	}
	return err == nil && n > 0 && (pfd[0].Revents&(unix.POLLIN|unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0)
}

func (p *TerminalPrompter) restoreEditMode() {
	p.mu.Lock()
	t := p.editOrigTermios
	p.editOrigTermios = nil
	p.mu.Unlock()

	if t != nil && p.file != nil {
		signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		fmt.Fprint(p.writer, "\033[?2004l")
		_ = restoreTermios(p.file.Fd(), t)
		signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
	}
}

// isWideRune reports whether rune r occupies 2 display columns in a terminal.
func isWideRune(r rune) bool {
	// Specific 2-column symbols and emoji in 0x2300..0x2BFF
	if (r >= 0x231A && r <= 0x231B) ||
		(r >= 0x2329 && r <= 0x232A) ||
		(r >= 0x23E9 && r <= 0x23F3) ||
		(r >= 0x23F8 && r <= 0x23FA) ||
		(r >= 0x25FD && r <= 0x25FE) ||
		(r >= 0x2614 && r <= 0x2615) ||
		(r >= 0x2648 && r <= 0x2653) ||
		r == 0x267F || r == 0x2693 || r == 0x26A1 ||
		(r >= 0x26AA && r <= 0x26AB) ||
		(r >= 0x26BD && r <= 0x26BE) ||
		(r >= 0x26C4 && r <= 0x26C5) ||
		r == 0x26CE || r == 0x26D4 || r == 0x26EA ||
		(r >= 0x26F2 && r <= 0x26F3) ||
		r == 0x26F5 || r == 0x26FA || r == 0x26FD ||
		r == 0x2705 || (r >= 0x270A && r <= 0x270B) ||
		r == 0x2728 || r == 0x274C || r == 0x274E ||
		(r >= 0x2753 && r <= 0x2755) || r == 0x2757 ||
		(r >= 0x2795 && r <= 0x2797) || r == 0x27B0 || r == 0x27BF ||
		(r >= 0x2B1B && r <= 0x2B1C) || r == 0x2B50 || r == 0x2B55 {
		return true
	}

	// East Asian Wide / Fullwidth / CJK Unicode blocks (2 columns)
	if (r >= 0x1100 && r <= 0x115F) || // Hangul Jamo
		(r >= 0x2E80 && r <= 0xA4CF && r != 0x303F) || // CJK Radicals, Symbols, Ideographs, Yi, Kana
		(r >= 0xA960 && r <= 0xA97C) || // Hangul Jamo Extended-A
		(r >= 0xAC00 && r <= 0xD7A3) || // Hangul Syllables
		(r >= 0xF900 && r <= 0xFAFF) || // CJK Compatibility Ideographs
		(r >= 0xFE10 && r <= 0xFE19) || // Vertical forms
		(r >= 0xFE30 && r <= 0xFE6F) || // CJK Compatibility Forms
		(r >= 0xFF01 && r <= 0xFF60) || // Fullwidth Forms
		(r >= 0xFFE0 && r <= 0xFFE6) || // Fullwidth Symbols
		(r >= 0x16FE0 && r <= 0x18D7F) || // Tangut / Ideographic Symbols
		(r >= 0x1AFF0 && r <= 0x1B2FB) || // Kana Supplement / Nushu
		(r >= 0x1F000 && r <= 0x1FAFF) || // Supplementary Emoji / Pictographs / Emoticons
		(r >= 0x20000 && r <= 0x3FFFD) { // CJK Extension B..I
		return true
	}
	return false
}

// runeDisplayWidth returns the visual column width of rune r in a terminal emulator.
func runeDisplayWidth(r rune) int {
	if r == 0 || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	// Zero-width spaces, variation selectors, filler runes
	if (r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) ||
		r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || r == 0xFEFF {
		return 0
	}
	if isWideRune(r) {
		return 2
	}
	return 1
}

// fitsInWidth reports whether the visual column width of runes is <= maxW,
// scanning at most maxW+1 runes so it runs in O(maxW).
func fitsInWidth(runes []rune, maxW int) bool {
	w := 0
	for _, r := range runes {
		w += runeDisplayWidth(r)
		if w > maxW {
			return false
		}
	}
	return true
}

func strDisplayWidth(runes []rune) int {
	w := 0
	for _, r := range runes {
		w += runeDisplayWidth(r)
	}
	return w
}

func getTerminalCols(fd uintptr) int {
	if ws, err := unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ); err == nil && ws.Col > 0 {
		return int(ws.Col)
	}
	return 80
}

// readCSISequence consumes an ECMA-48 CSI sequence:
// parameter bytes (0x30..0x3F) and intermediate bytes (0x20..0x2F) until final byte (0x40..0x7E).
func (p *TerminalPrompter) readCSISequence(ctx context.Context) (params []byte, finalByte byte) {
	const maxCSIBytes = 64
	for i := 0; i < maxCSIBytes; i++ {
		select {
		case <-ctx.Done():
			return params, 0
		case <-p.done:
			return params, 0
		default:
		}

		if !p.hasPendingInput(50) {
			return params, 0
		}
		c, err := p.reader.ReadByte()
		if err != nil {
			return params, 0
		}
		if c >= 0x40 && c <= 0x7E {
			return params, c
		}
		if c >= 0x20 && c <= 0x3F {
			params = append(params, c)
			continue
		}
		// Control byte (e.g. \r, \n, \x03, \x1b) interrupts incomplete sequence:
		// unread it so it is processed by the main loop rather than swallowed
		_ = p.reader.UnreadByte()
		return params, 0
	}
	return params, 0
}

func (p *TerminalPrompter) runInteractiveEdit(req editRequest) lineResult {
	defer p.restoreEditMode()

	initialRunes := []rune(req.initial)
	if len(initialRunes) > maxEditRunes {
		return lineResult{err: fmt.Errorf("command exceeds maximum interactive edit length (%d > %d chars)", len(initialRunes), maxEditRunes)}
	}

	// Verify foreground process group before attempting raw mode
	if fg, err := unix.IoctlGetInt(int(p.file.Fd()), unix.TIOCGPGRP); err == nil && fg > 0 {
		if fg != syscall.Getpgrp() {
			// Prompter is running in background process group: do not enter raw mode
			return lineResult{err: errPrompterBackground}
		}
	}

	signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
	orig, err := setRawMode(p.file.Fd())
	signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
	if err != nil {
		// Terminal doesn't support raw mode, fallback to plain line reading
		fmt.Fprintf(p.writer, "Edit command (press Enter to run):\n> ")
		var buf []byte
		overflow := false
		for {
			select {
			case <-req.ctx.Done():
				return lineResult{err: req.ctx.Err()}
			case <-p.done:
				return lineResult{err: errPrompterClosed}
			default:
			}

			if p.file != nil && !p.hasPendingInput(50) {
				continue
			}

			b, err := p.reader.ReadByte()
			if err != nil {
				return lineResult{err: err}
			}
			if b == '\n' {
				if overflow {
					return lineResult{err: errors.New("input line exceeds maximum length")}
				}
				trimmed := strings.TrimSpace(string(buf))
				if trimmed == "" {
					trimmed = req.initial
				}
				return lineResult{line: trimmed}
			}
			if len(buf) < maxLineBuf {
				buf = append(buf, b)
			} else {
				overflow = true
			}
		}
	}

	p.mu.Lock()
	p.editOrigTermios = orig
	p.mu.Unlock()

	// Enable bracketed paste mode on terminal
	fmt.Fprint(p.writer, "\033[?2004h")

	buf := initialRunes
	pos := len(buf)
	viewStart := 0
	inPaste := false
	dirty := false

	const (
		leftMarker  = "<"
		rightMarker = ">"
	)
	const markerWidth = 1

	redraw := func() {
		if pos < 0 {
			pos = 0
		}
		if pos > len(buf) {
			pos = len(buf)
		}

		cols := getTerminalCols(p.file.Fd())
		maxCols := cols - 1
		if maxCols < 8 {
			maxCols = 8
		}
		avail := maxCols - 2 // text area excluding "> "
		if avail < 4 {
			avail = 4
		}

		if fitsInWidth(buf, avail) {
			viewStart = 0
			cursorCol := 2 + strDisplayWidth(buf[:pos])
			fmt.Fprintf(p.writer, "\r\033[K> %s\r\033[%dG", string(buf), cursorCol+1)
			return
		}

		// Horizontal scrolling viewport using display column widths
		if pos < viewStart {
			viewStart = pos
		}

		targetContentWidth := avail - 2*markerWidth
		if targetContentWidth < 2 {
			targetContentWidth = 2
		}

		w := 0
		minStart := pos
		for minStart > 0 {
			rw := runeDisplayWidth(buf[minStart-1])
			if w+rw > targetContentWidth {
				break
			}
			w += rw
			minStart--
		}
		if viewStart < minStart {
			viewStart = minStart
		}

		hasLeft := viewStart > 0
		leftW := 0
		if hasLeft {
			leftW = markerWidth
		}

		sliceEnd := pos
		currentW := strDisplayWidth(buf[viewStart:sliceEnd])
		for sliceEnd < len(buf) {
			rw := runeDisplayWidth(buf[sliceEnd])
			rightW := 0
			if sliceEnd+1 < len(buf) {
				rightW = markerWidth
			}
			if leftW+currentW+rw+rightW > avail {
				break
			}
			currentW += rw
			sliceEnd++
		}

		hasRight := sliceEnd < len(buf)
		rightW := 0
		if hasRight {
			rightW = markerWidth
		}

		// Pull viewStart left if there is room to the left (e.g. after backspacing at the end of buf)
		for viewStart > 0 {
			prevRuneW := runeDisplayWidth(buf[viewStart-1])
			newLeftW := 0
			if viewStart-1 > 0 {
				newLeftW = markerWidth
			}
			if newLeftW+currentW+prevRuneW+rightW > avail {
				break
			}
			viewStart--
			currentW += prevRuneW
			leftW = newLeftW
			hasLeft = viewStart > 0
		}

		var lineBuilder strings.Builder
		lineBuilder.WriteString("> ")
		if hasLeft {
			lineBuilder.WriteString(leftMarker)
		}
		lineBuilder.WriteString(string(buf[viewStart:sliceEnd]))
		if hasRight {
			lineBuilder.WriteString(rightMarker)
		}

		cursorCol := 2 + leftW + strDisplayWidth(buf[viewStart:pos])
		fmt.Fprintf(p.writer, "\r\033[K%s\r\033[%dG", lineBuilder.String(), cursorCol+1)
	}

	fmt.Fprintf(p.writer, "Edit command (press Enter to run):\r\n")
	redraw()

	for {
		if dirty && !inPaste && p.reader.Buffered() == 0 {
			redraw()
			dirty = false
		}

		select {
		case <-req.ctx.Done():
			return lineResult{err: req.ctx.Err()}
		case <-p.done:
			return lineResult{err: errPrompterClosed}
		default:
		}

		if !p.hasPendingInput(50) {
			continue
		}

		b, err := p.reader.ReadByte()
		if err != nil {
			if p.isTTY && errors.Is(err, io.EOF) {
				return lineResult{err: io.EOF}
			}
			p.mu.Lock()
			p.streamErr = err
			p.mu.Unlock()
			return lineResult{err: err}
		}

		select {
		case <-req.ctx.Done():
			return lineResult{err: req.ctx.Err()}
		case <-p.done:
			return lineResult{err: errPrompterClosed}
		default:
		}

		switch {
		case b < 0x80:
			switch {
			case b == '\r' || b == '\n':
				if inPaste {
					// Inside bracketed paste: collapse CRLF or standalone \r or \n into a single space
					if b == '\r' && p.hasPendingInput(5) {
						if nextB, err := p.reader.ReadByte(); err == nil {
							if nextB != '\n' {
								_ = p.reader.UnreadByte()
							}
						}
					}
					if len(buf) >= maxEditRunes {
						return lineResult{err: errors.New("pasted command exceeds maximum editable length")}
					}
					buf = append(buf[:pos], append([]rune{' '}, buf[pos:]...)...)
					pos++
					dirty = true
					continue
				}
				fmt.Fprint(p.writer, "\r\n")
				return lineResult{line: string(buf)}

			case b == 0x09: // Tab
				if inPaste {
					if len(buf) >= maxEditRunes {
						return lineResult{err: errors.New("pasted command exceeds maximum editable length")}
					}
					buf = append(buf[:pos], append([]rune{' '}, buf[pos:]...)...)
					pos++
					dirty = true
				}
				continue

			case b == 0x03: // Ctrl+C
				fmt.Fprint(p.writer, "^C\r\n")
				return lineResult{err: errEditCancelled}

			case b == 0x1b: // Escape sequence
				if !p.hasPendingInput(50) {
					continue
				}
				b2, err := p.reader.ReadByte()
				if err != nil {
					continue
				}
				if b2 < 0x20 && b2 != 0x1b {
					_ = p.reader.UnreadByte()
					continue
				}

				hadExtraEsc := false
				for escCount := 0; b2 == 0x1b && escCount < 16; escCount++ {
					hadExtraEsc = true
					select {
					case <-req.ctx.Done():
						return lineResult{err: req.ctx.Err()}
					case <-p.done:
						return lineResult{err: errPrompterClosed}
					default:
					}
					if !p.hasPendingInput(50) {
						break
					}
					nextB, err := p.reader.ReadByte()
					if err != nil {
						break
					}
					if nextB < 0x20 && nextB != 0x1b {
						_ = p.reader.UnreadByte()
						break
					}
					b2 = nextB
				}

				if b2 == '[' {
					csiParams, finalByte := p.readCSISequence(req.ctx)
					paramStr := string(csiParams)

					if finalByte == '~' {
						if paramStr == "200" {
							inPaste = true
							continue
						} else if paramStr == "201" {
							inPaste = false
							dirty = true
							continue
						}
					}

					if inPaste {
						continue
					}

					switch finalByte {
					case 'D':
						if hadExtraEsc {
							if pos > 0 {
								for pos > 0 && unicode.IsSpace(buf[pos-1]) {
									pos--
								}
								for pos > 0 && !unicode.IsSpace(buf[pos-1]) {
									pos--
								}
								dirty = true
							}
						} else if paramStr == "" || paramStr == "1" {
							if pos > 0 {
								pos--
								dirty = true
							}
						} else if strings.HasPrefix(paramStr, "1;5") || strings.HasPrefix(paramStr, "1;3") {
							if pos > 0 {
								for pos > 0 && unicode.IsSpace(buf[pos-1]) {
									pos--
								}
								for pos > 0 && !unicode.IsSpace(buf[pos-1]) {
									pos--
								}
								dirty = true
							}
						}
					case 'C':
						if hadExtraEsc {
							if pos < len(buf) {
								for pos < len(buf) && !unicode.IsSpace(buf[pos]) {
									pos++
								}
								for pos < len(buf) && unicode.IsSpace(buf[pos]) {
									pos++
								}
								dirty = true
							}
						} else if paramStr == "" || paramStr == "1" {
							if pos < len(buf) {
								pos++
								dirty = true
							}
						} else if strings.HasPrefix(paramStr, "1;5") || strings.HasPrefix(paramStr, "1;3") {
							if pos < len(buf) {
								for pos < len(buf) && !unicode.IsSpace(buf[pos]) {
									pos++
								}
								for pos < len(buf) && unicode.IsSpace(buf[pos]) {
									pos++
								}
								dirty = true
							}
						}
					case 'H':
						pos = 0
						dirty = true
					case 'F':
						pos = len(buf)
						dirty = true
					case '~':
						switch paramStr {
						case "1", "7":
							pos = 0
							dirty = true
						case "4", "8":
							pos = len(buf)
							dirty = true
						case "3":
							if pos < len(buf) {
								buf = append(buf[:pos], buf[pos+1:]...)
								dirty = true
							}
						case "3;5", "3;3":
							if pos < len(buf) {
								end := pos
								for end < len(buf) && unicode.IsSpace(buf[end]) {
									end++
								}
								for end < len(buf) && !unicode.IsSpace(buf[end]) {
									end++
								}
								buf = append(buf[:pos], buf[end:]...)
								dirty = true
							}
						}
					}
					continue
				}

				if inPaste {
					continue
				}

				if b2 == 'O' {
					if p.hasPendingInput(50) {
						b3, err := p.reader.ReadByte()
						if err == nil {
							switch b3 {
							case 'H':
								pos = 0
								dirty = true
							case 'F':
								pos = len(buf)
								dirty = true
							case 'D':
								if pos > 0 {
									pos--
									dirty = true
								}
							case 'C':
								if pos < len(buf) {
									pos++
									dirty = true
								}
							}
						}
					}
					continue
				}

				switch b2 {
				case 'b', 'B':
					if pos > 0 {
						for pos > 0 && unicode.IsSpace(buf[pos-1]) {
							pos--
						}
						for pos > 0 && !unicode.IsSpace(buf[pos-1]) {
							pos--
						}
						dirty = true
					}
				case 'f', 'F':
					if pos < len(buf) {
						for pos < len(buf) && !unicode.IsSpace(buf[pos]) {
							pos++
						}
						for pos < len(buf) && unicode.IsSpace(buf[pos]) {
							pos++
						}
						dirty = true
					}
				case 0x7f, 0x08:
					if pos > 0 {
						end := pos
						for pos > 0 && unicode.IsSpace(buf[pos-1]) {
							pos--
						}
						for pos > 0 && !unicode.IsSpace(buf[pos-1]) {
							pos--
						}
						buf = append(buf[:pos], buf[end:]...)
						dirty = true
					}
				case 'd', 'D':
					if pos < len(buf) {
						end := pos
						for end < len(buf) && unicode.IsSpace(buf[end]) {
							end++
						}
						for end < len(buf) && !unicode.IsSpace(buf[end]) {
							end++
						}
						buf = append(buf[:pos], buf[end:]...)
						dirty = true
					}
				}

			case inPaste:
				// Inside bracketed paste, ignore control bytes (< 32, 127) except Ctrl+C and ESC (handled above)
				if b < 32 || b == 127 {
					continue
				}
				r := rune(b)
				if !protocol.NeedsEscape(r) {
					if len(buf) >= maxEditRunes {
						return lineResult{err: errors.New("pasted command exceeds maximum editable length")}
					}
					buf = append(buf[:pos], append([]rune{r}, buf[pos:]...)...)
					pos++
					dirty = true
				}

			case b == 0x04: // Ctrl+D
				if len(buf) == 0 {
					return lineResult{err: errEditCancelled}
				}
				if pos < len(buf) {
					buf = append(buf[:pos], buf[pos+1:]...)
					dirty = true
				}

			case b == 0x7f || b == 0x08: // Backspace
				if pos > 0 {
					buf = append(buf[:pos-1], buf[pos:]...)
					pos--
					dirty = true
				}

			case b == 0x01: // Ctrl+A (Home)
				pos = 0
				dirty = true

			case b == 0x05: // Ctrl+E (End)
				pos = len(buf)
				dirty = true

			case b == 0x02: // Ctrl+B (Left)
				if pos > 0 {
					pos--
					dirty = true
				}

			case b == 0x06: // Ctrl+F (Right)
				if pos < len(buf) {
					pos++
					dirty = true
				}

			case b == 0x0b: // Ctrl+K (Kill to end)
				buf = buf[:pos]
				dirty = true

			case b == 0x15: // Ctrl+U (Clear line)
				buf = buf[:0]
				pos = 0
				dirty = true

			case b == 0x17: // Ctrl+W (Delete word backwards)
				if pos > 0 {
					end := pos
					for pos > 0 && unicode.IsSpace(buf[pos-1]) {
						pos--
					}
					for pos > 0 && !unicode.IsSpace(buf[pos-1]) {
						pos--
					}
					buf = append(buf[:pos], buf[end:]...)
					dirty = true
				}

			case b == 0x0c: // Ctrl+L (Clear screen)
				fmt.Fprint(p.writer, "\033[2J\033[HEdit command (press Enter to run):\r\n")
				redraw()
				dirty = false

			case b >= 32 && b != 127: // Printable ASCII
				r := rune(b)
				if !protocol.NeedsEscape(r) {
					if len(buf) >= maxEditRunes {
						fmt.Fprint(p.writer, "\a")
					} else {
						buf = append(buf[:pos], append([]rune{r}, buf[pos:]...)...)
						pos++
						dirty = true
					}
				}
			}

		case b >= 0x80: // Multi-byte UTF-8 lead byte
			if b < 0xC2 || b > 0xF4 {
				continue
			}
			var utfBuf [utf8.UTFMax]byte
			utfBuf[0] = b
			n := 1
			for !utf8.FullRune(utfBuf[:n]) && n < utf8.UTFMax {
				select {
				case <-req.ctx.Done():
					return lineResult{err: req.ctx.Err()}
				case <-p.done:
					return lineResult{err: errPrompterClosed}
				default:
				}

				if !p.hasPendingInput(50) {
					break
				}
				cb, err := p.reader.ReadByte()
				if err != nil {
					if p.isTTY && errors.Is(err, io.EOF) {
						return lineResult{err: io.EOF}
					}
					p.mu.Lock()
					p.streamErr = err
					p.mu.Unlock()
					return lineResult{err: err}
				}
				if (cb & 0xC0) != 0x80 {
					_ = p.reader.UnreadByte()
					break
				}
				utfBuf[n] = cb
				n++
			}

			if utf8.FullRune(utfBuf[:n]) {
				r, width := utf8.DecodeRune(utfBuf[:n])
				if !(r == utf8.RuneError && width == 1) && unicode.IsPrint(r) && !protocol.NeedsEscape(r) {
					if inPaste && len(buf) >= maxEditRunes {
						return lineResult{err: errors.New("pasted command exceeds maximum editable length")}
					}
					if len(buf) >= maxEditRunes {
						fmt.Fprint(p.writer, "\a")
					} else {
						buf = append(buf[:pos], append([]rune{r}, buf[pos:]...)...)
						pos++
						dirty = true
					}
				}
			}
		}
	}
}

func (p *TerminalPrompter) promptEdit(ctx context.Context, initial string) (string, error) {
	if len([]rune(initial)) > maxEditRunes {
		return "", fmt.Errorf("command exceeds maximum interactive edit length (%d > %d chars)", len([]rune(initial)), maxEditRunes)
	}

	if !p.isTTY || p.file == nil {
		fmt.Fprintf(p.writer, "Edit command (press Enter to run):\n> ")
		line, err := p.readLineWithContext(ctx)
		if err != nil {
			return "", err
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			return initial, nil
		}
		return trimmed, nil
	}

	p.mu.Lock()
	if p.streamErr != nil {
		err := p.streamErr
		p.mu.Unlock()
		return "", err
	}
	p.mu.Unlock()

	res := p.runInteractiveEdit(editRequest{
		initial: initial,
		ctx:     ctx,
	})
	if res.err != nil {
		if ctx.Err() != nil {
			fmt.Fprint(p.writer, "\r\n")
		}
		return "", res.err
	}
	return res.line, nil
}

// PromptPassword prompts the operator for their sudo password without terminal echo.
func (p *TerminalPrompter) PromptPassword(ctx context.Context) ([]byte, error) {
	if !p.enterOp() {
		return nil, errPrompterClosed
	}
	defer p.leaveOp()

	p.mu.Lock()
	if p.streamErr != nil {
		err := p.streamErr
		p.mu.Unlock()
		return nil, err
	}
	p.mu.Unlock()

	if p.isTTY && p.file != nil {
		signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		orig, _ := disableEcho(p.file.Fd())
		signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
		if orig != nil {
			defer func() {
				signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
				_ = restoreTermios(p.file.Fd(), orig)
				signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
			}()
		}

		fmt.Fprintf(p.writer, "🔑 [sudo] Password: ")
		for {
			select {
			case <-ctx.Done():
				fmt.Fprintln(p.writer)
				return nil, ctx.Err()
			case <-p.done:
				fmt.Fprintln(p.writer)
				return nil, errPrompterClosed
			default:
			}
			if !p.hasPendingInput(50) {
				continue
			}
			readFn := p.readPasswordFn
			if readFn == nil {
				readFn = term.ReadPassword
			}
			pw, err := readFn(int(p.file.Fd()))
			fmt.Fprintln(p.writer)
			if err != nil {
				if len(pw) > 0 {
					memclr(pw)
				}
				return nil, err
			}
			return pw, nil
		}
	}

	fmt.Fprintf(p.writer, "🔑 [sudo] Password: ")

	line, err := p.readLineWithContext(ctx)
	fmt.Fprintln(p.writer)
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimRight(line, "\r\n")
	return []byte(trimmed), nil
}

// DrainPendingInput clears any buffered keystrokes from the user-space bufio.Reader
// and drains any pending non-blocking bytes from the terminal file descriptor.
func (p *TerminalPrompter) DrainPendingInput() error {
	p.mu.Lock()
	p.partialLine = p.partialLine[:0]
	p.partialTime = time.Time{}
	p.partialOverflow = false
	p.mu.Unlock()

	if p.file == nil {
		for p.streamReadCh != nil {
			select {
			case res := <-p.streamReadCh:
				p.streamReadCh = nil
				if res.err != nil {
					p.mu.Lock()
					p.streamErr = res.err
					p.mu.Unlock()
					return nil
				}
				if p.reader.Buffered() > 0 {
					_, _ = p.reader.Discard(p.reader.Buffered())
				}
			default:
				// In-flight ReadByte is still waiting on the underlying io.Reader,
				// so bufio.Reader is empty and owned by that goroutine.
				return nil
			}
		}
		if p.reader.Buffered() > 0 {
			_, _ = p.reader.Discard(p.reader.Buffered())
		}
		return nil
	}

	if p.reader.Buffered() > 0 {
		_, _ = p.reader.Discard(p.reader.Buffered())
	}

	if p.isTTY {
		var scratch [256]byte
		for p.hasPendingInput(0) {
			if p.reader.Buffered() > 0 {
				_, _ = p.reader.Discard(p.reader.Buffered())
				continue
			}
			n, err := p.reader.Read(scratch[:])
			if n <= 0 || err != nil {
				break
			}
		}
	}

	return nil
}

// readLineWithContext waits for a line of input or context cancellation.
// It discards any partial input entered before the current prompt was displayed.
func (p *TerminalPrompter) readLineWithContext(ctx context.Context) (string, error) {
	p.mu.Lock()
	if p.streamErr != nil {
		err := p.streamErr
		p.mu.Unlock()
		return "", err
	}
	promptStart := p.promptStartTime
	if len(p.partialLine) > 0 && !promptStart.IsZero() && p.partialTime.Before(promptStart) {
		p.partialLine = p.partialLine[:0]
		p.partialOverflow = false
		p.partialTime = time.Time{}
	}
	p.mu.Unlock()

	if p.file != nil {
		return p.readPollLine(ctx, promptStart)
	}
	return p.readStreamLine(ctx, promptStart)
}

func (p *TerminalPrompter) readPollLine(ctx context.Context, promptStart time.Time) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-p.done:
			return "", errPrompterClosed
		default:
		}

		if !p.hasPendingInput(50) {
			continue
		}

		b, err := p.reader.ReadByte()
		now := time.Now()
		if err != nil {
			if p.isTTY && errors.Is(err, io.EOF) {
				p.mu.Lock()
				p.partialLine = p.partialLine[:0]
				p.partialOverflow = false
				p.partialTime = time.Time{}
				p.mu.Unlock()
				return "", io.EOF
			}
			p.mu.Lock()
			p.streamErr = err
			p.mu.Unlock()
			return "", err
		}

		line, done, lineErr := p.appendLineByte(b, now, promptStart)
		if done {
			return line, lineErr
		}
	}
}

func (p *TerminalPrompter) readStreamLine(ctx context.Context, promptStart time.Time) (string, error) {
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-p.done:
			return "", errPrompterClosed
		default:
		}

		for p.streamReadCh == nil && p.reader.Buffered() > 0 {
			b, err := p.reader.ReadByte()
			now := time.Now()
			if err != nil {
				p.mu.Lock()
				p.streamErr = err
				p.mu.Unlock()
				return "", err
			}
			line, done, lineErr := p.appendLineByte(b, now, promptStart)
			if done {
				return line, lineErr
			}
		}

		if p.streamReadCh == nil {
			ch := make(chan streamByte, 1)
			p.streamReadCh = ch
			go func() {
				b, err := p.reader.ReadByte()
				ch <- streamByte{b: b, err: err, at: time.Now()}
			}()
		}

		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-p.done:
			return "", errPrompterClosed
		case res := <-p.streamReadCh:
			p.streamReadCh = nil
			if res.err != nil {
				p.mu.Lock()
				p.streamErr = res.err
				p.mu.Unlock()
				return "", res.err
			}
			line, done, lineErr := p.appendLineByte(res.b, res.at, promptStart)
			if done {
				return line, lineErr
			}
		}
	}
}

func (p *TerminalPrompter) appendLineByte(b byte, now, promptStart time.Time) (string, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.partialLine) > 0 && !promptStart.IsZero() && p.partialTime.Before(promptStart) {
		p.partialLine = p.partialLine[:0]
		p.partialOverflow = false
		p.partialTime = now
	}
	if len(p.partialLine) == 0 {
		p.partialTime = now
	}
	if b == '\n' {
		overflow := p.partialOverflow
		line := string(p.partialLine) + "\n"
		p.partialLine = p.partialLine[:0]
		p.partialOverflow = false
		p.partialTime = time.Time{}
		if overflow {
			return "", true, errors.New("input line exceeds maximum length")
		}
		return line, true, nil
	}
	if len(p.partialLine) < maxLineBuf {
		p.partialLine = append(p.partialLine, b)
	} else {
		p.partialOverflow = true
	}
	return "", false, nil
}

// handleContextErr prints and returns appropriate cancellation or timeout decisions.
func (p *TerminalPrompter) handleContextErr(ctx context.Context, timeoutMsg string) (ApprovalDecision, string, string, error) {
	p.mu.Lock()
	p.lastAbortTime = time.Now()
	p.mu.Unlock()

	if errors.Is(context.Cause(ctx), ErrClientDisconnected) {
		fmt.Fprintln(p.writer, "\n🔌 Agent disconnected — request cancelled.")
		return DecisionReject, "", "Agent disconnected — request cancelled", context.Cause(ctx)
	}
	if errors.Is(context.Cause(ctx), ErrServerShutdown) {
		fmt.Fprintln(p.writer, "\n🔴 Server shutting down — request cancelled.")
		return DecisionReject, "", "Server is shutting down", context.Cause(ctx)
	}
	fmt.Fprintf(p.writer, "\n⏳ %s\n", timeoutMsg)
	return DecisionTimeout, "", timeoutMsg, ctx.Err()
}

// Prompt presents the request to the human operator and collects an explicit decision.
func (p *TerminalPrompter) Prompt(ctx context.Context, req protocol.CommandRequest) (ApprovalDecision, string, string, error) {
	if !p.enterOp() {
		fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
		return DecisionReject, "", "Input stream closed or unavailable (EOF)", errPrompterClosed
	}
	defer p.leaveOp()
	if p.isTTY && p.file != nil {
		if fg, err := unix.IoctlGetInt(int(p.file.Fd()), unix.TIOCGPGRP); err == nil && fg > 0 {
			if fg != syscall.Getpgrp() {
				fmt.Fprintln(p.writer, "\n❌ Server process is running in background. Request rejected.")
				return DecisionReject, "", "Server process is running in background", errors.New("terminal prompter not in foreground process group")
			}
		}
	}

	p.mu.Lock()
	lastAbort := p.lastAbortTime
	p.mu.Unlock()
	if p.isTTY && !lastAbort.IsZero() {
		if elapsed := time.Since(lastAbort); elapsed < 300*time.Millisecond {
			rem := 300*time.Millisecond - elapsed
			select {
			case <-time.After(rem):
			case <-ctx.Done():
				return p.handleContextErr(ctx, "Cancelled during cooldown")
			}
		}
	}

	p.mu.Lock()
	streamErr := p.streamErr
	p.mu.Unlock()

	if streamErr != nil {
		fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
		return DecisionReject, "", "Input stream closed or unavailable (EOF)", streamErr
	}

	// Drain stale keystrokes so Enter pressed while idle does NOT approve this request.
	// Fail closed if the terminal input queue cannot be flushed.
	if err := p.DrainPendingInput(); err != nil {
		fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
		return DecisionReject, "", "cannot flush terminal input", err
	}

	p.mu.Lock()
	streamErr = p.streamErr
	p.mu.Unlock()
	if streamErr != nil {
		fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
		return DecisionReject, "", "Input stream closed or unavailable (EOF)", streamErr
	}

	// Sanitize all untrusted agent inputs without deleting bytes
	cleanReason := protocol.SanitizeTerminalText(req.Reason)
	cleanCmd := protocol.FormatCommand(req.Command, req.Args)
	cleanCwd := protocol.SanitizeTerminalText(req.Cwd)
	displayCwd := cleanCwd
	if len([]rune(displayCwd)) > 240 {
		displayCwd = string([]rune(displayCwd)[:240]) + "... [truncated]"
	}
	targetCwd := cleanCwd
	if len([]rune(targetCwd)) > 80 {
		targetCwd = string([]rune(targetCwd)[:80]) + "... [truncated]"
	}

	// Sanitize and render environment variables as defense-in-depth for standalone Prompter callers
	// (note: Server rejects requests with non-empty Env upfront before prompting).
	cleanEnv, blockedKeys := protocol.SanitizeEnv(req.Env)

	displayReason := cleanReason
	if len([]rune(cleanReason)) > 500 {
		displayReason = string([]rune(cleanReason)[:500]) + "... [truncated]"
	}

	fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	fmt.Fprintln(p.writer, "🔔 LMDTFY Command Execution Request:")
	fmt.Fprintf(p.writer, "   Reason:  %s\n", p.colorBlue(displayReason))
	fmt.Fprintf(p.writer, "   Command: %s\n", p.colorGreen(cleanCmd))
	if cleanCwd != "" {
		cwdWarning := ""
		if st, err := os.Stat(req.Cwd); err != nil || !st.IsDir() {
			cwdWarning = " " + p.colorRed("(⚠️ Directory does not exist locally — execution will fail unless directory exists)")
		} else {
			if evalCwd, err := filepath.EvalSymlinks(req.Cwd); err == nil {
				if realCwd, err := filepath.Abs(evalCwd); err == nil && realCwd != req.Cwd {
					sanitizedReal := protocol.SanitizeTerminalText(realCwd)
					if len([]rune(sanitizedReal)) > 240 {
						sanitizedReal = string([]rune(sanitizedReal)[:240]) + "... [truncated]"
					}
					cwdWarning = " " + p.colorBlue(fmt.Sprintf("(-> %s)", sanitizedReal))
				}
			}
		}
		fmt.Fprintf(p.writer, "   Cwd:     %s%s\n", p.colorBlue(displayCwd), cwdWarning)
	}

	// Sanitize every blocked key so terminal escapes (CSI/OSC) cannot spoof output
	if len(blockedKeys) > 0 {
		sanitizedBlocked := make([]string, len(blockedKeys))
		for i, k := range blockedKeys {
			sanitizedBlocked[i] = protocol.SanitizeTerminalText(k)
		}
		fmt.Fprintf(p.writer, "   %s %s\n", p.colorRed("⚠️  BLOCKED DANGEROUS / MALFORMED ENV VARS:"), strings.Join(sanitizedBlocked, ", "))
	}

	// Display clean environment variables in deterministic sorted order
	if len(cleanEnv) > 0 {
		fmt.Fprintln(p.writer, "   Environment:")
		sortedKeys := make([]string, 0, len(cleanEnv))
		for k := range cleanEnv {
			sortedKeys = append(sortedKeys, k)
		}
		sort.Strings(sortedKeys)
		for _, k := range sortedKeys {
			fmt.Fprintf(p.writer, "      %s=%s\n", protocol.SanitizeTerminalText(k), protocol.SanitizeTerminalText(cleanEnv[k]))
		}
	}
	fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	if len(cleanCmd) > 300 || len(cleanReason) > 300 || len(cleanCwd) > 200 {
		cmdRunes := []rune(cleanCmd)
		cmdPreview := cleanCmd
		if len(cmdRunes) > 160 {
			cmdPreview = string(cmdRunes[:100]) + " ... [truncated] ... " + string(cmdRunes[len(cmdRunes)-60:])
			fmt.Fprintf(p.writer, "   %s\n", p.colorRed(fmt.Sprintf("⚠️  Full command exceeds viewport (%d chars, %d args) — scroll up to inspect before approving", len(cmdRunes), len(req.Args))))
		}
		if cleanCwd != "" {
			fmt.Fprintf(p.writer, "   Target:  %s (cwd: %s)\n", cmdPreview, targetCwd)
		} else {
			fmt.Fprintf(p.writer, "   Target:  %s\n", cmdPreview)
		}
		fmt.Fprintln(p.writer, "────────────────────────────────────────────────────────────")
	}

	// Set promptStartTime AFTER DrainPendingInput and after the banner is presented to the operator
	p.mu.Lock()
	p.promptStartTime = time.Now()
	p.mu.Unlock()

	for {
		fmt.Fprintf(p.writer, "Approve execution? [%s] Run  [%s] Edit  [%s] Reject: ", p.colorBold("y"), p.colorBold("e"), p.colorBold("n"))
		line, err := p.readLineWithContext(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return p.handleContextErr(ctx, "Timed out waiting for operator approval.")
			}
			// On EOF / dead stdin / read error, NEVER auto-approve! Always reject.
			p.mu.Lock()
			p.lastAbortTime = time.Now()
			p.mu.Unlock()
			fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
			return DecisionReject, "", "Input stream closed or unavailable (EOF)", err
		}

		choice := strings.TrimSpace(strings.ToLower(line))
		switch choice {
		case "y", "yes":
			return DecisionApprove, "", "", nil

		case "e", "edit":
			if len([]rune(cleanCmd)) > maxEditRunes {
				fmt.Fprintf(p.writer, "⚠️  Command exceeds maximum interactive edit length (%d > %d chars). Please choose [%s] Run or [%s] Reject.\n", len([]rune(cleanCmd)), maxEditRunes, p.colorBold("y"), p.colorBold("n"))
				if err := p.DrainPendingInput(); err != nil {
					fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
					return DecisionReject, "", "cannot flush terminal input", err
				}
				p.mu.Lock()
				p.promptStartTime = time.Now()
				p.mu.Unlock()
				continue
			}

			edited, err := p.promptEdit(ctx, cleanCmd)
			if err != nil {
				if ctx.Err() != nil {
					return p.handleContextErr(ctx, "Timed out waiting for operator input during edit")
				}
				p.mu.Lock()
				p.lastAbortTime = time.Now()
				p.mu.Unlock()
				if errors.Is(err, errPrompterBackground) {
					fmt.Fprintln(p.writer, "\n❌ Server process is running in background. Request rejected.")
					return DecisionReject, "", "Server process is running in background", err
				}
				if errors.Is(err, errPrompterClosed) {
					fmt.Fprintln(p.writer, "\n🔴 Prompter closed — request cancelled.")
					return DecisionReject, "", "Prompter closed", err
				}
				if errors.Is(err, io.EOF) {
					fmt.Fprintln(p.writer, "\n❌ Non-interactive or closed input stream. Request rejected.")
					return DecisionReject, "", "Input stream closed or unavailable (EOF)", err
				}
				fmt.Fprintln(p.writer, "❌ Request cancelled.")
				return DecisionReject, "", "Cancelled by operator", nil
			}
			edited = strings.TrimSpace(edited)
			if edited == "" {
				fmt.Fprintln(p.writer, "No command entered. Please choose again.")
				if err := p.DrainPendingInput(); err != nil {
					fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
					return DecisionReject, "", "cannot flush terminal input", err
				}
				p.mu.Lock()
				p.promptStartTime = time.Now()
				p.mu.Unlock()
				continue
			}
			return DecisionEdit, edited, "", nil

		case "n", "no":
			fmt.Fprintf(p.writer, "Reject reason (optional): ")
			reason, err := p.readLineWithContext(ctx)
			if err != nil {
				// Operator explicitly rejected; timeout/EOF during optional reason must NOT flip decision to Timeout
				p.mu.Lock()
				p.lastAbortTime = time.Now()
				p.mu.Unlock()
				fmt.Fprintln(p.writer)
				return DecisionReject, "", "Declined by operator", nil
			}
			reason = strings.TrimSpace(reason)
			if reason == "" {
				reason = "Declined by operator"
			}
			fmt.Fprintln(p.writer, "❌ Request rejected.")
			return DecisionReject, "", reason, nil

		case "":
			// Explicitly reject empty enter as approval
			fmt.Fprintln(p.writer, "Empty response. Please explicitly type 'y', 'e', or 'n'.")
			if err := p.DrainPendingInput(); err != nil {
				fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
				return DecisionReject, "", "cannot flush terminal input", err
			}
			p.mu.Lock()
			p.promptStartTime = time.Now()
			p.mu.Unlock()

		default:
			fmt.Fprintln(p.writer, "Invalid input. Please enter 'y', 'e', or 'n'.")
			if err := p.DrainPendingInput(); err != nil {
				fmt.Fprintf(p.writer, "\n❌ Terminal input queue flush failed: %v. Request rejected for safety.\n", err)
				return DecisionReject, "", "cannot flush terminal input", err
			}
			p.mu.Lock()
			p.promptStartTime = time.Now()
			p.mu.Unlock()
		}
	}
}
