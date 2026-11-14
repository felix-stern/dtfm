// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type lineResult struct {
	line      string
	err       error
	timestamp time.Time
}

type editRequest struct {
	initial string
	resp    chan lineResult
	ctx     context.Context
}

func (p *TerminalPrompter) readLoop() {
	defer close(p.loopDone)
	var lineBuf []byte
	var lineStartTime time.Time
	overflow := false

	for {
		// Wait until Prompt() explicitly requests a line
		select {
		case <-p.wantLine:
		case req := <-p.wantEdit:
			res := p.runInteractiveEdit(req)
			p.mu.Lock()
			p.reading = false
			p.mu.Unlock()
			req.resp <- res
			continue
		case <-p.done:
			return
		}

		for {
			select {
			case <-p.done:
				return
			default:
			}

			// When reading from an OS terminal / file, poll with 50ms timeout so Close()
			// or stream closure can interrupt within 50ms without blocking forever
			if p.file != nil && !p.hasPendingInput(50) {
				continue
			}

			b, err := p.reader.ReadByte()
			now := time.Now()

			if err != nil {
				p.mu.Lock()
				p.reading = false
				p.mu.Unlock()

				if p.isTTY && errors.Is(err, io.EOF) {
					// On a terminal, Ctrl+D delivers EOF without closing /dev/tty.
					// Discard partial line, send EOF to cancel active prompt, but keep readLoop alive.
					lineBuf = lineBuf[:0]
					overflow = false
					select {
					case p.linesChan <- lineResult{err: io.EOF, timestamp: now}:
					case <-p.done:
						return
					}
					break
				}

				p.mu.Lock()
				p.streamErr = err
				p.mu.Unlock()

				select {
				case p.linesChan <- lineResult{line: string(lineBuf), err: err, timestamp: now}:
				case <-p.done:
				}
				return
			}

			p.mu.Lock()
			promptStart := p.promptStartTime
			p.mu.Unlock()

			if len(lineBuf) > 0 && !promptStart.IsZero() && lineStartTime.Before(promptStart) {
				// Partial keystrokes from an earlier cancelled/timed-out prompt must be discarded
				lineBuf = lineBuf[:0]
				overflow = false
				lineStartTime = now
			}

			if len(lineBuf) == 0 {
				lineStartTime = now
			}

			if b == '\n' {
				p.mu.Lock()
				p.reading = false
				p.mu.Unlock()

				var res lineResult
				if overflow {
					res = lineResult{err: errors.New("input line exceeds maximum length"), timestamp: lineStartTime}
					overflow = false
				} else {
					res = lineResult{line: string(lineBuf) + "\n", timestamp: lineStartTime}
				}
				lineBuf = lineBuf[:0]

				select {
				case p.linesChan <- res:
				case <-p.done:
					return
				}
				break
			}

			if len(lineBuf) < maxLineBuf {
				lineBuf = append(lineBuf, b)
			} else {
				overflow = true
			}
		}
	}
}

// requestLine signals readLoop to read exactly one line if not already reading.
func (p *TerminalPrompter) requestLine() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.reading || p.streamErr != nil {
		return
	}

	select {
	case p.wantLine <- struct{}{}:
		p.reading = true
	default:
	}
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

func (p *TerminalPrompter) drainLinesChan() {
	for {
		select {
		case res := <-p.linesChan:
			if res.err != nil && !(p.isTTY && errors.Is(res.err, io.EOF)) {
				p.mu.Lock()
				p.streamErr = res.err
				p.mu.Unlock()
			}
		default:
			return
		}
	}
}

// DrainPendingInput clears any queued keystrokes from the lines channel, the user-space
// bufio.Reader buffer, and the OS kernel input queue.
func (p *TerminalPrompter) DrainPendingInput() error {
	// 1. Drain pending lines already in the Go channel, preserving any terminal error
	p.drainLinesChan()

	// 2. Unconditionally flush OS kernel terminal buffer whenever isTTY && file != nil.
	// (flushTTYInput is a driver ioctl that safely flushes the kernel queue even while read() is in flight)
	if p.isTTY && p.file != nil {
		signal.Ignore(syscall.SIGTTOU, syscall.SIGTTIN)
		err := flushTTYInput(p.file.Fd())
		signal.Reset(syscall.SIGTTOU, syscall.SIGTTIN)
		if err != nil {
			return fmt.Errorf("failed to flush terminal input queue: %w", err)
		}
	}

	// 3. Re-drain channel once after flushing kernel queue
	p.drainLinesChan()

	p.mu.Lock()
	if !p.reading && p.reader.Buffered() > 0 {
		_, _ = p.reader.Discard(p.reader.Buffered())
	}
	p.mu.Unlock()

	return nil
}

// readLineWithContext waits for a line of input or context cancellation.
// It discards any line entered before the current prompt was displayed.
func (p *TerminalPrompter) readLineWithContext(ctx context.Context) (string, error) {
	for {
		// First check if there is an already queued line in linesChan
		select {
		case res := <-p.linesChan:
			if res.err != nil {
				return "", res.err
			}
			p.mu.Lock()
			start := p.promptStartTime
			p.mu.Unlock()
			if !start.IsZero() && res.timestamp.Before(start) {
				// Discard stale keystroke entered before prompt was presented
				continue
			}
			return res.line, nil
		case <-p.done:
			return "", errPrompterClosed
		case <-p.loopDone:
			return "", errPrompterClosed
		default:
		}

		p.mu.Lock()
		err := p.streamErr
		p.mu.Unlock()
		if err != nil {
			return "", err
		}

		// Request readLoop to read next line on demand
		p.requestLine()

		// Wait for line from readLoop, context cancellation, or prompter close
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-p.done:
			return "", errPrompterClosed
		case <-p.loopDone:
			return "", errPrompterClosed
		case res := <-p.linesChan:
			if res.err != nil {
				return "", res.err
			}
			p.mu.Lock()
			start := p.promptStartTime
			p.mu.Unlock()
			if !start.IsZero() && res.timestamp.Before(start) {
				// Discard stale keystroke entered before prompt was presented
				continue
			}
			return res.line, nil
		}
	}
}
