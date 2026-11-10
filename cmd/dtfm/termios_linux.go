//go:build linux

package main

import (
	"golang.org/x/sys/unix"
)

type termiosState = unix.Termios

// flushTTYInput flushes unread input from the terminal's kernel input queue.
func flushTTYInput(fd uintptr) error {
	return unix.IoctlSetInt(int(fd), unix.TCFLSH, unix.TCIFLUSH)
}

// getTermios retrieves the current terminal settings.
func getTermios(fd uintptr) (*termiosState, error) {
	return unix.IoctlGetTermios(int(fd), unix.TCGETS)
}

// restoreTermios restores terminal settings and flushes pending input (TCSAFLUSH).
func restoreTermios(fd uintptr, t *termiosState) error {
	if t == nil {
		return nil
	}
	return unix.IoctlSetTermios(int(fd), unix.TCSETSF, t)
}

// disableSusp disables the terminal VSUSP control character (Ctrl+Z) while a child process runs.
func disableSusp(fd uintptr, t *termiosState) {
	if t == nil {
		return
	}
	cp := *t
	cp.Cc[unix.VSUSP] = 0
	_ = unix.IoctlSetTermios(int(fd), unix.TCSETSF, &cp)
}
