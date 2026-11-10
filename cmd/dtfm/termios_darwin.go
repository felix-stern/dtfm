//go:build darwin

package main

import (
	"golang.org/x/sys/unix"
)

type termiosState = unix.Termios

// flushTTYInput flushes unread input from the terminal's kernel input queue on macOS.
func flushTTYInput(fd uintptr) error {
	// TIOCFLUSH on Darwin/BSD takes a pointer to an int with flags (1 = FREAD / TIOCPKT_FLUSHREAD).
	return unix.IoctlSetPointerInt(int(fd), unix.TIOCFLUSH, 1)
}

// getTermios retrieves the current terminal settings on macOS.
func getTermios(fd uintptr) (*termiosState, error) {
	return unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
}

// restoreTermios restores terminal settings and flushes pending input (TCSAFLUSH) on macOS.
func restoreTermios(fd uintptr, t *termiosState) error {
	if t == nil {
		return nil
	}
	return unix.IoctlSetTermios(int(fd), unix.TIOCSETAF, t)
}

// disableSusp disables the terminal VSUSP and VDSUSP control characters (Ctrl+Z and Ctrl+Y) while a child process runs on macOS.
func disableSusp(fd uintptr, t *termiosState) {
	if t == nil {
		return
	}
	cp := *t
	// On Darwin, _POSIX_VDISABLE is 0xff (255), not 0 (0 rebinds VSUSP to Ctrl+@/NUL).
	cp.Cc[unix.VSUSP] = 0xff
	cp.Cc[unix.VDSUSP] = 0xff
	_ = unix.IoctlSetTermios(int(fd), unix.TIOCSETAF, &cp)
}
