// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package main

import (
	"golang.org/x/sys/unix"
)

type termiosState = unix.Termios

// isTerminalFD returns true if the file descriptor refers to an actual terminal device.
func isTerminalFD(fd uintptr) bool {
	_, err := getTermios(fd)
	return err == nil
}

// flushTTYInput flushes unread input from the terminal's kernel input queue on macOS.
func flushTTYInput(fd uintptr) error {
	// TIOCFLUSH on Darwin/BSD takes a pointer to an int with flags (1 = FREAD / TIOCPKT_FLUSHREAD).
	return unix.IoctlSetPointerInt(int(fd), unix.TIOCFLUSH, 1)
}

// getTermios retrieves the current terminal settings on macOS.
func getTermios(fd uintptr) (*termiosState, error) {
	return unix.IoctlGetTermios(int(fd), unix.TIOCGETA)
}

// restoreTermios restores terminal settings on macOS.
func restoreTermios(fd uintptr, t *termiosState) error {
	if t == nil {
		return nil
	}
	_ = flushTTYInput(fd)
	return unix.IoctlSetTermios(int(fd), unix.TIOCSETA, t)
}

// setRawMode puts the terminal into raw mode for line editing on macOS, returning the previous state.
func setRawMode(fd uintptr) (*termiosState, error) {
	orig, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	raw := *orig
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	raw.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	raw.Cflag &^= unix.CSIZE | unix.PARENB
	raw.Cflag |= unix.CS8
	raw.Cc[unix.VMIN] = 1
	raw.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(int(fd), unix.TIOCSETA, &raw); err != nil {
		return nil, err
	}
	return orig, nil
}

// disableEcho disables terminal input echoing (ECHO/ECHONL) on macOS, returning the previous state.
func disableEcho(fd uintptr) (*termiosState, error) {
	orig, err := getTermios(fd)
	if err != nil {
		return nil, err
	}
	noEcho := *orig
	noEcho.Lflag &^= unix.ECHO | unix.ECHONL
	if err := unix.IoctlSetTermios(int(fd), unix.TIOCSETA, &noEcho); err != nil {
		return nil, err
	}
	return orig, nil
}
