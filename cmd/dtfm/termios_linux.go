// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

//go:build linux

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

// setRawMode puts the terminal into raw mode for line editing, returning the previous state.
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
	if err := unix.IoctlSetTermios(int(fd), unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return orig, nil
}
