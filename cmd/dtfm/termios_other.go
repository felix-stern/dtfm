// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

type termiosState struct{}

// isTerminalFD returns true if the file descriptor refers to an actual terminal device.
func isTerminalFD(fd uintptr) bool {
	_, err := unix.IoctlGetWinsize(int(fd), unix.TIOCGWINSZ)
	return err == nil
}

func flushTTYInput(fd uintptr) error {
	return errors.New("TTY input flush not supported on this platform")
}

func getTermios(fd uintptr) (*termiosState, error) {
	return nil, errors.New("termios not supported on this platform")
}

func restoreTermios(fd uintptr, t *termiosState) error {
	return nil
}

func disableSusp(fd uintptr, t *termiosState) {}

func setRawMode(fd uintptr) (*termiosState, error) {
	return nil, errors.New("raw mode not supported on this platform")
}
