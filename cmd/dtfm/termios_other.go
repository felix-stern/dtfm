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

func getTermios(fd uintptr) (*termiosState, error) {
	return nil, errors.New("termios not supported on this platform")
}

func restoreTermios(fd uintptr, t *termiosState) error {
	return nil
}

func setRawMode(fd uintptr) (*termiosState, error) {
	return nil, errors.New("raw mode not supported on this platform")
}

func disableEcho(fd uintptr) (*termiosState, error) {
	return nil, errors.New("termios not supported on this platform")
}
