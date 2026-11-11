// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package main

import "errors"

type termiosState struct{}

func flushTTYInput(fd uintptr) error {
	return errors.New("TTY input flush not supported on this platform")
}

func getTermios(fd uintptr) (*termiosState, error) {
	return nil, nil
}

func restoreTermios(fd uintptr, t *termiosState) error {
	return nil
}

func disableSusp(fd uintptr, t *termiosState) {}
