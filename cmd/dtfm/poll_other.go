// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd

package main

import (
	"golang.org/x/sys/unix"
)

const pollCloseEvents = unix.POLLHUP | unix.POLLERR | unix.POLLNVAL

func hasQueuedPeerEOF(_ uintptr) bool {
	return false
}
