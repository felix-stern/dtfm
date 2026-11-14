// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package main

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

const pollCloseEvents = unix.POLLHUP | unix.POLLERR | unix.POLLNVAL

// hasQueuedPeerEOF probes EVFILT_READ via kqueue when poll(2) reports POLLIN and unread
// bytes remain in the kernel socket receive queue, detecting peer half-close (SHUT_WR / FIN -> EV_EOF)
// on Darwin/BSD where POLLRDHUP is unavailable.
func hasQueuedPeerEOF(fd uintptr) bool {
	syscall.ForkLock.RLock()
	kq, err := unix.Kqueue()
	if err == nil {
		unix.CloseOnExec(kq)
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return false
	}
	defer func() { _ = unix.Close(kq) }()

	var change [1]unix.Kevent_t
	unix.SetKevent(&change[0], int(fd), unix.EVFILT_READ, unix.EV_ADD|unix.EV_ONESHOT)

	var events [1]unix.Kevent_t
	var zeroTimeout unix.Timespec
	for {
		n, kerr := unix.Kevent(kq, change[:], events[:], &zeroTimeout)
		if errors.Is(kerr, syscall.EINTR) {
			continue
		}
		if kerr != nil || n <= 0 {
			return false
		}
		return events[0].Flags&(unix.EV_EOF|unix.EV_ERROR) != 0
	}
}
