//go:build linux

package main

import (
	"golang.org/x/sys/unix"
)

const pollCloseEvents = unix.POLLHUP | unix.POLLRDHUP | unix.POLLERR
