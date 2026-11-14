// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import "os"

func (p *TerminalPrompter) useColor() bool {
	return p.isTTY && os.Getenv("NO_COLOR") == ""
}

func (p *TerminalPrompter) colorBlue(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;34m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorGreen(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;32m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorRed(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1;31m" + s + "\033[0m"
}

func (p *TerminalPrompter) colorBold(s string) string {
	if !p.useColor() {
		return s
	}
	return "\033[1m" + s + "\033[0m"
}
