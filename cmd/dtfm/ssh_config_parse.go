// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math"
	"strings"
)

// parseSSHDirective parses a single line of OpenSSH configuration.
// It strips unquoted comments, extracts keyword and arguments (supporting whitespace and '=' delimiters),
// and unquotes double-quoted arguments and keywords.
func parseSSHDirective(line string) (keyword string, args []string, ok bool) {
	inQuotes := false
	commentIdx := -1
	runes := []rune(line)
	for i, r := range runes {
		if r == '"' {
			inQuotes = !inQuotes
		} else if r == '#' && !inQuotes {
			commentIdx = i
			break
		}
	}
	if commentIdx != -1 {
		runes = runes[:commentIdx]
	}

	start := 0
	for start < len(runes) && (runes[start] == ' ' || runes[start] == '\t' || runes[start] == '\r' || runes[start] == '\n') {
		start++
	}
	end := len(runes)
	for end > start && (runes[end-1] == ' ' || runes[end-1] == '\t' || runes[end-1] == '\r' || runes[end-1] == '\n') {
		end--
	}
	if start >= end {
		return "", nil, false
	}
	runes = runes[start:end]

	i := 0
	if runes[0] == '"' {
		i++
		kwStart := i
		for i < len(runes) && runes[i] != '"' {
			i++
		}
		keyword = string(runes[kwStart:i])
		if i < len(runes) && runes[i] == '"' {
			i++
		}
	} else {
		for i < len(runes) && runes[i] != ' ' && runes[i] != '\t' && runes[i] != '=' {
			i++
		}
		keyword = string(runes[:i])
	}
	if keyword == "" {
		return "", nil, false
	}

	for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t') {
		i++
	}
	if i < len(runes) && runes[i] == '=' {
		i++
		for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
	}

	for i < len(runes) {
		for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
		if i >= len(runes) {
			break
		}

		if runes[i] == '"' {
			i++ // skip opening quote
			argStart := i
			for i < len(runes) && runes[i] != '"' {
				i++
			}
			args = append(args, string(runes[argStart:i]))
			if i < len(runes) && runes[i] == '"' {
				i++ // skip closing quote
			}
		} else {
			argStart := i
			for i < len(runes) && runes[i] != ' ' && runes[i] != '\t' {
				i++
			}
			args = append(args, string(runes[argStart:i]))
		}
	}

	return keyword, args, true
}

func isLmdtfyRemoteForward(keyword string, args []string) bool {
	if !strings.EqualFold(keyword, "RemoteForward") || len(args) == 0 {
		return false
	}
	remoteArg := args[0]
	return remoteArg == "lmdtfy.sock" || strings.HasSuffix(remoteArg, "/lmdtfy.sock")
}

// UpdateSSHConfig parses existing ssh_config content, updating the matching Host block
// or inserting a new one before any catch-all section.
func UpdateSSHConfig(originalContent string, host string, user string, remoteUID uint32, localSocket string) (string, error) {
	cleanHost, cleanUser, err := resolveHostAndUser(host, user)
	if err != nil {
		return "", err
	}
	if remoteUID >= math.MaxUint32 {
		return "", fmt.Errorf("remoteUID cannot be %d ((uid_t)-1)", remoteUID)
	}

	canonSocket, err := validateAndCanonicalizeLocalSocket(localSocket)
	if err != nil {
		return "", err
	}
	formattedSocket := formatSSHPathArg(canonSocket)

	useCRLF := strings.Contains(originalContent, "\r\n")
	eol := "\n"
	if useCRLF {
		eol = "\r\n"
	}

	rawLines := strings.Split(strings.ReplaceAll(originalContent, "\r\n", "\n"), "\n")
	hasTrailingNewline := len(rawLines) > 0 && rawLines[len(rawLines)-1] == ""
	if hasTrailingNewline {
		rawLines = rawLines[:len(rawLines)-1]
	}

	type section struct {
		startIdx    int
		endIdx      int
		isHost      bool
		isExactHost bool
		isCatchAll  bool
	}

	var sections []section
	var currentSec *section

	for i, line := range rawLines {
		kw, args, ok := parseSSHDirective(line)
		if !ok {
			continue
		}

		if strings.EqualFold(kw, "Host") {
			if currentSec != nil {
				currentSec.endIdx = i
				sections = append(sections, *currentSec)
			}
			isExact := len(args) == 1 && args[0] == cleanHost && !strings.ContainsAny(args[0], "*?!")
			isCatchAll := false
			for _, pat := range args {
				if strings.ContainsAny(pat, "*?") {
					isCatchAll = true
					break
				}
			}
			if len(args) > 1 {
				for _, pat := range args {
					if pat == cleanHost {
						isCatchAll = true
						break
					}
				}
			}
			currentSec = &section{
				startIdx:    i,
				endIdx:      len(rawLines),
				isHost:      true,
				isExactHost: isExact,
				isCatchAll:  isCatchAll,
			}
		} else if strings.EqualFold(kw, "Match") {
			if currentSec != nil {
				currentSec.endIdx = i
				sections = append(sections, *currentSec)
			}
			isCatchAll := true
			currentSec = &section{
				startIdx:    i,
				endIdx:      len(rawLines),
				isHost:      false,
				isExactHost: false,
				isCatchAll:  isCatchAll,
			}
		}
	}
	if currentSec != nil {
		currentSec.endIdx = len(rawLines)
		sections = append(sections, *currentSec)
	}

	var exactHostSecIndices []int
	for idx, s := range sections {
		if s.isExactHost {
			exactHostSecIndices = append(exactHostSecIndices, idx)
		}
	}

	// Case 1: No exact single-host Host block exists -> insert before first catch-all or append at EOF
	if len(exactHostSecIndices) == 0 {
		snippet, err := GenerateSnippet(cleanHost, cleanUser, remoteUID, canonSocket)
		if err != nil {
			return "", err
		}
		if useCRLF {
			snippet = strings.ReplaceAll(snippet, "\n", "\r\n")
		}

		firstCatchAllLine := -1
		for _, s := range sections {
			if s.isCatchAll {
				firstCatchAllLine = s.startIdx
				break
			}
		}

		if firstCatchAllLine != -1 {
			// Walk back across contiguous comments immediately above the catch-all header
			insertLine := firstCatchAllLine
			for insertLine > 0 {
				prevLine := strings.TrimSpace(rawLines[insertLine-1])
				if strings.HasPrefix(prevLine, "#") {
					insertLine--
				} else {
					break
				}
			}
			firstCatchAllLine = insertLine

			var resultLines []string
			resultLines = append(resultLines, rawLines[:firstCatchAllLine]...)

			if len(resultLines) > 0 && strings.TrimSpace(resultLines[len(resultLines)-1]) != "" {
				resultLines = append(resultLines, "")
			}

			snippetLines := strings.Split(strings.TrimRight(snippet, "\r\n"), "\n")
			for _, sl := range snippetLines {
				resultLines = append(resultLines, strings.TrimRight(sl, "\r"))
			}

			resultLines = append(resultLines, "")
			resultLines = append(resultLines, rawLines[firstCatchAllLine:]...)

			res := strings.Join(resultLines, eol) + eol
			return res, nil
		}

		// Append at EOF
		trimmedOriginal := strings.TrimRight(originalContent, "\r\n")
		if trimmedOriginal == "" {
			return snippet, nil
		}
		return trimmedOriginal + eol + eol + snippet, nil
	}

	// Case 2: One or more exact single-host Host blocks exist.
	// Update the first exact Host block in-place, and strip any stale lmdtfy RemoteForwards from subsequent exact blocks.
	primarySec := sections[exactHostSecIndices[0]]
	blockLines := rawLines[primarySec.startIdx:primarySec.endIdx]

	hasDtfmComment := false
	if primarySec.startIdx > 0 && strings.TrimSpace(rawLines[primarySec.startIdx-1]) == dtfmHeaderComment {
		hasDtfmComment = true
	}
	for _, bLine := range blockLines {
		if strings.TrimSpace(bLine) == dtfmHeaderComment {
			hasDtfmComment = true
			break
		}
	}

	indent := "    "
	var rfRelativeIndices []int
	var slbuRelativeIndices []int
	var userRelativeIndices []int

	for rIdx := 1; rIdx < len(blockLines); rIdx++ {
		bLine := blockLines[rIdx]
		trimmed := strings.TrimSpace(bLine)
		if trimmed == "" {
			continue
		}
		kw, args, ok := parseSSHDirective(bLine)
		if !strings.HasPrefix(trimmed, "#") {
			prefix := ""
			for _, ch := range bLine {
				if ch == ' ' || ch == '\t' {
					prefix += string(ch)
				} else {
					break
				}
			}
			if prefix != "" {
				indent = prefix
			}
		}

		if ok {
			if isLmdtfyRemoteForward(kw, args) {
				rfRelativeIndices = append(rfRelativeIndices, rIdx)
			} else if strings.EqualFold(kw, "StreamLocalBindUnlink") {
				slbuRelativeIndices = append(slbuRelativeIndices, rIdx)
			} else if strings.EqualFold(kw, "User") {
				userRelativeIndices = append(userRelativeIndices, rIdx)
			}
		}
	}

	desiredComment := indent + dtfmHeaderComment
	desiredRF := fmt.Sprintf("%sRemoteForward /run/user/%d/lmdtfy.sock %s", indent, remoteUID, formattedSocket)
	desiredSLBU := fmt.Sprintf("%sStreamLocalBindUnlink yes", indent)
	desiredUser := ""
	if cleanUser != "" {
		desiredUser = fmt.Sprintf("%sUser %s", indent, cleanUser)
	}

	var newBlockLines []string
	rfPlaced := false
	slbuPlaced := false
	userPlaced := desiredUser == ""

	for rIdx, bLine := range blockLines {
		if rIdx == 0 {
			newBlockLines = append(newBlockLines, bLine)
			if desiredUser != "" && len(userRelativeIndices) == 0 && !userPlaced {
				newBlockLines = append(newBlockLines, desiredUser)
				userPlaced = true
			}
			continue
		}

		kw, args, ok := parseSSHDirective(bLine)
		isLmdtfyRF := ok && isLmdtfyRemoteForward(kw, args)
		isSLBU := ok && strings.EqualFold(kw, "StreamLocalBindUnlink")
		isUser := ok && strings.EqualFold(kw, "User")

		if isUser && desiredUser != "" {
			if !userPlaced {
				newBlockLines = append(newBlockLines, desiredUser)
				userPlaced = true
			}
			// Drops any duplicate User lines in this block
			continue
		}

		if isLmdtfyRF {
			if !rfPlaced {
				if !hasDtfmComment {
					newBlockLines = append(newBlockLines, desiredComment)
					hasDtfmComment = true
				}
				newBlockLines = append(newBlockLines, desiredRF)
				rfPlaced = true
				if len(slbuRelativeIndices) == 0 && !slbuPlaced {
					newBlockLines = append(newBlockLines, desiredSLBU)
					slbuPlaced = true
				}
			}
			continue
		}

		if isSLBU {
			if !rfPlaced && len(rfRelativeIndices) == 0 {
				if !hasDtfmComment {
					newBlockLines = append(newBlockLines, desiredComment)
					hasDtfmComment = true
				}
				newBlockLines = append(newBlockLines, desiredRF)
				rfPlaced = true
			}
			if !slbuPlaced {
				newBlockLines = append(newBlockLines, desiredSLBU)
				slbuPlaced = true
			}
			continue
		}

		newBlockLines = append(newBlockLines, bLine)
	}

	if !rfPlaced || !slbuPlaced {
		insertIdx := 0
		for idx := 1; idx < len(newBlockLines); idx++ {
			trimmed := strings.TrimSpace(newBlockLines[idx])
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				insertIdx = idx
			}
		}

		var finalBlock []string
		for idx, line := range newBlockLines {
			finalBlock = append(finalBlock, line)
			if idx == insertIdx {
				if !rfPlaced {
					if !hasDtfmComment {
						finalBlock = append(finalBlock, desiredComment)
						hasDtfmComment = true
					}
					finalBlock = append(finalBlock, desiredRF)
					rfPlaced = true
				}
				if !slbuPlaced {
					finalBlock = append(finalBlock, desiredSLBU)
					slbuPlaced = true
				}
			}
		}
		newBlockLines = finalBlock
	}

	// Recompose the file, stripping any stale lmdtfy RemoteForwards from subsequent exact host blocks
	var resultLines []string
	resultLines = append(resultLines, rawLines[:primarySec.startIdx]...)
	resultLines = append(resultLines, newBlockLines...)

	subsequentExactSet := make(map[int]bool)
	for _, secIdx := range exactHostSecIndices[1:] {
		subsequentExactSet[secIdx] = true
	}

	for secIdx := 1; secIdx < len(sections); secIdx++ {
		sec := sections[secIdx]
		if sec.startIdx < primarySec.endIdx {
			continue
		}
		secLines := rawLines[sec.startIdx:sec.endIdx]
		if subsequentExactSet[secIdx] {
			for _, line := range secLines {
				kw, args, ok := parseSSHDirective(line)
				if ok && isLmdtfyRemoteForward(kw, args) {
					continue
				}
				resultLines = append(resultLines, line)
			}
		} else {
			resultLines = append(resultLines, secLines...)
		}
	}

	res := strings.Join(resultLines, eol) + eol
	return res, nil
}
