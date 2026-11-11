// Copyright 2026 Ivan Inozemtsev
// SPDX-License-Identifier: Apache-2.0

package protocol

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DefaultSocketPath returns the standard Unix domain socket path for dtfm / lmdtfy.
// Precedence:
// 1. $LMDTFY_SOCKET environment variable
// 2. /run/user/<uid>/lmdtfy.sock (if /run/user/<uid> directory exists, is owned by user, mode 0700)
// 3. ~/.lmdtfy.sock (fallback)
// 4. /tmp/lmdtfy-<uid>/lmdtfy.sock (secure private directory owned by user, mode 0700)
func DefaultSocketPath() string {
	if env := os.Getenv("LMDTFY_SOCKET"); env != "" {
		return env
	}
	uid := os.Getuid()
	if uid >= 0 {
		runDir := fmt.Sprintf("/run/user/%d", uid)
		if fi, err := os.Lstat(runDir); err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0077 == 0 {
			if stat, ok := fi.Sys().(*syscall.Stat_t); ok && stat.Uid == uint32(uid) {
				return filepath.Join(runDir, "lmdtfy.sock")
			}
		}
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		return filepath.Join(home, ".lmdtfy.sock")
	}
	if uid >= 0 {
		return filepath.Join(fmt.Sprintf("/tmp/lmdtfy-%d", uid), "lmdtfy.sock")
	}
	return "/tmp/lmdtfy-default/lmdtfy.sock"
}

func isSharedRuntimeDir(cleanDir string) bool {
	sharedPrefixes := []string{
		"/tmp",
		"/private/tmp",
		"/var/tmp",
		"/private/var/tmp",
		"/run/user",
		"/var/run/user",
		"/dev/shm",
		"/run/shm",
		"/var/folders",
		"/private/var/folders",
	}
	for _, p := range sharedPrefixes {
		if cleanDir == p || strings.HasPrefix(cleanDir, p+"/") {
			return true
		}
	}
	return false
}

// validateComponentSymlinks walks existing path components from root to absDir to detect
// untrusted intermediate symlinks and verify ownership/permissions of existing prefix directories.
// If a component does not exist yet, traversal stops.
func validateComponentSymlinks(absDir string) error {
	parts := strings.Split(absDir, string(filepath.Separator))
	current := ""
	uid := os.Getuid()
	for _, part := range parts {
		if part == "" {
			current = "/"
			continue
		}
		if current == "/" {
			current = "/" + part
		} else {
			current = current + "/" + part
		}

		cFi, err := os.Lstat(current)
		if err != nil {
			if os.IsNotExist(err) {
				break
			}
			return fmt.Errorf("cannot stat path component %s: %w", current, err)
		}
		if cFi.Mode()&os.ModeSymlink != 0 {
			// Only root-owned OS system symlinks (e.g. macOS /tmp -> private/tmp, Linux /var/run -> /run) are permitted
			stat, ok := cFi.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return fmt.Errorf("insecure socket path component %s: symlink owned by non-root UID", current)
			}
			parent := filepath.Dir(current)
			if isSharedRuntimeDir(parent) {
				return fmt.Errorf("insecure socket path component %s: symlink inside shared runtime directory %s", current, parent)
			}
			if evalParent, err := filepath.EvalSymlinks(parent); err == nil && isSharedRuntimeDir(evalParent) {
				return fmt.Errorf("insecure socket path component %s: symlink inside shared runtime directory %s (resolved: %s)", current, parent, evalParent)
			}
		} else if cFi.IsDir() {
			if stat, ok := cFi.Sys().(*syscall.Stat_t); ok && uid >= 0 {
				if stat.Uid != 0 && stat.Uid != uint32(uid) {
					return fmt.Errorf("insecure socket path component %s: owned by UID %d, expected UID %d or root (0)", current, stat.Uid, uid)
				}
			}
			// Non-sticky directories must not be group- or world-writable
			if cFi.Mode()&os.ModeSticky == 0 {
				if cFi.Mode().Perm()&0022 != 0 {
					return fmt.Errorf("insecure socket path component %s: permissions %04o allow group or world writes", current, cFi.Mode().Perm())
				}
			}
		}
	}
	return nil
}

func validateDirSecurity(absDir string, fi os.FileInfo, isClient bool) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("insecure socket directory %s: must not be a symlink", absDir)
	}

	if !fi.IsDir() {
		return fmt.Errorf("socket parent path %s is not a directory", absDir)
	}

	// Walk path components from root to absDir to detect untrusted intermediate symlinks
	if err := validateComponentSymlinks(absDir); err != nil {
		return err
	}

	checkAncestors := func(startDir string) error {
		curr := startDir
		uid := os.Getuid()
		for {
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
			pfi, err := os.Lstat(curr)
			if err != nil {
				return fmt.Errorf("cannot stat ancestor directory %s: %w", curr, err)
			}
			// Skip symlink inodes (e.g. /var/run -> /run on Linux has mode 0777).
			// Intermediate symlinks are checked for non-root/shared-runtime bypasses by validateComponentSymlinks,
			// and their targets are verified by checkAncestors(evalDir).
			if pfi.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if pstat, ok := pfi.Sys().(*syscall.Stat_t); ok && uid >= 0 {
				if pstat.Uid != 0 && pstat.Uid != uint32(uid) {
					return fmt.Errorf("insecure ancestor directory %s: owned by UID %d, expected UID %d or root (0)", curr, pstat.Uid, uid)
				}
			}
			// Non-sticky directories must not be group- or world-writable
			if pfi.Mode()&os.ModeSticky == 0 {
				if pfi.Mode().Perm()&0022 != 0 {
					return fmt.Errorf("insecure ancestor directory %s: permissions %04o allow group or world writes", curr, pfi.Mode().Perm())
				}
			}
		}
		return nil
	}

	if err := checkAncestors(absDir); err != nil {
		return err
	}

	evalDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return fmt.Errorf("failed to evaluate symlinks for %s: %w", absDir, err)
	}
	if evalDir != absDir {
		if err := checkAncestors(evalDir); err != nil {
			return err
		}
	}

	inShared := isSharedRuntimeDir(absDir)
	if isSharedRuntimeDir(evalDir) {
		inShared = true
	}

	uid := os.Getuid()
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if uid >= 0 && ok {
		if inShared {
			if stat.Uid != uint32(uid) {
				return fmt.Errorf("insecure socket directory %s: owned by UID %d, expected UID %d", absDir, stat.Uid, uid)
			}
			if fi.Mode().Perm()&0077 != 0 {
				return fmt.Errorf("insecure socket directory %s: permissions %04o are not restricted to owner (must be 0700 in shared runtime paths)", absDir, fi.Mode().Perm())
			}
		} else {
			if isClient {
				if stat.Uid != uint32(uid) && stat.Uid != 0 {
					return fmt.Errorf("insecure socket directory %s: owned by UID %d, expected UID %d or root (0)", absDir, stat.Uid, uid)
				}
			} else {
				if stat.Uid != uint32(uid) {
					return fmt.Errorf("insecure socket directory %s: owned by UID %d, expected UID %d", absDir, stat.Uid, uid)
				}
			}
			if fi.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("insecure socket directory %s: permissions %04o allow group or world writes", absDir, fi.Mode().Perm())
			}
		}
	}

	return nil
}

// EnsureSocketDir prepares and verifies the socket directory for the dtfm server.
// If the directory does not exist, it creates it with mode 0700.
// It verifies that the directory is not a symlink, is owned by the current user,
// and enforces strict permissions without mutating existing directories.
func EnsureSocketDir(sockPath string) error {
	dir := filepath.Dir(sockPath)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %s: %w", dir, err)
	}
	absDir = filepath.Clean(absDir)

	// Validate existing prefix components before MkdirAll to prevent symlink traversal in shared spaces
	if err := validateComponentSymlinks(absDir); err != nil {
		return err
	}

	fi, err := os.Lstat(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(absDir, 0700); err != nil {
				return fmt.Errorf("failed to create socket directory %s: %w", absDir, err)
			}
			fi, err = os.Lstat(absDir)
			if err != nil {
				return fmt.Errorf("failed to stat socket directory %s: %w", absDir, err)
			}
		} else {
			return fmt.Errorf("cannot access socket directory %s: %w", absDir, err)
		}
	}

	return validateDirSecurity(absDir, fi, false)
}

// ValidateClientSocketPath validates the socket parent directory for the lmdtfy client in read-only mode.
// If the directory does not exist, it returns nil so net.DialTimeout can fail with ENOENT
// and report an inactive session (exit code 2). If the directory exists, it enforces security checks.
func ValidateClientSocketPath(sockPath string) error {
	dir := filepath.Dir(sockPath)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute path for %s: %w", dir, err)
	}
	absDir = filepath.Clean(absDir)

	fi, err := os.Lstat(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			// Do not create directory on client; let net.Dial report ENOENT
			return nil
		}
		return fmt.Errorf("cannot access socket directory %s: %w", absDir, err)
	}

	return validateDirSecurity(absDir, fi, true)
}

// ValidateSocketPath validates that the parent directory of sockPath is secure.
// For backwards compatibility, it delegates to EnsureSocketDir.
func ValidateSocketPath(sockPath string) error {
	return EnsureSocketDir(sockPath)
}
