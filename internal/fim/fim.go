// Package fim keeps a baseline of watched files and reports how they change.
//
// Change events from the kernel name a path and the process that touched it;
// the watcher rechecks that path shortly afterwards and compares it with the
// baseline. A periodic full rescan catches changes no event reported, such as
// writes through a descriptor opened before the watch began.
package fim

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// MaxFiles bounds the baseline. Paths beyond it are not watched until a later
// rescan finds room.
const MaxFiles = 100_000

// Change kinds.
const (
	Created    = "created"
	Modified   = "modified"
	Deleted    = "deleted"
	Attributes = "attributes"
)

// State is one file's recorded attributes and, when hashed, content digest.
type State struct {
	Type    string
	Mode    fs.FileMode
	UID     uint32
	GID     uint32
	Size    int64
	ModTime time.Time
	// LinkTarget is a symlink's target; symlinks are never followed.
	LinkTarget string
	SHA256     string
	// HashSkipped says why SHA256 is empty: "disabled", "size",
	// "not_regular", or "unreadable".
	HashSkipped string
}

// Change describes how a watched path differs from its baseline.
type Change struct {
	Path     string
	Kind     string
	Changed  []string
	Previous *State
	Current  *State
}

// scanner reads watched files under root, which is "/" outside tests.
type scanner struct {
	root    string
	policy  policy.FileIntegrityPolicy
	maxSize int64
}

// Baseline scans every watched path. It reports truncated when MaxFiles
// stopped the scan early.
func (s scanner) Baseline() (map[string]State, bool) {
	states := make(map[string]State)
	truncated := false
	for _, pattern := range s.policy.Paths {
		stem, subtree := strings.CutSuffix(pattern, "/**")
		if !subtree {
			stem = pattern
		}
		if stem == "" {
			stem = "/"
		}
		if !s.scanTree(stem, subtree, states) {
			truncated = true
			break
		}
	}
	return states, truncated
}

// scanTree records path and, for a subtree, everything beneath it. It
// returns false once MaxFiles is reached.
func (s scanner) scanTree(path string, subtree bool, states map[string]State) bool {
	if !subtree {
		if state, ok := s.stat(path); ok && s.watched(path) {
			states[path] = state
		}
		return len(states) < MaxFiles
	}
	err := filepath.WalkDir(s.host(path), func(hostPath string, entry fs.DirEntry, err error) error {
		if err != nil {
			// Unreadable entries are skipped and stay unknown until a later
			// scan can read them.
			return nil //nolint:nilerr // skipping is the intended handling
		}
		path := s.logical(hostPath)
		if !s.watched(path) {
			if entry.IsDir() && path != "/" {
				return fs.SkipDir
			}
			return nil
		}
		if state, ok := s.stat(path); ok {
			states[path] = state
		}
		if len(states) >= MaxFiles {
			return fs.SkipAll
		}
		return nil
	})
	return err == nil && len(states) < MaxFiles
}

// watched reports whether path is selected by a watch pattern and not
// excluded.
func (s scanner) watched(path string) bool {
	return matchesAny(s.policy.Paths, path) && !matchesAny(s.policy.Exclude, path)
}

func matchesAny(patterns []string, path string) bool {
	for _, pattern := range patterns {
		if stem, ok := strings.CutSuffix(pattern, "/**"); ok {
			if stem == "" || path == stem || strings.HasPrefix(path, stem+"/") {
				return true
			}
		} else if path == pattern {
			return true
		}
	}
	return false
}

func (s scanner) host(path string) string {
	if s.root == "" || s.root == "/" {
		return path
	}
	return filepath.Join(s.root, path)
}

func (s scanner) logical(hostPath string) string {
	if s.root == "" || s.root == "/" {
		return hostPath
	}
	relative, err := filepath.Rel(s.root, hostPath)
	if err != nil {
		return hostPath
	}
	return filepath.Clean("/" + relative)
}

// stat records path without following a final symlink. It reports false
// when the path does not exist or cannot be read.
func (s scanner) stat(path string) (State, bool) {
	hostPath := s.host(path)
	info, err := os.Lstat(hostPath)
	if err != nil {
		return State{}, false
	}
	state := State{Type: fileType(info.Mode()), Mode: info.Mode().Perm() | info.Mode()&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky),
		Size: info.Size(), ModTime: info.ModTime().UTC()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		state.UID, state.GID = stat.Uid, stat.Gid
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		state.LinkTarget, _ = os.Readlink(hostPath)
		state.HashSkipped = "not_regular"
	case !info.Mode().IsRegular():
		state.HashSkipped = "not_regular"
	case !s.policy.HashEnabled():
		state.HashSkipped = "disabled"
	case info.Size() > s.maxSize:
		state.HashSkipped = "size"
	default:
		digest, err := hashFile(hostPath, s.maxSize)
		if err != nil {
			state.HashSkipped = "unreadable"
		} else {
			state.SHA256 = digest
		}
	}
	return state, true
}

func fileType(mode fs.FileMode) string {
	switch {
	case mode.IsRegular():
		return "file"
	case mode.IsDir():
		return "directory"
	case mode&fs.ModeSymlink != 0:
		return "symlink"
	default:
		return "other"
	}
}

// hashFile digests a regular file. O_NOFOLLOW and O_NONBLOCK keep a path
// swapped for a symlink or FIFO after the stat from redirecting or stalling
// the read, and the size limit is enforced on the bytes actually read.
func hashFile(path string, limit int64) (string, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0) //nolint:gosec // watched path selected by root-owned policy
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	hash := sha256.New()
	copied, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if copied > limit {
		return "", fmt.Errorf("file grew past %d bytes while hashing", limit)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// diff compares a path's baseline and current state.
func diff(path string, previous, current *State) (Change, bool) {
	switch {
	case previous == nil && current == nil:
		return Change{}, false
	case previous == nil:
		return Change{Path: path, Kind: Created, Current: current}, true
	case current == nil:
		return Change{Path: path, Kind: Deleted, Previous: previous}, true
	}
	var changed []string
	if previous.Type != current.Type {
		changed = append(changed, "type")
	}
	if contentChanged(previous, current) {
		changed = append(changed, "content")
	}
	if previous.Mode != current.Mode {
		changed = append(changed, "mode")
	}
	if previous.UID != current.UID {
		changed = append(changed, "owner")
	}
	if previous.GID != current.GID {
		changed = append(changed, "group")
	}
	if len(changed) == 0 {
		return Change{}, false
	}
	kind := Attributes
	if slices.Contains(changed, "content") || slices.Contains(changed, "type") {
		kind = Modified
	}
	return Change{Path: path, Kind: kind, Changed: changed, Previous: previous, Current: current}, true
}

// contentChanged compares digests when both sides were hashed, and falls
// back to size and modification time otherwise. Directories have no content
// to compare.
func contentChanged(previous, current *State) bool {
	switch {
	case current.Type == "directory":
		return false
	case current.Type == "symlink":
		return previous.LinkTarget != current.LinkTarget
	case previous.SHA256 != "" && current.SHA256 != "":
		return previous.SHA256 != current.SHA256
	default:
		return previous.Size != current.Size || !previous.ModTime.Equal(current.ModTime)
	}
}

// diffSubset reports changes for the baseline entries and current entries
// under path, and returns the updated states for those entries.
func diffSubset(path string, baseline, current map[string]State) []Change {
	keys := make(map[string]struct{})
	for key := range baseline {
		if key == path || strings.HasPrefix(key, strings.TrimSuffix(path, "/")+"/") {
			keys[key] = struct{}{}
		}
	}
	for key := range current {
		keys[key] = struct{}{}
	}
	changes := make([]Change, 0, len(keys))
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		var previous, now *State
		if state, ok := baseline[key]; ok {
			previous = &state
		}
		if state, ok := current[key]; ok {
			now = &state
		}
		if change, ok := diff(key, previous, now); ok {
			changes = append(changes, change)
		}
	}
	return changes
}
