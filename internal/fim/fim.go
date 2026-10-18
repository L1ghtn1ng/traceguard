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

// scanResult is what a scan found. Paths beneath an unreadable directory,
// or that a truncated scan never reached, are unknown rather than absent, so
// they are never reported as deleted.
type scanResult struct {
	states map[string]State
	// unreadable lists paths whose state or entries could not be read.
	unreadable []string
	// truncated means MaxFiles stopped the scan.
	truncated bool
}

func newScanResult() scanResult {
	return scanResult{states: make(map[string]State)}
}

// known reports whether the scan established path's state, present or
// absent.
func (r scanResult) known(path string) bool {
	if r.truncated {
		return false
	}
	for _, unreadable := range r.unreadable {
		if unreadable == "/" || path == unreadable || strings.HasPrefix(path, unreadable+"/") {
			return false
		}
	}
	return true
}

// Baseline scans every watched path.
func (s scanner) Baseline() scanResult {
	result := newScanResult()
	for _, pattern := range s.policy.Paths {
		stem, subtree := strings.CutSuffix(pattern, "/**")
		if !subtree {
			stem = pattern
		}
		if stem == "" {
			stem = "/"
		}
		if !s.scanTree(stem, subtree, &result) {
			break
		}
	}
	return result
}

// scanTree records path and, for a subtree, everything beneath it. It
// returns false once MaxFiles is reached.
func (s scanner) scanTree(path string, subtree bool, result *scanResult) bool {
	if !subtree {
		if s.watched(path) {
			s.record(path, result)
		}
		return s.withinLimit(result)
	}
	err := filepath.WalkDir(s.host(path), func(hostPath string, entry fs.DirEntry, err error) error {
		logical := s.logical(hostPath)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				result.unreadable = append(result.unreadable, logical)
			}
			return nil
		}
		if !s.watched(logical) {
			if entry.IsDir() && logical != "/" {
				return fs.SkipDir
			}
			return nil
		}
		s.record(logical, result)
		if !s.withinLimit(result) {
			return fs.SkipAll
		}
		return nil
	})
	return err == nil && s.withinLimit(result)
}

func (s scanner) withinLimit(result *scanResult) bool {
	if len(result.states) >= MaxFiles {
		result.truncated = true
		return false
	}
	return true
}

// record stores path's state, or marks it unreadable when it exists but
// cannot be read.
func (s scanner) record(path string, result *scanResult) {
	state, err := s.stat(path)
	switch {
	case err == nil:
		result.states[path] = state
	case !errors.Is(err, fs.ErrNotExist):
		result.unreadable = append(result.unreadable, path)
	}
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

// stat records path without following a final symlink.
func (s scanner) stat(path string) (State, error) {
	hostPath := s.host(path)
	info, err := os.Lstat(hostPath)
	if err != nil {
		return State{}, err
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
	return state, nil
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
	if current.Type == "file" && previous.Type == "file" && !previous.ModTime.Equal(current.ModTime) {
		changed = append(changed, "mtime")
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

// reconcile compares baseline and scanned states for keys. It returns the
// changes to report, for keys report accepts, and each key's state to store,
// nil meaning absent. A key the scan could not establish keeps its baseline,
// and a file whose new hash failed keeps its baseline digest while its size,
// type, and modification time are unchanged, so a later read compares against
// it rather than losing it.
func reconcile(keys []string, baseline map[string]State, result scanResult, report func(string) bool) ([]Change, map[string]*State) {
	changes := make([]Change, 0, len(keys))
	final := make(map[string]*State, len(keys))
	for _, key := range keys {
		previous, hadPrevious := baseline[key]
		current, hasCurrent := result.states[key]
		switch {
		case !hasCurrent && hadPrevious && !result.known(key):
			final[key] = &previous
			continue
		case hasCurrent && hadPrevious && current.HashSkipped == "unreadable" && previous.SHA256 != "" &&
			current.Type == previous.Type && current.Size == previous.Size && current.ModTime.Equal(previous.ModTime):
			current.SHA256, current.HashSkipped = previous.SHA256, ""
		}
		var before, after *State
		if hadPrevious {
			before = &previous
		}
		if hasCurrent {
			after = &current
		}
		final[key] = after
		if change, ok := diff(key, before, after); ok && report(key) {
			changes = append(changes, change)
		}
	}
	return changes, final
}

// affectedKeys lists the keys a check of path compares: the path, what the
// scan found, and, unless path is known to be a file, the baseline entries
// beneath it. Skipping the baseline walk for files keeps routine checks from
// scanning every baseline entry.
func affectedKeys(path string, baseline map[string]State, result scanResult) []string {
	keys := map[string]struct{}{path: {}}
	for key := range result.states {
		keys[key] = struct{}{}
	}
	previous, hadPrevious := baseline[path]
	current, hasCurrent := result.states[path]
	isFile := (hadPrevious && previous.Type != "directory") || (!hadPrevious && hasCurrent && current.Type != "directory")
	if !isFile {
		prefix := strings.TrimSuffix(path, "/") + "/"
		for key := range baseline {
			if strings.HasPrefix(key, prefix) {
				keys[key] = struct{}{}
			}
		}
	}
	return slices.Sorted(maps.Keys(keys))
}
