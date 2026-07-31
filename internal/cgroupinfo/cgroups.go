package cgroupinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const MaxScanEntries = 65536

type Entry struct {
	ID   uint64
	Path string
}

func Scan(root string) ([]Entry, error) {
	root = filepath.Clean(root)
	entries := make([]Entry, 0, 128)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		id, err := ID(path)
		if err != nil {
			return fmt.Errorf("read cgroup id for %q: %w", path, err)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		cgroupPath := "/"
		if relative != "." {
			cgroupPath = "/" + filepath.ToSlash(relative)
		}
		entries = append(entries, Entry{ID: id, Path: cgroupPath})
		if len(entries) > MaxScanEntries {
			return fmt.Errorf("cgroup count exceeds %d", MaxScanEntries)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scan cgroup v2 tree %q: %w", root, err)
	}
	slices.SortFunc(entries, func(left, right Entry) int {
		return strings.Compare(left.Path, right.Path)
	})
	return entries, nil
}

func ID(path string) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
	if err != nil {
		return 0, err
	}
	bytes := handle.Bytes()
	if len(bytes) < 8 {
		return 0, fmt.Errorf("cgroup file handle has %d bytes, want at least 8", len(bytes))
	}
	id := binary.NativeEndian.Uint64(bytes[:8])
	if id == 0 {
		return 0, errors.New("cgroup file handle returned id zero")
	}
	return id, nil
}

func Select(entries []Entry, exact, prefixes []string) []uint64 {
	selected := make(map[uint64]struct{})
	for _, entry := range entries {
		if slices.Contains(exact, entry.Path) {
			selected[entry.ID] = struct{}{}
			continue
		}
		for _, prefix := range prefixes {
			prefix = strings.TrimSuffix(prefix, "/")
			if prefix == "" {
				prefix = "/"
			}
			if entry.Path == prefix || prefix == "/" || strings.HasPrefix(entry.Path, prefix+"/") {
				selected[entry.ID] = struct{}{}
				break
			}
		}
	}
	ids := make([]uint64, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
