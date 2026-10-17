package cgroupinfo

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	MaxScanEntries          = 65536
	MaxAncestorLookupLevels = 64
	maxMountInfoLineBytes   = 1 << 20
)

type Entry struct {
	ID    uint64
	Path  string
	Level int
}

// Index resolves policy selectors without rebuilding a path map for every
// rule. Construct one after each cgroup scan and reuse it for the whole policy
// compilation pass.
type Index map[string]Entry

func NewIndex(entries []Entry) Index {
	index := make(Index, len(entries))
	for _, entry := range entries {
		// Hand-built entries in callers and tests may omit Level. Scanned
		// entries always carry the absolute hierarchy level.
		if entry.Level == 0 && entry.Path != "/" {
			entry.Level = pathLevel(entry.Path)
		}
		index[entry.Path] = entry
	}
	return index
}

func Scan(root string) ([]Entry, error) {
	return ScanContext(context.Background(), root)
}

func ScanContext(ctx context.Context, root string) ([]Entry, error) {
	root = filepath.Clean(root)
	rootLevel, err := cgroupRootLevel(root)
	if err != nil {
		return nil, fmt.Errorf("locate cgroup v2 hierarchy for %q: %w", root, err)
	}
	entries := make([]Entry, 0, 128)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
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
		entries = append(entries, Entry{ID: id, Path: cgroupPath, Level: rootLevel + pathLevel(relative)})
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

func cgroupRootLevel(root string) (int, error) {
	mountInfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return 0, err
	}
	defer func() { _ = mountInfo.Close() }()
	return cgroupRootLevelFromMountInfo(mountInfo, root)
}

func cgroupRootLevelFromMountInfo(mountInfo io.Reader, root string) (int, error) {
	root = filepath.Clean(root)
	bestMount := ""
	var bestLevel int
	scanner := bufio.NewScanner(mountInfo)
	scanner.Buffer(make([]byte, 4096), maxMountInfoLineBytes)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		separator := slices.Index(fields, "-")
		if separator < 0 || separator+1 >= len(fields) || len(fields) < 5 || fields[separator+1] != "cgroup2" {
			continue
		}
		hierarchyRoot := unescapeMountInfoPath(fields[3])
		mountPoint := filepath.Clean(unescapeMountInfoPath(fields[4]))
		relative, err := filepath.Rel(mountPoint, root)
		if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			continue
		}
		if len(mountPoint) <= len(bestMount) {
			continue
		}
		bestMount = mountPoint
		bestLevel = pathLevel(hierarchyRoot) + pathLevel(relative)
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read /proc/self/mountinfo: %w", err)
	}
	if bestMount == "" {
		return 0, errors.New("path is not within a cgroup v2 mount")
	}
	return bestLevel, nil
}

func unescapeMountInfoPath(value string) string {
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(value)
}

func pathLevel(path string) int {
	cleaned := filepath.Clean(path)
	if cleaned == "." || cleaned == string(filepath.Separator) {
		return 0
	}
	trimmed := strings.Trim(cleaned, string(filepath.Separator))
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, string(filepath.Separator)) + 1
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

// Resolve returns object IDs for exact selectors and stable ancestor IDs for
// prefix selectors. Prefix IDs are evaluated against the current task's cgroup
// ancestry in eBPF, so descendants created after compilation are covered.
func Resolve(entries []Entry, exact, prefixes []string) (exactIDs, ancestorIDs []uint64, resolveErr error) {
	return NewIndex(entries).Resolve(exact, prefixes)
}

func (index Index) Resolve(exact, prefixes []string) (exactIDs, ancestorIDs []uint64, resolveErr error) {
	resolve := func(paths []string, kind string, ancestor bool) ([]uint64, error) {
		ids := make([]uint64, 0, len(paths))
		seen := make(map[uint64]struct{}, len(paths))
		for _, path := range paths {
			entry, ok := index[path]
			if !ok {
				return nil, fmt.Errorf("%s selector %q does not exist", kind, path)
			}
			if ancestor && entry.Level >= MaxAncestorLookupLevels {
				return nil, fmt.Errorf("%s selector %q is at hierarchy level %d; maximum supported level is %d", kind, path, entry.Level, MaxAncestorLookupLevels-1)
			}
			if _, exists := seen[entry.ID]; !exists {
				seen[entry.ID] = struct{}{}
				ids = append(ids, entry.ID)
			}
		}
		slices.Sort(ids)
		return ids, nil
	}
	var err error
	exactIDs, err = resolve(exact, "exact cgroup", false)
	if err != nil {
		return nil, nil, err
	}
	ancestorIDs, err = resolve(prefixes, "cgroup prefix root", true)
	if err != nil {
		return nil, nil, err
	}
	return exactIDs, ancestorIDs, nil
}
