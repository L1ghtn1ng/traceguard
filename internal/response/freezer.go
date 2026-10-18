package response

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"golang.org/x/sys/unix"
)

// CgroupFreezer freezes cgroup v2 groups through cgroup.freeze. It refuses
// groups whose freezing would stop the host or TraceGuard itself: the root,
// top-level slices, init.scope, and any group containing TraceGuard.
type CgroupFreezer struct {
	// Root is the cgroup v2 hierarchy root, such as /sys/fs/cgroup.
	Root string
	// self reads TraceGuard's own cgroup path at each freeze, so the check
	// follows the daemon if it is moved.
	self func() (string, error)
	scan func(context.Context, string) ([]cgroupinfo.Entry, error)
	// idOf reads the cgroup ID of an open cgroup directory.
	idOf func(*os.File) (uint64, error)
}

// NewCgroupFreezer returns a freezer over root for a daemon whose cgroup
// procCgroup, normally /proc/self/cgroup, names.
func NewCgroupFreezer(root, procCgroup string) *CgroupFreezer {
	root = filepath.Clean(root)
	return &CgroupFreezer{
		Root: root, self: func() (string, error) { return LocateSelf(root, procCgroup, os.Getpid()) },
		scan: cgroupinfo.ScanContext, idOf: openCgroupID,
	}
}

// openCgroupID reads the cgroup ID of an open cgroup directory from its file
// handle, as cgroupinfo.ID does for a path.
func openCgroupID(directory *os.File) (uint64, error) {
	handle, _, err := unix.NameToHandleAt(int(directory.Fd()), "", unix.AT_EMPTY_PATH)
	if err != nil {
		return 0, err
	}
	bytes := handle.Bytes()
	if len(bytes) < 8 {
		return 0, fmt.Errorf("cgroup file handle has %d bytes, want at least 8", len(bytes))
	}
	return binary.NativeEndian.Uint64(bytes[:8]), nil
}

// openCgroup opens the cgroup directory at path if it still has the given
// ID. Reading and writing through the open directory binds them to that
// cgroup: if it is removed, its files are gone, and a new cgroup at the same
// path is never reached.
func (f *CgroupFreezer) openCgroup(path string, id uint64) (*os.File, bool, error) {
	directory, err := os.OpenFile(filepath.Join(f.Root, path), os.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0) //nolint:gosec // cgroupfs path from a validated scan
	if err != nil {
		return nil, false, err
	}
	current, err := f.idOf(directory)
	if err != nil || current != id {
		_ = directory.Close()
		return nil, false, err
	}
	return directory, true, nil
}

// LocateSelf returns the daemon's cgroup path in the hierarchy at root,
// confirmed by finding pid in that cgroup's cgroup.procs. In a private cgroup
// namespace /proc/self/cgroup names a path relative to the namespace, which
// would not match the host hierarchy, so the self-freeze check cannot be
// trusted there.
func LocateSelf(root, procCgroup string, pid int) (string, error) {
	path, err := SelfCgroup(procCgroup)
	if err != nil {
		return "", err
	}
	procs, err := os.ReadFile(filepath.Join(root, path, "cgroup.procs")) //nolint:gosec // cgroupfs path
	if err != nil {
		return "", fmt.Errorf("read %s cgroup.procs: %w", path, err)
	}
	if !slices.Contains(strings.Fields(string(procs)), strconv.Itoa(pid)) {
		return "", fmt.Errorf("process %d is not in %s under %s; TraceGuard may run in a private cgroup namespace", pid, path, root)
	}
	return path, nil
}

// SelfCgroup reads the calling process's cgroup v2 path from procCgroup,
// normally /proc/self/cgroup.
func SelfCgroup(procCgroup string) (string, error) {
	payload, err := os.ReadFile(procCgroup) //nolint:gosec // fixed /proc path
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(payload), "\n") {
		if path, ok := strings.CutPrefix(line, "0::"); ok && strings.HasPrefix(path, "/") {
			return filepath.Clean(path), nil
		}
	}
	return "", errors.New("no cgroup v2 entry in " + procCgroup)
}

// Check returns the path of the cgroup with the given ID, or why it must not
// be frozen, without changing anything.
func (f *CgroupFreezer) Check(id uint64) (string, error) {
	self, err := f.self()
	if err != nil {
		return "", &RefusedError{Reason: "cannot locate TraceGuard's own cgroup, so no cgroup is frozen: " + err.Error()}
	}
	entries, err := f.scan(context.Background(), f.Root)
	if err != nil {
		return "", err
	}
	var target *cgroupinfo.Entry
	for index := range entries {
		if entries[index].Path == "/" && entries[index].Level != 0 {
			return "", &RefusedError{Reason: "cgroup freezing requires cgroup-path at the cgroup v2 root"}
		}
		if entries[index].ID == id {
			target = &entries[index]
		}
	}
	if target == nil {
		return "", &RefusedError{Reason: fmt.Sprintf("cgroup %d no longer exists", id)}
	}
	if reason := freezeRefusal(*target, self); reason != "" {
		return "", &RefusedError{Reason: reason}
	}
	return target.Path, nil
}

// Freeze freezes the cgroup with the given ID and returns its path, and
// whether this call froze it. A cgroup that something else had already
// frozen is left as it is, so thawing later cannot undo that freeze.
func (f *CgroupFreezer) Freeze(id uint64) (string, bool, error) {
	path, err := f.Check(id)
	if err != nil {
		return "", false, err
	}
	// The cgroup may have been removed and its path reused since the scan;
	// freeze only the cgroup the alert named.
	directory, same, err := f.openCgroup(path, id)
	if err != nil || !same {
		return "", false, &RefusedError{Reason: fmt.Sprintf("cgroup %d no longer exists", id)}
	}
	defer func() { _ = directory.Close() }()
	if state, err := readFreeze(directory); err == nil && state == "1" {
		return path, false, nil
	}
	if err := writeFreeze(directory, "1"); err != nil {
		return "", false, fmt.Errorf("freeze cgroup %s: %w", path, err)
	}
	return path, true, nil
}

// freezeRefusal explains why target must not be frozen for a daemon in self, or
// returns "".
func freezeRefusal(target cgroupinfo.Entry, self string) string {
	switch {
	case target.Level < 2:
		return fmt.Sprintf("refusing to freeze %s: only cgroups below a top-level slice can be frozen", target.Path)
	case target.Path == "/init.scope" || strings.HasPrefix(target.Path, "/init.scope/"):
		return fmt.Sprintf("refusing to freeze %s: it contains init", target.Path)
	case self == target.Path || strings.HasPrefix(self, target.Path+"/"):
		return fmt.Sprintf("refusing to freeze %s: it contains TraceGuard", target.Path)
	}
	return ""
}

// Thaw unfreezes the cgroup at path if it is still the cgroup with id. A
// cgroup that no longer exists, or whose path now names a different cgroup,
// was thawed when it was removed.
func (f *CgroupFreezer) Thaw(id uint64, path string) error {
	directory, same, err := f.openCgroup(path, id)
	if errors.Is(err, fs.ErrNotExist) {
		// Only a mounted hierarchy proves the cgroup is gone; without one
		// the thaw must be retried.
		if _, rootErr := os.Stat(filepath.Join(f.Root, "cgroup.controllers")); rootErr != nil {
			return fmt.Errorf("thaw cgroup %s: cgroup hierarchy %s is unavailable: %w", path, f.Root, rootErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("thaw cgroup %s: %w", path, err)
	}
	if !same {
		return nil
	}
	defer func() { _ = directory.Close() }()
	if err := writeFreeze(directory, "0"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("thaw cgroup %s: %w", path, err)
	}
	return nil
}

// readFreeze reads cgroup.freeze in an open cgroup directory.
func readFreeze(directory *os.File) (string, error) {
	fd, err := unix.Openat(int(directory.Fd()), "cgroup.freeze", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), "cgroup.freeze")
	defer func() { _ = file.Close() }()
	buffer := make([]byte, 8)
	n, err := file.Read(buffer)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buffer[:n])), nil
}

// writeFreeze writes cgroup.freeze in an open cgroup directory.
func writeFreeze(directory *os.File, value string) error {
	fd, err := unix.Openat(int(directory.Fd()), "cgroup.freeze", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "cgroup.freeze")
	if _, err := file.WriteString(value); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
