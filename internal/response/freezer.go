package response

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
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
	id   func(string) (uint64, error)
}

// NewCgroupFreezer returns a freezer over root for a daemon whose cgroup
// procCgroup, normally /proc/self/cgroup, names.
func NewCgroupFreezer(root, procCgroup string) *CgroupFreezer {
	return &CgroupFreezer{
		Root: filepath.Clean(root), self: func() (string, error) { return SelfCgroup(procCgroup) },
		scan: cgroupinfo.ScanContext, id: cgroupinfo.ID,
	}
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

// Freeze freezes the cgroup with the given ID and returns its path.
func (f *CgroupFreezer) Freeze(id uint64) (string, error) {
	self, err := f.self()
	if err != nil {
		return "", fmt.Errorf("read TraceGuard's own cgroup: %w", err)
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
	if err := writeFreeze(filepath.Join(f.Root, target.Path), "1"); err != nil {
		return "", fmt.Errorf("freeze cgroup %s: %w", target.Path, err)
	}
	return target.Path, nil
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
	directory := filepath.Join(f.Root, path)
	current, err := f.id(directory)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("thaw cgroup %s: %w", path, err)
	}
	if current != id {
		return nil
	}
	if err := writeFreeze(directory, "0"); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("thaw cgroup %s: %w", path, err)
	}
	return nil
}

func writeFreeze(directory, value string) error {
	file, err := os.OpenFile(filepath.Join(directory, "cgroup.freeze"), os.O_WRONLY, 0) //nolint:gosec // cgroupfs path from a validated scan
	if err != nil {
		return err
	}
	if _, err := file.WriteString(value); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
