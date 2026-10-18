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
	// Self is TraceGuard's own cgroup path in the hierarchy.
	Self string
	scan func(context.Context, string) ([]cgroupinfo.Entry, error)
}

// NewCgroupFreezer returns a freezer over root for a daemon in self.
func NewCgroupFreezer(root, self string) *CgroupFreezer {
	return &CgroupFreezer{Root: filepath.Clean(root), Self: self, scan: cgroupinfo.ScanContext}
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
	entries, err := f.scan(context.Background(), f.Root)
	if err != nil {
		return "", err
	}
	var target *cgroupinfo.Entry
	for index := range entries {
		if entries[index].Path == "/" && entries[index].Level != 0 {
			return "", errors.New("cgroup freezing requires cgroup-path at the cgroup v2 root")
		}
		if entries[index].ID == id {
			target = &entries[index]
		}
	}
	if target == nil {
		return "", fmt.Errorf("cgroup %d no longer exists", id)
	}
	if err := f.allowed(*target); err != nil {
		return "", err
	}
	if err := writeFreeze(filepath.Join(f.Root, target.Path), "1"); err != nil {
		return "", fmt.Errorf("freeze cgroup %s: %w", target.Path, err)
	}
	return target.Path, nil
}

func (f *CgroupFreezer) allowed(target cgroupinfo.Entry) error {
	switch {
	case target.Level < 2:
		return fmt.Errorf("refusing to freeze %s: only cgroups below a top-level slice can be frozen", target.Path)
	case target.Path == "/init.scope" || strings.HasPrefix(target.Path, "/init.scope/"):
		return fmt.Errorf("refusing to freeze %s: it contains init", target.Path)
	case f.Self == target.Path || strings.HasPrefix(f.Self, target.Path+"/"):
		return fmt.Errorf("refusing to freeze %s: it contains TraceGuard", target.Path)
	}
	return nil
}

// Thaw unfreezes a cgroup. A cgroup that no longer exists is already thawed.
func (f *CgroupFreezer) Thaw(path string) error {
	err := writeFreeze(filepath.Join(f.Root, path), "0")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
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
