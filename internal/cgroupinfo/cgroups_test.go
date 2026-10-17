package cgroupinfo

import (
	"slices"
	"strings"
	"testing"
)

func TestResolveSeparatesExactAndPrefixRootIDs(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{ID: 1, Path: "/"},
		{ID: 2, Path: "/system.slice"},
		{ID: 3, Path: "/system.slice/api.service"},
		{ID: 4, Path: "/user.slice"},
	}
	exact, ancestors, err := Resolve(entries, []string{"/user.slice"}, []string{"/system.slice"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(exact, []uint64{4}) || !slices.Equal(ancestors, []uint64{2}) {
		t.Fatalf("Resolve() = exact %v ancestors %v, want [4] and [2]", exact, ancestors)
	}
}

func TestResolveRejectsMissingSelectorRoot(t *testing.T) {
	t.Parallel()
	entries := []Entry{{ID: 1, Path: "/"}, {ID: 2, Path: "/workload"}}
	if _, _, err := Resolve(entries, nil, []string{"/missing"}); err == nil {
		t.Fatal("Resolve() accepted a missing cgroup prefix root")
	}
}

func TestResolveRejectsPrefixBeyondKernelAncestorLookupBound(t *testing.T) {
	t.Parallel()

	supportedPath := "/" + strings.Join(slices.Repeat([]string{"level"}, MaxAncestorLookupLevels-1), "/")
	unsupportedPath := supportedPath + "/level"
	entries := []Entry{
		{ID: 1, Path: supportedPath, Level: MaxAncestorLookupLevels - 1},
		{ID: 2, Path: unsupportedPath, Level: MaxAncestorLookupLevels},
	}
	if _, ancestors, err := Resolve(entries, nil, []string{supportedPath}); err != nil || !slices.Equal(ancestors, []uint64{1}) {
		t.Fatalf("Resolve() rejected supported level: ancestors=%v err=%v", ancestors, err)
	}
	if _, _, err := Resolve(entries, nil, []string{unsupportedPath}); err == nil || !strings.Contains(err.Error(), "maximum supported level is 63") {
		t.Fatalf("Resolve() deep prefix error = %v", err)
	}
	if exact, _, err := Resolve(entries, []string{unsupportedPath}, nil); err != nil || !slices.Equal(exact, []uint64{2}) {
		t.Fatalf("Resolve() rejected deep exact selector: exact=%v err=%v", exact, err)
	}
}

func TestCgroupRootLevelUsesMountHierarchyRoot(t *testing.T) {
	t.Parallel()

	mountInfo := strings.NewReader("36 25 0:32 /delegated/root /sys/fs/cgroup rw,nosuid,nodev - cgroup2 cgroup rw\n")
	level, err := cgroupRootLevelFromMountInfo(mountInfo, "/sys/fs/cgroup/workloads")
	if err != nil {
		t.Fatal(err)
	}
	if level != 3 {
		t.Fatalf("cgroup root level = %d, want 3", level)
	}
}
