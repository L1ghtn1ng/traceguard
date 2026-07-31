package cgroupinfo

import (
	"slices"
	"testing"
)

func TestSelectExactAndPrefix(t *testing.T) {
	t.Parallel()
	entries := []Entry{
		{ID: 1, Path: "/"},
		{ID: 2, Path: "/system.slice"},
		{ID: 3, Path: "/system.slice/api.service"},
		{ID: 4, Path: "/user.slice"},
	}
	got := Select(entries, []string{"/user.slice"}, []string{"/system.slice"})
	want := []uint64{2, 3, 4}
	if !slices.Equal(got, want) {
		t.Fatalf("Select() = %v, want %v", got, want)
	}
}

func TestSelectRootPrefixMatchesAll(t *testing.T) {
	t.Parallel()
	entries := []Entry{{ID: 1, Path: "/"}, {ID: 2, Path: "/workload"}}
	if got := Select(entries, nil, []string{"/"}); !slices.Equal(got, []uint64{1, 2}) {
		t.Fatalf("Select() = %v", got)
	}
}
