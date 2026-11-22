package ebpf

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func TestParseCPUList(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		list string
		want []int
	}{
		{"0\n", []int{0}},
		{"0-3", []int{0, 1, 2, 3}},
		{"0-1,4,6-7\n", []int{0, 1, 4, 6, 7}},
	} {
		got, err := parseCPUList(tc.list)
		if err != nil || !slices.Equal(got, tc.want) {
			t.Errorf("parseCPUList(%q) = %v, %v; want %v", tc.list, got, err, tc.want)
		}
	}
	for _, list := range []string{"", "\n", "a", "1-", "3-1", "-1", "0,,1"} {
		if got, err := parseCPUList(list); err == nil {
			t.Errorf("parseCPUList(%q) = %v, want error", list, got)
		}
	}
}

func TestTracepointIDRejectsPathNames(t *testing.T) {
	t.Parallel()

	for _, tc := range [][2]string{{"syscalls", "../x"}, {"sys/calls", "sys_enter_execve"}, {"", "sys_enter_execve"}, {"syscalls", ""}} {
		if _, err := tracepointID(tc[0], tc[1]); err == nil || !strings.Contains(err.Error(), "invalid tracepoint") {
			t.Errorf("tracepointID(%q, %q) error = %v, want invalid tracepoint", tc[0], tc[1], err)
		}
	}
}

func TestAttachMonitorProgramsCoversEveryTracepointOnAllCPUs(t *testing.T) {
	t.Parallel()

	var closed []int
	var attached, covered []string
	next := 0
	closer := func() io.Closer {
		next++
		return &testCloser{id: next, closed: &closed}
	}
	functions := attachmentFunctions{
		attachCgroup: func(link.CgroupOptions) (io.Closer, error) { return closer(), nil },
		attachTracepoint: func(category, name string, _ *ebpf.Program) (io.Closer, error) {
			attached = append(attached, category+"/"+name)
			return closer(), nil
		},
		coverTracepointCPUs: func(category, name string) (io.Closer, error) {
			covered = append(covered, category+"/"+name)
			return closer(), nil
		},
	}

	links, err := attachMonitorPrograms("/sys/fs/cgroup", Options{SecurityEvents: true}, monitorObjects{}, functions)
	if err != nil {
		t.Fatalf("attachMonitorPrograms returned error: %v", err)
	}
	if len(attached) == 0 || !slices.Equal(attached, covered) {
		t.Fatalf("covered tracepoints = %v, want the attached ones %v", covered, attached)
	}
	if !slices.Contains(covered, "syscalls/sys_enter_memfd_create") || !slices.Contains(covered, "syscalls/sys_enter_execve") {
		t.Fatalf("covered tracepoints = %v, want memfd_create and execve", covered)
	}
	if len(links) != next {
		t.Fatalf("returned %d links, want every attachment and coverage closer (%d)", len(links), next)
	}
}

func TestAttachMonitorProgramsRollsBackWhenCPUCoverageFails(t *testing.T) {
	t.Parallel()

	var closed []int
	next := 0
	closer := func() io.Closer {
		next++
		return &testCloser{id: next, closed: &closed}
	}
	functions := attachmentFunctions{
		attachCgroup: func(link.CgroupOptions) (io.Closer, error) { return closer(), nil },
		attachTracepoint: func(string, string, *ebpf.Program) (io.Closer, error) {
			return closer(), nil
		},
		coverTracepointCPUs: func(string, string) (io.Closer, error) {
			return nil, errors.New("too many open files")
		},
	}

	links, err := attachMonitorPrograms("/sys/fs/cgroup", Options{}, monitorObjects{}, functions)
	if err == nil || !strings.Contains(err.Error(), "sys_enter_execve tracepoint perf events on every CPU") {
		t.Fatalf("attachMonitorPrograms error = %v, want CPU coverage failure", err)
	}
	if links != nil {
		t.Fatalf("links = %v, want nil", links)
	}
	want := make([]int, 0, next)
	for id := next; id >= 1; id-- {
		want = append(want, id)
	}
	if !slices.Equal(closed, want) {
		t.Fatalf("close order = %v, want %v", closed, want)
	}
}
