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

func TestKernelMaySkipSyscallTracepointPrograms(t *testing.T) {
	t.Parallel()

	for release, want := range map[string]bool{
		"6.12.40-generic":   false,
		"6.18.3":            false,
		"6.19.0":            true,
		"7.0.0-1020-azure":  true,
		"7.1.9":             true,
		"7.2.15+kali-amd64": false,
		"7.4.0-rc3":         false,
		"8.0.1":             false,
		"garbage":           true,
	} {
		if got := kernelMaySkipSyscallTracepointPrograms(release); got != want {
			t.Errorf("kernelMaySkipSyscallTracepointPrograms(%q) = %t, want %t", release, got, want)
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
	var tracepoints, covered []string
	next := 0
	closer := func() io.Closer {
		next++
		return &testCloser{id: next, closed: &closed}
	}
	functions := attachmentFunctions{
		attachCgroup: func(link.CgroupOptions) (io.Closer, error) { return closer(), nil },
		attachTracepoint: func(category, name string, _ *ebpf.Program) (io.Closer, error) {
			tracepoints = append(tracepoints, category+"/"+name)
			return closer(), nil
		},
		coverTracepointCPUs: func(category, name string) (io.Closer, error) {
			covered = append(covered, category+"/"+name)
			return closer(), nil
		},
	}

	attached, err := attachMonitorPrograms("/sys/fs/cgroup", Options{SecurityEvents: true}, monitorObjects{}, functions)
	if err != nil {
		t.Fatalf("attachMonitorPrograms returned error: %v", err)
	}
	if len(tracepoints) == 0 || !slices.Equal(tracepoints, covered) {
		t.Fatalf("covered tracepoints = %v, want the attached ones %v", covered, tracepoints)
	}
	if !slices.Contains(covered, "syscalls/sys_enter_memfd_create") || !slices.Contains(covered, "syscalls/sys_enter_execve") {
		t.Fatalf("covered tracepoints = %v, want memfd_create and execve", covered)
	}
	if len(attached.cpuEvents) != len(covered) {
		t.Fatalf("returned %d CPU event closers, want one per covered tracepoint (%d)", len(attached.cpuEvents), len(covered))
	}
	if len(attached.links) != next-len(covered) {
		t.Fatalf("returned %d program links, want %d: CPU events are not programs", len(attached.links), next-len(covered))
	}
}

func TestAttachMonitorProgramsSkipsUnneededCPUCoverage(t *testing.T) {
	t.Parallel()

	var closed []int
	functions := attachmentFunctions{
		attachCgroup: func(link.CgroupOptions) (io.Closer, error) { return &testCloser{closed: &closed}, nil },
		attachTracepoint: func(string, string, *ebpf.Program) (io.Closer, error) {
			return &testCloser{closed: &closed}, nil
		},
		coverTracepointCPUs: func(string, string) (io.Closer, error) { return nil, nil }, //nolint:nilnil // nil closer: kernel needs no coverage
	}

	attached, err := attachMonitorPrograms("/sys/fs/cgroup", Options{}, monitorObjects{}, functions)
	if err != nil {
		t.Fatalf("attachMonitorPrograms returned error: %v", err)
	}
	if len(attached.cpuEvents) != 0 || len(attached.links) == 0 {
		t.Fatalf("attachments = %d links, %d CPU events; want links only", len(attached.links), len(attached.cpuEvents))
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

	attached, err := attachMonitorPrograms("/sys/fs/cgroup", Options{}, monitorObjects{}, functions)
	if err == nil || !strings.Contains(err.Error(), "sys_enter_execve tracepoint perf events on every CPU") {
		t.Fatalf("attachMonitorPrograms error = %v, want CPU coverage failure", err)
	}
	if attached.links != nil || attached.cpuEvents != nil {
		t.Fatalf("attachments = %+v, want none", attached)
	}
	want := make([]int, 0, next)
	for id := next; id >= 1; id-- {
		want = append(want, id)
	}
	if !slices.Equal(closed, want) {
		t.Fatalf("close order = %v, want %v", closed, want)
	}
}

func TestAttachedProgramsExcludesTracepointCPUEvents(t *testing.T) {
	t.Parallel()

	var closed []int
	monitor := &Monitor{
		links:               []io.Closer{&testCloser{closed: &closed}, &testCloser{closed: &closed}},
		optionalLinks:       []io.Closer{&testCloser{closed: &closed}},
		tracepointCPUEvents: []io.Closer{&testCloser{closed: &closed}, &testCloser{closed: &closed}},
	}
	if got := monitor.AttachedPrograms(); got != 3 {
		t.Fatalf("AttachedPrograms = %d, want 3", got)
	}
}
