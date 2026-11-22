package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Kernels from 6.19 (which added copying of syscall user arguments to syscall
// trace events) up to, but not including, 7.2 can carry the stable backport of
// "tracing: perf: Fix stale head for perf syscall tracing" (upstream
// 2c2b322acdcc). Ubuntu's 7.0 kernels do. With it, perf_syscall_enter returns
// when the current CPU has no perf event on the syscall tracepoint, before the
// attached BPF program runs. That check only applies to syscalls that read user
// memory, such as execve, openat, unlinkat and memfd_create. A tracepoint link
// opens its perf event on a single CPU (cilium uses CPU 0), so on those kernels
// the program sees only syscalls made on that CPU. From 7.2 the kernel runs
// the BPF program before the check.
//
// coverTracepointCPUs opens a counting perf event for the tracepoint on every
// online CPU, so every CPU's list is non-empty and the program runs wherever
// the syscall is made. The events never sample. TraceGuard's syscall programs
// return 0, which makes the kernel skip perf output, so they cost no work per
// syscall. They cost one descriptor per syscall tracepoint per online CPU. A
// CPU that comes online after the agent starts is not covered until the next
// start.
func coverTracepointCPUs(category, name string) (tracepointCPUEvents, error) {
	id, err := tracepointID(category, name)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, fmt.Errorf("read online CPUs: %w", err)
	}
	cpus, err := parseCPUList(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse online CPUs: %w", err)
	}
	events := make(tracepointCPUEvents, 0, len(cpus))
	for _, cpu := range cpus {
		attr := unix.PerfEventAttr{
			Type:   unix.PERF_TYPE_TRACEPOINT,
			Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
			Config: id,
		}
		fd, err := unix.PerfEventOpen(&attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
		if errors.Is(err, unix.ENODEV) {
			// The CPU went offline after the online list was read.
			continue
		}
		if err != nil {
			_ = events.Close()
			return nil, fmt.Errorf("open %s/%s perf event on CPU %d: %w", category, name, cpu, err)
		}
		events = append(events, fd)
	}
	return events, nil
}

// needsTracepointCPUCoverage reports whether the running kernel may skip
// syscall tracepoint programs on CPUs without a perf event for the tracepoint.
// A release that cannot be read or parsed is treated as affected.
var needsTracepointCPUCoverage = sync.OnceValue(func() bool {
	release, err := kernelRelease()
	return err != nil || kernelMaySkipSyscallTracepointPrograms(release)
})

func kernelMaySkipSyscallTracepointPrograms(release string) bool {
	if _, _, ok := parseKernelRelease(release); !ok {
		return true
	}
	return isKernelAtLeast(release, 6, 19) && !isKernelAtLeast(release, 7, 2)
}

// tracepointCPUEvents holds the perf event descriptors coverTracepointCPUs opened.
type tracepointCPUEvents []int

func (e tracepointCPUEvents) Close() error {
	var errs []error
	for _, fd := range e {
		if err := unix.Close(fd); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

func tracepointID(category, name string) (uint64, error) {
	if !validTracepointName(category) || !validTracepointName(name) {
		return 0, fmt.Errorf("invalid tracepoint %q/%q", category, name)
	}
	var errs []error
	for _, root := range tracefsRoots {
		raw, err := os.ReadFile(filepath.Join(root, "events", category, name, "id")) //nolint:gosec // category and name are checked by validTracepointName
		if err != nil {
			errs = append(errs, err)
			continue
		}
		id, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse %s/%s tracepoint id: %w", category, name, err)
		}
		return id, nil
	}
	return 0, fmt.Errorf("read %s/%s tracepoint id: %w", category, name, errors.Join(errs...))
}

func validTracepointName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// parseCPUList parses a kernel CPU list such as "0-3,8,10-11".
func parseCPUList(list string) ([]int, error) {
	list = strings.TrimSpace(list)
	if list == "" {
		return nil, errors.New("empty CPU list")
	}
	var cpus []int
	for part := range strings.SplitSeq(list, ",") {
		first, last, isRange := strings.Cut(part, "-")
		start, err := strconv.Atoi(first)
		if err != nil || start < 0 {
			return nil, fmt.Errorf("invalid CPU %q", part)
		}
		end := start
		if isRange {
			end, err = strconv.Atoi(last)
			if err != nil || end < start {
				return nil, fmt.Errorf("invalid CPU range %q", part)
			}
		}
		for cpu := start; cpu <= end; cpu++ {
			cpus = append(cpus, cpu)
		}
	}
	return cpus, nil
}
