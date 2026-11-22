//go:build linux && ebpfintegration

package ebpf

// Temporary diagnostics for the ubuntu-26.04 tracepoint failures. Not for merge.

import (
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

func diagReadFile(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Logf("DIAG %s: %v", path, err)
		return
	}
	t.Logf("DIAG %s: %s", path, strings.TrimSpace(string(raw)))
}

func diagCounterProgram(t *testing.T, typ ebpf.ProgramType, counter *ebpf.Map) *ebpf.Program {
	t.Helper()
	insns := asm.Instructions{
		asm.StoreImm(asm.RFP, -4, 0, asm.Word),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.LoadMapPtr(asm.R1, counter.FD()),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
		asm.Mov.Imm(asm.R1, 1),
		asm.StoreXAdd(asm.R0, asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Type: typ, Instructions: insns, License: "GPL"})
	if err != nil {
		t.Fatalf("diag counter program: %v", err)
	}
	return prog
}

func diagCount(t *testing.T, counter *ebpf.Map) uint64 {
	t.Helper()
	var value uint64
	if err := counter.Lookup(uint32(0), &value); err != nil {
		t.Fatalf("lookup counter: %v", err)
	}
	return value
}

func TestZZDiagTracepointEnvironment(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	var uts unix.Utsname
	_ = unix.Uname(&uts)
	t.Logf("DIAG uname release=%s version=%s", unix.ByteSliceToString(uts.Release[:]), unix.ByteSliceToString(uts.Version[:]))
	t.Logf("DIAG go=%s", runtime.Version())
	for _, path := range []string{
		"/sys/kernel/security/lockdown",
		"/sys/kernel/security/lsm",
		"/proc/sys/kernel/perf_event_paranoid",
		"/proc/sys/kernel/unprivileged_bpf_disabled",
		"/proc/sys/kernel/bpf_stats_enabled",
		"/sys/kernel/tracing/events/syscalls/sys_enter_memfd_create/id",
		"/sys/kernel/tracing/events/syscalls/sys_enter_memfd_create/enable",
		"/sys/kernel/tracing/events/syscalls/sys_enter_memfd_create/format",
		"/sys/kernel/debug/tracing/events/syscalls/sys_enter_memfd_create/id",
		"/proc/self/status",
		"/proc/self/cgroup",
	} {
		diagReadFile(t, path)
	}
	features := DetectKernelFeatures()
	t.Logf("DIAG features=%+v", features)
}

func TestZZDiagCounterTracepoint(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Logf("DIAG EnableStats: %v", err)
	} else {
		defer stats.Close()
	}
	for _, tc := range []struct {
		name  string
		typ   ebpf.ProgramType
		raw   bool
		event string
	}{
		{name: "tracepoint/memfd", typ: ebpf.TracePoint, event: "sys_enter_memfd_create"},
		{name: "tracepoint/unlinkat", typ: ebpf.TracePoint, event: "sys_enter_unlinkat"},
		{name: "tracepoint/execve", typ: ebpf.TracePoint, event: "sys_enter_execve"},
		{name: "raw_tracepoint/sys_enter", typ: ebpf.RawTracepoint, raw: true, event: "sys_enter"},
	} {
		counter, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1})
		if err != nil {
			t.Fatal(err)
		}
		prog := diagCounterProgram(t, tc.typ, counter)
		var attached link.Link
		if tc.raw {
			attached, err = link.AttachRawTracepoint(link.RawTracepointOptions{Name: tc.event, Program: prog})
		} else {
			attached, err = link.Tracepoint("syscalls", tc.event, prog, nil)
		}
		if err != nil {
			t.Logf("DIAG %s attach: %v", tc.name, err)
			prog.Close()
			counter.Close()
			continue
		}
		info, _ := attached.Info()
		if info != nil {
			t.Logf("DIAG %s link type=%v", tc.name, info.Type)
		}
		for range 5 {
			fd, err := unix.MemfdCreate("traceguard-diag", unix.MFD_CLOEXEC)
			if err == nil {
				_ = unix.Close(fd)
			}
			path := t.TempDir() + "/diag"
			_ = os.WriteFile(path, nil, 0o600)
			_ = unix.Unlinkat(unix.AT_FDCWD, path, 0)
		}
		time.Sleep(200 * time.Millisecond)
		progStats, statsErr := prog.Stats()
		t.Logf("DIAG %s count=%d stats=%+v statsErr=%v", tc.name, diagCount(t, counter), progStats, statsErr)
		attached.Close()
		prog.Close()
		counter.Close()
	}
}

func TestZZDiagTraceguardMemfd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	stats, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err == nil {
		defer stats.Close()
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatal(err)
	}
	retainIntegrationProgram(spec, "trace_memfd_create")
	var objects struct {
		TraceMemfdCreate *ebpf.Program `ebpf:"trace_memfd_create"`
		Events           *ebpf.Map     `ebpf:"events"`
		RingbufDrops     *ebpf.Map     `ebpf:"ringbuf_drops"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceMemfdCreate.Close()
	defer objects.Events.Close()
	defer objects.RingbufDrops.Close()
	t.Logf("DIAG events map max_entries=%d", objects.Events.MaxEntries())
	tp, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objects.TraceMemfdCreate, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	for range 3 {
		fd, err := unix.MemfdCreate("traceguard-diag", unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatalf("memfd_create: %v", err)
		}
		_ = unix.Close(fd)
	}
	time.Sleep(100 * time.Millisecond)
	progStats, statsErr := objects.TraceMemfdCreate.Stats()
	t.Logf("DIAG trace_memfd_create stats=%+v err=%v", progStats, statsErr)
	var drops []uint64
	if err := objects.RingbufDrops.Lookup(uint32(EventMemfdCreate), &drops); err != nil {
		t.Logf("DIAG drops lookup: %v", err)
	} else {
		var total uint64
		for _, d := range drops {
			total += d
		}
		t.Logf("DIAG ringbuf drops for memfd kind=%d", total)
	}
	t.Logf("DIAG reader available=%d size=%d", reader.AvailableBytes(), reader.BufferSize())
	reader.SetDeadline(time.Now().Add(time.Second))
	for {
		record, err := reader.Read()
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Logf("DIAG read: %v", err)
			}
			break
		}
		event, err := decodeEvent(record.RawSample)
		t.Logf("DIAG record len=%d err=%v kind=%d pid=%d (want %d) filename=%q comm=%q", len(record.RawSample), err, event.Kind, event.PID, os.Getpid(), event.Filename, event.Comm)
	}
}
