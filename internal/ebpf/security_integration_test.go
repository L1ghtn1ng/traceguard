//go:build linux && ebpfintegration

package ebpf

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// attachSyscallTracepointForIntegration attaches program the way the monitor
// does, including the per-CPU perf events that keep it running on every CPU.
func attachSyscallTracepointForIntegration(t *testing.T, name string, program *ebpf.Program) {
	t.Helper()
	functions := defaultAttachmentFunctions()
	tracepoint, err := functions.attachTracepoint("syscalls", name, program)
	if err != nil {
		t.Fatalf("attach %s tracepoint: %v", name, err)
	}
	t.Cleanup(func() { _ = tracepoint.Close() })
	cover, err := functions.coverTracepointCPUs("syscalls", name)
	if err != nil {
		t.Fatalf("cover %s tracepoint on every CPU: %v", name, err)
	}
	t.Cleanup(func() { _ = cover.Close() })
}

// TestSyscallTracepointRunsOnEveryCPUForIntegration makes the syscall on each
// online CPU in turn. Linux 7.0 kernels skip syscall tracepoint programs on
// CPUs without a perf event for the tracepoint, which a single tracepoint link
// does not provide.
func TestSyscallTracepointRunsOnEveryCPUForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	raw, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		t.Fatal(err)
	}
	cpus, err := parseCPUList(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	retainIntegrationProgram(spec, "trace_memfd_create")
	var objects struct {
		TraceMemfdCreate *ebpf.Program `ebpf:"trace_memfd_create"`
		Events           *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceMemfdCreate.Close()
	defer objects.Events.Close()
	attachSyscallTracepointForIntegration(t, "sys_enter_memfd_create", objects.TraceMemfdCreate)
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer reader.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var original unix.CPUSet
	if err := unix.SchedGetaffinity(0, &original); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.SchedSetaffinity(0, &original) }()
	want := make(map[string]int, len(cpus))
	for _, cpu := range cpus {
		if !original.IsSet(cpu) {
			continue
		}
		var set unix.CPUSet
		set.Set(cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			t.Fatalf("pin to CPU %d: %v", cpu, err)
		}
		name := "traceguard-cpu-" + strconv.Itoa(cpu)
		fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
		if err != nil {
			t.Fatalf("memfd_create on CPU %d: %v", cpu, err)
		}
		_ = unix.Close(fd)
		want[name] = cpu
	}
	if len(want) == 0 {
		t.Skip("no online CPU is in this process's affinity mask")
	}

	reader.SetDeadline(time.Now().Add(2 * time.Second))
	for len(want) > 0 {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("no memfd_create event from CPUs %v before the deadline", want)
			}
			t.Fatalf("Read returned error: %v", err)
		}
		event, err := decodeEvent(record.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == EventMemfdCreate && event.PID == uint32(os.Getpid()) {
			delete(want, event.Filename)
		}
	}
}

func TestMemfdCreateTracepointEmitsSecurityEventForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	retainIntegrationProgram(spec, "trace_memfd_create")
	var objects struct {
		TraceMemfdCreate *ebpf.Program `ebpf:"trace_memfd_create"`
		Events           *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceMemfdCreate.Close()
	defer objects.Events.Close()
	attachSyscallTracepointForIntegration(t, "sys_enter_memfd_create", objects.TraceMemfdCreate)
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer reader.Close()

	fd, err := unix.MemfdCreate("traceguard-integration", unix.MFD_CLOEXEC)
	if err != nil {
		t.Fatalf("memfd_create: %v", err)
	}
	_ = unix.Close(fd)

	reader.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("no memfd_create event read before the deadline")
			}
			t.Fatalf("Read returned error: %v", err)
		}
		event, err := decodeEvent(record.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind != EventMemfdCreate || event.PID != uint32(os.Getpid()) {
			continue
		}
		if event.Filename != "traceguard-integration" || event.FileFlags != unix.MFD_CLOEXEC || event.UIDSource != "kernel" {
			t.Fatalf("memfd event = %+v", event)
		}
		return
	}
}

func TestExecTracepointCapturesCommandLineForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	retainIntegrationProgram(spec, "trace_execve")
	var objects struct {
		TraceExecve *ebpf.Program `ebpf:"trace_execve"`
		Events      *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceExecve.Close()
	defer objects.Events.Close()
	attachSyscallTracepointForIntegration(t, "sys_enter_execve", objects.TraceExecve)
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer reader.Close()

	marker := "traceguard-argv-" + strconv.Itoa(os.Getpid())
	if err := exec.Command("/bin/true", marker, "second").Run(); err != nil {
		t.Fatalf("run /bin/true: %v", err)
	}

	reader.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("no exec event with the marker read before the deadline")
			}
			t.Fatalf("Read returned error: %v", err)
		}
		event, err := decodeEvent(record.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind != EventExec || len(event.Args) < 2 || event.Args[1] != marker {
			continue
		}
		if event.Filename != "/bin/true" || len(event.Args) != 3 || event.Args[2] != "second" || event.ArgsTruncated {
			t.Fatalf("exec event = path %q args %q truncated %t", event.Filename, event.Args, event.ArgsTruncated)
		}
		return
	}
}

func TestUnlinkatTracepointEmitsFileChangeForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	retainIntegrationProgram(spec, "trace_unlinkat")
	var objects struct {
		TraceUnlinkat *ebpf.Program `ebpf:"trace_unlinkat"`
		Events        *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceUnlinkat.Close()
	defer objects.Events.Close()
	attachSyscallTracepointForIntegration(t, "sys_enter_unlinkat", objects.TraceUnlinkat)
	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer reader.Close()

	path := t.TempDir() + "/traceguard-unlink"
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Unlinkat(unix.AT_FDCWD, path, 0); err != nil {
		t.Fatalf("unlinkat: %v", err)
	}

	reader.SetDeadline(time.Now().Add(2 * time.Second))
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatal("no file change event read before the deadline")
			}
			t.Fatalf("Read returned error: %v", err)
		}
		event, err := decodeEvent(record.RawSample)
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind != EventFileChange || event.Filename != path {
			continue
		}
		if event.Operation != 0 || int32(event.FileMode) != unix.AT_FDCWD { //nolint:gosec // dirfd is signed
			t.Fatalf("file change event = %+v", event)
		}
		return
	}
}

func TestResponsePeerBlockDropsEgressForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	retainIntegrationProgram(spec, "trace_dns")
	var objects struct {
		TraceDns          *ebpf.Program `ebpf:"trace_dns"`
		Settings          *ebpf.Map     `ebpf:"settings"`
		PolicySelector    *ebpf.Map     `ebpf:"policy_selector"`
		ResponsePeers     *ebpf.Map     `ebpf:"response_peers"`
		ResponsePeerDrops *ebpf.Map     `ebpf:"response_peer_drops"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Settings.Close()
	defer objects.PolicySelector.Close()
	defer objects.ResponsePeers.Close()
	defer objects.ResponsePeerDrops.Close()
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, runtimeSettings{})
	monitor := &Monitor{objects: monitorObjects{ResponsePeers: objects.ResponsePeers, ResponsePeerDrops: objects.ResponsePeerDrops}}

	// ipv4DNSQuestionPacket is addressed to 0.0.0.1.
	packet := ipv4DNSQuestionPacket([]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}, false)
	peer := netip.MustParseAddr("0.0.0.1")
	if err := monitor.BlockPeer(peer, time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("BlockPeer: %v", err)
	}
	if result, _, err := objects.TraceDns.Test(packet); err != nil || result != 0 {
		t.Fatalf("blocked peer result = %d, %v; want 0", result, err)
	}
	if egress, _, err := monitor.ResponsePeerDrops(); err != nil || egress == 0 {
		t.Fatalf("egress drops = %d, %v", egress, err)
	}
	if err := monitor.UnblockPeer(peer); err != nil {
		t.Fatalf("UnblockPeer: %v", err)
	}
	if result, _, err := objects.TraceDns.Test(packet); err != nil || result != 1 {
		t.Fatalf("unblocked peer result = %d, %v; want 1", result, err)
	}
}
