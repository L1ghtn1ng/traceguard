//go:build linux && ebpfintegration

package ebpf

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

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
	tracepoint, err := link.Tracepoint("syscalls", "sys_enter_memfd_create", objects.TraceMemfdCreate, nil)
	if err != nil {
		t.Fatalf("attach tracepoint: %v", err)
	}
	defer tracepoint.Close()
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
