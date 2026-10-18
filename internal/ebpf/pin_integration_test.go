//go:build linux && ebpfintegration

package ebpf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func TestReplacePinnedMapOnBPFFSForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	root, err := os.MkdirTemp("/sys/fs/bpf", "traceguard-pin-test-") //nolint:usetesting // pins need a bpffs directory, which t.TempDir is not
	if err != nil {
		t.Skipf("bpffs unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })

	newRingBuffer := func(size uint32) *ebpf.Map {
		t.Helper()
		ring, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.RingBuf, MaxEntries: size})
		if err != nil {
			t.Fatalf("create ring buffer: %v", err)
		}
		t.Cleanup(func() { _ = ring.Close() })
		return ring
	}
	path := filepath.Join(root, "events")
	if err := newRingBuffer(1 << 16).Pin(path); err != nil {
		t.Fatalf("pin old ring buffer: %v", err)
	}
	if err := replacePinnedMap(path, newRingBuffer(1<<17)); err != nil {
		t.Fatalf("replacePinnedMap: %v", err)
	}
	pinned, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatalf("load replaced pin: %v", err)
	}
	defer func() { _ = pinned.Close() }()
	if got := pinned.MaxEntries(); got != 1<<17 {
		t.Fatalf("pinned ring buffer size = %d, want the replacement's %d", got, 1<<17)
	}
	if _, err := os.Stat(stagedPinPath(path)); !os.IsNotExist(err) {
		t.Fatalf("staged pin left behind: %v", err)
	}
}
