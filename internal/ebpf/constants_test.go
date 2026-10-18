package ebpf

import (
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestLoadConstantsSetConnectionDedupeWindow(t *testing.T) {
	t.Parallel()

	load := loadConstants{connectionDedupeWindow: 15 * time.Second, connectionDedupeMinBytes: 1 << 20}.specLoader(loadTraceguard)
	spec, err := load()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	var window uint64
	if err := spec.Variables["connection_dedupe_window_ns"].Get(&window); err != nil {
		t.Fatalf("read window: %v", err)
	}
	if window != uint64(15*time.Second) {
		t.Fatalf("connection_dedupe_window_ns = %d, want %d", window, uint64(15*time.Second))
	}
	var minBytes uint64
	if err := spec.Variables["connection_dedupe_min_bytes"].Get(&minBytes); err != nil {
		t.Fatalf("read minimum bytes: %v", err)
	}
	if minBytes != 1<<20 {
		t.Fatalf("connection_dedupe_min_bytes = %d, want %d", minBytes, 1<<20)
	}
}

func TestLoadConstantsSetRingBufferSize(t *testing.T) {
	t.Parallel()

	spec, err := loadConstants{ringBufferSize: 64 << 20}.specLoader(loadTraceguard)()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if got := spec.Maps["events"].MaxEntries; got != 64<<20 {
		t.Fatalf("events MaxEntries = %d, want %d", got, 64<<20)
	}

	spec, err = loadConstants{}.specLoader(loadTraceguard)()
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	if got := spec.Maps["events"].MaxEntries; got != 16<<20 {
		t.Fatalf("default events MaxEntries = %d, want the compiled-in 16 MiB", got)
	}
}

func TestLoadConstantsRejectInvalidRingBufferSize(t *testing.T) {
	t.Parallel()

	for _, size := range []uint32{3 << 20, 100} {
		spec, err := loadTraceguard()
		if err != nil {
			t.Fatal(err)
		}
		if err := (loadConstants{ringBufferSize: size}).apply(spec); err == nil || !strings.Contains(err.Error(), "power of two") {
			t.Fatalf("size %d error = %v, want a power-of-two error", size, err)
		}
	}
}

func TestRingBufferResized(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		pinned, requested uint32
		want              bool
	}{
		{16 << 20, 16 << 20, false},
		{16 << 20, 0, false},
		{16 << 20, 64 << 20, true},
		{64 << 20, 16 << 20, true},
	} {
		if got := ringBufferResized(test.pinned, test.requested); got != test.want {
			t.Errorf("ringBufferResized(%d, %d) = %t, want %t", test.pinned, test.requested, got, test.want)
		}
	}
}

func TestLoadConstantsRejectInvalidInput(t *testing.T) {
	t.Parallel()

	spec, err := loadTraceguard()
	if err != nil {
		t.Fatal(err)
	}
	if err := (loadConstants{connectionDedupeWindow: -time.Second}).apply(spec); err == nil || !strings.Contains(err.Error(), "negative") {
		t.Fatalf("negative window error = %v", err)
	}
	if err := (loadConstants{}).apply(&ebpf.CollectionSpec{}); err == nil || !strings.Contains(err.Error(), "lacks") {
		t.Fatalf("missing variable error = %v", err)
	}
}

func TestEveryObjectExposesConnectionDedupeWindow(t *testing.T) {
	t.Parallel()

	for _, load := range []func() (*ebpf.CollectionSpec, error){
		loadTraceguard, loadTraceguardDNSCompat, loadTraceguardRecvmsgCompat, loadTraceguardDNSRecvmsgCompat,
		loadTraceguardLinux71, loadTraceguardLinux71DNSCompat, loadTraceguardLinux71RecvmsgCompat, loadTraceguardLinux71DNSRecvmsgCompat,
	} {
		spec, err := load()
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"connection_dedupe_window_ns", "connection_dedupe_min_bytes"} {
			variable := spec.Variables[name]
			if variable == nil || !variable.Constant() || variable.Size() != 8 {
				t.Fatalf("%s = %#v, want an 8-byte read-only constant", name, variable)
			}
		}
		if quiet := spec.Maps["sockops_quiet"]; quiet == nil || quiet.Type != ebpf.LRUHash || quiet.KeySize != 8 {
			t.Fatalf("sockops_quiet = %#v, want an LRU hash keyed by socket cookie", quiet)
		}
	}
}
