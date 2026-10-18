package ebpf

import (
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestLoadConstantsSetConnectionDedupeWindow(t *testing.T) {
	t.Parallel()

	load := loadConstants{connectionDedupeWindow: 15 * time.Second}.specLoader(loadTraceguard)
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
		variable := spec.Variables["connection_dedupe_window_ns"]
		if variable == nil || !variable.Constant() || variable.Size() != 8 {
			t.Fatalf("connection_dedupe_window_ns = %#v, want an 8-byte read-only constant", variable)
		}
	}
}
