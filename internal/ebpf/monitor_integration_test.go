//go:build linux && ebpfintegration

package ebpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type integrationPrograms struct {
	TraceDns *ebpf.Program `ebpf:"trace_dns"`
}

func TestTraceDNSProgramLoadsForIntegration(t *testing.T) {
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

	var objects integrationPrograms
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		t.Fatalf("LoadAndAssign returned error: %v", err)
	}
	defer objects.TraceDns.Close()
}
