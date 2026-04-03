//go:build linux && ebpfintegration

package ebpf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type integrationPrograms struct {
	TraceDns               *ebpf.Program `ebpf:"trace_dns"`
	TraceConnectionIngress *ebpf.Program `ebpf:"trace_connection_ingress"`
	TraceSendmsg4          *ebpf.Program `ebpf:"trace_sendmsg4"`
	TraceSendmsg6          *ebpf.Program `ebpf:"trace_sendmsg6"`
	TraceRecvmsg4          *ebpf.Program `ebpf:"trace_recvmsg4"`
	TraceRecvmsg6          *ebpf.Program `ebpf:"trace_recvmsg6"`
	TraceConnect4          *ebpf.Program `ebpf:"trace_connect4"`
	TraceConnect6          *ebpf.Program `ebpf:"trace_connect6"`
	TracePostBind4         *ebpf.Program `ebpf:"trace_post_bind4"`
	TracePostBind6         *ebpf.Program `ebpf:"trace_post_bind6"`
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
	defer objects.TraceConnectionIngress.Close()
	defer objects.TraceSendmsg4.Close()
	defer objects.TraceSendmsg6.Close()
	defer objects.TraceRecvmsg4.Close()
	defer objects.TraceRecvmsg6.Close()
	defer objects.TraceConnect4.Close()
	defer objects.TraceConnect6.Close()
	defer objects.TracePostBind4.Close()
	defer objects.TracePostBind6.Close()
}
