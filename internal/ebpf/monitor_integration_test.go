//go:build linux && ebpfintegration

package ebpf

import (
	"encoding/binary"
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
	Settings               *ebpf.Map     `ebpf:"settings"`
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
	defer objects.Settings.Close()
}

func TestTraceDNSMalformedIPv6UDPFailClosedInBlockMode(t *testing.T) {
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
	var objects struct {
		TraceDns *ebpf.Program `ebpf:"trace_dns"`
		Settings *ebpf.Map     `ebpf:"settings"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		t.Fatalf("LoadAndAssign returned error: %v", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Settings.Close()

	packet := malformedIPv6UDPDNSPacket()
	if err := objects.Settings.Put(uint32(0), runtimeSettings{}); err != nil {
		t.Fatalf("set observe mode: %v", err)
	}
	if result, _, err := objects.TraceDns.Test(packet); err != nil {
		t.Fatalf("test observe packet: %v", err)
	} else if result != 1 {
		t.Fatalf("observe result = %d, want 1", result)
	}
	if err := objects.Settings.Put(uint32(0), runtimeSettings{BlockEnabled: 1}); err != nil {
		t.Fatalf("set block mode: %v", err)
	}
	if result, _, err := objects.TraceDns.Test(packet); err != nil {
		t.Fatalf("test block packet: %v", err)
	} else if result != 0 {
		t.Fatalf("block result = %d, want 0", result)
	}
}

func malformedIPv6UDPDNSPacket() []byte {
	packet := make([]byte, 40+8+1)
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], 9)
	packet[6] = 17
	packet[7] = 64
	packet[39] = 1
	binary.BigEndian.PutUint16(packet[40:42], 12345)
	binary.BigEndian.PutUint16(packet[42:44], 53)
	binary.BigEndian.PutUint16(packet[44:46], 9)
	return packet
}
