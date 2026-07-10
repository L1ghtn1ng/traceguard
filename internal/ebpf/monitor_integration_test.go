//go:build linux && ebpfintegration

package ebpf

import (
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

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
	retainIntegrationProgram(spec, "trace_dns")

	var objects struct {
		TraceDns *ebpf.Program `ebpf:"trace_dns"`
		Settings *ebpf.Map     `ebpf:"settings"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
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
	retainIntegrationProgram(spec, "trace_dns")
	var objects struct {
		TraceDns *ebpf.Program `ebpf:"trace_dns"`
		Settings *ebpf.Map     `ebpf:"settings"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
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

func retainIntegrationProgram(spec *ebpf.CollectionSpec, name string) {
	for programName := range spec.Programs {
		if programName != name {
			delete(spec.Programs, programName)
		}
	}
}

func fatalVerifierError(t *testing.T, operation string, err error) {
	t.Helper()
	var verifierErr *ebpf.VerifierError
	if errors.As(err, &verifierErr) {
		t.Fatalf("%s returned verifier error: %-40v", operation, verifierErr)
	}
	t.Fatalf("%s returned error: %v", operation, err)
}

func malformedIPv6UDPDNSPacket() []byte {
	const ethernetHeaderLen = 14
	packet := make([]byte, ethernetHeaderLen+40+8+1)
	binary.BigEndian.PutUint16(packet[12:14], 0x86dd)
	ip := packet[ethernetHeaderLen:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 9)
	ip[6] = 17
	ip[7] = 64
	ip[39] = 1
	binary.BigEndian.PutUint16(ip[40:42], 12345)
	binary.BigEndian.PutUint16(ip[42:44], 53)
	binary.BigEndian.PutUint16(ip[44:46], 9)
	return packet
}
