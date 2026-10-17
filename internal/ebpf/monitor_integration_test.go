//go:build linux && ebpfintegration

package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

const bindPolarityHelperCgroupEnv = "TRACEGUARD_BIND_POLARITY_HELPER_CGROUP"

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

func TestLinux71MonitorObjectsLoadForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}

	objects, features, err := loadLinux71MonitorObjects(newCollectionOptions(), KernelFeatures{
		KernelAtLeast612: true,
		KernelAtLeast71:  true,
	})
	if err != nil {
		fatalVerifierError(t, "loadLinux71MonitorObjects", err)
	}
	defer objects.Close()
	if !features.EnhancedTelemetry {
		t.Fatal("enhanced telemetry was not selected")
	}
}

func TestOptionalLoadAttemptsLeaveCorePolicyMapsWritable(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	options := newCollectionOptions()
	objects, features, err := loadMonitorObjects(options)
	if err != nil {
		fatalVerifierError(t, "loadMonitorObjects", err)
	}
	defer objects.Close()
	optional := loadOptionalPrograms(features.SelectedObject, options, objects, nil)
	defer optional.Close()

	if err := objects.Settings.Put(uint32(0), runtimeSettings{}); err != nil {
		t.Fatalf("settings map became unusable after optional loads: %v", err)
	}
	if err := objects.DaemonIdentity.Put(uint32(0), daemonProcessIdentity{TGID: 1, StartTicks: 1}); err != nil {
		t.Fatalf("daemon identity map became unusable after optional loads: %v", err)
	}
	key := encodePathLPMKey(egressIdentity{kind: egressIdentityGlobal}, 0, 0, "/tmp/tool", true)
	if err := objects.ExecAllowPaths.Put(key, uint32(1)); err != nil {
		t.Fatalf("exec path map became unusable after optional loads: %v", err)
	}
}

func TestOptionalProgramsPassVerifierForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	options := newCollectionOptions()
	objects, features, err := loadMonitorObjects(options)
	if err != nil {
		fatalVerifierError(t, "loadMonitorObjects", err)
	}
	defer objects.Close()
	optional := loadOptionalPrograms(features.SelectedObject, options, objects, nil)
	defer optional.Close()

	// Optional hooks may be missing on older kernels, but a verifier rejection
	// means the program can never load and its policy section can never apply.
	for name, loadErr := range optional.Failures {
		var verifierErr *ebpf.VerifierError
		if errors.As(loadErr, &verifierErr) {
			t.Errorf("optional program %s rejected by verifier: %+v", name, verifierErr)
			continue
		}
		t.Logf("optional program %s unavailable on this kernel: %v", name, loadErr)
	}
}

func TestBind4VerdictPolarityForIntegration(t *testing.T) {
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
	retainIntegrationProgram(spec, "trace_bind4")
	var objects struct {
		TraceBind4     *ebpf.Program `ebpf:"trace_bind4"`
		Settings       *ebpf.Map     `ebpf:"settings"`
		PolicySelector *ebpf.Map     `ebpf:"policy_selector"`
		Bind4Allow     *ebpf.Map     `ebpf:"bind4_allow_rules"`
		Bind4Block     *ebpf.Map     `ebpf:"bind4_block_rules"`
		Events         *ebpf.Map     `ebpf:"events"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "load bind4 polarity program", err)
	}
	t.Cleanup(func() {
		_ = objects.TraceBind4.Close()
		_ = objects.Settings.Close()
		_ = objects.PolicySelector.Close()
		_ = objects.Bind4Allow.Close()
		_ = objects.Bind4Block.Close()
		_ = objects.Events.Close()
	})

	compiled, err := compileEgressPolicy(EgressPolicyConfig{Rules: []EgressRuleConfig{{
		ID: "block-bind", Action: "block",
		CIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}, Protocols: []string{"tcp"},
	}}})
	if err != nil {
		t.Fatalf("compile bind policy: %v", err)
	}
	if err := syncEgress4MapSlot(objects.Bind4Block, compiled.block4, 0); err != nil {
		t.Fatalf("publish bind policy: %v", err)
	}
	if err := syncEgress4MapSlot(objects.Bind4Block, compiled.block4, 1); err != nil {
		t.Fatalf("publish second bind policy slot: %v", err)
	}

	cgroupPath, err := os.MkdirTemp("/sys/fs/cgroup", "traceguard-bind-polarity-")
	if err != nil {
		t.Fatalf("create test cgroup: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Remove(cgroupPath); err != nil {
			t.Errorf("remove test cgroup: %v", err)
		}
	})
	attached, err := link.AttachCgroup(link.CgroupOptions{
		Path: cgroupPath, Attach: ebpf.AttachCGroupInet4Bind, Program: objects.TraceBind4,
	})
	if err != nil {
		t.Fatalf("attach bind4 polarity program: %v", err)
	}
	t.Cleanup(func() {
		if err := attached.Close(); err != nil {
			t.Errorf("close bind4 polarity link: %v", err)
		}
	})

	settings := runtimeSettings{BindEnabled: 1}
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, settings)
	runBindPolarityHelper(t, cgroupPath, false)
	settings.BindEnforce = 1
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 1, 2, settings)
	runBindPolarityHelper(t, cgroupPath, true)
}

func TestBind4VerdictPolarityHelper(t *testing.T) {
	cgroupPath := os.Getenv(bindPolarityHelperCgroupEnv)
	if cgroupPath == "" {
		return
	}
	pid := []byte(strconv.Itoa(os.Getpid()))
	if err := os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), pid, 0o600); err != nil {
		t.Fatalf("join test cgroup: %v", err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	wantDeny, parseErr := strconv.ParseBool(os.Getenv("TRACEGUARD_BIND_POLARITY_HELPER_DENY"))
	if parseErr != nil {
		t.Fatalf("parse helper expectation: %v", parseErr)
	}
	if wantDeny {
		if err == nil {
			_ = listener.Close()
			t.Fatal("enforced bind unexpectedly succeeded")
		}
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("enforced bind error = %v, want EPERM", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("dry-run bind failed: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close dry-run listener: %v", err)
	}
}

func runBindPolarityHelper(t *testing.T, cgroupPath string, wantDeny bool) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestBind4VerdictPolarityHelper$", "-test.v")
	command.Env = append(os.Environ(),
		bindPolarityHelperCgroupEnv+"="+cgroupPath,
		"TRACEGUARD_BIND_POLARITY_HELPER_DENY="+strconv.FormatBool(wantDeny),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bind polarity helper failed: %v\n%s", err, output)
	}
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
		TraceDns       *ebpf.Program `ebpf:"trace_dns"`
		Settings       *ebpf.Map     `ebpf:"settings"`
		PolicySelector *ebpf.Map     `ebpf:"policy_selector"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Settings.Close()
	defer objects.PolicySelector.Close()

	packet := malformedIPv6UDPDNSPacket()
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, runtimeSettings{})
	if result, _, err := objects.TraceDns.Test(packet); err != nil {
		t.Fatalf("test observe packet: %v", err)
	} else if result != 1 {
		t.Fatalf("observe result = %d, want 1", result)
	}
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 1, 2, runtimeSettings{BlockEnabled: 1})
	if result, _, err := objects.TraceDns.Test(packet); err != nil {
		t.Fatalf("test block packet: %v", err)
	} else if result != 0 {
		t.Fatalf("block result = %d, want 0", result)
	}
}

func TestTraceDNSTCPBatchFailsClosedInBlockMode(t *testing.T) {
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
		TraceDns       *ebpf.Program `ebpf:"trace_dns"`
		Settings       *ebpf.Map     `ebpf:"settings"`
		PolicySelector *ebpf.Map     `ebpf:"policy_selector"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Settings.Close()
	defer objects.PolicySelector.Close()

	single := ipv4TCPDNSPacket(false)
	batched := ipv4TCPDNSPacket(true)
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, runtimeSettings{})
	if result, _, err := objects.TraceDns.Test(batched); err != nil {
		t.Fatalf("test observe batch: %v", err)
	} else if result != 1 {
		t.Fatalf("observe batch result = %d, want 1", result)
	}
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 1, 2, runtimeSettings{BlockEnabled: 1})
	if result, _, err := objects.TraceDns.Test(single); err != nil {
		t.Fatalf("test single DNS message: %v", err)
	} else if result != 1 {
		t.Fatalf("single DNS result = %d, want 1", result)
	}
	if result, _, err := objects.TraceDns.Test(batched); err != nil {
		t.Fatalf("test block batch: %v", err)
	} else if result != 0 {
		t.Fatalf("block batch result = %d, want 0", result)
	}
}

func TestTraceDNSMultiQuestionFailsClosedInBlockMode(t *testing.T) {
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
		TraceDns       *ebpf.Program `ebpf:"trace_dns"`
		Settings       *ebpf.Map     `ebpf:"settings"`
		PolicySelector *ebpf.Map     `ebpf:"policy_selector"`
		Blocklist      *ebpf.Map     `ebpf:"blocklist"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Settings.Close()
	defer objects.PolicySelector.Close()
	defer objects.Blocklist.Close()
	blocked, err := encodeDomainKey("blocked.example")
	if err != nil {
		t.Fatalf("encode blocked question: %v", err)
	}
	if err := objects.Blocklist.Put(blocked, uint8(1)); err != nil {
		t.Fatalf("install blocked question: %v", err)
	}

	packets := map[string][]byte{
		"IPv4 UDP": multiQuestionDNSPacket(false, false),
		"IPv4 TCP": multiQuestionDNSPacket(false, true),
		"IPv6 UDP": multiQuestionDNSPacket(true, false),
		"IPv6 TCP": multiQuestionDNSPacket(true, true),
	}
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, runtimeSettings{})
	for name, packet := range packets {
		if result, _, err := objects.TraceDns.Test(packet); err != nil {
			t.Fatalf("test observe %s multi-question request: %v", name, err)
		} else if result != 1 {
			t.Fatalf("observe %s result = %d, want 1", name, result)
		}
	}
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 1, 2, runtimeSettings{BlockEnabled: 1})
	for name, packet := range packets {
		if result, _, err := objects.TraceDns.Test(packet); err != nil {
			t.Fatalf("test block %s multi-question request: %v", name, err)
		} else if result != 0 {
			t.Fatalf("block %s result = %d, want 0", name, result)
		}
	}
}

func TestTraceDNSMalformedQuestionsFailClosedInBlockMode(t *testing.T) {
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
		TraceDns       *ebpf.Program `ebpf:"trace_dns"`
		Settings       *ebpf.Map     `ebpf:"settings"`
		PolicySelector *ebpf.Map     `ebpf:"policy_selector"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Settings.Close()
	defer objects.PolicySelector.Close()

	withTypeClass := func(qname []byte) []byte {
		return append(append([]byte{}, qname...), 0, 1, 0, 1)
	}
	questions := map[string][]byte{
		"compression pointer": withTypeClass([]byte{0xc0, 0x0c}),
		"64-byte label":       withTypeClass(append(append([]byte{64}, bytes.Repeat([]byte{'a'}, 64)...), 0)),
		"embedded zero":       withTypeClass([]byte{3, 'a', 0, 'b', 0}),
		"missing type class":  {7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0},
	}
	packets := make(map[string][]byte, 2*len(questions))
	for name, question := range questions {
		packets[name+" UDP"] = ipv4DNSQuestionPacket(question, false)
		packets[name+" TCP"] = ipv4DNSQuestionPacket(question, true)
	}

	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, runtimeSettings{})
	for name, packet := range packets {
		if result, _, err := objects.TraceDns.Test(packet); err != nil {
			t.Fatalf("test observe %s: %v", name, err)
		} else if result != 1 {
			t.Fatalf("observe %s result = %d, want 1", name, result)
		}
	}
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 1, 2, runtimeSettings{BlockEnabled: 1})
	for name, packet := range packets {
		if result, _, err := objects.TraceDns.Test(packet); err != nil {
			t.Fatalf("test block %s: %v", name, err)
		} else if result != 0 {
			t.Fatalf("block %s result = %d, want 0", name, result)
		}
	}
}

func retainIntegrationProgram(spec *ebpf.CollectionSpec, name string) {
	for programName := range spec.Programs {
		if programName != name {
			delete(spec.Programs, programName)
		}
	}
}

func publishIntegrationSettings(t *testing.T, settingsMap, selectorMap *ebpf.Map, slot uint8, generation uint32, settings runtimeSettings) {
	t.Helper()
	settings.ActivePolicySlot = slot
	settings.PolicyGeneration = generation
	if err := settingsMap.Put(uint32(slot), settings); err != nil {
		t.Fatalf("write policy settings slot %d: %v", slot, err)
	}
	if err := selectorMap.Put(uint32(0), encodePolicySelector(slot, generation)); err != nil {
		t.Fatalf("publish policy selector: %v", err)
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

// withEthernetHeader prefixes an IP packet with the Ethernet header that
// BPF_PROG_TEST_RUN consumes for skb programs; cgroup_skb programs then see
// the IP header at offset 0, as they do when attached.
func withEthernetHeader(packet []byte) []byte {
	const ethernetHeaderLen = 14
	frame := make([]byte, ethernetHeaderLen+len(packet))
	etherType := uint16(0x0800)
	if len(packet) > 0 && packet[0]>>4 == 6 {
		etherType = 0x86dd
	}
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[ethernetHeaderLen:], packet)
	return frame
}

func malformedIPv6UDPDNSPacket() []byte {
	packet := make([]byte, 40+8+1)
	ip := packet
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 9)
	ip[6] = 17
	ip[7] = 64
	ip[39] = 1
	binary.BigEndian.PutUint16(ip[40:42], 12345)
	binary.BigEndian.PutUint16(ip[42:44], 53)
	binary.BigEndian.PutUint16(ip[44:46], 9)
	return withEthernetHeader(packet)
}

func ipv4TCPDNSPacket(batched bool) []byte {
	qname := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	dns := make([]byte, 12+len(qname)+4)
	binary.BigEndian.PutUint16(dns[4:6], 1)
	copy(dns[12:], qname)
	binary.BigEndian.PutUint16(dns[len(dns)-4:len(dns)-2], 1)
	binary.BigEndian.PutUint16(dns[len(dns)-2:], 1)
	payload := make([]byte, 2+len(dns))
	binary.BigEndian.PutUint16(payload[:2], uint16(len(dns)))
	copy(payload[2:], dns)
	if batched {
		payload = append(payload, payload...)
	}

	packet := make([]byte, 20+20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = unix.IPPROTO_TCP
	packet[19] = 1
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	packet[32] = 5 << 4
	copy(packet[40:], payload)
	return withEthernetHeader(packet)
}

func ipv4DNSQuestionPacket(question []byte, tcp bool) []byte {
	dns := make([]byte, 12, 12+len(question))
	binary.BigEndian.PutUint16(dns[4:6], 1)
	dns = append(dns, question...)
	payload := dns
	protocol := uint8(unix.IPPROTO_UDP)
	transportLength := 8
	if tcp {
		payload = make([]byte, 2+len(dns))
		binary.BigEndian.PutUint16(payload[:2], uint16(len(dns)))
		copy(payload[2:], dns)
		protocol = unix.IPPROTO_TCP
		transportLength = 20
	}
	packet := make([]byte, 20+transportLength+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	packet[19] = 1
	binary.BigEndian.PutUint16(packet[20:22], 12345)
	binary.BigEndian.PutUint16(packet[22:24], 53)
	if tcp {
		packet[32] = 5 << 4
	} else {
		binary.BigEndian.PutUint16(packet[24:26], uint16(transportLength+len(payload)))
	}
	copy(packet[20+transportLength:], payload)
	return withEthernetHeader(packet)
}

func multiQuestionDNSPacket(ipv6, tcp bool) []byte {
	question := func(label string) []byte {
		encoded := make([]byte, 0, len(label)+6)
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, label...)
		encoded = append(encoded, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1)
		return encoded
	}
	dns := make([]byte, 12)
	binary.BigEndian.PutUint16(dns[4:6], 2)
	dns = append(dns, question("allowed")...)
	dns = append(dns, question("blocked")...)
	payload := dns
	protocol := uint8(unix.IPPROTO_UDP)
	transportLength := 8
	if tcp {
		payload = make([]byte, 2+len(dns))
		binary.BigEndian.PutUint16(payload[:2], uint16(len(dns)))
		copy(payload[2:], dns)
		protocol = unix.IPPROTO_TCP
		transportLength = 20
	}

	ipLength := 20
	if ipv6 {
		ipLength = 40
	}
	packet := make([]byte, ipLength+transportLength+len(payload))
	if ipv6 {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-ipLength))
		packet[6] = protocol
		packet[7] = 64
		packet[39] = 1
	} else {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8] = 64
		packet[9] = protocol
		packet[19] = 1
	}
	binary.BigEndian.PutUint16(packet[ipLength:ipLength+2], 12345)
	binary.BigEndian.PutUint16(packet[ipLength+2:ipLength+4], 53)
	if tcp {
		packet[ipLength+12] = 5 << 4
	} else {
		binary.BigEndian.PutUint16(packet[ipLength+4:ipLength+6], uint16(transportLength+len(payload)))
	}
	copy(packet[ipLength+transportLength:], payload)
	return withEthernetHeader(packet)
}
