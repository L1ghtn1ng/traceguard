package ebpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestSelectOptionalProgramIsolatesVerifierScope(t *testing.T) {
	t.Parallel()
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatal(err)
	}
	before := len(spec.Programs)
	selected, err := selectOptionalProgram(spec, "trace_connect_unix")
	if err != nil {
		t.Fatal(err)
	}
	if len(selected.Programs) != 1 || selected.Programs["trace_connect_unix"] == nil {
		t.Fatalf("selected programs = %#v, want only trace_connect_unix", selected.Programs)
	}
	if len(spec.Programs) != before {
		t.Fatalf("source spec program count = %d, want %d", len(spec.Programs), before)
	}
	if _, err := selectOptionalProgram(spec, "missing"); err == nil {
		t.Fatal("selectOptionalProgram() accepted a missing program")
	}
}

func TestSockoptPolicyRejectsOversizedExpansion(t *testing.T) {
	t.Parallel()
	uids := make([]uint32, 256)
	for index := range uids {
		uids[index] = uint32(index)
	}
	options := make([]SockoptOption, 72)
	for index := range options {
		options[index] = SockoptOption{Level: 1, OptName: uint32(index)}
	}
	_, err := compileSockoptPolicy(SockoptPolicyConfig{Rules: []SockoptRuleConfig{{
		ID: "too-large", Action: "block", UIDs: uids, HasUIDSelector: true,
		Options: options,
	}}})
	if err == nil {
		t.Fatal("compileSockoptPolicy() accepted expansion beyond map capacity")
	}
}

func TestSockoptPolicyCompilesOnlyListedPairs(t *testing.T) {
	t.Parallel()
	compiled, err := compileSockoptPolicy(SockoptPolicyConfig{Rules: []SockoptRuleConfig{{
		ID: "pairs", Action: "block",
		Options: []SockoptOption{{Level: 1, OptName: 36}, {Level: 0, OptName: 19}},
	}}})
	if err != nil {
		t.Fatalf("compileSockoptPolicy() error = %v", err)
	}
	if len(compiled.block) != 2 {
		t.Fatalf("block entries = %d, want 2: %#v", len(compiled.block), compiled.block)
	}
	// SOL_IP/36 is IP_DROP_MEMBERSHIP and SOL_SOCKET/19 is SO_SNDLOWAT; neither
	// may be produced by crossing the listed levels and names.
	for _, key := range []sockoptKey{{Level: 0, OptName: 36}, {Level: 1, OptName: 19}} {
		key.Kind = egressIdentityGlobal
		if _, exists := compiled.block[key]; exists {
			t.Fatalf("compiled unrelated pair level=%d optname=%d", key.Level, key.OptName)
		}
	}
}

func TestOptionalMapReplacementsOmitNilHandles(t *testing.T) {
	t.Parallel()
	replacements := optionalMapReplacements(monitorObjects{}, nil)
	if len(replacements) != 0 {
		t.Fatalf("replacements = %#v, want empty map", replacements)
	}
}

func TestOptionalMapReplacementsSharePolicyPublicationMaps(t *testing.T) {
	t.Parallel()

	dummy := &ebpf.Map{}
	replacements := optionalMapReplacements(monitorObjects{
		Settings: dummy, PolicySelector: dummy, PolicyReaders: dummy,
		DaemonIdentity: dummy, RuleNames: dummy, Events: dummy, RingbufDrops: dummy,
	}, nil)
	for _, name := range []string{"settings", "policy_selector", "policy_readers", "daemon_identity", "rule_names", "events", "ringbuf_drops"} {
		if replacements[name] != dummy {
			t.Errorf("replacement %q = %p, want shared map %p", name, replacements[name], dummy)
		}
	}
}
