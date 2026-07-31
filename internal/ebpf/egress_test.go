package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestCompileEgressPolicyExpandsIdentityProtocolAndFamily(t *testing.T) {
	t.Parallel()
	compiled, err := compileEgressPolicy(EgressPolicyConfig{
		Rules: []EgressRuleConfig{{
			ID:                "workload-web",
			Action:            "block",
			UIDs:              []uint32{1000},
			CgroupIDs:         []uint64{42},
			HasUIDSelector:    true,
			HasCgroupSelector: true,
			CIDRs: []netip.Prefix{
				netip.MustParsePrefix("10.2.0.0/16"),
				netip.MustParsePrefix("2001:db8::/32"),
			},
			Ports: []uint16{443},
		}},
	})
	if err != nil {
		t.Fatalf("compileEgressPolicy() error = %v", err)
	}
	if got, want := len(compiled.block4), 2; got != want {
		t.Fatalf("IPv4 entries = %d, want %d", got, want)
	}
	if got, want := len(compiled.block6), 2; got != want {
		t.Fatalf("IPv6 entries = %d, want %d", got, want)
	}
	for key := range compiled.block4 {
		if got, want := key.PrefixLen, uint32(egressIdentityBytes*8+16); got != want {
			t.Fatalf("prefix length = %d, want %d", got, want)
		}
		if got, want := key.Data[1], uint8(egressIdentityUIDCgroup); got != want {
			t.Fatalf("identity kind = %d, want %d", got, want)
		}
		if got, want := binary.NativeEndian.Uint32(key.Data[2:6]), uint32(1000); got != want {
			t.Fatalf("uid = %d, want %d", got, want)
		}
		if got, want := binary.NativeEndian.Uint64(key.Data[6:14]), uint64(42); got != want {
			t.Fatalf("cgroup id = %d, want %d", got, want)
		}
		if got, want := binary.BigEndian.Uint16(key.Data[15:17]), uint16(443); got != want {
			t.Fatalf("port = %d, want %d", got, want)
		}
	}
}

func TestCompileEgressPolicySkipsUnresolvedCgroupRule(t *testing.T) {
	t.Parallel()
	compiled, err := compileEgressPolicy(EgressPolicyConfig{
		Rules: []EgressRuleConfig{{
			ID:                "future-workload",
			Action:            "block",
			HasCgroupSelector: true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.block4)+len(compiled.block6) != 0 {
		t.Fatalf("unresolved rule produced entries: IPv4=%d IPv6=%d", len(compiled.block4), len(compiled.block6))
	}
}

func TestCompileEgressPolicyAllowAndBlockAreIndependent(t *testing.T) {
	t.Parallel()
	compiled, err := compileEgressPolicy(EgressPolicyConfig{
		Rules: []EgressRuleConfig{
			{ID: "deny-all", Action: "block"},
			{ID: "allow-dns", Action: "allow", Ports: []uint16{53}, Protocols: []string{"udp"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled.allow4) == 0 || len(compiled.block4) == 0 {
		t.Fatalf("allow/block entries = %d/%d, want both", len(compiled.allow4), len(compiled.block4))
	}
}
