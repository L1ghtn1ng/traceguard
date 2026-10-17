package ebpf

import (
	"encoding/binary"
	"net/netip"
	"strings"
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

func TestCompileEgressPolicyRejectsAggregateExpansionBeforeBuildingIt(t *testing.T) {
	t.Parallel()

	makeRule := func(id string, firstUID uint32) EgressRuleConfig {
		uids := make([]uint32, 128)
		for index := range uids {
			uids[index] = firstUID + uint32(index)
		}
		ports := make([]uint16, 65)
		for index := range ports {
			ports[index] = uint16(index + 1)
		}
		return EgressRuleConfig{
			ID: id, Action: "block", UIDs: uids, HasUIDSelector: true,
			CIDRs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			Ports: ports, Protocols: []string{"tcp"},
		}
	}

	_, err := compileEgressPolicy(EgressPolicyConfig{Rules: []EgressRuleConfig{
		makeRule("first", 1000),
		makeRule("second", 2000),
	}})
	if err == nil || !strings.Contains(err.Error(), "IPv4 block egress entries exceed map capacity") {
		t.Fatalf("compileEgressPolicy() error = %v, want aggregate capacity rejection", err)
	}
}

func TestCompileEgressPolicyEncodesAncestorIdentityKinds(t *testing.T) {
	t.Parallel()

	compiled, err := compileEgressPolicy(EgressPolicyConfig{Rules: []EgressRuleConfig{{
		ID: "prefix", Action: "block", UIDs: []uint32{1000},
		CgroupAncestorIDs: []uint64{42}, HasUIDSelector: true, HasCgroupSelector: true,
		CIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protocols: []string{"tcp"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	for key := range compiled.block4 {
		if key.Data[1] != egressIdentityUIDCgroupAncestor {
			t.Fatalf("identity kind = %d, want ancestor kind %d", key.Data[1], egressIdentityUIDCgroupAncestor)
		}
		if got := binary.NativeEndian.Uint64(key.Data[6:14]); got != 42 {
			t.Fatalf("ancestor cgroup ID = %d, want 42", got)
		}
	}
}

func TestCanonicalPrefixNormalizesIPv4MappedIPv6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "native IPv4", input: "192.0.2.129/24", want: "192.0.2.0/24"},
		{name: "native IPv6", input: "2001:db8::1/64", want: "2001:db8::/64"},
		{name: "mapped host", input: "::ffff:192.0.2.129/128", want: "192.0.2.129/32"},
		{name: "mapped subnet", input: "::ffff:192.0.2.129/120", want: "192.0.2.0/24"},
		{name: "ambiguous mapped range", input: "::ffff:192.0.2.129/95", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := canonicalPrefix(netip.MustParsePrefix(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("canonicalPrefix(%q) = %s, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("canonicalPrefix(%q) returned error: %v", tt.input, err)
			}
			if got.String() != tt.want {
				t.Fatalf("canonicalPrefix(%q) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}
