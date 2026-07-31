package blocklist

import (
	"context"
	"net"
	"net/netip"
	"reflect"
	"testing"
)

func TestParsePolicyRulesSupportsDNSPolicyEntries(t *testing.T) {
	t.Parallel()

	rules, err := ParsePolicyRules(
		[]string{"*", "suffix:blocked.example", "https://dns.example/dns-query", "192.0.2.0/24"},
		[]string{"corp.example", "*.trusted.example", "dot://one.one.one.one"},
	)
	if err != nil {
		t.Fatalf("ParsePolicyRules() error = %v", err)
	}
	if !rules.BlockAllDomains || !rules.BlockAllResolvers {
		t.Fatalf("deny-all flags = %v, %v; want both true", rules.BlockAllDomains, rules.BlockAllResolvers)
	}
	if got, want := rules.AllowDomains, []string{"corp.example", "one.one.one.one"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowDomains = %v, want %v", got, want)
	}
	if got, want := rules.BlockSuffixes, []string{"blocked.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("BlockSuffixes = %v, want %v", got, want)
	}
	if got, want := rules.AllowSuffixes, []string{"trusted.example"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowSuffixes = %v, want %v", got, want)
	}
	if len(rules.BlockEndpoints) != 1 || rules.BlockEndpoints[0].Kind != EndpointKindDoH {
		t.Fatalf("BlockEndpoints = %#v, want one DoH endpoint", rules.BlockEndpoints)
	}
	if len(rules.AllowEndpoints) != 1 || rules.AllowEndpoints[0].Kind != EndpointKindDoT {
		t.Fatalf("AllowEndpoints = %#v, want one DoT endpoint", rules.AllowEndpoints)
	}
	if got, want := len(rules.BlockEndpointCIDRs), 2; got != want {
		t.Fatalf("len(BlockEndpointCIDRs) = %d, want %d", got, want)
	}
}

func TestPolicyAllowRulesTakePrecedence(t *testing.T) {
	t.Parallel()

	policy := NewPolicy(Rules{
		BlockAllDomains:   true,
		BlockAllResolvers: true,
		AllowDomains:      []string{"exact.example"},
		AllowSuffixes:     []string{"trusted.example"},
		AllowEndpointCIDRs: []EndpointCIDR{{
			Kind:   EndpointKindDoH,
			Prefix: netip.MustParsePrefix("192.0.2.0/24"),
			Port:   443,
		}},
	}, nil, nil)

	if got := policy.DomainDecision("exact.example"); got != DecisionAllow {
		t.Fatalf("exact domain decision = %q, want %q", got, DecisionAllow)
	}
	if got := policy.DomainDecision("api.trusted.example"); got != DecisionAllow {
		t.Fatalf("suffix domain decision = %q, want %q", got, DecisionAllow)
	}
	if got := policy.DomainDecision("blocked.example"); got != DecisionBlock {
		t.Fatalf("blocked domain decision = %q, want %q", got, DecisionBlock)
	}
	if got := policy.EndpointDecision("doh", "192.0.2.10", 443); got != DecisionAllow {
		t.Fatalf("allowed endpoint decision = %q, want %q", got, DecisionAllow)
	}
	if got := policy.EndpointDecision("dot", "192.0.2.10", 853); got != DecisionBlock {
		t.Fatalf("blocked endpoint decision = %q, want %q", got, DecisionBlock)
	}
}

func TestResolveEndpointsDoesNotLookUpLiteralIPs(t *testing.T) {
	t.Parallel()

	resolved, err := ResolveEndpoints(context.Background(), []EndpointRule{
		{Kind: EndpointKindDoH, Host: "192.0.2.1", Port: 443},
		{Kind: EndpointKindDoT, Host: "2001:db8::1", Port: 853},
	})
	if err != nil {
		t.Fatalf("ResolveEndpoints() error = %v", err)
	}
	if len(resolved) != 2 {
		t.Fatalf("ResolveEndpoints() returned %d entries, want 2", len(resolved))
	}
	if !resolved[0].IP.Equal(net.ParseIP("192.0.2.1")) || !resolved[1].IP.Equal(net.ParseIP("2001:db8::1")) {
		t.Fatalf("resolved IPs = %v, %v", resolved[0].IP, resolved[1].IP)
	}
}
