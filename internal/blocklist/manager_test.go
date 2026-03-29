package blocklist

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseEntriesNormalizesAndDeduplicates(t *testing.T) {
	t.Parallel()

	input := strings.NewReader(`
# comment
Example.com
https://api.EXAMPLE.com/path
127.0.0.1 bad.example.org
*.example.com
bad entry$
`)

	got, err := ParseEntries(input)
	if err != nil {
		t.Fatalf("ParseEntries returned error: %v", err)
	}

	want := []string{
		"api.example.com",
		"bad.example.org",
		"example.com",
	}

	if len(got) != len(want) {
		t.Fatalf("ParseEntries length mismatch got=%d want=%d values=%v", len(got), len(want), got)
	}

	for idx := range want {
		if got[idx] != want[idx] {
			t.Fatalf("ParseEntries[%d] = %q, want %q", idx, got[idx], want[idx])
		}
	}
}

func TestNormalizeDomainRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	cases := []string{
		"",
		"http://",
		"with space.example",
		"UPPER_bad^",
		strings.Repeat("a", 64) + ".example",
	}

	for _, input := range cases {
		if got, ok := normalizeDomain(input); ok {
			t.Fatalf("normalizeDomain(%q) = %q, expected rejection", input, got)
		}
	}
}

func TestParseRulesIncludesDoHEndpoints(t *testing.T) {
	t.Parallel()

	rules, err := ParseRules(strings.NewReader(`
https://dns.google/dns-query
dot://one.one.one.one
allow:good.example.org
*.corp.example
suffix:svc.cluster.local
example.org
`))
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}

	if len(rules.BlockDomains) != 3 {
		t.Fatalf("expected 3 block domains, got %d: %v", len(rules.BlockDomains), rules.BlockDomains)
	}
	if len(rules.BlockEndpoints) != 2 {
		t.Fatalf("expected 2 block endpoints, got %d: %v", len(rules.BlockEndpoints), rules.BlockEndpoints)
	}
	if len(rules.AllowDomains) != 1 || rules.AllowDomains[0] != "good.example.org" {
		t.Fatalf("unexpected allow domains: %v", rules.AllowDomains)
	}
	if len(rules.BlockSuffixes) != 2 {
		t.Fatalf("expected 2 block suffixes, got %d: %v", len(rules.BlockSuffixes), rules.BlockSuffixes)
	}
}

func TestParseRulesSupportsDenyAllMarker(t *testing.T) {
	t.Parallel()

	rules, err := ParseRules(strings.NewReader(`
*
allow:resolver.example.com
allow:https://1.1.1.1/dns-query
`))
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}

	if !rules.BlockAllDomains || !rules.BlockAllResolvers {
		t.Fatalf("expected deny-all markers to be set, got %+v", rules)
	}
	if len(rules.AllowDomains) != 1 || rules.AllowDomains[0] != "resolver.example.com" {
		t.Fatalf("unexpected allow domains: %v", rules.AllowDomains)
	}
	if len(rules.AllowEndpoints) != 1 {
		t.Fatalf("expected 1 allow endpoint, got %d: %v", len(rules.AllowEndpoints), rules.AllowEndpoints)
	}
	if got := rules.AllowEndpoints[0].Host; got != "1.1.1.1" {
		t.Fatalf("allow endpoint host = %q, want 1.1.1.1", got)
	}
}

func TestParseRulesSupportsIPv6EndpointLiterals(t *testing.T) {
	t.Parallel()

	rules, err := ParseRules(strings.NewReader(`
allow:https://[2606:4700:4700::1111]/dns-query
allow:dot://[2606:4700:4700::1111]
`))
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}

	if len(rules.AllowEndpoints) != 2 {
		t.Fatalf("expected 2 allow endpoints, got %d: %v", len(rules.AllowEndpoints), rules.AllowEndpoints)
	}
	for _, endpoint := range rules.AllowEndpoints {
		if endpoint.Host != "2606:4700:4700::1111" {
			t.Fatalf("allow endpoint host = %q, want canonical IPv6 literal", endpoint.Host)
		}
	}
}

func TestParseRulesSupportsBareIPLiterals(t *testing.T) {
	t.Parallel()

	rules, err := ParseRules(strings.NewReader(`
allow:1.1.1.1
allow:[2606:4700:4700::1111]
9.9.9.9
`))
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}

	if len(rules.AllowEndpoints) != 4 {
		t.Fatalf("expected 4 allow endpoints, got %d: %v", len(rules.AllowEndpoints), rules.AllowEndpoints)
	}
	if len(rules.BlockEndpoints) != 2 {
		t.Fatalf("expected 2 block endpoints, got %d: %v", len(rules.BlockEndpoints), rules.BlockEndpoints)
	}
	for _, endpoint := range append(append([]EndpointRule{}, rules.AllowEndpoints...), rules.BlockEndpoints...) {
		switch endpoint.Port {
		case 443, 853:
		default:
			t.Fatalf("unexpected implicit endpoint port %d in %v", endpoint.Port, endpoint)
		}
	}
}

func TestParseRulesSupportsBareCIDRs(t *testing.T) {
	t.Parallel()

	rules, err := ParseRules(strings.NewReader(`
allow:1.1.1.0/24
allow:2606:4700:4700::/48
9.9.9.0/24
`))
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}

	if len(rules.AllowEndpointCIDRs) != 4 {
		t.Fatalf("expected 4 allow endpoint cidrs, got %d: %v", len(rules.AllowEndpointCIDRs), rules.AllowEndpointCIDRs)
	}
	if len(rules.BlockEndpointCIDRs) != 2 {
		t.Fatalf("expected 2 block endpoint cidrs, got %d: %v", len(rules.BlockEndpointCIDRs), rules.BlockEndpointCIDRs)
	}
	for _, cidr := range append(append([]EndpointCIDR{}, rules.AllowEndpointCIDRs...), rules.BlockEndpointCIDRs...) {
		switch cidr.Port {
		case 443, 853:
		default:
			t.Fatalf("unexpected implicit cidr port %d in %v", cidr.Port, cidr)
		}
	}
}

func TestPolicyAllowOverridesBlock(t *testing.T) {
	t.Parallel()

	rules := Rules{
		BlockDomains: []string{"example.com"},
		AllowDomains: []string{"example.com"},
	}
	policy := NewPolicy(rules, nil, nil)
	if got := policy.DomainDecision("example.com"); got != DecisionAllow {
		t.Fatalf("DomainDecision = %q, want %q", got, DecisionAllow)
	}
}

func TestPolicySuffixMatchesSubdomains(t *testing.T) {
	t.Parallel()

	rules := Rules{
		BlockSuffixes: []string{"example.com"},
		AllowDomains:  []string{"allowed.example.com"},
	}
	policy := NewPolicy(rules, nil, nil)
	if got := policy.DomainDecision("api.example.com"); got != DecisionBlock {
		t.Fatalf("DomainDecision(api.example.com) = %q, want %q", got, DecisionBlock)
	}
	if got := policy.DomainDecision("allowed.example.com"); got != DecisionAllow {
		t.Fatalf("DomainDecision(allowed.example.com) = %q, want %q", got, DecisionAllow)
	}
}

func TestPolicyAllowSuffixOverridesBlockExact(t *testing.T) {
	t.Parallel()

	rules := Rules{
		BlockDomains:  []string{"api.example.com"},
		AllowSuffixes: []string{"example.com"},
	}
	policy := NewPolicy(rules, nil, nil)
	if got := policy.DomainDecision("api.example.com"); got != DecisionAllow {
		t.Fatalf("DomainDecision(api.example.com) = %q, want %q", got, DecisionAllow)
	}
}

func TestPolicyDenyAllUsesAllowOverrides(t *testing.T) {
	t.Parallel()

	rules := Rules{
		BlockAllDomains:   true,
		BlockAllResolvers: true,
		AllowDomains:      []string{"allowed.example.com"},
	}
	policy := NewPolicy(rules, nil, []ResolvedEndpoint{{
		Kind: EndpointKindDoH,
		Host: "1.1.1.1",
		Port: 443,
		IP:   []byte{1, 1, 1, 1},
	}})
	if got := policy.DomainDecision("blocked.example.com"); got != DecisionBlock {
		t.Fatalf("DomainDecision(blocked.example.com) = %q, want %q", got, DecisionBlock)
	}
	if got := policy.DomainDecision("allowed.example.com"); got != DecisionAllow {
		t.Fatalf("DomainDecision(allowed.example.com) = %q, want %q", got, DecisionAllow)
	}
	if got := policy.EndpointDecision("doh", "9.9.9.9", 443); got != DecisionBlock {
		t.Fatalf("EndpointDecision(9.9.9.9) = %q, want %q", got, DecisionBlock)
	}
	if got := policy.EndpointDecision("doh", "1.1.1.1", 443); got != DecisionAllow {
		t.Fatalf("EndpointDecision(1.1.1.1) = %q, want %q", got, DecisionAllow)
	}
}

func TestPolicyCIDRMatchesResolvers(t *testing.T) {
	t.Parallel()

	rules, err := ParseRules(strings.NewReader(`
allow:1.1.1.0/24
9.9.9.0/24
allow:2606:4700:4700::/48
2606:4700:4800::/48
`))
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}

	policy := NewPolicy(rules, nil, nil)
	if got := policy.EndpointDecision("doh", "1.1.1.9", 443); got != DecisionAllow {
		t.Fatalf("EndpointDecision(1.1.1.9/443) = %q, want %q", got, DecisionAllow)
	}
	if got := policy.EndpointDecision("dot", "9.9.9.10", 853); got != DecisionBlock {
		t.Fatalf("EndpointDecision(9.9.9.10/853) = %q, want %q", got, DecisionBlock)
	}
	if got := policy.EndpointDecision("doh", "2606:4700:4700::1111", 443); got != DecisionAllow {
		t.Fatalf("EndpointDecision(2606:4700:4700::1111/443) = %q, want %q", got, DecisionAllow)
	}
	if got := policy.EndpointDecision("dot", "2606:4700:4800::1111", 853); got != DecisionBlock {
		t.Fatalf("EndpointDecision(2606:4700:4800::1111/853) = %q, want %q", got, DecisionBlock)
	}
}

func TestResolveEndpointsSkipsDNSForLiteralIPs(t *testing.T) {
	t.Parallel()

	resolved, err := ResolveEndpoints(context.Background(), []EndpointRule{{
		Kind: EndpointKindDoH,
		Host: "1.1.1.1",
		Port: 443,
	}, {
		Kind: EndpointKindDoH,
		Host: "2606:4700:4700::1111",
		Port: 443,
	}})
	if err != nil {
		t.Fatalf("ResolveEndpoints returned error: %v", err)
	}

	if len(resolved) != 2 {
		t.Fatalf("expected 2 resolved endpoints, got %d: %v", len(resolved), resolved)
	}
	if got := resolved[0].IP.String(); got != "1.1.1.1" {
		t.Fatalf("resolved[0].IP = %q, want 1.1.1.1", got)
	}
	if got := resolved[1].IP.String(); got != "2606:4700:4700::1111" {
		t.Fatalf("resolved[1].IP = %q, want 2606:4700:4700::1111", got)
	}
}

func TestManagerRejectsOversizedRemoteBlocklist(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		payload := strings.Repeat("example.com\n", (maxRemoteBlocklistBytes/12)+2)
		_, _ = w.Write([]byte(payload))
	}))
	defer server.Close()

	manager := NewManager(Config{
		URL:           server.URL,
		CachePath:     filepath.Join(t.TempDir(), "blocklist.txt"),
		RefreshPeriod: time.Hour,
	})
	if transport, ok := manager.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	if _, err := manager.Load(t.Context()); err == nil || !strings.Contains(err.Error(), "response exceeds") {
		t.Fatalf("Load() error = %v, want oversize response rejection", err)
	}
}

func TestWriteCacheUsesRestrictedPermissions(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "blocklist.txt")
	if err := writeCache(path, []byte("example.com\n")); err != nil {
		t.Fatalf("writeCache returned error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat cache file: %v", err)
	}
	if got, want := info.Mode().Perm(), os.FileMode(0o640); got != want {
		t.Fatalf("cache mode = %o, want %o", got, want)
	}
}
