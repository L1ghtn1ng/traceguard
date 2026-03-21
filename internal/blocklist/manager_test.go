package blocklist

import (
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
