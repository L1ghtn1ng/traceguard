package threatintel

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func domainFeed(id string, block bool) policy.ThreatIntelFeed {
	return policy.ThreatIntelFeed{ID: id, Path: "/feeds/" + id, Type: policy.FeedTypeDomains, Block: block}
}

func addressFeed(id string, block bool) policy.ThreatIntelFeed {
	return policy.ThreatIntelFeed{ID: id, Path: "/feeds/" + id, Type: policy.FeedTypeAddresses, Block: block}
}

func mustParse(t *testing.T, config policy.ThreatIntelFeed, payload string) Feed {
	t.Helper()
	feed, err := Parse(config, []byte(payload))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return feed
}

func TestParseFeedsNormalizesAndDeduplicates(t *testing.T) {
	t.Parallel()

	domains := mustParse(t, domainFeed("bad", false), "# feed\nEvil.Example.\nevil.example\n\nc2.example # beacon\n")
	if !slices.Equal(domains.Domains, []string{"c2.example", "evil.example"}) || len(domains.Digest) != 64 {
		t.Fatalf("domains = %v digest %q", domains.Domains, domains.Digest)
	}
	addresses := mustParse(t, addressFeed("ips", false), "203.0.113.7\n198.51.100.0/24\n198.51.100.9/24\n::ffff:192.0.2.1\n::ffff:192.0.3.0/120\n2001:db8::/32\n")
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("192.0.3.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("203.0.113.7/32"),
	}
	if !slices.Equal(addresses.Prefixes, want) {
		t.Fatalf("prefixes = %v, want %v", addresses.Prefixes, want)
	}
}

func TestParseRejectsInvalidIndicators(t *testing.T) {
	t.Parallel()

	if _, err := Parse(domainFeed("bad", false), []byte("ok.example\nnot a domain\n")); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("invalid domain error = %v", err)
	}
	if _, err := Parse(addressFeed("ips", false), []byte("300.1.1.1\n")); err == nil || !strings.Contains(err.Error(), "invalid address") {
		t.Fatalf("invalid address error = %v", err)
	}
	// Unmapped, this would become 0.0.0.0/0 and match every IPv4 address.
	if _, err := Parse(addressFeed("ips", true), []byte("::ffff:192.0.2.0/64\n")); err == nil || !strings.Contains(err.Error(), "shorter than /96") {
		t.Fatalf("short mapped prefix error = %v", err)
	}
}

func TestLoadReadsFeedFiles(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := domainFeed("bad", false)
	config.Path = path
	feeds, err := Load([]policy.ThreatIntelFeed{config})
	if err != nil || len(feeds) != 1 || feeds[0].Domains[0] != "evil.example" {
		t.Fatalf("Load = %+v, %v", feeds, err)
	}
	config.Path = filepath.Join(t.TempDir(), "missing.txt")
	if _, err := Load([]policy.ThreatIntelFeed{config}); err == nil || !strings.Contains(err.Error(), `feed "bad"`) {
		t.Fatalf("missing feed error = %v", err)
	}
}

func TestMatcherMatchesDomainsAndSubdomains(t *testing.T) {
	t.Parallel()

	matcher := NewMatcher([]Feed{mustParse(t, domainFeed("bad", false), "evil.example\n")})
	event := func(at int64, domain string, cgroup uint64) detection.Event {
		return detection.Event{Timestamp: time.Unix(at, 0), Name: "dns", Fields: map[string]any{"domain": domain, "cgroup_id": cgroup}}
	}
	alerts := matcher.Evaluate(event(1, "Login.EVIL.example.", 1))
	if len(alerts) != 1 || alerts[0].ID == "" || alerts[0].RuleID != "threat_intel.bad" || alerts[0].Severity != "warning" ||
		alerts[0].Fields["threat_intel_indicator"] != "evil.example" || alerts[0].Fields["threat_intel_feed"] != "bad" {
		t.Fatalf("alerts = %+v", alerts)
	}
	if alerts := matcher.Evaluate(event(2, "notevil.example", 1)); len(alerts) != 0 {
		t.Fatal("a different domain sharing a suffix matched")
	}
	if alerts := matcher.Evaluate(event(3, "evil.example", 1)); len(alerts) != 0 {
		t.Fatal("cooldown did not suppress a repeat for the same cgroup")
	}
	if alerts := matcher.Evaluate(event(4, "evil.example", 2)); len(alerts) != 1 {
		t.Fatal("cooldown suppressed another cgroup")
	}
	if alerts := matcher.Evaluate(event(700, "evil.example", 1)); len(alerts) != 1 {
		t.Fatal("alert did not return after the cooldown")
	}
}

func TestMatcherMatchesAddressesByLongestPrefix(t *testing.T) {
	t.Parallel()

	matcher := NewMatcher([]Feed{
		mustParse(t, addressFeed("hosts", false), "198.51.100.9\n"),
		mustParse(t, addressFeed("ranges", false), "198.51.100.0/24\n2001:db8::/32\n"),
	})
	for _, test := range []struct {
		event, address, feed, indicator string
	}{
		{"connection", "198.51.100.9", "hosts", "198.51.100.9/32"},
		{"egress_blocked", "198.51.100.10", "ranges", "198.51.100.0/24"},
		{"resolver", "2001:db8::53", "ranges", "2001:db8::/32"},
		{"connection", "::ffff:198.51.100.10", "ranges", "198.51.100.0/24"},
	} {
		field := "peer_address"
		if test.event == "resolver" {
			field = "address"
		}
		alerts := matcher.Evaluate(detection.Event{Timestamp: time.Unix(1, 0), Name: test.event, Fields: map[string]any{field: test.address, "cgroup_id": test.address}})
		if len(alerts) != 1 || alerts[0].Fields["threat_intel_feed"] != test.feed || alerts[0].Fields["threat_intel_indicator"] != test.indicator {
			t.Errorf("%s %s: alerts = %+v", test.event, test.address, alerts)
		}
	}
	if alerts := matcher.Evaluate(detection.Event{Name: "connection", Fields: map[string]any{"peer_address": "203.0.113.1"}}); len(alerts) != 0 {
		t.Fatal("unlisted address matched")
	}
	if alerts := matcher.Evaluate(detection.Event{Name: "exec", Fields: map[string]any{"peer_address": "198.51.100.9"}}); len(alerts) != 0 {
		t.Fatal("an event without a peer matched")
	}
}

func TestEnforceAddsBlockingFeedsWithinLimits(t *testing.T) {
	t.Parallel()

	var addresses strings.Builder
	for index := range 300 {
		addresses.WriteString(netip.AddrFrom4([4]byte{198, 51, byte(index / 256), byte(index % 256)}).String() + "\n")
	}
	feeds := []Feed{
		mustParse(t, domainFeed("bad", true), "evil.example\n"),
		mustParse(t, addressFeed("ips", true), addresses.String()),
		mustParse(t, domainFeed("watch", false), "watched.example\n"),
	}
	bundle, err := Enforce(policy.Bundle{}, feeds)
	if err != nil {
		t.Fatalf("Enforce returned error: %v", err)
	}
	if !slices.Equal(bundle.DNS.BlockSuffixes, []string{"evil.example"}) {
		t.Fatalf("block suffixes = %v, want only the blocking feed", bundle.DNS.BlockSuffixes)
	}
	if len(bundle.Egress.Rules) != 2 || bundle.Egress.Rules[0].ID != "threat_intel.ips.1" ||
		len(bundle.Egress.Rules[0].Destinations.CIDRs) != 256 || len(bundle.Egress.Rules[1].Destinations.CIDRs) != 44 {
		t.Fatalf("egress rules = %+v", bundle.Egress.Rules)
	}

	var tooMany strings.Builder
	for index := range policy.MaxDNSRules + 1 {
		tooMany.WriteString("d" + strings.Repeat("x", index%7) + string(rune('a'+index%26)) + string(rune('a'+index/26%26)) + string(rune('a'+index/676)) + ".example\n")
	}
	large := mustParse(t, domainFeed("large", true), tooMany.String())
	if _, err := Enforce(policy.Bundle{}, []Feed{large}); err == nil || !strings.Contains(err.Error(), "set block: false") {
		t.Fatalf("oversized blocking feed error = %v", err)
	}
}

func TestMatcherCooldownsUseCachedCgroupAndSurviveReload(t *testing.T) {
	t.Parallel()

	feeds := []Feed{mustParse(t, domainFeed("bad", false), "evil.example\n")}
	event := func(at int64, cgroup uint64) detection.Event {
		return detection.Event{Timestamp: time.Unix(at, 0), Name: "dns", Fields: map[string]any{"domain": "evil.example", "cached_cgroup_id": cgroup}}
	}
	matcher := NewMatcher(feeds)
	if len(matcher.Evaluate(event(1, 1))) != 1 || len(matcher.Evaluate(event(2, 2))) != 1 {
		t.Fatal("socket-cache attributed events from two cgroups did not each alert")
	}
	reloaded := NewMatcher(feeds)
	reloaded.InheritCooldowns(matcher)
	if alerts := reloaded.Evaluate(event(3, 1)); len(alerts) != 0 {
		t.Fatal("a reloaded matcher forgot the cooldown")
	}
}

func TestMatcherCooldownsPerHostFeedAndCapacity(t *testing.T) {
	t.Parallel()

	short, long := addressFeed("short", false), addressFeed("long", false)
	short.Cooldown = &policy.Duration{Duration: time.Minute}
	long.Cooldown = &policy.Duration{Duration: time.Hour}
	matcher := NewMatcher([]Feed{mustParse(t, short, "198.51.100.0/24\n"), mustParse(t, long, "203.0.113.0/24\n")})
	event := func(at int64, peer string, cgroup uint64) detection.Event {
		return detection.Event{Timestamp: time.Unix(at, 0), Name: "connection", Fields: map[string]any{"peer_address": peer, "cgroup_id": cgroup}}
	}

	// Each host in a listed range alerts, so each can get its own response.
	if len(matcher.Evaluate(event(1, "203.0.113.5", 1))) != 1 || len(matcher.Evaluate(event(2, "203.0.113.6", 1))) != 1 {
		t.Fatal("a second host in the same range was suppressed")
	}
	if len(matcher.Evaluate(event(3, "203.0.113.5", 1))) != 0 {
		t.Fatal("a repeat for the same host was not suppressed")
	}

	// Fill the records with the short feed; its expiry must not clear the
	// long feed's hour.
	for index := range maxCooldowns {
		matcher.Evaluate(event(10, fmt.Sprintf("198.51.100.%d", index%256), uint64(index)+100))
	}
	matcher.Evaluate(event(200, "198.51.100.1", 1))
	if len(matcher.Evaluate(event(300, "203.0.113.5", 1))) != 0 {
		t.Fatal("a short feed's cooldown cleared a long feed's record")
	}

	// A full set of live records still holds the new record's cooldown.
	full := NewMatcher([]Feed{mustParse(t, long, "203.0.113.0/24\n")})
	for index := range maxCooldowns {
		full.Evaluate(event(1, "203.0.113.9", uint64(index)+100))
	}
	if len(full.Evaluate(event(2, "203.0.113.7", 1))) != 1 || len(full.Evaluate(event(3, "203.0.113.7", 1))) != 0 {
		t.Fatal("a match recorded while the cooldowns were full alerted again")
	}
}

func TestShadowedReportsAllowRulesThatLetBlocksThrough(t *testing.T) {
	t.Parallel()

	feeds := []Feed{
		mustParse(t, addressFeed("c2", true), "203.0.113.0/24\n198.51.100.7\n"),
		mustParse(t, domainFeed("phish", true), "evil.example\nbad.example\n"),
		mustParse(t, addressFeed("alerts-only", false), "203.0.113.0/24\n"),
	}
	bundle := policy.Bundle{
		Egress: policy.EgressPolicy{Rules: []policy.EgressRule{
			{ID: "office", Action: "allow", Destinations: policy.EgressDestinations{CIDRs: []string{"203.0.113.128/25"}}},
			{ID: "deny-tor", Action: "block", Destinations: policy.EgressDestinations{CIDRs: []string{"198.51.100.0/24"}}},
		}},
	}
	bundle.DNS.AllowSuffixes = []string{"cdn.evil.example"}
	got := Shadowed(bundle, feeds)
	want := []Shadow{{Feed: "c2", Rule: "office", Indicators: 1}, {Feed: "phish", Rule: "dns.allow", Indicators: 1}}
	if !slices.Equal(got, want) {
		t.Fatalf("Shadowed = %+v, want %+v", got, want)
	}
}
