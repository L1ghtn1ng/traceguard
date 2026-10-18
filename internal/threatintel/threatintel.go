// Package threatintel loads local indicator feeds, matches events against
// them, and expands blocking feeds into kernel policy.
package threatintel

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/safefile"
)

const (
	// MaxFeedBytes bounds one feed file.
	MaxFeedBytes = 64 << 20
	// MaxFeedIndicators bounds one feed's indicators.
	MaxFeedIndicators = 1_000_000
	// maxCooldowns bounds remembered alert cooldowns.
	maxCooldowns = 16384
	// blockRuleCIDRs is the egress rule CIDR limit blocking feeds are split by.
	blockRuleCIDRs = 256
)

// Feed is one loaded indicator file.
type Feed struct {
	Config   policy.ThreatIntelFeed
	Domains  []string
	Prefixes []netip.Prefix
	// Digest is the SHA-256 of the file contents.
	Digest string
}

// Load reads and parses every configured feed.
func Load(feeds []policy.ThreatIntelFeed) ([]Feed, error) {
	loaded := make([]Feed, 0, len(feeds))
	for _, config := range feeds {
		payload, err := safefile.ReadFile(config.Path, MaxFeedBytes)
		if err != nil {
			return nil, fmt.Errorf("read threat intel feed %q: %w", config.ID, err)
		}
		feed, err := Parse(config, payload)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, feed)
	}
	return loaded, nil
}

// Parse reads one indicator per line. Blank lines and text after # are
// ignored. Domain feeds take hostnames; address feeds take IP addresses or
// CIDR prefixes.
func Parse(config policy.ThreatIntelFeed, payload []byte) (Feed, error) {
	sum := sha256.Sum256(payload)
	feed := Feed{Config: config, Digest: hex.EncodeToString(sum[:])}
	domains := make(map[string]struct{})
	prefixes := make(map[netip.Prefix]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	line := 0
	for scanner.Scan() {
		line++
		text, _, _ := strings.Cut(scanner.Text(), "#")
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		switch config.Type {
		case policy.FeedTypeDomains:
			domain, ok := blocklist.NormalizeDomain(text)
			if !ok {
				return Feed{}, fmt.Errorf("threat intel feed %q line %d: invalid domain %q", config.ID, line, text)
			}
			domains[domain] = struct{}{}
		default:
			prefix, err := parsePrefix(text)
			if err != nil {
				return Feed{}, fmt.Errorf("threat intel feed %q line %d: %w", config.ID, line, err)
			}
			prefixes[prefix] = struct{}{}
		}
		if len(domains)+len(prefixes) > MaxFeedIndicators {
			return Feed{}, fmt.Errorf("threat intel feed %q exceeds %d indicators", config.ID, MaxFeedIndicators)
		}
	}
	if err := scanner.Err(); err != nil {
		return Feed{}, fmt.Errorf("threat intel feed %q line %d: %w", config.ID, line+1, err)
	}
	feed.Domains = slices.Sorted(maps.Keys(domains))
	feed.Prefixes = slices.SortedFunc(maps.Keys(prefixes), func(left, right netip.Prefix) int {
		return strings.Compare(left.String(), right.String())
	})
	return feed, nil
}

func parsePrefix(text string) (netip.Prefix, error) {
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid address prefix %q", text)
		}
		if prefix.Addr().Is4In6() && prefix.Bits() < 96 {
			// It would reach beyond ::ffff:0:0/96, and unmapped it would
			// cover every IPv4 address.
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %q is shorter than /96", text)
		}
		return netip.PrefixFrom(prefix.Addr().Unmap(), unmappedBits(prefix)).Masked(), nil
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address %q", text)
	}
	address = address.Unmap()
	return netip.PrefixFrom(address, address.BitLen()), nil
}

// unmappedBits converts an IPv4-mapped IPv6 prefix length, at least /96, to
// IPv4.
func unmappedBits(prefix netip.Prefix) int {
	if prefix.Addr().Is4In6() {
		return prefix.Bits() - 96
	}
	return prefix.Bits()
}

// Enforce returns bundle with every blocking feed added to its DNS suffix
// block rules or as egress block rules, validated against policy limits.
func Enforce(bundle policy.Bundle, feeds []Feed) (policy.Bundle, error) {
	// Clone once so appending never writes into the caller's backing array.
	bundle.Egress.Rules = slices.Clone(bundle.Egress.Rules)
	for _, feed := range feeds {
		if !feed.Config.Block {
			continue
		}
		bundle.DNS.BlockSuffixes = mergeSorted(bundle.DNS.BlockSuffixes, feed.Domains)
		for start := 0; start < len(feed.Prefixes); start += blockRuleCIDRs {
			chunk := feed.Prefixes[start:min(start+blockRuleCIDRs, len(feed.Prefixes))]
			cidrs := make([]string, 0, len(chunk))
			for _, prefix := range chunk {
				cidrs = append(cidrs, prefix.String())
			}
			bundle.Egress.Rules = append(bundle.Egress.Rules, policy.EgressRule{
				ID:           fmt.Sprintf("%s.%d", feed.Config.RuleID(), start/blockRuleCIDRs+1),
				Action:       "block",
				Destinations: policy.EgressDestinations{CIDRs: cidrs},
			})
		}
	}
	if err := bundle.Validate(); err != nil {
		return policy.Bundle{}, fmt.Errorf("blocking threat intel feeds exceed policy limits; set block: false on large feeds: %w", err)
	}
	return bundle, nil
}

func mergeSorted(existing, extra []string) []string {
	merged := append(slices.Clone(existing), extra...)
	slices.Sort(merged)
	return slices.Compact(merged)
}

type indicator struct {
	feed  int
	value string
}

// prefixIndex finds the longest listed prefix containing an address.
type prefixIndex struct {
	byLength map[int]map[netip.Prefix]int
	lengths  []int
}

func (p *prefixIndex) add(prefix netip.Prefix, feed int) {
	if p.byLength == nil {
		p.byLength = make(map[int]map[netip.Prefix]int)
	}
	bits := prefix.Bits()
	if p.byLength[bits] == nil {
		p.byLength[bits] = make(map[netip.Prefix]int)
		p.lengths = append(p.lengths, bits)
		slices.Sort(p.lengths)
		slices.Reverse(p.lengths)
	}
	if _, exists := p.byLength[bits][prefix]; !exists {
		p.byLength[bits][prefix] = feed
	}
}

func (p *prefixIndex) lookup(address netip.Addr) (netip.Prefix, int, bool) {
	for _, bits := range p.lengths {
		prefix, err := address.Prefix(bits)
		if err != nil {
			continue
		}
		if feed, ok := p.byLength[bits][prefix]; ok {
			return prefix, feed, true
		}
	}
	return netip.Prefix{}, 0, false
}

// Matcher raises alerts for events whose domain or peer address is in a feed.
type Matcher struct {
	feeds   []Feed
	domains map[string]int
	ipv4    prefixIndex
	ipv6    prefixIndex

	mu sync.Mutex
	// cooldowns maps a cooldown key to when its cooldown ends.
	cooldowns map[string]time.Time
}

// NewMatcher indexes feeds. A domain also matches its subdomains, and a
// prefix matches every address in it; the first feed listing an indicator
// reports it.
func NewMatcher(feeds []Feed) *Matcher {
	m := &Matcher{feeds: feeds, domains: make(map[string]int), cooldowns: make(map[string]time.Time)}
	for index, feed := range feeds {
		for _, domain := range feed.Domains {
			if _, ok := m.domains[domain]; !ok {
				m.domains[domain] = index
			}
		}
		for _, prefix := range feed.Prefixes {
			if prefix.Addr().Is4() {
				m.ipv4.add(prefix, index)
			} else {
				m.ipv6.add(prefix, index)
			}
		}
	}
	return m
}

// InheritCooldowns carries alert cooldowns over from the matcher this one
// replaces, so reloading a feed does not repeat suppressed alerts.
func (m *Matcher) InheritCooldowns(previous *Matcher) {
	if previous == nil {
		return
	}
	previous.mu.Lock()
	cooldowns := maps.Clone(previous.cooldowns)
	previous.mu.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	maps.Copy(m.cooldowns, cooldowns)
}

// domainEvents and addressEvents carry the fields a matcher checks.
var (
	domainEvents  = []string{"dns", "blocked"}
	addressEvents = []string{"connection", "resolver", "resolver_blocked", "egress_blocked", "egress_would_block"}
)

// Evaluate returns an alert when the event's domain or peer address is in a
// feed, unless the same indicator alerted for the same cgroup within the
// feed's cooldown.
func (m *Matcher) Evaluate(event detection.Event) []detection.Alert {
	if m == nil || len(m.feeds) == 0 {
		return nil
	}
	var match indicator
	var ok bool
	switch {
	case slices.Contains(domainEvents, event.Name):
		match, ok = m.matchDomain(event.Fields["domain"])
	case slices.Contains(addressEvents, event.Name):
		match, ok = m.matchAddress(address(event))
	}
	if !ok {
		return nil
	}
	feed := m.feeds[match.feed].Config
	if !m.allow(feed, match, address(event), event) {
		return nil
	}
	fields := maps.Clone(event.Fields)
	fields["threat_intel_feed"] = feed.ID
	fields["threat_intel_indicator"] = match.value
	return []detection.Alert{{
		ID: rand.Text(), RuleID: feed.RuleID(), Severity: feed.AlertSeverity(),
		Message: "an event matched threat intelligence feed " + feed.ID,
		Tags:    []string{"threat-intel", feed.Type}, Count: 1, Timestamp: event.Timestamp, Fields: fields,
	}}
}

// address returns an address event's peer address.
func address(event detection.Event) string {
	peer, _ := event.Fields["peer_address"].(string)
	if peer == "" {
		peer, _ = event.Fields["address"].(string)
	}
	return peer
}

func (m *Matcher) matchDomain(value any) (indicator, bool) {
	domain, _ := value.(string)
	domain, ok := blocklist.NormalizeDomain(domain)
	if !ok {
		return indicator{}, false
	}
	for candidate := domain; strings.Contains(candidate, "."); {
		if feed, found := m.domains[candidate]; found {
			return indicator{feed: feed, value: candidate}, true
		}
		_, candidate, _ = strings.Cut(candidate, ".")
	}
	return indicator{}, false
}

func (m *Matcher) matchAddress(text string) (indicator, bool) {
	address, err := netip.ParseAddr(text)
	if err != nil {
		return indicator{}, false
	}
	address = address.Unmap()
	index := &m.ipv6
	if address.Is4() {
		index = &m.ipv4
	}
	prefix, feed, found := index.lookup(address)
	if !found {
		return indicator{}, false
	}
	return indicator{feed: feed, value: prefix.String()}, true
}

// allow applies the feed's cooldown per indicator, peer address, and
// cgroup. Keying by peer address lets every host in a listed range alert, and
// so drive its own response. Each record keeps its own end time, so a feed
// with a short cooldown never clears another feed's records; when the records
// are full, the one ending soonest makes room.
func (m *Matcher) allow(feed policy.ThreatIntelFeed, match indicator, peer string, event detection.Event) bool {
	cooldown := feed.AlertCooldown()
	if cooldown <= 0 {
		return true
	}
	cgroup := event.Fields["cgroup_id"]
	if cgroup == nil {
		// Socket-cache attribution carries the cgroup separately.
		cgroup = event.Fields["cached_cgroup_id"]
	}
	if feed.Type != policy.FeedTypeAddresses {
		peer = ""
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%v", feed.ID, match.value, peer, cgroup)
	now := event.Timestamp
	m.mu.Lock()
	defer m.mu.Unlock()
	if until, ok := m.cooldowns[key]; ok && now.Before(until) {
		return false
	}
	if _, ok := m.cooldowns[key]; !ok && len(m.cooldowns) >= maxCooldowns {
		for existing, until := range m.cooldowns {
			if !now.Before(until) {
				delete(m.cooldowns, existing)
			}
		}
		if len(m.cooldowns) >= maxCooldowns {
			var soonest string
			var soonestUntil time.Time
			for existing, until := range m.cooldowns {
				if soonestUntil.IsZero() || until.Before(soonestUntil) {
					soonest, soonestUntil = existing, until
				}
			}
			delete(m.cooldowns, soonest)
		}
	}
	m.cooldowns[key] = now.Add(cooldown)
	return true
}

// Indicators returns how many indicators each feed holds, by feed ID.
func (m *Matcher) Indicators() map[string]int {
	counts := make(map[string]int, len(m.feeds))
	for _, feed := range m.feeds {
		counts[feed.Config.ID] = len(feed.Domains) + len(feed.Prefixes)
	}
	return counts
}

// Shadow is a blocking feed's indicators that an allow rule lets through.
// Allow rules are checked before block rules, so the feed blocks none of
// them for the traffic that rule matches.
type Shadow struct {
	Feed       string
	Rule       string
	Indicators int
}

// Shadowed lists blocking feeds whose indicators overlap an egress allow
// rule's destinations or a DNS allow entry in bundle, the policy before
// Enforce adds the feeds.
func Shadowed(bundle policy.Bundle, feeds []Feed) []Shadow {
	var shadows []Shadow
	for _, feed := range feeds {
		if !feed.Config.Block {
			continue
		}
		for _, rule := range bundle.Egress.Rules {
			if rule.Action != "allow" {
				continue
			}
			if count := overlappingPrefixes(feed.Prefixes, rule.Destinations.CIDRs); count > 0 {
				shadows = append(shadows, Shadow{Feed: feed.Config.ID, Rule: rule.ID, Indicators: count})
			}
		}
		if count := overlappingDomains(feed.Domains, bundle.DNS.AllowDomains, bundle.DNS.AllowSuffixes); count > 0 {
			shadows = append(shadows, Shadow{Feed: feed.Config.ID, Rule: "dns.allow", Indicators: count})
		}
	}
	return shadows
}

// overlappingPrefixes counts prefixes that share an address with cidrs;
// omitted CIDRs match every destination.
func overlappingPrefixes(prefixes []netip.Prefix, cidrs []string) int {
	if len(prefixes) == 0 {
		return 0
	}
	if len(cidrs) == 0 {
		return len(prefixes)
	}
	allowed := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			allowed = append(allowed, prefix.Masked())
		}
	}
	count := 0
	for _, prefix := range prefixes {
		if slices.ContainsFunc(allowed, prefix.Overlaps) {
			count++
		}
	}
	return count
}

// overlappingDomains counts blocked domains that an allowed domain or suffix
// covers in whole or in part.
func overlappingDomains(domains, allowDomains, allowSuffixes []string) int {
	count := 0
	for _, domain := range domains {
		overlaps := slices.ContainsFunc(allowDomains, func(allowed string) bool {
			return allowed == domain || strings.HasSuffix(allowed, "."+domain)
		}) || slices.ContainsFunc(allowSuffixes, func(allowed string) bool {
			return allowed == domain || strings.HasSuffix(allowed, "."+domain) || strings.HasSuffix(domain, "."+allowed)
		})
		if overlaps {
			count++
		}
	}
	return count
}
