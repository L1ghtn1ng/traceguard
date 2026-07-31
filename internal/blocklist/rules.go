package blocklist

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

type ruleAction uint8

const (
	ruleBlock ruleAction = iota + 1
	ruleAllow
)

type ruleAccumulator struct {
	blockAllDomains    bool
	blockAllResolvers  bool
	blockDomains       map[string]struct{}
	allowDomains       map[string]struct{}
	blockSuffixes      map[string]struct{}
	allowSuffixes      map[string]struct{}
	blockEndpoints     map[string]EndpointRule
	allowEndpoints     map[string]EndpointRule
	blockEndpointCIDRs map[string]EndpointCIDR
	allowEndpointCIDRs map[string]EndpointCIDR
}

func newRuleAccumulator() *ruleAccumulator {
	return &ruleAccumulator{
		blockDomains:       make(map[string]struct{}),
		allowDomains:       make(map[string]struct{}),
		blockSuffixes:      make(map[string]struct{}),
		allowSuffixes:      make(map[string]struct{}),
		blockEndpoints:     make(map[string]EndpointRule),
		allowEndpoints:     make(map[string]EndpointRule),
		blockEndpointCIDRs: make(map[string]EndpointCIDR),
		allowEndpointCIDRs: make(map[string]EndpointCIDR),
	}
}

// ParsePolicyRules parses strict policy entries. Each entry's action comes only
// from the list containing it; legacy action prefixes and invalid entries fail.
func ParsePolicyRules(block, allow []string) (Rules, error) {
	rules := newRuleAccumulator()
	for _, group := range []struct {
		name    string
		entries []string
		action  ruleAction
	}{
		{name: "block", entries: block, action: ruleBlock},
		{name: "allow", entries: allow, action: ruleAllow},
	} {
		for index, raw := range group.entries {
			value := strings.TrimSpace(raw)
			lower := strings.ToLower(value)
			if strings.HasPrefix(lower, "allow:") || strings.HasPrefix(lower, "block:") {
				return Rules{}, fmt.Errorf("dns.%s[%d] must not include an action prefix", group.name, index)
			}
			if !rules.addTarget(value, group.action) {
				return Rules{}, fmt.Errorf("dns.%s[%d] is invalid: %q", group.name, index, raw)
			}
		}
	}
	return rules.build(), nil
}

func (r *ruleAccumulator) addTarget(target string, action ruleAction) bool {
	if target == "*" {
		if action == ruleBlock {
			r.blockAllDomains = true
			r.blockAllResolvers = true
			return true
		}
		return false
	}
	if suffix, ok := normalizeSuffix(target); ok {
		if action == ruleAllow {
			r.allowSuffixes[suffix] = struct{}{}
			return true
		}
		r.blockSuffixes[suffix] = struct{}{}
		return true
	}
	if cidrs, ok := normalizeResolverCIDR(target); ok {
		for _, cidr := range cidrs {
			if action == ruleAllow {
				r.allowEndpointCIDRs[endpointCIDRKey(cidr)] = cidr
				continue
			}
			r.blockEndpointCIDRs[endpointCIDRKey(cidr)] = cidr
		}
		return true
	}
	if endpoints, ok := normalizeResolverLiteral(target); ok {
		for _, endpoint := range endpoints {
			if action == ruleAllow {
				r.allowEndpoints[endpointKey(endpoint)] = endpoint
				continue
			}
			r.blockEndpoints[endpointKey(endpoint)] = endpoint
		}
		return true
	}
	if endpoint, ok := normalizeEndpoint(target); ok {
		if action == ruleAllow {
			r.allowEndpoints[endpointKey(endpoint)] = endpoint
			if net.ParseIP(endpoint.Host) == nil {
				r.allowDomains[endpoint.Host] = struct{}{}
			}
			return true
		}
		r.blockEndpoints[endpointKey(endpoint)] = endpoint
		if net.ParseIP(endpoint.Host) == nil {
			r.blockDomains[endpoint.Host] = struct{}{}
		}
		return true
	}
	if domain, ok := normalizeDomain(target); ok {
		if action == ruleAllow {
			r.allowDomains[domain] = struct{}{}
			return true
		}
		r.blockDomains[domain] = struct{}{}
		return true
	}
	return false
}

func (r *ruleAccumulator) build() Rules {
	return Rules{
		BlockAllDomains:    r.blockAllDomains,
		BlockAllResolvers:  r.blockAllResolvers,
		BlockDomains:       sortedDomains(r.blockDomains),
		AllowDomains:       sortedDomains(r.allowDomains),
		BlockSuffixes:      sortedDomains(r.blockSuffixes),
		AllowSuffixes:      sortedDomains(r.allowSuffixes),
		BlockEndpoints:     sortedEndpoints(r.blockEndpoints),
		AllowEndpoints:     sortedEndpoints(r.allowEndpoints),
		BlockEndpointCIDRs: sortedEndpointCIDRs(r.blockEndpointCIDRs),
		AllowEndpointCIDRs: sortedEndpointCIDRs(r.allowEndpointCIDRs),
	}
}

func normalizeSuffix(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	lower := strings.ToLower(value)
	switch {
	case strings.HasPrefix(lower, "suffix:"):
		value = strings.TrimSpace(value[len("suffix:"):])
	case strings.HasPrefix(value, "*."):
		value = strings.TrimSpace(value[2:])
	default:
		return "", false
	}

	normalized, ok := normalizeDomain(value)
	if !ok {
		return "", false
	}
	return normalized, true
}

func sortedDomains(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func sortedEndpoints(values map[string]EndpointRule) []EndpointRule {
	out := make([]EndpointRule, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	slices.SortFunc(out, func(a, b EndpointRule) int {
		if a.Kind != b.Kind {
			return strings.Compare(string(a.Kind), string(b.Kind))
		}
		if a.Host != b.Host {
			return strings.Compare(a.Host, b.Host)
		}
		switch {
		case a.Port < b.Port:
			return -1
		case a.Port > b.Port:
			return 1
		default:
			return 0
		}
	})
	return out
}

func sortedEndpointCIDRs(values map[string]EndpointCIDR) []EndpointCIDR {
	out := make([]EndpointCIDR, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	slices.SortFunc(out, func(a, b EndpointCIDR) int {
		if a.Kind != b.Kind {
			return strings.Compare(string(a.Kind), string(b.Kind))
		}
		if a.Prefix.Addr().BitLen() != b.Prefix.Addr().BitLen() {
			if a.Prefix.Addr().BitLen() < b.Prefix.Addr().BitLen() {
				return -1
			}
			return 1
		}
		if a.Prefix.String() != b.Prefix.String() {
			return strings.Compare(a.Prefix.String(), b.Prefix.String())
		}
		switch {
		case a.Port < b.Port:
			return -1
		case a.Port > b.Port:
			return 1
		default:
			return 0
		}
	})
	return out
}

func normalizeDomain(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}

	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", false
		}
		raw = parsed.Hostname()
	}

	if strings.Contains(raw, "/") {
		raw = strings.SplitN(raw, "/", 2)[0]
	}

	raw = strings.Trim(raw, ".")
	raw = strings.TrimPrefix(raw, "*.")
	raw = strings.ToLower(raw)
	if raw == "" {
		return "", false
	}
	if !strings.Contains(raw, ".") {
		return "", false
	}

	if len(raw) > 255 {
		return "", false
	}

	for label := range strings.SplitSeq(raw, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return "", false
		}
	}

	return raw, true
}

func normalizeEndpoint(raw string) (EndpointRule, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return EndpointRule{}, false
	}

	switch {
	case strings.HasPrefix(raw, "https://"):
		parsed, err := url.Parse(raw)
		if err != nil {
			return EndpointRule{}, false
		}
		host, ok := normalizeEndpointHost(parsed.Hostname())
		if !ok {
			return EndpointRule{}, false
		}
		port := uint16(443)
		if parsed.Port() != "" {
			var parsedPort int
			if _, err := fmt.Sscanf(parsed.Port(), "%d", &parsedPort); err != nil || parsedPort <= 0 || parsedPort > 65535 {
				return EndpointRule{}, false
			}
			port = uint16(parsedPort)
		}
		return EndpointRule{Kind: EndpointKindDoH, Host: host, Port: port}, true
	case strings.HasPrefix(raw, "dot://"), strings.HasPrefix(raw, "tls://"):
		parsed, err := url.Parse(raw)
		if err != nil {
			return EndpointRule{}, false
		}
		host, ok := normalizeEndpointHost(parsed.Hostname())
		if !ok {
			return EndpointRule{}, false
		}
		port := uint16(853)
		if parsed.Port() != "" {
			var parsedPort int
			if _, err := fmt.Sscanf(parsed.Port(), "%d", &parsedPort); err != nil || parsedPort <= 0 || parsedPort > 65535 {
				return EndpointRule{}, false
			}
			port = uint16(parsedPort)
		}
		return EndpointRule{Kind: EndpointKindDoT, Host: host, Port: port}, true
	default:
		return EndpointRule{}, false
	}
}

func normalizeResolverLiteral(raw string) ([]EndpointRule, bool) {
	host, ok := normalizeIPLiteral(raw)
	if !ok {
		return nil, false
	}
	return []EndpointRule{
		{Kind: EndpointKindDoH, Host: host, Port: 443},
		{Kind: EndpointKindDoT, Host: host, Port: 853},
	}, true
}

func normalizeResolverCIDR(raw string) ([]EndpointCIDR, bool) {
	prefix, ok := normalizeIPPrefix(raw)
	if !ok {
		return nil, false
	}
	return []EndpointCIDR{
		{Kind: EndpointKindDoH, Prefix: prefix, Port: 443},
		{Kind: EndpointKindDoT, Prefix: prefix, Port: 853},
	}, true
}

func normalizeIPLiteral(raw string) (string, bool) {
	value := strings.TrimSpace(raw)
	value = strings.TrimPrefix(value, "[")
	value = strings.TrimSuffix(value, "]")
	ip := net.ParseIP(value)
	if ip == nil {
		return "", false
	}
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return ip.String(), true
}

func normalizeIPPrefix(raw string) (netip.Prefix, bool) {
	value := strings.TrimSpace(raw)
	if !strings.Contains(value, "/") {
		return netip.Prefix{}, false
	}
	if strings.HasPrefix(value, "[") {
		end := strings.IndexByte(value, ']')
		if end == -1 || end+1 >= len(value) || value[end+1] != '/' {
			return netip.Prefix{}, false
		}
		value = value[1:end] + value[end+1:]
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, false
	}
	return prefix.Masked(), true
}

func normalizeEndpointHost(raw string) (string, bool) {
	if ip, ok := normalizeIPLiteral(raw); ok {
		return ip, true
	}
	return normalizeDomain(raw)
}

func endpointKey(endpoint EndpointRule) string {
	return fmt.Sprintf("%s|%s|%d", endpoint.Kind, endpoint.Host, endpoint.Port)
}

func endpointCIDRKey(endpoint EndpointCIDR) string {
	return fmt.Sprintf("%s|%s|%d", endpoint.Kind, endpoint.Prefix.String(), endpoint.Port)
}

func resolvedEndpointKey(endpoint ResolvedEndpoint) string {
	return fmt.Sprintf("%s|%s|%d|%s", endpoint.Kind, endpoint.Host, endpoint.Port, endpoint.IP.String())
}

func bytesCompare(a, b []byte) int {
	limit := min(len(b), len(a))
	for i := range limit {
		switch {
		case a[i] < b[i]:
			return -1
		case a[i] > b[i]:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}
