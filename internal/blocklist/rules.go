package blocklist

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
)

func ParseEntries(r io.Reader) ([]string, error) {
	rules, err := ParseRules(r)
	if err != nil {
		return nil, err
	}
	return rules.BlockDomains, nil
}

func ParseRules(r io.Reader) (Rules, error) {
	blockDomains := make(map[string]struct{})
	allowDomains := make(map[string]struct{})
	blockSuffixes := make(map[string]struct{})
	allowSuffixes := make(map[string]struct{})
	blockEndpoints := make(map[string]EndpointRule)
	allowEndpoints := make(map[string]EndpointRule)
	blockEndpointCIDRs := make(map[string]EndpointCIDR)
	allowEndpointCIDRs := make(map[string]EndpointCIDR)
	var blockAllDomains bool
	var blockAllResolvers bool
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if ip := net.ParseIP(fields[0]); ip != nil {
			parsedRule := false
			for _, field := range fields[1:] {
				if strings.HasPrefix(field, "#") {
					break
				}
				parsedRule = true
				addRuleEntry(field, ruleBlock, &blockAllDomains, &blockAllResolvers, blockDomains, allowDomains, blockSuffixes, allowSuffixes, blockEndpoints, allowEndpoints, blockEndpointCIDRs, allowEndpointCIDRs)
			}
			if !parsedRule {
				addRuleEntry(fields[0], ruleBlock, &blockAllDomains, &blockAllResolvers, blockDomains, allowDomains, blockSuffixes, allowSuffixes, blockEndpoints, allowEndpoints, blockEndpointCIDRs, allowEndpointCIDRs)
			}
			continue
		}

		addRuleEntry(fields[0], ruleBlock, &blockAllDomains, &blockAllResolvers, blockDomains, allowDomains, blockSuffixes, allowSuffixes, blockEndpoints, allowEndpoints, blockEndpointCIDRs, allowEndpointCIDRs)
	}

	if err := scanner.Err(); err != nil {
		return Rules{}, err
	}

	rules := Rules{
		BlockAllDomains:    blockAllDomains,
		BlockAllResolvers:  blockAllResolvers,
		BlockDomains:       sortedDomains(blockDomains),
		AllowDomains:       sortedDomains(allowDomains),
		BlockSuffixes:      sortedDomains(blockSuffixes),
		AllowSuffixes:      sortedDomains(allowSuffixes),
		BlockEndpoints:     sortedEndpoints(blockEndpoints),
		AllowEndpoints:     sortedEndpoints(allowEndpoints),
		BlockEndpointCIDRs: sortedEndpointCIDRs(blockEndpointCIDRs),
		AllowEndpointCIDRs: sortedEndpointCIDRs(allowEndpointCIDRs),
	}
	return rules, nil
}

type ruleAction uint8

const (
	ruleBlock ruleAction = iota + 1
	ruleAllow
)

func addRuleEntry(raw string, defaultAction ruleAction, blockAllDomains, blockAllResolvers *bool, blockDomains, allowDomains, blockSuffixes, allowSuffixes map[string]struct{}, blockEndpoints, allowEndpoints map[string]EndpointRule, blockEndpointCIDRs, allowEndpointCIDRs map[string]EndpointCIDR) {
	action, target := splitRulePrefix(raw, defaultAction)
	if target == "*" {
		if action == ruleBlock {
			*blockAllDomains = true
			*blockAllResolvers = true
		}
		return
	}
	if suffix, ok := normalizeSuffix(target); ok {
		if action == ruleAllow {
			allowSuffixes[suffix] = struct{}{}
			return
		}
		blockSuffixes[suffix] = struct{}{}
		return
	}
	if cidrs, ok := normalizeResolverCIDR(target); ok {
		for _, cidr := range cidrs {
			if action == ruleAllow {
				allowEndpointCIDRs[endpointCIDRKey(cidr)] = cidr
				continue
			}
			blockEndpointCIDRs[endpointCIDRKey(cidr)] = cidr
		}
		return
	}
	if endpoints, ok := normalizeResolverLiteral(target); ok {
		for _, endpoint := range endpoints {
			if action == ruleAllow {
				allowEndpoints[endpointKey(endpoint)] = endpoint
				continue
			}
			blockEndpoints[endpointKey(endpoint)] = endpoint
		}
		return
	}
	if endpoint, ok := normalizeEndpoint(target); ok {
		if action == ruleAllow {
			allowEndpoints[endpointKey(endpoint)] = endpoint
			if net.ParseIP(endpoint.Host) == nil {
				allowDomains[endpoint.Host] = struct{}{}
			}
			return
		}
		blockEndpoints[endpointKey(endpoint)] = endpoint
		if net.ParseIP(endpoint.Host) == nil {
			blockDomains[endpoint.Host] = struct{}{}
		}
		return
	}
	if domain, ok := normalizeDomain(target); ok {
		if action == ruleAllow {
			allowDomains[domain] = struct{}{}
			return
		}
		blockDomains[domain] = struct{}{}
	}
}

func splitRulePrefix(raw string, defaultAction ruleAction) (ruleAction, string) {
	value := strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(value), "allow:") {
		return ruleAllow, strings.TrimSpace(value[len("allow:"):])
	}
	if strings.HasPrefix(strings.ToLower(value), "block:") {
		return ruleBlock, strings.TrimSpace(value[len("block:"):])
	}
	return defaultAction, value
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

func mergeDomains(groups ...[]string) []string {
	dedup := make(map[string]struct{})
	for _, group := range groups {
		for _, domain := range group {
			dedup[domain] = struct{}{}
		}
	}

	out := make([]string, 0, len(dedup))
	for domain := range dedup {
		out = append(out, domain)
	}
	slices.Sort(out)
	return out
}

func mergeRules(groups ...Rules) Rules {
	var merged Rules
	for _, group := range groups {
		merged.BlockAllDomains = merged.BlockAllDomains || group.BlockAllDomains
		merged.BlockAllResolvers = merged.BlockAllResolvers || group.BlockAllResolvers
	}
	merged.BlockDomains = mergeDomains(func() [][]string {
		out := make([][]string, 0, len(groups))
		for _, group := range groups {
			out = append(out, group.BlockDomains)
		}
		return out
	}()...)
	merged.AllowDomains = mergeDomains(func() [][]string {
		out := make([][]string, 0, len(groups))
		for _, group := range groups {
			out = append(out, group.AllowDomains)
		}
		return out
	}()...)
	merged.BlockSuffixes = mergeDomains(func() [][]string {
		out := make([][]string, 0, len(groups))
		for _, group := range groups {
			out = append(out, group.BlockSuffixes)
		}
		return out
	}()...)
	merged.AllowSuffixes = mergeDomains(func() [][]string {
		out := make([][]string, 0, len(groups))
		for _, group := range groups {
			out = append(out, group.AllowSuffixes)
		}
		return out
	}()...)
	merged.BlockEndpoints = mergeEndpointGroups(groups, func(group Rules) []EndpointRule { return group.BlockEndpoints })
	merged.AllowEndpoints = mergeEndpointGroups(groups, func(group Rules) []EndpointRule { return group.AllowEndpoints })
	merged.BlockEndpointCIDRs = mergeEndpointCIDRGroups(groups, func(group Rules) []EndpointCIDR { return group.BlockEndpointCIDRs })
	merged.AllowEndpointCIDRs = mergeEndpointCIDRGroups(groups, func(group Rules) []EndpointCIDR { return group.AllowEndpointCIDRs })
	return merged
}

func mergeEndpointGroups(groups []Rules, pick func(Rules) []EndpointRule) []EndpointRule {
	seen := make(map[string]struct{})
	out := make([]EndpointRule, 0)
	for _, group := range groups {
		for _, endpoint := range pick(group) {
			key := endpointKey(endpoint)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, endpoint)
		}
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

func mergeEndpointCIDRGroups(groups []Rules, pick func(Rules) []EndpointCIDR) []EndpointCIDR {
	seen := make(map[string]struct{})
	out := make([]EndpointCIDR, 0)
	for _, group := range groups {
		for _, cidr := range pick(group) {
			key := endpointCIDRKey(cidr)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, cidr)
		}
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
