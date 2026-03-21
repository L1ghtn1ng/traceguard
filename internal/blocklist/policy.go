package blocklist

import (
	"fmt"
	"net"
	"strings"
)

type Decision string

const (
	DecisionNone  Decision = "none"
	DecisionAllow Decision = "allow"
	DecisionBlock Decision = "block"
)

type Policy struct {
	allowDomains   map[string]struct{}
	blockDomains   map[string]struct{}
	allowSuffixes  []string
	blockSuffixes  []string
	allowEndpoints map[string]struct{}
	blockEndpoints map[string]struct{}
}

func NewPolicy(rules Rules, blockResolved, allowResolved []ResolvedEndpoint) *Policy {
	policy := &Policy{
		allowDomains:   make(map[string]struct{}, len(rules.AllowDomains)),
		blockDomains:   make(map[string]struct{}, len(rules.BlockDomains)),
		allowSuffixes:  append([]string(nil), rules.AllowSuffixes...),
		blockSuffixes:  append([]string(nil), rules.BlockSuffixes...),
		allowEndpoints: make(map[string]struct{}, len(allowResolved)),
		blockEndpoints: make(map[string]struct{}, len(blockResolved)),
	}
	for _, domain := range rules.AllowDomains {
		policy.allowDomains[domain] = struct{}{}
	}
	for _, domain := range rules.BlockDomains {
		policy.blockDomains[domain] = struct{}{}
	}
	for _, endpoint := range allowResolved {
		policy.allowEndpoints[resolvedPolicyKey(string(endpoint.Kind), endpoint.IP, endpoint.Port)] = struct{}{}
	}
	for _, endpoint := range blockResolved {
		policy.blockEndpoints[resolvedPolicyKey(string(endpoint.Kind), endpoint.IP, endpoint.Port)] = struct{}{}
	}
	return policy
}

func (p *Policy) DomainDecision(domain string) Decision {
	if p == nil {
		return DecisionNone
	}
	normalized, ok := normalizeDomain(domain)
	if !ok {
		return DecisionNone
	}
	if _, allowed := p.allowDomains[normalized]; allowed {
		return DecisionAllow
	}
	if matchesSuffix(normalized, p.allowSuffixes) {
		return DecisionAllow
	}
	if _, blocked := p.blockDomains[normalized]; blocked {
		return DecisionBlock
	}
	if matchesSuffix(normalized, p.blockSuffixes) {
		return DecisionBlock
	}
	return DecisionNone
}

func (p *Policy) EndpointDecision(transport, address string, port uint16) Decision {
	if p == nil {
		return DecisionNone
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return DecisionNone
	}
	key := resolvedPolicyKey(transport, ip, port)
	if _, allowed := p.allowEndpoints[key]; allowed {
		return DecisionAllow
	}
	if _, blocked := p.blockEndpoints[key]; blocked {
		return DecisionBlock
	}
	return DecisionNone
}

func resolvedPolicyKey(transport string, ip net.IP, port uint16) string {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	return fmt.Sprintf("%s|%s|%d", transport, ip.String(), port)
}

func matchesSuffix(domain string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}
