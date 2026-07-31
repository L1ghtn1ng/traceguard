package blocklist

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

type EndpointKind string

const (
	EndpointKindDoH EndpointKind = "doh"
	EndpointKindDoT EndpointKind = "dot"
)

type EndpointRule struct {
	Kind EndpointKind
	Host string
	Port uint16
}

type EndpointCIDR struct {
	Kind   EndpointKind
	Prefix netip.Prefix
	Port   uint16
}

type Rules struct {
	BlockAllDomains    bool
	BlockAllResolvers  bool
	BlockDomains       []string
	AllowDomains       []string
	BlockSuffixes      []string
	AllowSuffixes      []string
	BlockEndpoints     []EndpointRule
	AllowEndpoints     []EndpointRule
	BlockEndpointCIDRs []EndpointCIDR
	AllowEndpointCIDRs []EndpointCIDR
}

type ResolvedEndpoint struct {
	Kind EndpointKind
	Host string
	Port uint16
	IP   net.IP
}

func ResolveEndpoints(ctx context.Context, endpoints []EndpointRule) ([]ResolvedEndpoint, error) {
	resolver := net.DefaultResolver
	dedup := make(map[string]ResolvedEndpoint)
	for _, endpoint := range endpoints {
		if ip := net.ParseIP(endpoint.Host); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				ip = ip4
			}
			resolved := ResolvedEndpoint{
				Kind: endpoint.Kind,
				Host: endpoint.Host,
				Port: endpoint.Port,
				IP:   append(net.IP(nil), ip...),
			}
			dedup[resolvedEndpointKey(resolved)] = resolved
			continue
		}
		addrs, err := resolver.LookupIP(ctx, "ip", endpoint.Host)
		if err != nil {
			return nil, fmt.Errorf("resolve endpoint host %q: %w", endpoint.Host, err)
		}
		for _, addr := range addrs {
			if ip := addr.To4(); ip != nil {
				addr = ip
			}
			resolved := ResolvedEndpoint{
				Kind: endpoint.Kind,
				Host: endpoint.Host,
				Port: endpoint.Port,
				IP:   append(net.IP(nil), addr...),
			}
			dedup[resolvedEndpointKey(resolved)] = resolved
		}
	}

	out := make([]ResolvedEndpoint, 0, len(dedup))
	for _, endpoint := range dedup {
		out = append(out, endpoint)
	}
	slices.SortFunc(out, func(a, b ResolvedEndpoint) int {
		if a.Kind != b.Kind {
			return strings.Compare(string(a.Kind), string(b.Kind))
		}
		if a.Host != b.Host {
			return strings.Compare(a.Host, b.Host)
		}
		if cmp := bytesCompare(a.IP, b.IP); cmp != 0 {
			return cmp
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
	return out, nil
}
