package blocklist

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const userAgent = "traceguard/1"

const maxRemoteBlocklistBytes = 8 << 20

type Config struct {
	URL           string
	CachePath     string
	RefreshPeriod time.Duration
	ManualDomains []string
	ManualAllow   []string
}

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

type Manager struct {
	client *http.Client
	cfg    Config
}

func NewManager(cfg Config) *Manager {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &Manager{
		client: &http.Client{
			Timeout:   30 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL == nil || req.URL.Scheme != "https" {
					return errors.New("redirect target must use https")
				}
				return nil
			},
		},
		cfg: cfg,
	}
}

func (m *Manager) Run(ctx context.Context, apply func(Rules) error) error {
	rules, err := m.Load(ctx)
	if err != nil {
		return err
	}
	if err := apply(rules); err != nil {
		return fmt.Errorf("apply initial blocklist: %w", err)
	}

	if m.cfg.URL == "" {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(m.cfg.RefreshPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			rules, err := m.Load(ctx)
			if err != nil {
				return fmt.Errorf("refresh blocklist: %w", err)
			}
			if err := apply(rules); err != nil {
				return fmt.Errorf("apply refreshed blocklist: %w", err)
			}
		}
	}
}

func (m *Manager) Watch(ctx context.Context, apply func(Rules) error) error {
	if m.cfg.URL == "" {
		<-ctx.Done()
		return nil
	}

	ticker := time.NewTicker(m.cfg.RefreshPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			rules, err := m.Load(ctx)
			if err != nil {
				return fmt.Errorf("refresh blocklist: %w", err)
			}
			if err := apply(rules); err != nil {
				return fmt.Errorf("apply refreshed blocklist: %w", err)
			}
		}
	}
}

func (m *Manager) Load(ctx context.Context) (Rules, error) {
	manualEntries := make([]string, 0, len(m.cfg.ManualDomains)+len(m.cfg.ManualAllow))
	manualEntries = append(manualEntries, m.cfg.ManualDomains...)
	for _, value := range m.cfg.ManualAllow {
		manualEntries = append(manualEntries, "allow:"+value)
	}

	manual, err := ParseRules(strings.NewReader(strings.Join(manualEntries, "\n")))
	if err != nil {
		return Rules{}, fmt.Errorf("parse manual rules: %w", err)
	}

	if m.cfg.URL == "" {
		return manual, nil
	}

	cacheFresh, err := isCacheFresh(m.cfg.CachePath, m.cfg.RefreshPeriod)
	if err != nil {
		return Rules{}, err
	}

	var remote Rules
	switch {
	case cacheFresh:
		remote, err = m.readCache()
	default:
		remote, err = m.fetchAndCache(ctx)
		if err != nil {
			stale, staleErr := m.readCache()
			if staleErr != nil {
				return Rules{}, err
			}
			remote = stale
		}
	}

	return mergeRules(manual, remote), nil
}

func (m *Manager) fetchAndCache(ctx context.Context) (Rules, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.URL, nil)
	if err != nil {
		return Rules{}, fmt.Errorf("build blocklist request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := m.client.Do(req)
	if err != nil {
		return Rules{}, fmt.Errorf("fetch remote blocklist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Rules{}, fmt.Errorf("fetch remote blocklist: unexpected HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBlocklistBytes+1))
	if err != nil {
		return Rules{}, fmt.Errorf("read remote blocklist: %w", err)
	}
	if len(body) > maxRemoteBlocklistBytes {
		return Rules{}, fmt.Errorf("read remote blocklist: response exceeds %d bytes", maxRemoteBlocklistBytes)
	}

	rules, err := ParseRules(strings.NewReader(string(body)))
	if err != nil {
		return Rules{}, fmt.Errorf("parse remote blocklist: %w", err)
	}

	if err := writeCache(m.cfg.CachePath, body); err != nil {
		return Rules{}, err
	}

	return rules, nil
}

func (m *Manager) readCache() (Rules, error) {
	if err := rejectSymlink(m.cfg.CachePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Rules{}, fmt.Errorf("read cache %q: %w", m.cfg.CachePath, err)
	}

	file, err := os.Open(m.cfg.CachePath)
	if err != nil {
		return Rules{}, fmt.Errorf("read cache %q: %w", m.cfg.CachePath, err)
	}
	defer file.Close()
	if err := requireRegularFile(file, m.cfg.CachePath); err != nil {
		return Rules{}, err
	}

	rules, err := ParseRules(file)
	if err != nil {
		return Rules{}, fmt.Errorf("parse cache %q: %w", m.cfg.CachePath, err)
	}
	return rules, nil
}

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

	for _, label := range strings.Split(raw, ".") {
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

func writeCache(path string, content []byte) error {
	if path == "" {
		return errors.New("cache path is empty")
	}
	if err := rejectSymlink(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("persist cache %q: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	temp, err := os.CreateTemp(filepath.Dir(path), "traceguard-blocklist-*.tmp")
	if err != nil {
		return fmt.Errorf("create cache temp file: %w", err)
	}
	defer os.Remove(temp.Name())

	if _, err := temp.Write(content); err != nil {
		temp.Close()
		return fmt.Errorf("write cache temp file: %w", err)
	}
	if err := temp.Chmod(0o640); err != nil {
		temp.Close()
		return fmt.Errorf("chmod cache temp file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close cache temp file: %w", err)
	}

	if err := os.Rename(temp.Name(), path); err != nil {
		return fmt.Errorf("persist cache: %w", err)
	}
	return nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q must not be a symlink", path)
	}
	return nil
}

func requireRegularFile(file *os.File, path string) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat cache %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cache %q is not a regular file", path)
	}
	return nil
}

func isCacheFresh(path string, ttl time.Duration) (bool, error) {
	if err := rejectSymlink(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat cache %q: %w", path, err)
	}
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("stat cache %q: not a regular file", path)
		}
		return time.Since(info.ModTime()) < ttl, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat cache %q: %w", path, err)
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
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
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
