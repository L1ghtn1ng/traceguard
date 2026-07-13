package blocklist

import (
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
	"slices"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"golang.org/x/sys/unix"
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

type LoadSource string

const (
	LoadSourceManual     LoadSource = "manual"
	LoadSourceRemote     LoadSource = "remote"
	LoadSourceCache      LoadSource = "cache"
	LoadSourceStaleCache LoadSource = "stale_cache"
)

type LoadMetadata struct {
	Source            LoadSource
	CachePersistError string
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
				if req.URL == nil || req.URL.Scheme != "https" || len(via) == 0 || !sameOrigin(req.URL, via[0].URL) {
					return errors.New("redirect target must keep the original HTTPS origin")
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
	return m.WatchWithMetadata(ctx, func(rules Rules, _ LoadMetadata, err error) error {
		if err != nil {
			return err
		}
		return apply(rules)
	})
}

func (m *Manager) WatchWithMetadata(ctx context.Context, apply func(Rules, LoadMetadata, error) error) error {
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
			rules, metadata, err := m.LoadWithMetadata(ctx)
			if err != nil {
				if callbackErr := apply(rules, metadata, err); callbackErr != nil {
					return fmt.Errorf("refresh blocklist: %w", callbackErr)
				}
				continue
			}
			if err := apply(rules, metadata, nil); err != nil {
				return fmt.Errorf("apply refreshed blocklist: %w", err)
			}
		}
	}
}

func (m *Manager) Load(ctx context.Context) (Rules, error) {
	rules, _, err := m.LoadWithMetadata(ctx)
	return rules, err
}

func (m *Manager) LoadWithMetadata(ctx context.Context) (Rules, LoadMetadata, error) {
	manualEntries := make([]string, 0, len(m.cfg.ManualDomains)+len(m.cfg.ManualAllow))
	manualEntries = append(manualEntries, m.cfg.ManualDomains...)
	for _, value := range m.cfg.ManualAllow {
		manualEntries = append(manualEntries, "allow:"+value)
	}

	manual, err := ParseRules(strings.NewReader(strings.Join(manualEntries, "\n")))
	if err != nil {
		return Rules{}, LoadMetadata{Source: LoadSourceManual}, fmt.Errorf("parse manual rules: %w", err)
	}

	if m.cfg.URL == "" {
		return manual, LoadMetadata{Source: LoadSourceManual}, nil
	}

	cacheFresh, err := isCacheFresh(m.cfg.CachePath, m.cfg.RefreshPeriod)
	if err != nil {
		return Rules{}, LoadMetadata{Source: LoadSourceCache}, err
	}

	var remote Rules
	metadata := LoadMetadata{Source: LoadSourceRemote}
	source := LoadSourceRemote
	switch {
	case cacheFresh:
		source = LoadSourceCache
		remote, err = m.readCache()
		if err != nil {
			return Rules{}, LoadMetadata{Source: source}, err
		}
	default:
		var body []byte
		remote, body, err = m.fetch(ctx)
		if err != nil {
			stale, staleErr := m.readCache()
			if staleErr != nil {
				return Rules{}, LoadMetadata{Source: source}, err
			}
			remote = stale
			source = LoadSourceStaleCache
		} else if cacheErr := writeCache(m.cfg.CachePath, body); cacheErr != nil {
			metadata.CachePersistError = cacheErr.Error()
		}
	}

	metadata.Source = source
	return mergeRules(manual, remote), metadata, nil
}

func (m *Manager) fetch(ctx context.Context) (Rules, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.URL, nil)
	if err != nil {
		return Rules{}, nil, fmt.Errorf("build blocklist request: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := m.client.Do(req)
	if err != nil {
		return Rules{}, nil, fmt.Errorf("fetch remote blocklist: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Rules{}, nil, fmt.Errorf("fetch remote blocklist: unexpected HTTP status %s", resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRemoteBlocklistBytes+1))
	if err != nil {
		return Rules{}, nil, fmt.Errorf("read remote blocklist: %w", err)
	}
	if len(body) > maxRemoteBlocklistBytes {
		return Rules{}, nil, fmt.Errorf("read remote blocklist: response exceeds %d bytes", maxRemoteBlocklistBytes)
	}

	rules, err := ParseRules(strings.NewReader(string(body)))
	if err != nil {
		return Rules{}, nil, fmt.Errorf("parse remote blocklist: %w", err)
	}
	return rules, body, nil
}

func (m *Manager) readCache() (Rules, error) {
	payload, err := safefile.ReadFile(m.cfg.CachePath, maxRemoteBlocklistBytes)
	if err != nil {
		return Rules{}, fmt.Errorf("read cache %q: %w", m.cfg.CachePath, err)
	}
	rules, err := ParseRules(strings.NewReader(string(payload)))
	if err != nil {
		return Rules{}, fmt.Errorf("parse cache %q: %w", m.cfg.CachePath, err)
	}
	return rules, nil
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
	if err := safefile.WriteFileAtomic(path, content, 0o640); err != nil {
		return fmt.Errorf("persist cache %q; path must not traverse symlinks: %w", path, err)
	}
	return nil
}

func isCacheFresh(path string, ttl time.Duration) (bool, error) {
	file, err := safefile.OpenAbsolute(path, unix.O_RDONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat cache %q: %w", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, fmt.Errorf("stat cache %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("stat cache %q: not a regular file", path)
	}
	return time.Since(info.ModTime()) < ttl, nil
}

func sameOrigin(left, right *url.URL) bool {
	if left == nil || right == nil {
		return false
	}
	return strings.EqualFold(left.Scheme, right.Scheme) && strings.EqualFold(left.Host, right.Host)
}
