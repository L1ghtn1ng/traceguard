package app

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type policyController struct {
	ctx           context.Context
	cfg           config.Config
	monitor       *ebpf.Monitor
	recorder      *eventsink.Recorder
	metrics       *telemetry.Registry
	mu            sync.Mutex
	endpointIndex atomic.Pointer[map[string]string]
	runtimePolicy atomic.Pointer[blocklist.Policy]
}

type policyReloadResult struct {
	Metadata blocklist.LoadMetadata
	Phase    string
	Err      error
}

func runPolicyReloads(ctx context.Context, reloadCh <-chan struct{}, load func(context.Context) (blocklist.Rules, blocklist.LoadMetadata, error), apply func(blocklist.Rules) error, report func(policyReloadResult)) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-reloadCh:
			if !ok {
				return
			}
			rules, metadata, err := load(ctx)
			if err != nil {
				report(policyReloadResult{Metadata: metadata, Phase: "load", Err: err})
				continue
			}
			if err := apply(rules); err != nil {
				report(policyReloadResult{Metadata: metadata, Phase: "apply", Err: err})
				continue
			}
			report(policyReloadResult{Metadata: metadata, Phase: "complete"})
		}
	}
}

func newPolicyController(ctx context.Context, cfg config.Config, monitor *ebpf.Monitor, recorder *eventsink.Recorder, metrics *telemetry.Registry) *policyController {
	return &policyController{ctx: ctx, cfg: cfg, monitor: monitor, recorder: recorder, metrics: metrics}
}

func (p *policyController) Apply(rules blocklist.Rules) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := validateRulesForMode(p.cfg, rules); err != nil {
		return err
	}
	blockResolved, err := blocklist.ResolveEndpoints(p.ctx, rules.BlockEndpoints)
	if err != nil {
		return fmt.Errorf("resolve block endpoint rules: %w", err)
	}
	allowResolved, err := blocklist.ResolveEndpoints(p.ctx, rules.AllowEndpoints)
	if err != nil {
		return fmt.Errorf("resolve allow endpoint rules: %w", err)
	}

	blockEndpoints := make([]ebpf.ResolverEndpoint, 0, len(blockResolved))
	allowEndpoints := make([]ebpf.ResolverEndpoint, 0, len(allowResolved))
	blockCIDRs := make([]ebpf.ResolverCIDR, 0, len(rules.BlockEndpointCIDRs))
	allowCIDRs := make([]ebpf.ResolverCIDR, 0, len(rules.AllowEndpointCIDRs))
	index := make(map[string]string, len(blockResolved)+len(allowResolved))
	for _, endpoint := range blockResolved {
		blockEndpoints = append(blockEndpoints, ebpf.ResolverEndpoint{Transport: string(endpoint.Kind), IP: endpoint.IP, Port: endpoint.Port})
		index[resolverIndexKey(string(endpoint.Kind), endpoint.IP.String(), endpoint.Port)] = endpoint.Host
	}
	for _, endpoint := range allowResolved {
		allowEndpoints = append(allowEndpoints, ebpf.ResolverEndpoint{Transport: string(endpoint.Kind), IP: endpoint.IP, Port: endpoint.Port})
		index[resolverIndexKey(string(endpoint.Kind), endpoint.IP.String(), endpoint.Port)] = endpoint.Host
	}
	for _, cidr := range rules.BlockEndpointCIDRs {
		blockCIDRs = append(blockCIDRs, ebpf.ResolverCIDR{Transport: string(cidr.Kind), Prefix: cidr.Prefix, Port: cidr.Port})
	}
	for _, cidr := range rules.AllowEndpointCIDRs {
		allowCIDRs = append(allowCIDRs, ebpf.ResolverCIDR{Transport: string(cidr.Kind), Prefix: cidr.Prefix, Port: cidr.Port})
	}
	runtimePolicy := blocklist.NewPolicy(rules, blockResolved, allowResolved)

	if err := p.monitor.ApplyPolicy(ebpf.PolicyConfig{
		BlockEnabled:      p.cfg.Block && !p.cfg.DryRun,
		BlockAllDomains:   rules.BlockAllDomains,
		BlockAllResolvers: rules.BlockAllResolvers,
		BlockedDomains:    rules.BlockDomains,
		AllowedDomains:    rules.AllowDomains,
		AllowedSuffixes:   rules.AllowSuffixes,
		BlockedEndpoints:  blockEndpoints,
		AllowedEndpoints:  allowEndpoints,
		BlockedCIDRs:      blockCIDRs,
		AllowedCIDRs:      allowCIDRs,
	}); err != nil {
		return fmt.Errorf("commit kernel policy: %w", err)
	}

	p.endpointIndex.Store(&index)
	p.runtimePolicy.Store(runtimePolicy)
	p.metrics.SetPolicyCounts(len(rules.BlockDomains)+len(rules.AllowDomains)+len(rules.BlockSuffixes)+len(rules.AllowSuffixes), len(blockResolved)+len(allowResolved)+len(rules.BlockEndpointCIDRs)+len(rules.AllowEndpointCIDRs))
	p.metrics.SetPolicyRuleCounts(policyRuleCounts(rules, len(blockResolved), len(allowResolved)))
	p.metrics.SetPolicyLastLoaded()
	p.metrics.IncBlocklistRefresh(true)
	p.recorder.InfoIfChanged("policy loaded", map[string]any{
		"block_all_domains":    rules.BlockAllDomains,
		"block_all_resolvers":  rules.BlockAllResolvers,
		"block_domains":        len(rules.BlockDomains),
		"allow_domains":        len(rules.AllowDomains),
		"block_suffixes":       len(rules.BlockSuffixes),
		"allow_suffixes":       len(rules.AllowSuffixes),
		"block_endpoints":      len(blockResolved),
		"allow_endpoints":      len(allowResolved),
		"block_endpoint_cidrs": len(rules.BlockEndpointCIDRs),
		"allow_endpoint_cidrs": len(rules.AllowEndpointCIDRs),
		"source":               p.cfg.BlocklistURL,
		"cache":                p.cfg.CachePath,
		"dry_run":              p.cfg.DryRun,
	})
	return nil
}
