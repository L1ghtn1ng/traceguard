package app

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type policyController struct {
	ctx           context.Context
	cfg           config.Config
	monitor       *ebpf.Monitor
	recorder      *eventsink.Recorder
	metrics       *telemetry.Registry
	detector      *detection.Engine
	mu            sync.Mutex
	bundle        policyconfig.Bundle
	cgroups       []cgroupinfo.Entry
	blockResolved []blocklist.ResolvedEndpoint
	allowResolved []blocklist.ResolvedEndpoint
	endpointIndex atomic.Pointer[map[string]string]
	runtimePolicy atomic.Pointer[blocklist.Policy]
}

func newPolicyController(ctx context.Context, cfg config.Config, monitor *ebpf.Monitor, recorder *eventsink.Recorder, metrics *telemetry.Registry, detector *detection.Engine) *policyController {
	return &policyController{ctx: ctx, cfg: cfg, monitor: monitor, recorder: recorder, metrics: metrics, detector: detector}
}

func (p *policyController) ApplyBundle(bundle policyconfig.Bundle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	bundleChanged := !reflect.DeepEqual(bundle, p.bundle)
	refreshEndpoints := policyHasResolverEndpoints(p.bundle) || policyHasResolverEndpoints(bundle)
	if !bundleChanged && !refreshEndpoints {
		return nil
	}
	cgroups := p.cgroups
	if bundleChanged {
		var err error
		cgroups, err = p.scanCgroups(bundle)
		if err != nil {
			return err
		}
	}
	previous := p.cgroups
	p.cgroups = cgroups
	if err := p.applyLocked(bundle, true); err != nil {
		p.cgroups = previous
		return err
	}
	if bundleChanged {
		if err := p.detector.Replace(bundle.DetectionRules, bundle.DisabledRuleIDs); err != nil {
			p.cgroups = previous
			return fmt.Errorf("replace detection policy: %w", err)
		}
		p.metrics.SetDetectionRules(p.detector.RuleCount())
		p.recorder.InfoIfChanged("detection policy loaded", map[string]any{
			"rules": p.detector.RuleCount(),
		})
	}
	p.bundle = bundle
	return nil
}

func policyHasResolverEndpoints(bundle policyconfig.Bundle) bool {
	return len(bundle.DNS.BlockEndpoints)+len(bundle.DNS.AllowEndpoints) > 0
}

func (p *policyController) ReconcileCgroups() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cgroups, err := p.scanCgroups(p.bundle)
	if err != nil {
		return err
	}
	if slices.Equal(cgroups, p.cgroups) {
		return nil
	}
	previous := p.cgroups
	p.cgroups = cgroups
	if err := p.applyLocked(p.bundle, false); err != nil {
		p.cgroups = previous
		return err
	}
	p.metrics.IncCgroupReconcile(true)
	return nil
}

func (p *policyController) scanCgroups(bundle policyconfig.Bundle) ([]cgroupinfo.Entry, error) {
	for _, rule := range bundle.Egress.Rules {
		if len(rule.Selectors.CgroupPaths) > 0 || len(rule.Selectors.CgroupPrefixes) > 0 {
			entries, err := cgroupinfo.Scan(p.cfg.CgroupPath)
			if err != nil {
				return nil, fmt.Errorf("resolve egress cgroup selectors: %w", err)
			}
			selected := make(map[uint64]struct{})
			for _, candidate := range bundle.Egress.Rules {
				for _, id := range cgroupinfo.Select(entries, candidate.Selectors.CgroupPaths, candidate.Selectors.CgroupPrefixes) {
					selected[id] = struct{}{}
				}
			}
			relevant := make([]cgroupinfo.Entry, 0, len(selected))
			for _, entry := range entries {
				if _, ok := selected[entry.ID]; ok {
					relevant = append(relevant, entry)
				}
			}
			return relevant, nil
		}
	}
	return nil, nil
}

func (p *policyController) applyLocked(bundle policyconfig.Bundle, refreshEndpoints bool) error {
	rules := bundle.DNS
	if err := validateRulesForMode(p.cfg, rules); err != nil {
		return err
	}
	blockResolved := p.blockResolved
	allowResolved := p.allowResolved
	if refreshEndpoints {
		var err error
		blockResolved, err = blocklist.ResolveEndpoints(p.ctx, rules.BlockEndpoints)
		if err != nil {
			return fmt.Errorf("resolve block endpoint rules: %w", err)
		}
		allowResolved, err = blocklist.ResolveEndpoints(p.ctx, rules.AllowEndpoints)
		if err != nil {
			return fmt.Errorf("resolve allow endpoint rules: %w", err)
		}
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
	egress, err := compileEgressPolicy(p.cfg, bundle.Egress, p.cgroups)
	if err != nil {
		return err
	}

	if err := p.monitor.ApplyPolicy(ebpf.PolicyConfig{
		BlockEnabled:      p.cfg.Block && !p.cfg.DryRun,
		BlockAllDomains:   rules.BlockAllDomains,
		BlockAllResolvers: rules.BlockAllResolvers,
		BlockedDomains:    rules.BlockDomains,
		AllowedDomains:    rules.AllowDomains,
		BlockedSuffixes:   rules.BlockSuffixes,
		AllowedSuffixes:   rules.AllowSuffixes,
		BlockedEndpoints:  blockEndpoints,
		AllowedEndpoints:  allowEndpoints,
		BlockedCIDRs:      blockCIDRs,
		AllowedCIDRs:      allowCIDRs,
		Egress:            egress,
	}); err != nil {
		return fmt.Errorf("commit kernel policy: %w", err)
	}

	p.endpointIndex.Store(&index)
	p.runtimePolicy.Store(runtimePolicy)
	p.blockResolved = blockResolved
	p.allowResolved = allowResolved
	p.metrics.SetPolicyCounts(len(rules.BlockDomains)+len(rules.AllowDomains)+len(rules.BlockSuffixes)+len(rules.AllowSuffixes), len(blockResolved)+len(allowResolved)+len(rules.BlockEndpointCIDRs)+len(rules.AllowEndpointCIDRs))
	p.metrics.SetPolicyRuleCounts(policyRuleCounts(rules, len(blockResolved), len(allowResolved)))
	egressAllow := 0
	egressBlock := 0
	for _, rule := range bundle.Egress.Rules {
		if rule.Action == "allow" {
			egressAllow++
		} else {
			egressBlock++
		}
	}
	p.metrics.SetEgressRuleCounts(egressAllow, egressBlock)
	p.metrics.SetPolicyLastLoaded()
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
		"policy_path":          p.cfg.PolicyPath,
		"policy_url":           p.cfg.PolicyURL,
		"policy_cache":         p.cfg.PolicyCachePath,
		"dry_run":              p.cfg.DryRun,
		"egress_default":       bundle.Egress.Default,
		"egress_rules":         len(bundle.Egress.Rules),
	})
	return nil
}

func compileEgressPolicy(cfg config.Config, source policyconfig.EgressPolicy, cgroups []cgroupinfo.Entry) (ebpf.EgressPolicyConfig, error) {
	enabled := (cfg.Block || cfg.DryRun) && (len(source.Rules) > 0 || source.Default == "block")
	compiled := ebpf.EgressPolicyConfig{
		Enabled:      enabled,
		Enforce:      enabled && cfg.Block && !cfg.DryRun,
		DefaultBlock: source.Default == "block",
		Rules:        make([]ebpf.EgressRuleConfig, 0, len(source.Rules)),
	}
	for _, rule := range source.Rules {
		cidrs := make([]netip.Prefix, 0, len(rule.Destinations.CIDRs))
		for _, value := range rule.Destinations.CIDRs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return ebpf.EgressPolicyConfig{}, fmt.Errorf("egress rule %q destination %q: %w", rule.ID, value, err)
			}
			cidrs = append(cidrs, prefix.Masked())
		}
		hasCgroupSelector := len(rule.Selectors.CgroupPaths) > 0 || len(rule.Selectors.CgroupPrefixes) > 0
		compiled.Rules = append(compiled.Rules, ebpf.EgressRuleConfig{
			ID:                rule.ID,
			Action:            rule.Action,
			UIDs:              slices.Clone(rule.Selectors.UIDs),
			CgroupIDs:         cgroupinfo.Select(cgroups, rule.Selectors.CgroupPaths, rule.Selectors.CgroupPrefixes),
			HasUIDSelector:    len(rule.Selectors.UIDs) > 0,
			HasCgroupSelector: hasCgroupSelector,
			CIDRs:             cidrs,
			Ports:             slices.Clone(rule.Destinations.Ports),
			Protocols:         slices.Clone(rule.Destinations.Protocols),
		})
	}
	return compiled, nil
}
