package app

import (
	"context"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/fim"
	"github.com/L1ghtn1ng/traceguard/internal/netprefix"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/threatintel"
)

type policyController struct {
	ctx           context.Context
	cfg           config.Config
	monitor       *ebpf.Monitor
	recorder      *eventsink.Recorder
	metrics       *telemetry.Registry
	detector      *detection.Engine
	integrity     *fim.Watcher
	intel         *atomic.Pointer[threatintel.Matcher]
	mu            sync.Mutex
	source        policyconfig.Bundle
	bundle        policyconfig.Bundle
	feedDigest    string
	cgroups       []cgroupinfo.Entry
	blockResolved []blocklist.ResolvedEndpoint
	allowResolved []blocklist.ResolvedEndpoint
	digest        string
}

func newPolicyController(ctx context.Context, cfg config.Config, monitor *ebpf.Monitor, recorder *eventsink.Recorder, metrics *telemetry.Registry, detector *detection.Engine, integrity *fim.Watcher, intel *atomic.Pointer[threatintel.Matcher]) *policyController {
	return &policyController{ctx: ctx, cfg: cfg, monitor: monitor, recorder: recorder, metrics: metrics, detector: detector, integrity: integrity, intel: intel}
}

// expandThreatIntel loads a policy's feeds and adds blocking feeds to its
// kernel rules, returning the effective bundle and a digest of every feed.
func expandThreatIntel(source policyconfig.Bundle) (policyconfig.Bundle, []threatintel.Feed, string, error) {
	feeds, err := threatintel.Load(source.ThreatIntel.Feeds)
	if err != nil {
		return policyconfig.Bundle{}, nil, "", err
	}
	bundle, err := threatintel.Enforce(source, feeds)
	if err != nil {
		return policyconfig.Bundle{}, nil, "", err
	}
	digests := make([]string, 0, len(feeds))
	for _, feed := range feeds {
		digests = append(digests, feed.Config.ID+"="+feed.Digest)
	}
	return bundle, feeds, strings.Join(digests, ","), nil
}

// Source returns the policy as it was last applied, before feed expansion.
func (p *policyController) Source() policyconfig.Bundle {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.source
}

func (p *policyController) ApplyBundle(source policyconfig.Bundle) error {
	bundle, feeds, feedDigest, err := expandThreatIntel(source)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := validateEffectiveBundle(p.cfg, bundle); err != nil {
		return err
	}
	bundleChanged := !reflect.DeepEqual(bundle, p.bundle) || feedDigest != p.feedDigest
	refreshEndpoints := policyHasResolverEndpoints(p.bundle) || policyHasResolverEndpoints(bundle)
	if !bundleChanged && !refreshEndpoints {
		return nil
	}
	cgroups := p.cgroups
	var detections detection.CompiledRules
	if bundleChanged {
		cgroups, err = p.scanCgroups(bundle)
		if err != nil {
			return err
		}
		// Compile detections before the kernel commit so a failure cannot
		// leave the kernel and controller on different policies.
		detections, err = detection.Compile(bundle)
		if err != nil {
			return fmt.Errorf("compile detection policy: %w", err)
		}
	}
	previous := p.cgroups
	p.cgroups = cgroups
	if err := p.applyLocked(bundle, true); err != nil {
		p.cgroups = previous
		return err
	}
	if bundleChanged {
		p.integrity.Configure(bundle.FileIntegrity)
		matcher := threatintel.NewMatcher(feeds)
		p.intel.Store(matcher)
		p.metrics.SetThreatIntelIndicators(matcher.Indicators())
		p.detector.Install(detections)
		p.metrics.SetDetectionRules(p.detector.RuleCount())
		p.recorder.InfoIfChanged("detection policy loaded", map[string]any{
			"rules": p.detector.RuleCount(),
		})
	}
	p.source = source
	p.bundle = bundle
	p.feedDigest = feedDigest
	return nil
}

// validateBundleForMode runs every check that does not touch the kernel,
// including loading threat intelligence feeds. The YAML manager uses it
// before committing a fetched remote document.
func validateBundleForMode(cfg config.Config, source policyconfig.Bundle) error {
	bundle, _, _, err := expandThreatIntel(source)
	if err != nil {
		return err
	}
	return validateEffectiveBundle(cfg, bundle)
}

func validateEffectiveBundle(cfg config.Config, bundle policyconfig.Bundle) error {
	if err := bundle.Validate(); err != nil {
		return fmt.Errorf("validate effective policy: %w", err)
	}
	if err := validateEnforcedCgroupSelectors(cfg, bundle); err != nil {
		return err
	}
	if err := validateRulesForMode(cfg, bundle.DNS); err != nil {
		return err
	}
	if _, err := detection.Compile(bundle); err != nil {
		return fmt.Errorf("compile detection policy: %w", err)
	}
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
	selectors := enforcementSelectors(bundle)
	if len(selectors) == 0 {
		return nil, nil
	}
	entries, err := cgroupinfo.ScanContext(p.ctx, p.cfg.CgroupPath)
	if err != nil {
		return nil, fmt.Errorf("resolve policy cgroup selectors: %w", err)
	}
	index := cgroupinfo.NewIndex(entries)
	selected := make(map[uint64]struct{})
	for _, selector := range selectors {
		exactIDs, ancestorIDs, err := index.Resolve(selector.CgroupPaths, selector.CgroupPrefixes)
		if err != nil {
			return nil, fmt.Errorf("resolve policy cgroup selectors: %w", err)
		}
		for _, id := range append(exactIDs, ancestorIDs...) {
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

// Digest returns the SHA-256 of the policy that is active in the kernel and
// detection engine, or "" before any policy has been applied.
func (p *policyController) Digest() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.digest
}

// RecordApplied records a policy published outside ApplyBundle, such as the
// empty policy used without a policy source or in emergency allow mode.
func (p *policyController) RecordApplied(bundle policyconfig.Bundle) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	digest, err := bundle.Digest()
	if err != nil {
		return err
	}
	p.setDigestLocked(digest)
	p.integrity.Configure(bundle.FileIntegrity)
	return nil
}

func (p *policyController) setDigestLocked(digest string) {
	p.digest = digest
	p.metrics.SetPolicyDigest(digest)
}

func (p *policyController) applyLocked(bundle policyconfig.Bundle, refreshEndpoints bool) error {
	digest, err := bundle.Digest()
	if err != nil {
		return err
	}
	rules := bundle.DNS
	if err := validateRulesForMode(p.cfg, rules); err != nil {
		return err
	}
	blockResolved := p.blockResolved
	allowResolved := p.allowResolved
	if refreshEndpoints {
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
	for _, endpoint := range blockResolved {
		blockEndpoints = append(blockEndpoints, ebpf.ResolverEndpoint{Transport: string(endpoint.Kind), IP: endpoint.IP, Port: endpoint.Port})
	}
	for _, endpoint := range allowResolved {
		allowEndpoints = append(allowEndpoints, ebpf.ResolverEndpoint{Transport: string(endpoint.Kind), IP: endpoint.IP, Port: endpoint.Port})
	}
	for _, cidr := range rules.BlockEndpointCIDRs {
		blockCIDRs = append(blockCIDRs, ebpf.ResolverCIDR{Transport: string(cidr.Kind), Prefix: cidr.Prefix, Port: cidr.Port})
	}
	for _, cidr := range rules.AllowEndpointCIDRs {
		allowCIDRs = append(allowCIDRs, ebpf.ResolverCIDR{Transport: string(cidr.Kind), Prefix: cidr.Prefix, Port: cidr.Port})
	}
	cgroups := cgroupinfo.NewIndex(p.cgroups)
	egress, err := compileEgressPolicy(p.cfg, bundle.Egress, cgroups)
	if err != nil {
		return err
	}
	execPolicy, err := compilePathPolicy(p.cfg, bundle.Exec, cgroups)
	if err != nil {
		return err
	}
	filePolicy, err := compileFilePolicy(p.cfg, bundle.File, cgroups)
	if err != nil {
		return err
	}
	bindPolicy, err := compileBindPolicy(p.cfg, bundle.Bind, cgroups)
	if err != nil {
		return err
	}
	unixPolicy, err := compileUnixPolicy(p.cfg, bundle.Unix, cgroups)
	if err != nil {
		return err
	}
	sockoptPolicy, err := compileSockoptPolicy(p.cfg, bundle.Sockopt, cgroups)
	if err != nil {
		return err
	}
	if err := p.monitor.ApplyPolicy(ebpf.PolicyConfig{
		BlockEnabled:      !p.cfg.EmergencyAllow && p.cfg.Block && !p.cfg.DryRun,
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
		Exec:              execPolicy,
		File:              filePolicy,
		Bind:              bindPolicy,
		Unix:              unixPolicy,
		Sockopt:           sockoptPolicy,
	}); err != nil {
		return fmt.Errorf("commit kernel policy: %w", err)
	}
	// Report hook health only for the policy that is now active.
	p.updateHookHealth(execPolicy, filePolicy, bindPolicy, unixPolicy, sockoptPolicy)
	p.setDigestLocked(digest)

	p.blockResolved = blockResolved
	p.allowResolved = allowResolved
	p.metrics.SetPolicyCounts(len(rules.BlockDomains)+len(rules.AllowDomains)+len(rules.BlockSuffixes)+len(rules.AllowSuffixes), len(blockResolved)+len(allowResolved)+len(rules.BlockEndpointCIDRs)+len(rules.AllowEndpointCIDRs))
	counts := policyRuleCounts(rules, len(blockResolved), len(allowResolved))
	addEnforcementRuleCounts(counts, bundle)
	p.metrics.SetPolicyRuleCounts(counts)
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
		"policy_sha256":        digest,
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
		"policy_url":           config.SanitizeURL(p.cfg.PolicyURL),
		"policy_cache":         p.cfg.PolicyCachePath,
		"dry_run":              p.cfg.DryRun,
		"egress_default":       bundle.Egress.Default,
		"egress_rules":         len(bundle.Egress.Rules),
		"exec_rules":           len(bundle.Exec.Rules),
		"file_rules":           len(bundle.File.Rules),
		"bind_rules":           len(bundle.Bind.Rules),
		"unix_rules":           len(bundle.Unix.Rules),
		"sockopt_rules":        len(bundle.Sockopt.Rules),
	})
	return nil
}

func compileEgressPolicy(cfg config.Config, source policyconfig.EgressPolicy, cgroups cgroupinfo.Index) (ebpf.EgressPolicyConfig, error) {
	blockRules := 0
	for _, rule := range source.Rules {
		if rule.Action == "block" {
			blockRules++
		}
	}
	enabled := enforcementSectionEnabled(cfg, source.Default, blockRules, true)
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
			canonical, err := netprefix.Canonical(prefix)
			if err != nil {
				return ebpf.EgressPolicyConfig{}, fmt.Errorf("egress rule %q destination %q: %w", rule.ID, value, err)
			}
			cidrs = append(cidrs, canonical)
		}
		hasCgroupSelector := len(rule.Selectors.CgroupPaths) > 0 || len(rule.Selectors.CgroupPrefixes) > 0
		exactCgroups, ancestorCgroups, err := cgroups.Resolve(rule.Selectors.CgroupPaths, rule.Selectors.CgroupPrefixes)
		if err != nil {
			return ebpf.EgressPolicyConfig{}, fmt.Errorf("egress rule %q: %w", rule.ID, err)
		}
		compiled.Rules = append(compiled.Rules, ebpf.EgressRuleConfig{
			ID:                rule.ID,
			Action:            rule.Action,
			UIDs:              slices.Clone(rule.Selectors.UIDs),
			CgroupIDs:         exactCgroups,
			CgroupAncestorIDs: ancestorCgroups,
			HasUIDSelector:    len(rule.Selectors.UIDs) > 0,
			HasCgroupSelector: hasCgroupSelector,
			CIDRs:             cidrs,
			Ports:             slices.Clone(rule.Destinations.Ports),
			Protocols:         slices.Clone(rule.Destinations.Protocols),
		})
	}
	return compiled, nil
}
