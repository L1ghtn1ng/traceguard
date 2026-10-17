package app

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
)

const hostCgroupRoot = "/sys/fs/cgroup"

func validateEnforcedCgroupSelectors(cfg config.Config, bundle policyconfig.Bundle) error {
	if cfg.EmergencyAllow || (!cfg.Block && !cfg.DryRun) {
		return nil
	}
	check := func(section, id, action string, selectors policyconfig.EgressSelectors) error {
		if action == "block" && (len(selectors.CgroupPaths) > 0 || len(selectors.CgroupPrefixes) > 0) {
			return fmt.Errorf("%s rule %q uses cgroup selectors for a block decision; cgroup IDs can change when a selected path is recreated, so block and dry-run modes require cgroup-scoped exceptions to be allow rules", section, id)
		}
		return nil
	}
	for _, rule := range bundle.Egress.Rules {
		if err := check("egress", rule.ID, rule.Action, rule.Selectors); err != nil {
			return err
		}
	}
	for _, rule := range bundle.Exec.Rules {
		if err := check("exec", rule.ID, rule.Action, rule.Selectors); err != nil {
			return err
		}
	}
	for _, rule := range bundle.File.Rules {
		if err := check("file", rule.ID, rule.Action, rule.Selectors); err != nil {
			return err
		}
	}
	for _, rule := range bundle.Bind.Rules {
		if err := check("bind", rule.ID, rule.Action, rule.Selectors); err != nil {
			return err
		}
	}
	for _, rule := range bundle.Unix.Rules {
		if err := check("unix", rule.ID, rule.Action, rule.Selectors); err != nil {
			return err
		}
	}
	for _, rule := range bundle.Sockopt.Rules {
		if err := check("sockopt", rule.ID, rule.Action, rule.Selectors); err != nil {
			return err
		}
	}
	return nil
}

func enforcementSelectors(bundle policyconfig.Bundle) []policyconfig.EgressSelectors {
	selectors := make([]policyconfig.EgressSelectors, 0)
	appendSelector := func(selector policyconfig.EgressSelectors) {
		if len(selector.CgroupPaths) > 0 || len(selector.CgroupPrefixes) > 0 {
			selectors = append(selectors, selector)
		}
	}
	for _, rule := range bundle.Egress.Rules {
		appendSelector(rule.Selectors)
	}
	for _, rule := range bundle.Exec.Rules {
		appendSelector(rule.Selectors)
	}
	for _, rule := range bundle.File.Rules {
		appendSelector(rule.Selectors)
	}
	for _, rule := range bundle.Bind.Rules {
		appendSelector(rule.Selectors)
	}
	for _, rule := range bundle.Unix.Rules {
		appendSelector(rule.Selectors)
	}
	for _, rule := range bundle.Sockopt.Rules {
		appendSelector(rule.Selectors)
	}
	return selectors
}

func compilePathPolicy(cfg config.Config, source policyconfig.PathPolicy, cgroups cgroupinfo.Index) (ebpf.PathPolicyConfig, error) {
	enabled := enforcementSectionEnabled(cfg, source.Default, pathBlockCount(source.Rules), false)
	compiled := ebpf.PathPolicyConfig{Enabled: enabled, Enforce: enabled && cfg.Block && !cfg.DryRun, Rules: make([]ebpf.PathRuleConfig, 0, len(source.Rules))}
	for _, rule := range source.Rules {
		compiledRule, err := compilePathRule(rule.ID, rule.Action, rule.Selectors, rule.Match.PathGlobs, nil, cgroups)
		if err != nil {
			return ebpf.PathPolicyConfig{}, err
		}
		compiled.Rules = append(compiled.Rules, compiledRule)
	}
	return compiled, nil
}

func compileFilePolicy(cfg config.Config, source policyconfig.FilePolicy, cgroups cgroupinfo.Index) (ebpf.PathPolicyConfig, error) {
	blockRules := 0
	for _, rule := range source.Rules {
		if rule.Action == "block" {
			blockRules++
		}
	}
	enabled := enforcementSectionEnabled(cfg, source.Default, blockRules, false)
	compiled := ebpf.PathPolicyConfig{Enabled: enabled, Enforce: enabled && cfg.Block && !cfg.DryRun, Rules: make([]ebpf.PathRuleConfig, 0, len(source.Rules))}
	for _, rule := range source.Rules {
		access := make([]uint8, 0, len(rule.Match.Access))
		if len(rule.Match.Access) == 1 {
			switch rule.Match.Access[0] {
			case "read":
				access = append(access, 1)
			case "write":
				access = append(access, 2)
			}
		}
		compiledRule, err := compilePathRule(rule.ID, rule.Action, rule.Selectors, rule.Match.PathGlobs, access, cgroups)
		if err != nil {
			return ebpf.PathPolicyConfig{}, err
		}
		compiled.Rules = append(compiled.Rules, compiledRule)
	}
	return compiled, nil
}

func compileUnixPolicy(cfg config.Config, source policyconfig.UnixPolicy, cgroups cgroupinfo.Index) (ebpf.PathPolicyConfig, error) {
	blockRules := 0
	for _, rule := range source.Rules {
		if rule.Action == "block" {
			blockRules++
		}
	}
	enabled := enforcementSectionEnabled(cfg, source.Default, blockRules, true)
	compiled := ebpf.PathPolicyConfig{
		Enabled: enabled, Enforce: enabled && cfg.Block && !cfg.DryRun,
		DefaultBlock: source.Default == "block", Rules: make([]ebpf.PathRuleConfig, 0, len(source.Rules)),
	}
	for _, rule := range source.Rules {
		operations := make([]uint8, 0, len(rule.Match.Operations))
		for _, operation := range rule.Match.Operations {
			switch operation {
			case "connect":
				operations = append(operations, 1)
			case "sendmsg":
				operations = append(operations, 2)
			case "recvmsg":
				operations = append(operations, 4)
			}
		}
		compiledRule, err := compilePathRule(rule.ID, rule.Action, rule.Selectors, rule.Match.PathGlobs, operations, cgroups)
		if err != nil {
			return ebpf.PathPolicyConfig{}, err
		}
		compiled.Rules = append(compiled.Rules, compiledRule)
	}
	return compiled, nil
}

func compilePathRule(id, action string, selectors policyconfig.EgressSelectors, paths []string, accessOrOps []uint8, cgroups cgroupinfo.Index) (ebpf.PathRuleConfig, error) {
	exactCgroups, ancestorCgroups, err := cgroups.Resolve(selectors.CgroupPaths, selectors.CgroupPrefixes)
	if err != nil {
		return ebpf.PathRuleConfig{}, fmt.Errorf("path rule %q: %w", id, err)
	}
	return ebpf.PathRuleConfig{
		ID: id, Action: action, UIDs: slices.Clone(selectors.UIDs),
		CgroupIDs:         exactCgroups,
		CgroupAncestorIDs: ancestorCgroups,
		HasUIDSelector:    len(selectors.UIDs) > 0,
		HasCgroupSelector: len(selectors.CgroupPaths) > 0 || len(selectors.CgroupPrefixes) > 0,
		PathGlobs:         slices.Clone(paths), AccessOrOps: slices.Clone(accessOrOps),
	}, nil
}

func compileBindPolicy(cfg config.Config, source policyconfig.BindPolicy, cgroups cgroupinfo.Index) (ebpf.EgressPolicyConfig, error) {
	egress := policyconfig.EgressPolicy{Default: source.Default, Rules: make([]policyconfig.EgressRule, 0, len(source.Rules))}
	for _, rule := range source.Rules {
		egress.Rules = append(egress.Rules, policyconfig.EgressRule{
			ID: rule.ID, Action: rule.Action, Selectors: rule.Selectors, Destinations: rule.Endpoints,
		})
	}
	return compileEgressPolicy(cfg, egress, cgroups)
}

func compileSockoptPolicy(cfg config.Config, source policyconfig.SockoptPolicy, cgroups cgroupinfo.Index) (ebpf.SockoptPolicyConfig, error) {
	blockRules := 0
	for _, rule := range source.Rules {
		if rule.Action == "block" {
			blockRules++
		}
	}
	enabled := enforcementSectionEnabled(cfg, source.Default, blockRules, true)
	compiled := ebpf.SockoptPolicyConfig{
		Enabled: enabled, Enforce: enabled && cfg.Block && !cfg.DryRun, DefaultBlock: source.Default == "block",
		Rules: make([]ebpf.SockoptRuleConfig, 0, len(source.Rules)),
	}
	for _, rule := range source.Rules {
		// Validation guarantees each name's own level is listed, so compile one
		// (level, name) pair per name instead of crossing levels with names.
		options := make([]ebpf.SockoptOption, 0, len(rule.Match.OptNames))
		for _, optname := range rule.Match.OptNames {
			level, ok := policyconfig.SockoptOptionLevel(optname)
			if !ok {
				return ebpf.SockoptPolicyConfig{}, fmt.Errorf("sockopt rule %q: unsupported socket option name %q", rule.ID, optname)
			}
			options = append(options, ebpf.SockoptOption{Level: sockoptLevel(level), OptName: sockoptName(optname)})
		}
		exactCgroups, ancestorCgroups, err := cgroups.Resolve(rule.Selectors.CgroupPaths, rule.Selectors.CgroupPrefixes)
		if err != nil {
			return ebpf.SockoptPolicyConfig{}, fmt.Errorf("sockopt rule %q: %w", rule.ID, err)
		}
		compiled.Rules = append(compiled.Rules, ebpf.SockoptRuleConfig{
			ID: rule.ID, Action: rule.Action, UIDs: slices.Clone(rule.Selectors.UIDs),
			CgroupIDs:         exactCgroups,
			CgroupAncestorIDs: ancestorCgroups,
			HasUIDSelector:    len(rule.Selectors.UIDs) > 0,
			HasCgroupSelector: len(rule.Selectors.CgroupPaths) > 0 || len(rule.Selectors.CgroupPrefixes) > 0,
			Options:           options,
		})
	}
	return compiled, nil
}

func enforcementSectionEnabled(cfg config.Config, defaultAction string, blockRules int, allowDefaultBlock bool) bool {
	if cfg.EmergencyAllow || (!cfg.Block && !cfg.DryRun) {
		return false
	}
	return blockRules > 0 || (allowDefaultBlock && defaultAction == "block")
}

func pathBlockCount(rules []policyconfig.PathRule) int {
	count := 0
	for _, rule := range rules {
		if rule.Action == "block" {
			count++
		}
	}
	return count
}

func sockoptLevel(name string) uint32 {
	switch strings.TrimSpace(strings.ToLower(name)) {
	case "socket", "sol_socket":
		return 1
	case "ip", "sol_ip":
		return 0
	case "ipv6", "sol_ipv6":
		return 41
	default:
		return 0
	}
}

func sockoptName(name string) uint32 {
	switch strings.TrimSpace(strings.ToLower(name)) {
	case "so_mark":
		return 36
	case "so_reuseport":
		return 15
	case "ip_transparent":
		return 19
	case "ipv6_transparent":
		return 75
	default:
		return 0
	}
}

func addEnforcementRuleCounts(counts map[string]int, bundle policyconfig.Bundle) {
	add := func(kind string, actions []string) {
		for _, action := range actions {
			counts[action+"|"+kind]++
		}
	}
	for _, rule := range bundle.Exec.Rules {
		add("exec", []string{rule.Action})
	}
	for _, rule := range bundle.File.Rules {
		add("file", []string{rule.Action})
	}
	for _, rule := range bundle.Bind.Rules {
		add("bind", []string{rule.Action})
	}
	for _, rule := range bundle.Unix.Rules {
		add("unix", []string{rule.Action})
	}
	for _, rule := range bundle.Sockopt.Rules {
		add("sockopt", []string{rule.Action})
	}
}

func (p *policyController) updateHookHealth(execPolicy, filePolicy ebpf.PathPolicyConfig, bindPolicy ebpf.EgressPolicyConfig, unixPolicy ebpf.PathPolicyConfig, sockoptPolicy ebpf.SockoptPolicyConfig) {
	state := p.monitor.AttachState()
	hostScope := filepath.Clean(p.cfg.CgroupPath) == hostCgroupRoot
	p.metrics.SetHookHealthy("lsm-exec", !execPolicy.Enabled || (hostScope && state.LSMExecAttached))
	p.metrics.SetHookHealthy("lsm-file", !filePolicy.Enabled || (hostScope && state.LSMFileAttached))
	require4, require6 := bindPolicy.DefaultBlock, bindPolicy.DefaultBlock
	for _, rule := range bindPolicy.Rules {
		if len(rule.CIDRs) == 0 {
			require4, require6 = true, true
		}
		for _, prefix := range rule.CIDRs {
			// IPv4-mapped and dual-stack wildcard binds reach IPv4 policy
			// through bind6, so IPv4 rules need both hooks.
			require4 = require4 || prefix.Addr().Unmap().Is4()
			require6 = true
		}
	}
	p.metrics.SetHookHealthy("bind", !bindPolicy.Enabled || ((!require4 || state.Bind4Attached) && (!require6 || state.Bind6Attached)))
	// recvmsg decisions are audit-only, so only connect and sendmsg gate health.
	requireConnect, requireSendmsg := unixPolicy.DefaultBlock, unixPolicy.DefaultBlock
	for _, rule := range unixPolicy.Rules {
		if len(rule.AccessOrOps) == 0 {
			requireConnect, requireSendmsg = true, true
		}
		for _, op := range rule.AccessOrOps {
			requireConnect = requireConnect || op == 1
			requireSendmsg = requireSendmsg || op == 2
		}
	}
	p.metrics.SetHookHealthy("unix", !unixPolicy.Enabled || ((!requireConnect || state.UnixConnectAttached) && (!requireSendmsg || state.UnixSendmsgAttached)))
	p.metrics.SetHookHealthy("sockopt", !sockoptPolicy.Enabled || state.SockoptAttached)
}
