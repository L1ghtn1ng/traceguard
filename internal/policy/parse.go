package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strings"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"go.yaml.in/yaml/v3"
)

func Parse(payload []byte) (Document, error) {
	if int64(len(payload)) > MaxDocumentBytes {
		return Document{}, fmt.Errorf("policy document exceeds %d bytes", MaxDocumentBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("decode policy yaml: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return Document{}, errors.New("policy must contain exactly one YAML document")
		}
		return Document{}, fmt.Errorf("decode trailing policy yaml: %w", err)
	}
	if err := document.Validate(); err != nil {
		return Document{}, err
	}
	for index := range document.DetectionRules {
		if document.DetectionRules[index].Enabled == nil {
			enabled := true
			document.DetectionRules[index].Enabled = &enabled
		}
		if document.DetectionRules[index].Threshold.Count == 0 {
			document.DetectionRules[index].Threshold.Count = 1
		}
	}
	return document, nil
}

func Merge(base, overlay Document) (Bundle, error) {
	if base.Version == 0 {
		base.Version = Version
	}
	if overlay.Version == 0 {
		overlay.Version = Version
	}
	if err := base.Validate(); err != nil {
		return Bundle{}, fmt.Errorf("validate base policy: %w", err)
	}
	if err := overlay.Validate(); err != nil {
		return Bundle{}, fmt.Errorf("validate local overlay: %w", err)
	}

	disabled := make(map[string]struct{}, len(base.DisabledRuleIDs)+len(overlay.DisabledRuleIDs))
	for _, id := range append(slices.Clone(base.DisabledRuleIDs), overlay.DisabledRuleIDs...) {
		disabled[id] = struct{}{}
	}
	overlayIDs := make(map[string]struct{}, len(overlay.Egress.Rules)+len(overlay.Exec.Rules)+len(overlay.File.Rules)+len(overlay.Bind.Rules)+len(overlay.Unix.Rules)+len(overlay.Sockopt.Rules)+len(overlay.DetectionRules))
	for _, rule := range overlay.Egress.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.Exec.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.File.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.Bind.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.Unix.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.Sockopt.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.DetectionRules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, sequence := range overlay.DetectionSequences {
		overlayIDs[sequence.ID] = struct{}{}
	}
	mergeDetectionByID := func(baseRules, overlayRules []DetectionRule) []DetectionRule {
		merged := make(map[string]DetectionRule, len(baseRules)+len(overlayRules))
		for _, rule := range baseRules {
			if _, replaced := overlayIDs[rule.ID]; replaced {
				continue
			}
			merged[rule.ID] = rule
		}
		for _, rule := range overlayRules {
			merged[rule.ID] = rule
		}
		out := make([]DetectionRule, 0, len(merged))
		for id, rule := range merged {
			if _, skip := disabled[id]; skip || (rule.Enabled != nil && !*rule.Enabled) {
				continue
			}
			out = append(out, rule)
		}
		slices.SortFunc(out, func(left, right DetectionRule) int { return strings.Compare(left.ID, right.ID) })
		return out
	}

	dns, err := parseDNS(DNSPolicy{
		Block: append(slices.Clone(base.DNS.Block), overlay.DNS.Block...),
		Allow: append(slices.Clone(base.DNS.Allow), overlay.DNS.Allow...),
	})
	if err != nil {
		return Bundle{}, err
	}
	defaultAction := mergeDefault(base.Egress.Default, overlay.Egress.Default)
	profiles := append(slices.Clone(base.BuiltinProfiles), overlay.BuiltinProfiles...)
	slices.Sort(profiles)
	profiles = slices.Compact(profiles)
	disabledIDs := make([]string, 0, len(disabled))
	for id := range disabled {
		disabledIDs = append(disabledIDs, id)
	}
	slices.Sort(disabledIDs)

	bundle := Bundle{
		DNS: dns,
		Egress: EgressPolicy{
			Default: defaultAction,
			Rules:   mergeRulesByID(base.Egress.Rules, overlay.Egress.Rules, overlayIDs, disabled, func(rule EgressRule) string { return rule.ID }),
		},
		Exec: PathPolicy{
			Default: mergeDefault(base.Exec.Default, overlay.Exec.Default),
			Rules:   mergeRulesByID(base.Exec.Rules, overlay.Exec.Rules, overlayIDs, disabled, func(rule PathRule) string { return rule.ID }),
		},
		File: FilePolicy{
			Default: mergeDefault(base.File.Default, overlay.File.Default),
			Rules:   mergeRulesByID(base.File.Rules, overlay.File.Rules, overlayIDs, disabled, func(rule FileRule) string { return rule.ID }),
		},
		Bind: BindPolicy{
			Default: mergeDefault(base.Bind.Default, overlay.Bind.Default),
			Rules:   mergeRulesByID(base.Bind.Rules, overlay.Bind.Rules, overlayIDs, disabled, func(rule BindRule) string { return rule.ID }),
		},
		Unix: UnixPolicy{
			Default: mergeDefault(base.Unix.Default, overlay.Unix.Default),
			Rules:   mergeRulesByID(base.Unix.Rules, overlay.Unix.Rules, overlayIDs, disabled, func(rule UnixRule) string { return rule.ID }),
		},
		Sockopt: SockoptPolicy{
			Default: mergeDefault(base.Sockopt.Default, overlay.Sockopt.Default),
			Rules:   mergeRulesByID(base.Sockopt.Rules, overlay.Sockopt.Rules, overlayIDs, disabled, func(rule SockoptRule) string { return rule.ID }),
		},
		DetectionRules:      mergeDetectionByID(base.DetectionRules, overlay.DetectionRules),
		DetectionExceptions: mergeExceptionsByID(base.DetectionExceptions, overlay.DetectionExceptions),
		DetectionSequences:  mergeSequencesByID(base.DetectionSequences, overlay.DetectionSequences, overlayIDs, disabled),
		FileIntegrity:       mergeFileIntegrity(base.FileIntegrity, overlay.FileIntegrity),
		ThreatIntel:         mergeThreatIntel(base.ThreatIntel, overlay.ThreatIntel),
		Responses:           mergeResponsesByID(base.Responses, overlay.Responses),
		BuiltinProfiles:     profiles,
		DisabledRuleIDs:     disabledIDs,
	}
	if err := bundle.Validate(); err != nil {
		return Bundle{}, fmt.Errorf("validate merged policy: %w", err)
	}
	return bundle, nil
}

// Validate enforces the source limits on the final effective policy before any
// DNS lookup, cgroup scan, or eBPF compilation is attempted.
func (b Bundle) Validate() error {
	document := Document{
		Version: Version, BuiltinProfiles: slices.Clone(b.BuiltinProfiles),
		DisabledRuleIDs: slices.Clone(b.DisabledRuleIDs), Egress: b.Egress,
		Exec: b.Exec, File: b.File, Bind: b.Bind, Unix: b.Unix,
		Sockopt: b.Sockopt, DetectionRules: slices.Clone(b.DetectionRules),
		DetectionExceptions: slices.Clone(b.DetectionExceptions),
		DetectionSequences:  slices.Clone(b.DetectionSequences),
		FileIntegrity:       b.FileIntegrity,
		ThreatIntel:         b.ThreatIntel,
		Responses:           slices.Clone(b.Responses),
	}
	if err := document.Validate(); err != nil {
		return err
	}
	dnsCount := len(b.DNS.BlockDomains) + len(b.DNS.AllowDomains) +
		len(b.DNS.BlockSuffixes) + len(b.DNS.AllowSuffixes) +
		len(b.DNS.BlockEndpoints) + len(b.DNS.AllowEndpoints) +
		len(b.DNS.BlockEndpointCIDRs) + len(b.DNS.AllowEndpointCIDRs)
	if dnsCount > MaxDNSRules {
		return fmt.Errorf("merged dns rule count %d exceeds %d", dnsCount, MaxDNSRules)
	}
	hostnames := 0
	for _, endpoint := range append(slices.Clone(b.DNS.BlockEndpoints), b.DNS.AllowEndpoints...) {
		if net.ParseIP(endpoint.Host) == nil {
			hostnames++
		}
	}
	if hostnames > MaxResolverHostnames {
		return fmt.Errorf("resolver hostname count %d exceeds %d", hostnames, MaxResolverHostnames)
	}
	selectorCount := 0
	addSelectors := func(selectors EgressSelectors) {
		selectorCount += len(selectors.CgroupPaths) + len(selectors.CgroupPrefixes)
	}
	for _, rule := range b.Egress.Rules {
		addSelectors(rule.Selectors)
	}
	for _, rule := range b.Exec.Rules {
		addSelectors(rule.Selectors)
	}
	for _, rule := range b.File.Rules {
		addSelectors(rule.Selectors)
	}
	for _, rule := range b.Bind.Rules {
		addSelectors(rule.Selectors)
	}
	for _, rule := range b.Unix.Rules {
		addSelectors(rule.Selectors)
	}
	for _, rule := range b.Sockopt.Rules {
		addSelectors(rule.Selectors)
	}
	if selectorCount > MaxPolicySelectors {
		return fmt.Errorf("merged cgroup selector count %d exceeds %d", selectorCount, MaxPolicySelectors)
	}
	thresholdSamples := 0
	for _, rule := range b.DetectionRules {
		count := rule.Threshold.Count
		if count == 0 {
			count = 1
		}
		thresholdSamples += count
		if thresholdSamples > MaxDetectionSamples {
			return fmt.Errorf("detection threshold sample budget %d exceeds %d", thresholdSamples, MaxDetectionSamples)
		}
	}
	return nil
}

func mergeDefault(base, overlay string) string {
	if overlay != "" {
		return overlay
	}
	if base != "" {
		return base
	}
	return "allow"
}

func mergeRulesByID[T any](base, overlay []T, overlayIDs, disabled map[string]struct{}, id func(T) string) []T {
	merged := make(map[string]T, len(base)+len(overlay))
	for _, rule := range base {
		ruleID := id(rule)
		if _, replaced := overlayIDs[ruleID]; !replaced {
			merged[ruleID] = rule
		}
	}
	for _, rule := range overlay {
		merged[id(rule)] = rule
	}
	out := make([]T, 0, len(merged))
	for ruleID, rule := range merged {
		if _, skip := disabled[ruleID]; !skip {
			out = append(out, rule)
		}
	}
	slices.SortFunc(out, func(left, right T) int { return strings.Compare(id(left), id(right)) })
	return out
}

func parseDNS(policy DNSPolicy) (blocklist.Rules, error) {
	rules, err := blocklist.ParsePolicyRules(policy.Block, policy.Allow)
	if err != nil {
		return blocklist.Rules{}, fmt.Errorf("parse dns policy: %w", err)
	}
	return rules, nil
}

// mergeExceptionsByID lets an overlay exception replace a base exception with
// the same ID.
func mergeExceptionsByID(base, overlay []DetectionException) []DetectionException {
	merged := make(map[string]DetectionException, len(base)+len(overlay))
	for _, exception := range base {
		merged[exception.ID] = exception
	}
	for _, exception := range overlay {
		merged[exception.ID] = exception
	}
	out := make([]DetectionException, 0, len(merged))
	for _, exception := range merged {
		out = append(out, exception)
	}
	slices.SortFunc(out, func(left, right DetectionException) int { return strings.Compare(left.ID, right.ID) })
	return out
}

// mergeFileIntegrity watches the union of both sources' paths and exclusions;
// settings the overlay sets replace the base's.
func mergeFileIntegrity(base, overlay FileIntegrityPolicy) FileIntegrityPolicy {
	union := func(left, right []string) []string {
		merged := append(slices.Clone(left), right...)
		slices.Sort(merged)
		return slices.Compact(merged)
	}
	merged := FileIntegrityPolicy{
		Paths: union(base.Paths, overlay.Paths), Exclude: union(base.Exclude, overlay.Exclude),
		Hash: base.Hash, MaxHashBytes: base.MaxHashBytes, RescanInterval: base.RescanInterval,
	}
	if overlay.Hash != nil {
		merged.Hash = overlay.Hash
	}
	if overlay.MaxHashBytes != nil {
		merged.MaxHashBytes = overlay.MaxHashBytes
	}
	if overlay.RescanInterval != nil {
		merged.RescanInterval = overlay.RescanInterval
	}
	return merged
}
