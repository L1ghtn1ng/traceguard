package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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
	overlayIDs := make(map[string]struct{}, len(overlay.Egress.Rules)+len(overlay.DetectionRules))
	for _, rule := range overlay.Egress.Rules {
		overlayIDs[rule.ID] = struct{}{}
	}
	for _, rule := range overlay.DetectionRules {
		overlayIDs[rule.ID] = struct{}{}
	}
	mergeByID := func(baseRules, overlayRules []EgressRule) []EgressRule {
		merged := make(map[string]EgressRule, len(baseRules)+len(overlayRules))
		for _, rule := range baseRules {
			if _, replaced := overlayIDs[rule.ID]; replaced {
				continue
			}
			merged[rule.ID] = rule
		}
		for _, rule := range overlayRules {
			merged[rule.ID] = rule
		}
		out := make([]EgressRule, 0, len(merged))
		for id, rule := range merged {
			if _, skip := disabled[id]; !skip {
				out = append(out, rule)
			}
		}
		slices.SortFunc(out, func(left, right EgressRule) int { return strings.Compare(left.ID, right.ID) })
		return out
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
	defaultAction := base.Egress.Default
	if defaultAction == "" {
		defaultAction = "allow"
	}
	if overlay.Egress.Default != "" {
		defaultAction = overlay.Egress.Default
	}
	profiles := append(slices.Clone(base.BuiltinProfiles), overlay.BuiltinProfiles...)
	slices.Sort(profiles)
	profiles = slices.Compact(profiles)
	disabledIDs := make([]string, 0, len(disabled))
	for id := range disabled {
		disabledIDs = append(disabledIDs, id)
	}
	slices.Sort(disabledIDs)

	return Bundle{
		DNS: dns,
		Egress: EgressPolicy{
			Default: defaultAction,
			Rules:   mergeByID(base.Egress.Rules, overlay.Egress.Rules),
		},
		DetectionRules:  mergeDetectionByID(base.DetectionRules, overlay.DetectionRules),
		BuiltinProfiles: profiles,
		DisabledRuleIDs: disabledIDs,
	}, nil
}

func parseDNS(policy DNSPolicy) (blocklist.Rules, error) {
	rules, err := blocklist.ParsePolicyRules(policy.Block, policy.Allow)
	if err != nil {
		return blocklist.Rules{}, fmt.Errorf("parse dns policy: %w", err)
	}
	return rules, nil
}
