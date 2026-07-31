package detection

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

type Event struct {
	Timestamp time.Time
	Name      string
	Fields    map[string]any
}

type Alert struct {
	RuleID    string
	Severity  string
	Message   string
	Tags      []string
	Count     int
	Window    time.Duration
	Timestamp time.Time
	Fields    map[string]any
}

type Engine struct {
	mu        sync.Mutex
	rules     []compiledRule
	groups    map[string]*groupState
	groupKeys []string
	groupNext int
	maxGroups int
}

type compiledRule struct {
	rule         policy.DetectionRule
	matchCIDRs   []netip.Prefix
	excludeCIDRs []netip.Prefix
}

type groupState struct {
	timestamps []time.Time
	lastAlert  time.Time
}

func New(custom []policy.DetectionRule, disabled []string) (*Engine, error) {
	rules, err := compileRules(effectiveRules(custom, disabled))
	if err != nil {
		return nil, err
	}
	return &Engine{
		rules:     rules,
		groups:    make(map[string]*groupState),
		maxGroups: policy.MaxDetectionGroups,
	}, nil
}

func (e *Engine) Replace(custom []policy.DetectionRule, disabled []string) error {
	rules, err := compileRules(effectiveRules(custom, disabled))
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = rules
	e.groups = make(map[string]*groupState)
	e.groupKeys = nil
	e.groupNext = 0
	return nil
}

func (e *Engine) Evaluate(event Event) []Alert {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	} else {
		event.Timestamp = event.Timestamp.UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	alerts := make([]Alert, 0, 1)
	for index := range e.rules {
		rule := &e.rules[index]
		if !slices.Contains(rule.rule.Events, event.Name) ||
			!matches(rule.rule.Match, rule.matchCIDRs, event.Fields) ||
			(!emptyMatch(rule.rule.Exclude) && matches(rule.rule.Exclude, rule.excludeCIDRs, event.Fields)) {
			continue
		}

		count := rule.rule.Threshold.Count
		if count == 0 {
			count = 1
		}
		key := groupKey(rule.rule.ID, rule.rule.Threshold.GroupBy, event.Fields)
		state := e.groups[key]
		if state == nil {
			e.makeRoom(key)
			state = &groupState{}
			e.groups[key] = state
		}

		window := rule.rule.Threshold.Within.Duration
		if count > 1 {
			cutoff := event.Timestamp.Add(-window)
			first := 0
			for first < len(state.timestamps) && state.timestamps[first].Before(cutoff) {
				first++
			}
			state.timestamps = append(state.timestamps[first:], event.Timestamp)
			if len(state.timestamps) > count {
				state.timestamps = state.timestamps[len(state.timestamps)-count:]
			}
			if len(state.timestamps) < count {
				continue
			}
		}
		if cooldown := rule.rule.Cooldown.Duration; cooldown > 0 &&
			!state.lastAlert.IsZero() && event.Timestamp.Sub(state.lastAlert) < cooldown {
			continue
		}
		state.lastAlert = event.Timestamp
		alerts = append(alerts, Alert{
			RuleID:    rule.rule.ID,
			Severity:  rule.rule.Severity,
			Message:   rule.rule.Message,
			Tags:      slices.Clone(rule.rule.Tags),
			Count:     count,
			Window:    window,
			Timestamp: event.Timestamp,
			Fields:    cloneFields(event.Fields),
		})
	}
	return alerts
}

func (e *Engine) RuleCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.rules)
}

func (e *Engine) StateCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.groups)
}

func (e *Engine) makeRoom(key string) {
	if len(e.groups) < e.maxGroups {
		e.groupKeys = append(e.groupKeys, key)
		return
	}
	if e.maxGroups <= 0 || len(e.groupKeys) == 0 {
		return
	}
	if e.groupNext >= len(e.groupKeys) {
		e.groupNext = 0
	}
	delete(e.groups, e.groupKeys[e.groupNext])
	e.groupKeys[e.groupNext] = key
	e.groupNext = (e.groupNext + 1) % len(e.groupKeys)
}

func compileRules(rules []policy.DetectionRule) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))
	for _, rule := range rules {
		matchCIDRs, err := parseCIDRs(rule.Match.DestinationCIDRs)
		if err != nil {
			return nil, fmt.Errorf("compile detection rule %q match: %w", rule.ID, err)
		}
		excludeCIDRs, err := parseCIDRs(rule.Exclude.DestinationCIDRs)
		if err != nil {
			return nil, fmt.Errorf("compile detection rule %q exclude: %w", rule.ID, err)
		}
		compiled = append(compiled, compiledRule{
			rule:         rule,
			matchCIDRs:   matchCIDRs,
			excludeCIDRs: excludeCIDRs,
		})
	}
	return compiled, nil
}

func parseCIDRs(values []string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	return prefixes, nil
}

func matches(match policy.DetectionMatch, cidrs []netip.Prefix, fields map[string]any) bool {
	return matchStrings(match.Actions, stringField(fields, "action", "policy")) &&
		matchStrings(match.Directions, stringField(fields, "direction")) &&
		matchStrings(match.Transports, stringField(fields, "transport")) &&
		matchStrings(match.Protocols, stringField(fields, "socket_protocol", "transport")) &&
		matchUint32s(match.UIDs, uint32Field(fields, "kernel_uid", "uid")) &&
		matchDomains(match.Domains, stringField(fields, "domain")) &&
		matchSuffixes(match.DomainSuffixes, stringField(fields, "domain")) &&
		matchAddress(cidrs, stringField(fields, "peer_address", "address")) &&
		matchUint16s(match.Ports, uint16Field(fields, "peer_port", "port")) &&
		matchGlobs(match.ExecutableGlobs, stringField(fields, "exe", "filename")) &&
		matchGlobs(match.CommandGlobs, commandField(fields)) &&
		matchGlobs(match.FilePathGlobs, stringField(fields, "path", "filename")) &&
		matchStrings(match.FileAccess, stringField(fields, "file_access")) &&
		matchPrefixes(match.CgroupPrefixes, stringField(fields, "cgroup")) &&
		matchStrings(match.Services, stringField(fields, "service")) &&
		matchStrings(match.ContainerIDs, stringField(fields, "container_id")) &&
		matchStrings(match.PodUIDs, stringField(fields, "pod_uid")) &&
		matchStrings(match.KubernetesNamespace, stringField(fields, "k8s_namespace")) &&
		matchStrings(match.KubernetesPods, stringField(fields, "k8s_pod")) &&
		matchStrings(match.KubernetesAccounts, stringField(fields, "k8s_service_account")) &&
		matchStrings(match.KubernetesOwners, stringField(fields, "k8s_owner")) &&
		matchStrings(match.KubernetesApps, stringField(fields, "k8s_app")) &&
		matchStrings(match.LSMSources, stringField(fields, "lsm_source")) &&
		matchStrings(match.LSMLabels, stringField(fields, "lsm_label"))
}

func matchStrings(values []string, candidate string) bool {
	return len(values) == 0 || slices.Contains(values, candidate)
}

func matchDomains(values []string, candidate string) bool {
	if len(values) == 0 {
		return true
	}
	candidate = normalizeDomain(candidate)
	for _, value := range values {
		if candidate == normalizeDomain(value) {
			return true
		}
	}
	return false
}

func matchSuffixes(values []string, candidate string) bool {
	if len(values) == 0 {
		return true
	}
	candidate = normalizeDomain(candidate)
	for _, value := range values {
		suffix := strings.TrimPrefix(normalizeDomain(value), "*.")
		if candidate == suffix || strings.HasSuffix(candidate, "."+suffix) {
			return true
		}
	}
	return false
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func matchAddress(prefixes []netip.Prefix, candidate string) bool {
	if len(prefixes) == 0 {
		return true
	}
	address, err := netip.ParseAddr(candidate)
	if err != nil {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func matchUint32s(values []uint32, candidate uint32) bool {
	return len(values) == 0 || slices.Contains(values, candidate)
}

func matchUint16s(values []uint16, candidate uint16) bool {
	return len(values) == 0 || slices.Contains(values, candidate)
}

func matchGlobs(patterns []string, candidate string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if strings.HasSuffix(pattern, "/**") &&
			(candidate == strings.TrimSuffix(pattern, "/**") || strings.HasPrefix(candidate, strings.TrimSuffix(pattern, "**"))) {
			return true
		}
		matchPattern := strings.ReplaceAll(pattern, "/", "\x00")
		matchCandidate := strings.ReplaceAll(candidate, "/", "\x00")
		if matched, _ := filepath.Match(matchPattern, matchCandidate); matched {
			return true
		}
	}
	return false
}

func matchPrefixes(prefixes []string, candidate string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, prefix := range prefixes {
		if candidate == prefix || strings.HasPrefix(candidate, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

func stringField(fields map[string]any, names ...string) string {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			if text, ok := value.(string); ok {
				return text
			}
		}
	}
	return ""
}

func uint32Field(fields map[string]any, names ...string) uint32 {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			switch number := value.(type) {
			case uint:
				return uint32(number)
			case uint16:
				return uint32(number)
			case uint32:
				return number
			case uint64:
				return uint32(number)
			case int:
				return uint32(number)
			case int64:
				return uint32(number)
			case float64:
				return uint32(number)
			}
		}
	}
	return 0
}

func uint16Field(fields map[string]any, names ...string) uint16 {
	return uint16(uint32Field(fields, names...))
}

func commandField(fields map[string]any) string {
	switch command := fields["cmdline"].(type) {
	case []string:
		return strings.Join(command, " ")
	case string:
		return command
	default:
		return ""
	}
}

func groupKey(ruleID string, fields []string, values map[string]any) string {
	var builder strings.Builder
	builder.WriteString(ruleID)
	for _, field := range fields {
		builder.WriteByte(0)
		builder.WriteString(field)
		builder.WriteByte('=')
		switch field {
		case "destination":
			builder.WriteString(stringField(values, "peer_address", "address"))
		case "executable":
			builder.WriteString(stringField(values, "exe", "filename"))
		case "pod":
			builder.WriteString(stringField(values, "pod_uid", "k8s_pod"))
		case "container":
			builder.WriteString(stringField(values, "container_id"))
		case "uid":
			builder.WriteString(fmt.Sprint(uint32Field(values, "kernel_uid", "uid")))
		default:
			builder.WriteString(fmt.Sprint(values[field]))
		}
	}
	return builder.String()
}

func emptyMatch(match policy.DetectionMatch) bool {
	return len(match.Actions)+len(match.Directions)+len(match.Transports)+len(match.Protocols)+
		len(match.UIDs)+len(match.Domains)+len(match.DomainSuffixes)+len(match.DestinationCIDRs)+
		len(match.Ports)+len(match.ExecutableGlobs)+len(match.CommandGlobs)+len(match.FilePathGlobs)+
		len(match.FileAccess)+len(match.CgroupPrefixes)+len(match.Services)+len(match.ContainerIDs)+
		len(match.PodUIDs)+len(match.KubernetesNamespace)+len(match.KubernetesPods)+
		len(match.KubernetesAccounts)+len(match.KubernetesOwners)+len(match.KubernetesApps)+
		len(match.LSMSources)+len(match.LSMLabels) == 0
}

func cloneFields(fields map[string]any) map[string]any {
	cloned := make(map[string]any, len(fields))
	for key, value := range fields {
		cloned[key] = value
	}
	return cloned
}
