package policy

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
)

const (
	Version                  = 1
	MaxDocumentBytes   int64 = 4 << 20
	MaxEgressRules           = 1024
	MaxDetectionRules        = 256
	MaxDetectionGroups       = 16384
	MaxThresholdWindow       = time.Hour
	MaxThresholdCount        = 10000
	MaxRuleListValues        = 256
)

var ruleIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalText(text []byte) error {
	value, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	d.Duration = value
	return nil
}

type Document struct {
	Version         int             `yaml:"version"`
	BuiltinProfiles []string        `yaml:"builtin_profiles,omitempty"`
	DisabledRuleIDs []string        `yaml:"disabled_rule_ids,omitempty"`
	DNS             DNSPolicy       `yaml:"dns,omitempty"`
	Egress          EgressPolicy    `yaml:"egress,omitempty"`
	DetectionRules  []DetectionRule `yaml:"detections,omitempty"`
}

type DNSPolicy struct {
	Block []string `yaml:"block,omitempty"`
	Allow []string `yaml:"allow,omitempty"`
}

type EgressPolicy struct {
	Default string       `yaml:"default,omitempty"`
	Rules   []EgressRule `yaml:"rules,omitempty"`
}

type EgressRule struct {
	ID           string             `yaml:"id"`
	Action       string             `yaml:"action"`
	Selectors    EgressSelectors    `yaml:"selectors,omitempty"`
	Destinations EgressDestinations `yaml:"destinations,omitempty"`
}

type EgressSelectors struct {
	UIDs           []uint32 `yaml:"uids,omitempty"`
	CgroupPaths    []string `yaml:"cgroup_paths,omitempty"`
	CgroupPrefixes []string `yaml:"cgroup_prefixes,omitempty"`
}

type EgressDestinations struct {
	CIDRs     []string `yaml:"cidrs,omitempty"`
	Ports     []uint16 `yaml:"ports,omitempty"`
	Protocols []string `yaml:"protocols,omitempty"`
}

type DetectionRule struct {
	ID        string         `yaml:"id"`
	Enabled   *bool          `yaml:"enabled,omitempty"`
	Severity  string         `yaml:"severity"`
	Events    []string       `yaml:"events"`
	Match     DetectionMatch `yaml:"match,omitempty"`
	Exclude   DetectionMatch `yaml:"exclude,omitempty"`
	Threshold Threshold      `yaml:"threshold,omitempty"`
	Cooldown  Duration       `yaml:"cooldown,omitempty"`
	Message   string         `yaml:"message"`
	Tags      []string       `yaml:"tags,omitempty"`
}

type DetectionMatch struct {
	Actions             []string `yaml:"actions,omitempty"`
	Directions          []string `yaml:"directions,omitempty"`
	Transports          []string `yaml:"transports,omitempty"`
	Protocols           []string `yaml:"protocols,omitempty"`
	UIDs                []uint32 `yaml:"uids,omitempty"`
	Domains             []string `yaml:"domains,omitempty"`
	DomainSuffixes      []string `yaml:"domain_suffixes,omitempty"`
	DestinationCIDRs    []string `yaml:"destination_cidrs,omitempty"`
	Ports               []uint16 `yaml:"ports,omitempty"`
	ExecutableGlobs     []string `yaml:"executable_globs,omitempty"`
	CommandGlobs        []string `yaml:"command_globs,omitempty"`
	FilePathGlobs       []string `yaml:"file_path_globs,omitempty"`
	FileAccess          []string `yaml:"file_access,omitempty"`
	CgroupPrefixes      []string `yaml:"cgroup_prefixes,omitempty"`
	Services            []string `yaml:"services,omitempty"`
	ContainerIDs        []string `yaml:"container_ids,omitempty"`
	PodUIDs             []string `yaml:"pod_uids,omitempty"`
	KubernetesNamespace []string `yaml:"k8s_namespaces,omitempty"`
	KubernetesPods      []string `yaml:"k8s_pods,omitempty"`
	KubernetesAccounts  []string `yaml:"k8s_service_accounts,omitempty"`
	KubernetesOwners    []string `yaml:"k8s_owners,omitempty"`
	KubernetesApps      []string `yaml:"k8s_apps,omitempty"`
	LSMSources          []string `yaml:"lsm_sources,omitempty"`
	LSMLabels           []string `yaml:"lsm_labels,omitempty"`
}

type Threshold struct {
	Count   int      `yaml:"count,omitempty"`
	Within  Duration `yaml:"within,omitempty"`
	GroupBy []string `yaml:"group_by,omitempty"`
}

type Bundle struct {
	DNS             blocklist.Rules
	Egress          EgressPolicy
	DetectionRules  []DetectionRule
	BuiltinProfiles []string
	DisabledRuleIDs []string
}

func (d Document) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("unsupported policy version %d, want %d", d.Version, Version)
	}
	for _, profile := range d.BuiltinProfiles {
		if profile != "baseline" {
			return fmt.Errorf("unsupported builtin profile %q", profile)
		}
	}
	if err := validateIDs(d.DisabledRuleIDs, "disabled rule"); err != nil {
		return err
	}
	if len(d.Egress.Rules) > MaxEgressRules {
		return fmt.Errorf("egress rule count %d exceeds %d", len(d.Egress.Rules), MaxEgressRules)
	}
	if len(d.DetectionRules) > MaxDetectionRules {
		return fmt.Errorf("detection rule count %d exceeds %d", len(d.DetectionRules), MaxDetectionRules)
	}
	if d.Egress.Default == "" {
		d.Egress.Default = "allow"
	}
	if d.Egress.Default != "allow" && d.Egress.Default != "block" {
		return fmt.Errorf("egress default must be allow or block")
	}

	ids := make(map[string]string, len(d.Egress.Rules)+len(d.DetectionRules))
	for index := range d.Egress.Rules {
		rule := &d.Egress.Rules[index]
		if err := validateRuleID(rule.ID); err != nil {
			return fmt.Errorf("egress rule %d: %w", index, err)
		}
		if previous, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate rule id %q in %s and egress", rule.ID, previous)
		}
		ids[rule.ID] = "egress"
		if err := rule.validate(); err != nil {
			return fmt.Errorf("egress rule %q: %w", rule.ID, err)
		}
	}
	for index := range d.DetectionRules {
		rule := &d.DetectionRules[index]
		if err := validateRuleID(rule.ID); err != nil {
			return fmt.Errorf("detection rule %d: %w", index, err)
		}
		if previous, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate rule id %q in %s and detections", rule.ID, previous)
		}
		ids[rule.ID] = "detections"
		if err := rule.validate(); err != nil {
			return fmt.Errorf("detection rule %q: %w", rule.ID, err)
		}
	}
	if _, err := parseDNS(d.DNS); err != nil {
		return err
	}
	return nil
}

func (r EgressRule) validate() error {
	if r.Action != "allow" && r.Action != "block" {
		return fmt.Errorf("action must be allow or block")
	}
	for name, count := range map[string]int{
		"uids":              len(r.Selectors.UIDs),
		"cgroup paths":      len(r.Selectors.CgroupPaths),
		"cgroup prefixes":   len(r.Selectors.CgroupPrefixes),
		"destination cidrs": len(r.Destinations.CIDRs),
		"ports":             len(r.Destinations.Ports),
		"protocols":         len(r.Destinations.Protocols),
	} {
		if count > MaxRuleListValues {
			return fmt.Errorf("%s count %d exceeds %d", name, count, MaxRuleListValues)
		}
	}
	for _, path := range append(slices.Clone(r.Selectors.CgroupPaths), r.Selectors.CgroupPrefixes...) {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("cgroup selector %q must be a clean absolute cgroup path", path)
		}
	}
	for _, cidr := range r.Destinations.CIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid destination cidr %q: %w", cidr, err)
		}
	}
	for _, protocol := range r.Destinations.Protocols {
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("unsupported protocol %q", protocol)
		}
	}
	return nil
}

func (r DetectionRule) validate() error {
	if r.Enabled != nil && !*r.Enabled {
		return nil
	}
	switch r.Severity {
	case "debug", "informational", "notice", "warning", "error", "critical", "alert", "emergency":
	default:
		return fmt.Errorf("unsupported severity %q", r.Severity)
	}
	if len(r.Events) == 0 {
		return fmt.Errorf("events must not be empty")
	}
	for _, event := range r.Events {
		if !slices.Contains(supportedDetectionEvents, event) {
			return fmt.Errorf("unsupported event %q", event)
		}
	}
	if strings.TrimSpace(r.Message) == "" {
		return fmt.Errorf("message must not be empty")
	}
	if len(r.Tags) > 16 {
		return fmt.Errorf("tag count %d exceeds 16", len(r.Tags))
	}
	for _, tag := range r.Tags {
		if strings.TrimSpace(tag) == "" || len(tag) > 64 {
			return fmt.Errorf("invalid tag %q", tag)
		}
	}
	if r.Cooldown.Duration < 0 {
		return fmt.Errorf("cooldown must not be negative")
	}
	if err := r.Match.validate(); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if err := r.Exclude.validate(); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	count := r.Threshold.Count
	if count == 0 {
		count = 1
	}
	if count < 1 {
		return fmt.Errorf("threshold count must be positive")
	}
	if count > MaxThresholdCount {
		return fmt.Errorf("threshold count %d exceeds %d", count, MaxThresholdCount)
	}
	if count > 1 {
		if r.Threshold.Within.Duration <= 0 || r.Threshold.Within.Duration > MaxThresholdWindow {
			return fmt.Errorf("threshold within must be between 1ns and %s", MaxThresholdWindow)
		}
		if len(r.Threshold.GroupBy) == 0 {
			return fmt.Errorf("threshold group_by is required when count exceeds 1")
		}
	}
	for _, field := range r.Threshold.GroupBy {
		if !slices.Contains(supportedGroupFields, field) {
			return fmt.Errorf("unsupported threshold group field %q", field)
		}
	}
	return nil
}

func (m DetectionMatch) validate() error {
	for name, count := range map[string]int{
		"actions":               len(m.Actions),
		"directions":            len(m.Directions),
		"transports":            len(m.Transports),
		"protocols":             len(m.Protocols),
		"uids":                  len(m.UIDs),
		"domains":               len(m.Domains),
		"domain suffixes":       len(m.DomainSuffixes),
		"destination cidrs":     len(m.DestinationCIDRs),
		"ports":                 len(m.Ports),
		"executable globs":      len(m.ExecutableGlobs),
		"command globs":         len(m.CommandGlobs),
		"file path globs":       len(m.FilePathGlobs),
		"file access":           len(m.FileAccess),
		"cgroup prefixes":       len(m.CgroupPrefixes),
		"services":              len(m.Services),
		"container ids":         len(m.ContainerIDs),
		"pod uids":              len(m.PodUIDs),
		"kubernetes namespaces": len(m.KubernetesNamespace),
		"kubernetes pods":       len(m.KubernetesPods),
		"kubernetes accounts":   len(m.KubernetesAccounts),
		"kubernetes owners":     len(m.KubernetesOwners),
		"kubernetes apps":       len(m.KubernetesApps),
		"lsm sources":           len(m.LSMSources),
		"lsm labels":            len(m.LSMLabels),
	} {
		if count > MaxRuleListValues {
			return fmt.Errorf("%s count %d exceeds %d", name, count, MaxRuleListValues)
		}
	}
	for _, cidr := range m.DestinationCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("invalid destination cidr %q: %w", cidr, err)
		}
	}
	for _, pattern := range append(append(slices.Clone(m.ExecutableGlobs), m.CommandGlobs...), m.FilePathGlobs...) {
		if _, err := filepath.Match(pattern, "probe"); err != nil {
			return fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
	}
	for _, protocol := range m.Protocols {
		if protocol != "tcp" && protocol != "udp" {
			return fmt.Errorf("unsupported protocol %q", protocol)
		}
	}
	for _, direction := range m.Directions {
		if direction != "inbound" && direction != "outbound" {
			return fmt.Errorf("unsupported direction %q", direction)
		}
	}
	for _, access := range m.FileAccess {
		if access != "read" && access != "write" && access != "unknown" {
			return fmt.Errorf("unsupported file access %q", access)
		}
	}
	return nil
}

func validateRuleID(id string) error {
	if !ruleIDPattern.MatchString(id) {
		return fmt.Errorf("invalid rule id %q", id)
	}
	return nil
}

func validateIDs(ids []string, kind string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if err := validateRuleID(id); err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
		if _, exists := seen[id]; exists {
			return fmt.Errorf("duplicate %s id %q", kind, id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

var supportedDetectionEvents = []string{
	"dns", "blocked", "exec", "resolver", "resolver_blocked",
	"connection", "file_access", "file_created", "egress_blocked", "egress_would_block",
}

var supportedGroupFields = []string{
	"cgroup", "executable", "program", "uid", "domain", "destination", "path",
	"service", "container", "pod", "k8s_namespace",
}
