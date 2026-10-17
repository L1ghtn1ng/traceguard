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
	"github.com/L1ghtn1ng/traceguard/internal/netprefix"
)

const (
	Version                         = 1
	MaxDocumentBytes          int64 = 4 << 20
	MaxEgressRules                  = 1024
	MaxEnforcementRules             = 1024
	MaxDetectionRules               = 256
	MaxDetectionGroups              = 16384
	MaxThresholdWindow              = time.Hour
	MaxThresholdCount               = 10000
	MaxRuleListValues               = 256
	MaxDetectionMessageBytes        = 4096
	MaxDetectionPathStemBytes       = 247
	MaxDetectionSamples             = 65536
	MaxPolicySelectors              = 4096
	MaxDNSRules                     = 4096
	MaxResolverHostnames            = 256
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
	Exec            PathPolicy      `yaml:"exec,omitempty"`
	File            FilePolicy      `yaml:"file,omitempty"`
	Bind            BindPolicy      `yaml:"bind,omitempty"`
	Unix            UnixPolicy      `yaml:"unix,omitempty"`
	Sockopt         SockoptPolicy   `yaml:"sockopt,omitempty"`
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

type PathPolicy struct {
	Default string     `yaml:"default,omitempty"`
	Rules   []PathRule `yaml:"rules,omitempty"`
}

type PathRule struct {
	ID        string          `yaml:"id"`
	Action    string          `yaml:"action"`
	Selectors EgressSelectors `yaml:"selectors,omitempty"`
	Match     PathMatch       `yaml:"match,omitempty"`
}

type PathMatch struct {
	PathGlobs []string `yaml:"path_globs,omitempty"`
}

type FilePolicy struct {
	Default string     `yaml:"default,omitempty"`
	Rules   []FileRule `yaml:"rules,omitempty"`
}

type FileRule struct {
	ID        string          `yaml:"id"`
	Action    string          `yaml:"action"`
	Selectors EgressSelectors `yaml:"selectors,omitempty"`
	Match     FileMatch       `yaml:"match,omitempty"`
}

type FileMatch struct {
	PathGlobs []string `yaml:"path_globs,omitempty"`
	Access    []string `yaml:"access,omitempty"`
}

type BindPolicy struct {
	Default string     `yaml:"default,omitempty"`
	Rules   []BindRule `yaml:"rules,omitempty"`
}

type BindRule struct {
	ID        string             `yaml:"id"`
	Action    string             `yaml:"action"`
	Selectors EgressSelectors    `yaml:"selectors,omitempty"`
	Endpoints EgressDestinations `yaml:"endpoints,omitempty"`
}

type UnixPolicy struct {
	Default string     `yaml:"default,omitempty"`
	Rules   []UnixRule `yaml:"rules,omitempty"`
}

type UnixRule struct {
	ID        string          `yaml:"id"`
	Action    string          `yaml:"action"`
	Selectors EgressSelectors `yaml:"selectors,omitempty"`
	Match     UnixMatch       `yaml:"match,omitempty"`
}

type UnixMatch struct {
	PathGlobs  []string `yaml:"path_globs,omitempty"`
	Operations []string `yaml:"operations,omitempty"`
}

type SockoptPolicy struct {
	Default string        `yaml:"default,omitempty"`
	Rules   []SockoptRule `yaml:"rules,omitempty"`
}

type SockoptRule struct {
	ID        string          `yaml:"id"`
	Action    string          `yaml:"action"`
	Selectors EgressSelectors `yaml:"selectors,omitempty"`
	Match     SockoptMatch    `yaml:"match,omitempty"`
}

type SockoptMatch struct {
	Levels   []string `yaml:"levels,omitempty"`
	OptNames []string `yaml:"optnames,omitempty"`
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
	Exec            PathPolicy
	File            FilePolicy
	Bind            BindPolicy
	Unix            UnixPolicy
	Sockopt         SockoptPolicy
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
	for name, count := range map[string]int{
		"exec": len(d.Exec.Rules), "file": len(d.File.Rules), "bind": len(d.Bind.Rules),
		"unix": len(d.Unix.Rules), "sockopt": len(d.Sockopt.Rules),
	} {
		if count > MaxEnforcementRules {
			return fmt.Errorf("%s rule count %d exceeds %d", name, count, MaxEnforcementRules)
		}
	}
	if len(d.DetectionRules) > MaxDetectionRules {
		return fmt.Errorf("detection rule count %d exceeds %d", len(d.DetectionRules), MaxDetectionRules)
	}
	if count := len(d.DNS.Block) + len(d.DNS.Allow); count > MaxDNSRules {
		return fmt.Errorf("dns rule count %d exceeds %d", count, MaxDNSRules)
	}
	if d.Egress.Default == "" {
		d.Egress.Default = "allow"
	}
	if d.Egress.Default != "allow" && d.Egress.Default != "block" {
		return fmt.Errorf("egress default must be allow or block")
	}
	for name, value := range map[string]string{"exec": d.Exec.Default, "file": d.File.Default} {
		if value != "" && value != "allow" {
			return fmt.Errorf("%s default must be allow", name)
		}
	}
	for name, value := range map[string]string{"bind": d.Bind.Default, "unix": d.Unix.Default, "sockopt": d.Sockopt.Default} {
		if value != "" && value != "allow" && value != "block" {
			return fmt.Errorf("%s default must be allow or block", name)
		}
	}

	ids := make(map[string]string, len(d.Egress.Rules)+len(d.Exec.Rules)+len(d.File.Rules)+len(d.Bind.Rules)+len(d.Unix.Rules)+len(d.Sockopt.Rules)+len(d.DetectionRules))
	validateID := func(id, area string, index int) error {
		if err := validateRuleID(id); err != nil {
			return fmt.Errorf("%s rule %d: %w", area, index, err)
		}
		if previous, exists := ids[id]; exists {
			return fmt.Errorf("duplicate rule id %q in %s and %s", id, previous, area)
		}
		ids[id] = area
		return nil
	}
	for index := range d.Egress.Rules {
		rule := &d.Egress.Rules[index]
		if err := validateID(rule.ID, "egress", index); err != nil {
			return err
		}
		if err := rule.validate(); err != nil {
			return fmt.Errorf("egress rule %q: %w", rule.ID, err)
		}
	}
	for index, rule := range d.Exec.Rules {
		if err := validateID(rule.ID, "exec", index); err != nil {
			return err
		}
		if err := rule.validate(false); err != nil {
			return fmt.Errorf("exec rule %q: %w", rule.ID, err)
		}
	}
	for index, rule := range d.File.Rules {
		if err := validateID(rule.ID, "file", index); err != nil {
			return err
		}
		if err := rule.validate(); err != nil {
			return fmt.Errorf("file rule %q: %w", rule.ID, err)
		}
	}
	for index, rule := range d.Bind.Rules {
		if err := validateID(rule.ID, "bind", index); err != nil {
			return err
		}
		if err := rule.validate(); err != nil {
			return fmt.Errorf("bind rule %q: %w", rule.ID, err)
		}
	}
	for index, rule := range d.Unix.Rules {
		if err := validateID(rule.ID, "unix", index); err != nil {
			return err
		}
		if err := rule.validate(); err != nil {
			return fmt.Errorf("unix rule %q: %w", rule.ID, err)
		}
	}
	for index, rule := range d.Sockopt.Rules {
		if err := validateID(rule.ID, "sockopt", index); err != nil {
			return err
		}
		if err := rule.validate(); err != nil {
			return fmt.Errorf("sockopt rule %q: %w", rule.ID, err)
		}
	}
	for index := range d.DetectionRules {
		rule := &d.DetectionRules[index]
		if err := validateID(rule.ID, "detections", index); err != nil {
			return err
		}
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
	if err := validateSelectors(r.Selectors); err != nil {
		return err
	}
	for name, count := range map[string]int{
		"destination cidrs": len(r.Destinations.CIDRs),
		"ports":             len(r.Destinations.Ports),
		"protocols":         len(r.Destinations.Protocols),
	} {
		if count > MaxRuleListValues {
			return fmt.Errorf("%s count %d exceeds %d", name, count, MaxRuleListValues)
		}
	}
	if err := validateUnique(r.Destinations.CIDRs, "destination cidr"); err != nil {
		return err
	}
	if err := validateUnique(r.Destinations.Ports, "destination port"); err != nil {
		return err
	}
	// Port 0 is the kernel wildcard key, so an explicit 0 would match every
	// port. Omit ports instead; that already covers ephemeral (port 0) binds.
	if slices.Contains(r.Destinations.Ports, 0) {
		return fmt.Errorf("port 0 is not allowed; omit ports to match any port")
	}
	if err := validateUnique(r.Destinations.Protocols, "destination protocol"); err != nil {
		return err
	}
	for _, cidr := range r.Destinations.CIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("invalid destination cidr %q: %w", cidr, err)
		}
		if _, err := netprefix.Canonical(prefix); err != nil {
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
	if len(r.Message) > MaxDetectionMessageBytes {
		return fmt.Errorf("message length %d exceeds %d bytes", len(r.Message), MaxDetectionMessageBytes)
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
	if err := validateDetectionEventFields(r.Events, r.Match, r.Match); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if err := validateDetectionEventFields(r.Events, r.Exclude, r.Match, r.Exclude); err != nil {
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
	if len(r.Threshold.GroupBy) > len(supportedGroupFields) {
		return fmt.Errorf("threshold group_by count %d exceeds %d", len(r.Threshold.GroupBy), len(supportedGroupFields))
	}
	if err := validateUnique(r.Threshold.GroupBy, "threshold group field"); err != nil {
		return err
	}
	for _, field := range r.Threshold.GroupBy {
		if slices.Contains(processIdentityGroupFields, field) {
			if err := validateDetectionProcessIdentity(r.Events, "threshold group_by "+field, r.Match); err != nil {
				return err
			}
		}
	}
	for _, field := range r.Threshold.GroupBy {
		if !slices.Contains(supportedGroupFields, field) {
			return fmt.Errorf("unsupported threshold group field %q", field)
		}
		if field == "path" {
			for _, event := range r.Events {
				if !slices.Contains(resolvedPathDetectionEvents, event) {
					return fmt.Errorf("threshold group field %q requires resolved-path enforcement events; %q is unsupported", field, event)
				}
			}
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
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return fmt.Errorf("invalid destination cidr %q: %w", cidr, err)
		}
		if _, err := netprefix.Canonical(prefix); err != nil {
			return fmt.Errorf("invalid destination cidr %q: %w", cidr, err)
		}
	}
	for _, pattern := range m.CommandGlobs {
		if _, err := filepath.Match(pattern, "probe"); err != nil {
			return fmt.Errorf("invalid glob %q: %w", pattern, err)
		}
	}
	for _, pattern := range append(slices.Clone(m.ExecutableGlobs), m.FilePathGlobs...) {
		if err := validateDetectionPathPattern(pattern); err != nil {
			return err
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
	if len(m.CommandGlobs) > 0 {
		return fmt.Errorf("command_globs are unavailable because command lines are not captured at event time")
	}
	for _, field := range []struct {
		name  string
		count int
	}{
		{name: "cgroup_prefixes", count: len(m.CgroupPrefixes)},
		{name: "services", count: len(m.Services)},
		{name: "container_ids", count: len(m.ContainerIDs)},
		{name: "pod_uids", count: len(m.PodUIDs)},
		{name: "k8s_namespaces", count: len(m.KubernetesNamespace)},
		{name: "k8s_pods", count: len(m.KubernetesPods)},
		{name: "k8s_service_accounts", count: len(m.KubernetesAccounts)},
		{name: "k8s_owners", count: len(m.KubernetesOwners)},
		{name: "k8s_apps", count: len(m.KubernetesApps)},
		{name: "lsm_sources", count: len(m.LSMSources)},
		{name: "lsm_labels", count: len(m.LSMLabels)},
	} {
		if field.count > 0 {
			return fmt.Errorf("%s are unavailable because the value is not captured at event time", field.name)
		}
	}
	return nil
}

func validateDetectionPathPattern(pattern string) error {
	stem := pattern
	if strings.HasSuffix(pattern, "/**") {
		stem = strings.TrimSuffix(pattern, "/**")
		if stem == "" {
			stem = "/"
		}
	} else if strings.ContainsAny(pattern, `*?[\`) {
		return fmt.Errorf("detection path glob %q must be an exact path or end in /**", pattern)
	}
	if !filepath.IsAbs(stem) || filepath.Clean(stem) != stem || strings.ContainsAny(stem, `*?[\`) {
		return fmt.Errorf("detection path glob %q must have a clean absolute literal stem", pattern)
	}
	if len(stem) > MaxDetectionPathStemBytes {
		return fmt.Errorf("detection path glob %q has a %d-byte stem; maximum is %d", pattern, len(stem), MaxDetectionPathStemBytes)
	}
	return nil
}

func validateDetectionEventFields(events []string, match DetectionMatch, identityScopes ...DetectionMatch) error {
	if len(match.UIDs) > 0 {
		if err := validateDetectionProcessIdentity(events, "uids", identityScopes...); err != nil {
			return err
		}
	}
	if len(match.ExecutableGlobs) > 0 {
		for _, event := range events {
			if event != "exec_blocked" && event != "exec_would_block" {
				return fmt.Errorf("executable_globs require only exec_blocked or exec_would_block events with kernel-resolved paths; %q is unsupported", event)
			}
		}
	}
	if len(match.FilePathGlobs) > 0 {
		for _, event := range events {
			if event != "file_blocked" && event != "file_would_block" {
				return fmt.Errorf("file_path_globs require only file_blocked or file_would_block events with kernel-resolved paths; %q is unsupported", event)
			}
		}
	}
	return nil
}

func validateDetectionProcessIdentity(events []string, field string, scopes ...DetectionMatch) error {
	for _, event := range events {
		if slices.Contains(eventsWithoutProcessIdentity, event) {
			return fmt.Errorf("%s require event-time process identity; %q exposes only absent or cached identity", field, event)
		}
		if event == "connection" && connectionMayUseCachedIdentity(scopes) {
			return fmt.Errorf("%s require event-time process identity; connection rules that may match inbound TCP must restrict directions to outbound or protocols to udp", field)
		}
	}
	return nil
}

func connectionMayUseCachedIdentity(scopes []DetectionMatch) bool {
	allowsInbound := true
	allowsTCP := true
	for _, scope := range scopes {
		if len(scope.Directions) > 0 && !slices.Contains(scope.Directions, "inbound") {
			allowsInbound = false
		}
		if len(scope.Protocols) > 0 && !slices.Contains(scope.Protocols, "tcp") {
			allowsTCP = false
		}
	}
	return allowsInbound && allowsTCP
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
	"exec_blocked", "exec_would_block", "file_blocked", "file_would_block",
	"bind_blocked", "bind_would_block", "unix_blocked", "unix_would_block",
	"sockopt_blocked", "sockopt_would_block", "tcp_sockops",
}

var supportedGroupFields = []string{
	"cgroup", "executable", "program", "uid", "domain", "destination", "path",
}

var processIdentityGroupFields = []string{
	"cgroup", "executable", "program", "uid",
}

var eventsWithoutProcessIdentity = []string{
	"dns", "blocked", "tcp_sockops",
}

var resolvedPathDetectionEvents = []string{
	"exec_blocked", "exec_would_block", "file_blocked", "file_would_block",
	"unix_blocked", "unix_would_block",
}
