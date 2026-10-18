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
	Version                             = 1
	MaxDocumentBytes              int64 = 4 << 20
	MaxEgressRules                      = 1024
	MaxEnforcementRules                 = 1024
	MaxDetectionRules                   = 256
	MaxDetectionExceptions              = 256
	MaxExceptionReasonBytes             = 512
	MaxFileIntegrityPaths               = 256
	DefaultFileIntegrityHashBytes       = 16 << 20
	MaxFileIntegrityHashBytes           = 1 << 30
	DefaultFileIntegrityRescan          = time.Hour
	MinFileIntegrityRescan              = time.Minute
	MaxDetectionGroups                  = 16384
	MaxThresholdWindow                  = time.Hour
	MaxThresholdCount                   = 10000
	MaxRuleListValues                   = 256
	MaxDetectionMessageBytes            = 4096
	MaxDetectionPathStemBytes           = 247
	MaxDetectionSamples                 = 65536
	MaxPolicySelectors                  = 4096
	MaxDNSRules                         = 4096
	MaxResolverHostnames                = 256
)

var (
	ruleIDPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	mitreTacticPattern    = regexp.MustCompile(`^TA[0-9]{4}$`)
	mitreTechniquePattern = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)
)

const (
	// ProfileBaseline is always enabled.
	ProfileBaseline = "baseline"
	// ProfileRuntime adds runtime threat detections over security events.
	ProfileRuntime = "runtime"
)

// BuiltinProfiles lists every built-in detection profile.
var BuiltinProfiles = []string{ProfileBaseline, ProfileRuntime}

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

// Timestamp is an RFC 3339 instant; the zero value means unset.
type Timestamp struct {
	time.Time
}

func (t *Timestamp) UnmarshalText(text []byte) error {
	value, err := time.Parse(time.RFC3339, string(text))
	if err != nil {
		return fmt.Errorf("timestamp must be RFC 3339, for example 2026-12-31T00:00:00Z: %w", err)
	}
	t.Time = value.UTC()
	return nil
}

type Document struct {
	Version             int                  `yaml:"version"`
	BuiltinProfiles     []string             `yaml:"builtin_profiles,omitempty"`
	DisabledRuleIDs     []string             `yaml:"disabled_rule_ids,omitempty"`
	DNS                 DNSPolicy            `yaml:"dns,omitempty"`
	Egress              EgressPolicy         `yaml:"egress,omitempty"`
	Exec                PathPolicy           `yaml:"exec,omitempty"`
	File                FilePolicy           `yaml:"file,omitempty"`
	Bind                BindPolicy           `yaml:"bind,omitempty"`
	Unix                UnixPolicy           `yaml:"unix,omitempty"`
	Sockopt             SockoptPolicy        `yaml:"sockopt,omitempty"`
	DetectionRules      []DetectionRule      `yaml:"detections,omitempty"`
	DetectionExceptions []DetectionException `yaml:"detection_exceptions,omitempty"`
	FileIntegrity       FileIntegrityPolicy  `yaml:"file_integrity,omitempty"`
}

// FileIntegrityPolicy selects the files whose content and attributes are
// baselined and compared after change events and on a periodic rescan.
type FileIntegrityPolicy struct {
	Paths   []string `yaml:"paths,omitempty"`
	Exclude []string `yaml:"exclude,omitempty"`
	// Hash enables SHA-256 content hashing; it defaults to true.
	Hash *bool `yaml:"hash,omitempty"`
	// MaxHashBytes caps the size of a hashed file; larger files are compared
	// by metadata only.
	MaxHashBytes int64 `yaml:"max_hash_bytes,omitempty"`
	// RescanInterval is the full rescan period; 0 disables periodic rescans.
	RescanInterval *Duration `yaml:"rescan_interval,omitempty"`
}

// Enabled reports whether any path is watched.
func (f FileIntegrityPolicy) Enabled() bool { return len(f.Paths) > 0 }

// HashEnabled reports whether content hashing is on.
func (f FileIntegrityPolicy) HashEnabled() bool { return f.Hash == nil || *f.Hash }

// HashLimit returns the largest file size that is hashed.
func (f FileIntegrityPolicy) HashLimit() int64 {
	if f.MaxHashBytes == 0 {
		return DefaultFileIntegrityHashBytes
	}
	return f.MaxHashBytes
}

// Rescan returns the periodic rescan interval, 0 when disabled.
func (f FileIntegrityPolicy) Rescan() time.Duration {
	if f.RescanInterval == nil {
		return DefaultFileIntegrityRescan
	}
	return f.RescanInterval.Duration
}

func (f FileIntegrityPolicy) validate() error {
	if count := len(f.Paths) + len(f.Exclude); count > MaxFileIntegrityPaths {
		return fmt.Errorf("path and exclude count %d exceeds %d", count, MaxFileIntegrityPaths)
	}
	if len(f.Exclude) > 0 && len(f.Paths) == 0 {
		return fmt.Errorf("exclude requires paths")
	}
	for _, list := range [][]string{f.Paths, f.Exclude} {
		if err := validateUnique(list, "file integrity path"); err != nil {
			return err
		}
		for _, pattern := range list {
			if err := validateDetectionPathPattern(pattern); err != nil {
				return err
			}
		}
	}
	if f.MaxHashBytes < 0 || f.MaxHashBytes > MaxFileIntegrityHashBytes {
		return fmt.Errorf("max_hash_bytes must be between 0 and %d", MaxFileIntegrityHashBytes)
	}
	if f.RescanInterval != nil && f.RescanInterval.Duration != 0 && f.RescanInterval.Duration < MinFileIntegrityRescan {
		return fmt.Errorf("rescan_interval must be 0 or at least %s", MinFileIntegrityRescan)
	}
	return nil
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
	MITRE     MITRE          `yaml:"mitre,omitempty"`
	// Compliance holds free-form control references, such as pci-dss:10.2.7.
	Compliance []string `yaml:"compliance,omitempty"`
}

// MITRE maps a detection to MITRE ATT&CK tactic and technique IDs.
type MITRE struct {
	Tactics    []string `yaml:"tactics,omitempty"`
	Techniques []string `yaml:"techniques,omitempty"`
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
	LocalPorts          []uint16 `yaml:"local_ports,omitempty"`
	ExecutableGlobs     []string `yaml:"executable_globs,omitempty"`
	CommandGlobs        []string `yaml:"command_globs,omitempty"`
	FilePathGlobs       []string `yaml:"file_path_globs,omitempty"`
	UnixPathGlobs       []string `yaml:"unix_path_globs,omitempty"`
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
	Operations          []string `yaml:"operations,omitempty"`
	ExecSources         []string `yaml:"exec_sources,omitempty"`
	MountFSTypes        []string `yaml:"mount_fstypes,omitempty"`
	Capabilities        []string `yaml:"capabilities,omitempty"`
	Changes             []string `yaml:"changes,omitempty"`
}

// DetectionException suppresses alerts from the listed rules for events that
// match, until it expires. Matching events also do not count toward the rules'
// thresholds.
type DetectionException struct {
	ID      string         `yaml:"id"`
	Rules   []string       `yaml:"rules"`
	Reason  string         `yaml:"reason"`
	Expires Timestamp      `yaml:"expires,omitempty"`
	Match   DetectionMatch `yaml:"match"`
}

// Active reports whether the exception applies at the given time.
func (e DetectionException) Active(at time.Time) bool {
	return e.Expires.IsZero() || at.Before(e.Expires.Time)
}

type Threshold struct {
	Count   int      `yaml:"count,omitempty"`
	Within  Duration `yaml:"within,omitempty"`
	GroupBy []string `yaml:"group_by,omitempty"`
}

type Bundle struct {
	DNS                 blocklist.Rules
	Egress              EgressPolicy
	Exec                PathPolicy
	File                FilePolicy
	Bind                BindPolicy
	Unix                UnixPolicy
	Sockopt             SockoptPolicy
	DetectionRules      []DetectionRule
	DetectionExceptions []DetectionException
	FileIntegrity       FileIntegrityPolicy
	BuiltinProfiles     []string
	DisabledRuleIDs     []string
}

func (d Document) Validate() error {
	if d.Version != Version {
		return fmt.Errorf("unsupported policy version %d, want %d", d.Version, Version)
	}
	for _, profile := range d.BuiltinProfiles {
		if !slices.Contains(BuiltinProfiles, profile) {
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
	if len(d.DetectionExceptions) > MaxDetectionExceptions {
		return fmt.Errorf("detection exception count %d exceeds %d", len(d.DetectionExceptions), MaxDetectionExceptions)
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
	if err := d.FileIntegrity.validate(); err != nil {
		return fmt.Errorf("file_integrity: %w", err)
	}
	exceptionIDs := make(map[string]struct{}, len(d.DetectionExceptions))
	for index, exception := range d.DetectionExceptions {
		if err := validateRuleID(exception.ID); err != nil {
			return fmt.Errorf("detection exception %d: %w", index, err)
		}
		if _, exists := exceptionIDs[exception.ID]; exists {
			return fmt.Errorf("duplicate detection exception id %q", exception.ID)
		}
		exceptionIDs[exception.ID] = struct{}{}
		if err := exception.validate(); err != nil {
			return fmt.Errorf("detection exception %q: %w", exception.ID, err)
		}
	}
	if _, err := parseDNS(d.DNS); err != nil {
		return err
	}
	return nil
}

func (e DetectionException) validate() error {
	if len(e.Rules) == 0 {
		return fmt.Errorf("rules must not be empty")
	}
	if len(e.Rules) > MaxRuleListValues {
		return fmt.Errorf("rules count %d exceeds %d", len(e.Rules), MaxRuleListValues)
	}
	if err := validateIDs(e.Rules, "exception rule"); err != nil {
		return err
	}
	if strings.TrimSpace(e.Reason) == "" {
		return fmt.Errorf("reason must not be empty")
	}
	if len(e.Reason) > MaxExceptionReasonBytes {
		return fmt.Errorf("reason length %d exceeds %d bytes", len(e.Reason), MaxExceptionReasonBytes)
	}
	if e.Match.Empty() {
		return fmt.Errorf("match must not be empty; disable the rule with disabled_rule_ids instead")
	}
	if err := e.Match.validate(); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	return nil
}

// ValidateExceptionFor checks that an exception's match only uses fields the
// rule's events carry at event time.
func ValidateExceptionFor(rule DetectionRule, exception DetectionException) error {
	if err := validateDetectionEventFields(rule.Events, exception.Match, rule.Match, exception.Match); err != nil {
		return fmt.Errorf("detection exception %q for rule %q: %w", exception.ID, rule.ID, err)
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
	for name, values := range map[string][]string{
		"mitre tactic": r.MITRE.Tactics, "mitre technique": r.MITRE.Techniques, "compliance reference": r.Compliance,
	} {
		if len(values) > 16 {
			return fmt.Errorf("%s count %d exceeds 16", name, len(values))
		}
		if err := validateUnique(values, name); err != nil {
			return err
		}
	}
	for _, tactic := range r.MITRE.Tactics {
		if !mitreTacticPattern.MatchString(tactic) {
			return fmt.Errorf("invalid mitre tactic %q; use an ID such as TA0005", tactic)
		}
	}
	for _, technique := range r.MITRE.Techniques {
		if !mitreTechniquePattern.MatchString(technique) {
			return fmt.Errorf("invalid mitre technique %q; use an ID such as T1055 or T1055.008", technique)
		}
	}
	for _, reference := range r.Compliance {
		if strings.TrimSpace(reference) == "" || len(reference) > 64 {
			return fmt.Errorf("invalid compliance reference %q", reference)
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
		"local ports":           len(m.LocalPorts),
		"executable globs":      len(m.ExecutableGlobs),
		"command globs":         len(m.CommandGlobs),
		"file path globs":       len(m.FilePathGlobs),
		"unix path globs":       len(m.UnixPathGlobs),
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
		"operations":            len(m.Operations),
		"exec sources":          len(m.ExecSources),
		"mount fstypes":         len(m.MountFSTypes),
		"capabilities":          len(m.Capabilities),
		"changes":               len(m.Changes),
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
	for _, pattern := range m.UnixPathGlobs {
		if err := validateEnforcedPathGlob(pattern, true); err != nil {
			return fmt.Errorf("invalid unix path glob: %w", err)
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
	for _, source := range m.ExecSources {
		if source != "path" && source != "fd" {
			return fmt.Errorf("unsupported exec source %q", source)
		}
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

// Empty reports whether the match sets no conditions and so matches every event.
func (m DetectionMatch) Empty() bool {
	return len(m.Actions)+len(m.Directions)+len(m.Transports)+len(m.Protocols)+
		len(m.UIDs)+len(m.Domains)+len(m.DomainSuffixes)+len(m.DestinationCIDRs)+
		len(m.Ports)+len(m.LocalPorts)+len(m.ExecutableGlobs)+len(m.CommandGlobs)+
		len(m.FilePathGlobs)+len(m.UnixPathGlobs)+
		len(m.FileAccess)+len(m.CgroupPrefixes)+len(m.Services)+len(m.ContainerIDs)+
		len(m.PodUIDs)+len(m.KubernetesNamespace)+len(m.KubernetesPods)+
		len(m.KubernetesAccounts)+len(m.KubernetesOwners)+len(m.KubernetesApps)+
		len(m.LSMSources)+len(m.LSMLabels)+len(m.Operations)+len(m.ExecSources)+
		len(m.MountFSTypes)+len(m.Capabilities)+len(m.Changes) == 0
}

func validateDetectionPathPattern(pattern string) error {
	stem := pattern
	if before, ok := strings.CutSuffix(pattern, "/**"); ok {
		stem = before
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
			if event != "file_blocked" && event != "file_would_block" && event != "file_integrity" {
				return fmt.Errorf("file_path_globs require only file_blocked, file_would_block, or file_integrity events with resolved paths; %q is unsupported", event)
			}
		}
	}
	if len(match.UnixPathGlobs) > 0 {
		for _, event := range events {
			if event != "unix_blocked" && event != "unix_would_block" {
				return fmt.Errorf("unix_path_globs require only unix_blocked or unix_would_block events; %q is unsupported", event)
			}
		}
	}
	if len(match.LocalPorts) > 0 {
		for _, event := range events {
			if !slices.Contains(localPortDetectionEvents, event) {
				return fmt.Errorf("local_ports require events that carry a local port; %q is unsupported", event)
			}
		}
	}
	for _, selector := range []struct {
		name, event, reason string
		count               int
	}{
		{"command_globs", "exec", "whose command line is captured at syscall entry", len(match.CommandGlobs)},
		{"exec_sources", "exec", "whose executable source is captured at syscall entry", len(match.ExecSources)},
		{"mount_fstypes", "mount", "which carry the requested filesystem type", len(match.MountFSTypes)},
		{"capabilities", "privilege_change", "whose capset requests carry capabilities", len(match.Capabilities)},
		{"changes", "file_integrity", "which carry the change kind", len(match.Changes)},
	} {
		if selector.count == 0 {
			continue
		}
		for _, event := range events {
			if event != selector.event {
				return fmt.Errorf("%s require %s events, %s; %q is unsupported", selector.name, selector.event, selector.reason, event)
			}
		}
	}
	for _, change := range match.Changes {
		if !slices.Contains([]string{"created", "modified", "deleted", "attributes"}, change) {
			return fmt.Errorf("unsupported change %q", change)
		}
	}
	for _, capability := range match.Capabilities {
		if !slices.Contains(CapabilityNames, capability) {
			return fmt.Errorf("unsupported capability %q", capability)
		}
	}
	if len(match.Operations) > 0 {
		var known []string
		for _, event := range events {
			operations, ok := SecurityEventOperations[event]
			if !ok {
				return fmt.Errorf("operations require security events that carry an operation; %q is unsupported", event)
			}
			known = append(known, operations...)
		}
		for _, operation := range match.Operations {
			if !slices.Contains(known, operation) {
				return fmt.Errorf("operation %q is not carried by events %v", operation, events)
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
	"memfd_create", "ptrace", "process_vm", "module_load", "bpf_prog_load",
	"io_uring_setup", "mount", "namespace_change", "privilege_change",
	"file_change", "file_integrity",
}

// CapabilityNames lists the capabilities a capset event can report: the low
// 32 capability bits, in bit order.
var CapabilityNames = []string{
	"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid",
	"setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner",
	"sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice",
	"sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap",
}

// SecurityEventOperations lists the operation names each security event can
// carry in its operation field.
var SecurityEventOperations = map[string][]string{
	"ptrace":           {"traceme", "poketext", "pokedata", "pokeuser", "attach", "seize"},
	"process_vm":       {"read", "write"},
	"module_load":      {"init_module", "finit_module"},
	"namespace_change": {"setns", "unshare"},
	"privilege_change": {"setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "capset"},
	"file_change":      {"unlink", "rmdir", "rename", "chmod", "chown", "truncate"},
}

var supportedGroupFields = []string{
	"cgroup", "executable", "program", "uid", "domain", "destination", "peer", "path",
}

var processIdentityGroupFields = []string{
	"cgroup", "executable", "program", "uid",
}

var eventsWithoutProcessIdentity = []string{
	"dns", "blocked", "tcp_sockops", "file_integrity",
}

var localPortDetectionEvents = []string{
	"connection", "egress_blocked", "egress_would_block",
	"bind_blocked", "bind_would_block", "tcp_sockops",
}

var resolvedPathDetectionEvents = []string{
	"exec_blocked", "exec_would_block", "file_blocked", "file_would_block",
	"unix_blocked", "unix_would_block", "file_integrity",
}
