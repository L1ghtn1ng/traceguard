package detection

import (
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"math"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/netprefix"
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
	mu         sync.Mutex
	rules      []compiledRule
	exceptions []policy.DetectionException
	suppressed map[string]uint64
	groups     map[groupKey]*groupState
	groupKeys  []groupKey
	groupNext  int
	maxGroups  int
	samples    int
	maxSamples int
}

type groupKey [sha256.Size]byte

type compiledRule struct {
	rule         policy.DetectionRule
	matchCIDRs   []netip.Prefix
	excludeCIDRs []netip.Prefix
	exceptions   []compiledException
}

type compiledException struct {
	exception policy.DetectionException
	cidrs     []netip.Prefix
}

// ExceptionStatus reports one detection exception's state and how many
// events it has suppressed since it was first installed.
type ExceptionStatus struct {
	ID         string
	Expired    bool
	Suppressed uint64
}

type groupState struct {
	timestamps []int64
	lastAlert  time.Time
}

func New(custom []policy.DetectionRule, disabled []string) (*Engine, error) {
	compiled, err := Compile(custom, disabled, nil)
	if err != nil {
		return nil, err
	}
	return &Engine{
		rules:      compiled.rules,
		suppressed: make(map[string]uint64),
		groups:     make(map[groupKey]*groupState),
		maxGroups:  policy.MaxDetectionGroups,
		maxSamples: policy.MaxDetectionSamples,
	}, nil
}

// CompiledRules is a validated detection rule set that Install can apply
// without failing.
type CompiledRules struct {
	rules      []compiledRule
	exceptions []policy.DetectionException
}

// Compile validates and compiles detection rules and their exceptions without
// changing an engine. An exception may name a disabled rule, but not one that
// is neither built in nor defined.
func Compile(custom []policy.DetectionRule, disabled []string, exceptions []policy.DetectionException) (CompiledRules, error) {
	rules, err := compileRules(effectiveRules(custom, disabled))
	if err != nil {
		return CompiledRules{}, err
	}
	// definitions holds every rule an exception may name, enabled or not, so
	// an exception is validated against its rule even while that rule is
	// disabled and cannot fail later when the rule is re-enabled.
	definitions := make(map[string]policy.DetectionRule, len(custom)+len(BaselineRules()))
	for _, rule := range append(BaselineRules(), custom...) {
		definitions[rule.ID] = rule
	}
	active := make(map[string]*compiledRule, len(rules))
	for index := range rules {
		active[rules[index].rule.ID] = &rules[index]
	}
	for _, exception := range exceptions {
		cidrs, err := parseCIDRs(exception.Match.DestinationCIDRs)
		if err != nil {
			return CompiledRules{}, fmt.Errorf("compile detection exception %q: %w", exception.ID, err)
		}
		for _, id := range exception.Rules {
			definition, ok := definitions[id]
			if !ok {
				return CompiledRules{}, fmt.Errorf("detection exception %q references unknown rule %q", exception.ID, id)
			}
			if err := policy.ValidateExceptionFor(definition, exception); err != nil {
				return CompiledRules{}, err
			}
			rule, ok := active[id]
			if !ok {
				continue
			}
			rule.exceptions = append(rule.exceptions, compiledException{exception: exception, cidrs: cidrs})
		}
	}
	return CompiledRules{rules: rules, exceptions: slices.Clone(exceptions)}, nil
}

func (e *Engine) Replace(custom []policy.DetectionRule, disabled []string) error {
	compiled, err := Compile(custom, disabled, nil)
	if err != nil {
		return err
	}
	e.Install(compiled)
	return nil
}

// Install replaces the active rules and resets grouping state. Suppression
// counts carry over for exceptions that remain installed.
func (e *Engine) Install(compiled CompiledRules) {
	e.mu.Lock()
	defer e.mu.Unlock()
	suppressed := make(map[string]uint64, len(compiled.exceptions))
	for _, exception := range compiled.exceptions {
		suppressed[exception.ID] = e.suppressed[exception.ID]
	}
	e.rules = compiled.rules
	e.exceptions = compiled.exceptions
	e.suppressed = suppressed
	e.groups = make(map[groupKey]*groupState)
	e.groupKeys = nil
	e.groupNext = 0
	e.samples = 0
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
	matchContext := eventMatchContext{fields: event.Fields}
	for index := range e.rules {
		rule := &e.rules[index]
		if !slices.Contains(rule.rule.Events, event.Name) ||
			!matches(rule.rule.Match, rule.matchCIDRs, &matchContext) ||
			(!rule.rule.Exclude.Empty() && matches(rule.rule.Exclude, rule.excludeCIDRs, &matchContext)) {
			continue
		}
		if id, ok := rule.suppressingException(event.Timestamp, &matchContext); ok {
			e.suppressed[id]++
			continue
		}

		count := rule.rule.Threshold.Count
		if count == 0 {
			count = 1
		}
		cooldown := rule.rule.Cooldown.Duration
		if count == 1 && cooldown <= 0 {
			alerts = append(alerts, newAlert(rule, event, count))
			continue
		}

		key := makeGroupKey(rule.rule.ID, rule.rule.Threshold.GroupBy, event.Fields)
		state := e.groups[key]
		if state == nil {
			e.makeRoom(key)
			if e.maxGroups <= 0 {
				continue
			}
			state = &groupState{}
			e.groups[key] = state
		}

		window := rule.rule.Threshold.Within.Duration
		if count > 1 {
			cutoff := event.Timestamp.Add(-window).UnixNano()
			first := 0
			for first < len(state.timestamps) && state.timestamps[first] < cutoff {
				first++
			}
			if first > 0 {
				state.timestamps = slices.Clone(state.timestamps[first:])
				e.samples -= first
			}
			e.makeSampleRoom(key)
			state = e.groups[key]
			if state == nil || e.maxSamples <= 0 {
				continue
			}
			state.timestamps = append(state.timestamps, event.Timestamp.UnixNano())
			e.samples++
			if len(state.timestamps) > count {
				dropped := len(state.timestamps) - count
				state.timestamps = slices.Clone(state.timestamps[dropped:])
				e.samples -= dropped
			}
			if len(state.timestamps) < count {
				continue
			}
		}
		if cooldown > 0 &&
			!state.lastAlert.IsZero() && event.Timestamp.Sub(state.lastAlert) < cooldown {
			continue
		}
		state.lastAlert = event.Timestamp
		alerts = append(alerts, newAlert(rule, event, count))
	}
	return alerts
}

func (r *compiledRule) suppressingException(at time.Time, context *eventMatchContext) (string, bool) {
	for index := range r.exceptions {
		exception := &r.exceptions[index]
		if exception.exception.Active(at) && matches(exception.exception.Match, exception.cidrs, context) {
			return exception.exception.ID, true
		}
	}
	return "", false
}

// ExceptionStatus returns every installed exception, sorted by ID.
func (e *Engine) ExceptionStatus(now time.Time) []ExceptionStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	statuses := make([]ExceptionStatus, 0, len(e.exceptions))
	for _, exception := range e.exceptions {
		statuses = append(statuses, ExceptionStatus{
			ID: exception.ID, Expired: !exception.Active(now), Suppressed: e.suppressed[exception.ID],
		})
	}
	slices.SortFunc(statuses, func(left, right ExceptionStatus) int { return strings.Compare(left.ID, right.ID) })
	return statuses
}

// RecordFields returns the alert as structured record fields: the matched
// event's fields plus the detection metadata.
func (a Alert) RecordFields(sourceEvent string) map[string]any {
	fields := cloneFields(a.Fields)
	fields["source_event"] = sourceEvent
	fields["event"] = "detection_alert"
	fields["detection_rule_id"] = a.RuleID
	fields["severity"] = a.Severity
	fields["detection_message"] = a.Message
	fields["tags"] = slices.Clone(a.Tags)
	fields["threshold_count"] = a.Count
	if a.Window > 0 {
		fields["threshold_window"] = a.Window.String()
	}
	return fields
}

func newAlert(rule *compiledRule, event Event, count int) Alert {
	return Alert{
		RuleID: rule.rule.ID, Severity: rule.rule.Severity, Message: rule.rule.Message,
		Tags: slices.Clone(rule.rule.Tags), Count: count, Window: rule.rule.Threshold.Within.Duration,
		Timestamp: event.Timestamp, Fields: cloneFields(event.Fields),
	}
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

func (e *Engine) StateSampleCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.samples
}

func (e *Engine) makeRoom(key groupKey) {
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
	e.deleteGroup(e.groupKeys[e.groupNext])
	e.groupKeys[e.groupNext] = key
	e.groupNext = (e.groupNext + 1) % len(e.groupKeys)
}

func (e *Engine) makeSampleRoom(preserve groupKey) {
	for e.samples >= e.maxSamples && len(e.groups) > 1 {
		if e.groupNext >= len(e.groupKeys) {
			e.groupNext = 0
		}
		candidate := e.groupKeys[e.groupNext]
		if candidate == preserve {
			e.groupNext = (e.groupNext + 1) % len(e.groupKeys)
			continue
		}
		e.deleteGroup(candidate)
		e.groupKeys = append(e.groupKeys[:e.groupNext], e.groupKeys[e.groupNext+1:]...)
	}
	if e.samples >= e.maxSamples {
		state := e.groups[preserve]
		if state != nil && len(state.timestamps) > 0 {
			state.timestamps = slices.Clone(state.timestamps[1:])
			e.samples--
		}
	}
}

func (e *Engine) deleteGroup(key groupKey) {
	if state := e.groups[key]; state != nil {
		e.samples -= len(state.timestamps)
	}
	delete(e.groups, key)
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
		canonical, err := netprefix.Canonical(prefix)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, canonical)
	}
	return prefixes, nil
}

type eventMatchContext struct {
	fields map[string]any
}

func matches(match policy.DetectionMatch, cidrs []netip.Prefix, context *eventMatchContext) bool {
	fields := context.fields
	return matchStrings(match.Actions, stringField(fields, "action", "policy")) &&
		matchStrings(match.Directions, stringField(fields, "direction")) &&
		matchStrings(match.Transports, stringField(fields, "transport")) &&
		matchStrings(match.Protocols, stringField(fields, "socket_protocol", "transport")) &&
		matchUint32Field(match.UIDs, fields, "kernel_uid", "uid") &&
		matchDomains(match.Domains, stringField(fields, "domain")) &&
		matchSuffixes(match.DomainSuffixes, stringField(fields, "domain")) &&
		matchAddress(cidrs, stringField(fields, "peer_address", "address")) &&
		matchUint16Field(match.Ports, fields, "peer_port", "port") &&
		matchUint16Field(match.LocalPorts, fields, "local_port") &&
		matchCanonicalPathGlobs(match.ExecutableGlobs, stringField(fields, "exe"), boolField(fields, "path_truncated")) &&
		len(match.CommandGlobs) == 0 &&
		matchCanonicalPathGlobs(match.FilePathGlobs, stringField(fields, "path"), boolField(fields, "path_truncated")) &&
		matchLiteralPathGlobs(match.UnixPathGlobs, stringField(fields, "path"), boolField(fields, "path_truncated")) &&
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
	if address.Is4In6() {
		address = address.Unmap()
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func matchUint32Field(values []uint32, fields map[string]any, names ...string) bool {
	if len(values) == 0 {
		return true
	}
	candidate, ok := uint32Field(fields, names...)
	return ok && slices.Contains(values, candidate)
}

func matchUint16Field(values []uint16, fields map[string]any, names ...string) bool {
	if len(values) == 0 {
		return true
	}
	candidate, ok := uint16Field(fields, names...)
	return ok && slices.Contains(values, candidate)
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

func matchCanonicalPathGlobs(patterns []string, candidate string, truncated bool) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if truncated && !strings.HasSuffix(pattern, "/**") {
			continue
		}
		if matchGlobs([]string{pattern}, candidate) {
			return true
		}
	}
	return false
}

// matchLiteralPathGlobs matches exact paths and /** subtrees without glob
// metacharacters, because abstract Unix socket names may contain them.
func matchLiteralPathGlobs(patterns []string, candidate string, truncated bool) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if stem, ok := strings.CutSuffix(pattern, "/**"); ok {
			if candidate == stem || strings.HasPrefix(candidate, stem+"/") {
				return true
			}
		} else if !truncated && candidate == pattern {
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

func boolField(fields map[string]any, name string) bool {
	value, _ := fields[name].(bool)
	return value
}

func uint32Field(fields map[string]any, names ...string) (uint32, bool) {
	for _, name := range names {
		if value, ok := fields[name]; ok {
			switch number := value.(type) {
			case uint:
				if converted, valid := uint32FromUint64(uint64(number)); valid {
					return converted, true
				}
			case uint16:
				return uint32(number), true
			case uint32:
				return number, true
			case uint64:
				if converted, valid := uint32FromUint64(number); valid {
					return converted, true
				}
			case int:
				if converted, valid := uint32FromInt64(int64(number)); valid {
					return converted, true
				}
			case int64:
				if converted, valid := uint32FromInt64(number); valid {
					return converted, true
				}
			case float64:
				if number >= 0 && number <= math.MaxUint32 && math.Trunc(number) == number {
					return uint32(number), true
				}
			}
		}
	}
	return 0, false
}

func uint16Field(fields map[string]any, names ...string) (uint16, bool) {
	value, ok := uint32Field(fields, names...)
	if !ok || value > math.MaxUint16 {
		return 0, false
	}
	return uint16(value), true
}

func uint32FromUint64(value uint64) (uint32, bool) {
	if value > math.MaxUint32 {
		return 0, false
	}
	return uint32(value), true
}

func uint32FromInt64(value int64) (uint32, bool) {
	if value < 0 || value > math.MaxUint32 {
		return 0, false
	}
	return uint32(value), true
}

// actingExecutable identifies the process that caused an event. Exec decision
// events carry the denied target in exe, so they group by the calling program.
func actingExecutable(values map[string]any) string {
	switch stringField(values, "event") {
	case "exec_blocked", "exec_would_block":
		return stringField(values, "program")
	default:
		return stringField(values, "exe", "program")
	}
}

func makeGroupKey(ruleID string, fields []string, values map[string]any) groupKey {
	hash := sha256.New()
	_, _ = io.WriteString(hash, ruleID)
	for _, field := range fields {
		_, _ = hash.Write([]byte{0})
		_, _ = io.WriteString(hash, field)
		_, _ = hash.Write([]byte{'='})
		switch field {
		case "destination", "peer":
			_, _ = io.WriteString(hash, stringField(values, "peer_address", "address"))
		case "executable":
			_, _ = io.WriteString(hash, actingExecutable(values))
		case "path":
			_, _ = io.WriteString(hash, stringField(values, "path"))
		case "cgroup":
			if cgroupID, ok := values["cgroup_id"]; ok && cgroupID != nil {
				_, _ = fmt.Fprint(hash, cgroupID)
			} else {
				_, _ = fmt.Fprintf(hash, "missing:%v:%v:%v", values["pid"], values["process_start_ticks"], values["program"])
			}
		case "uid":
			if uid, ok := uint32Field(values, "kernel_uid", "uid"); ok {
				_, _ = fmt.Fprint(hash, uid)
			} else {
				_, _ = io.WriteString(hash, "missing")
			}
		default:
			_, _ = fmt.Fprint(hash, values[field])
		}
	}
	var key groupKey
	copy(key[:], hash.Sum(nil))
	return key
}

func cloneFields(fields map[string]any) map[string]any {
	cloned := make(map[string]any, len(fields))
	maps.Copy(cloned, fields)
	return cloned
}
