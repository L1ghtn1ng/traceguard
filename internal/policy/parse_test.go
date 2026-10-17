package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseEnforcementSections(t *testing.T) {
	t.Parallel()
	document, err := Parse([]byte(`
version: 1
exec:
  default: allow
  rules:
    - id: exec-temp
      action: block
      match: {path_globs: [/tmp/**]}
file:
  rules:
    - id: file-shadow
      action: block
      match: {path_globs: [/etc/shadow], access: [write]}
bind:
  default: block
  rules:
    - id: bind-dns
      action: allow
      endpoints: {ports: [53], protocols: [udp]}
unix:
  rules:
    - id: unix-docker
      action: block
      match: {path_globs: ["@docker.sock"], operations: [connect]}
sockopt:
  rules:
    - id: sockopt-mark
      action: block
      match: {levels: [socket], optnames: [so_mark]}
detections:
  - id: kernel-denials
    severity: warning
    events: [exec_blocked, exec_would_block, file_blocked, file_would_block, bind_blocked, bind_would_block, unix_blocked, unix_would_block, sockopt_blocked, sockopt_would_block, tcp_sockops]
    message: kernel policy signal
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(document.Exec.Rules) != 1 || len(document.File.Rules) != 1 || len(document.Bind.Rules) != 1 || len(document.Unix.Rules) != 1 || len(document.Sockopt.Rules) != 1 {
		t.Fatalf("enforcement rule counts = exec %d file %d bind %d unix %d sockopt %d", len(document.Exec.Rules), len(document.File.Rules), len(document.Bind.Rules), len(document.Unix.Rules), len(document.Sockopt.Rules))
	}
}

func TestParseEnforcementPathBoundaries(t *testing.T) {
	t.Parallel()
	exact240 := "/" + strings.Repeat("a", 239)
	prefix240 := "/" + strings.Repeat("b", 239) + "/**"
	input := fmt.Sprintf("version: 1\nexec:\n  rules:\n    - id: exact-boundary\n      action: block\n      match: {path_globs: [%q]}\n    - id: prefix-boundary\n      action: block\n      match: {path_globs: [%q]}\n", exact240, prefix240)
	if _, err := Parse([]byte(input)); err != nil {
		t.Fatalf("Parse() rejected 240-byte boundary: %v", err)
	}
}

func TestParseRejectsUnsafeEnforcementRules(t *testing.T) {
	t.Parallel()
	tooLong := "/" + strings.Repeat("a", 240)
	tests := map[string]struct {
		body string
		want string
	}{
		"exec default block":      {"exec: {default: block}\n", "exec default must be allow"},
		"empty path match":        {"exec:\n  rules:\n    - {id: empty, action: block, match: {path_globs: []}}\n", "path_globs must not be empty"},
		"root exact quoted":       {"exec:\n  rules:\n    - {id: root, action: block, match: {path_globs: [\"/\"]}}\n", "exact root path is not allowed"},
		"unsupported wildcard":    {"file:\n  rules:\n    - {id: wildcard, action: block, match: {path_globs: [/tmp/*]}}\n", "only exact paths and /** prefixes"},
		"short prefix":            {"file:\n  rules:\n    - {id: short, action: block, match: {path_globs: [/a/**]}}\n", "between 4 and 240 bytes"},
		"long exact":              {fmt.Sprintf("exec:\n  rules:\n    - {id: long, action: block, match: {path_globs: [%q]}}\n", tooLong), "exceeds 240 bytes"},
		"long prefix":             {fmt.Sprintf("exec:\n  rules:\n    - {id: long-prefix, action: block, match: {path_globs: [%q]}}\n", tooLong+"/**"), "between 4 and 240 bytes"},
		"invalid access":          {"file:\n  rules:\n    - {id: access, action: block, match: {path_globs: [/etc/passwd], access: [execute]}}\n", "unsupported access"},
		"empty abstract":          {"unix:\n  rules:\n    - {id: abstract, action: block, match: {path_globs: [\"@\"]}}\n", "must include a name"},
		"long abstract":           {fmt.Sprintf("unix:\n  rules:\n    - {id: abstract, action: block, match: {path_globs: [%q]}}\n", "@"+strings.Repeat("a", 108)), "exceeds 107 bytes"},
		"empty sockopt levels":    {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [], optnames: [so_mark]}}\n", "match.levels must not be empty"},
		"empty sockopt names":     {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [socket], optnames: []}}\n", "match.optnames must not be empty"},
		"unknown sockopt":         {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [socket], optnames: [so_debug]}}\n", "unsupported socket option name"},
		"duplicate sockopt level": {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [socket, socket], optnames: [so_mark]}}\n", "duplicate socket option level"},
		"duplicate sockopt name":  {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [socket], optnames: [so_mark, so_mark]}}\n", "duplicate socket option name"},
		"egress port zero":        {"egress:\n  rules:\n    - {id: egress, action: block, destinations: {ports: [0]}}\n", "port 0 is not allowed"},
		"bind port zero":          {"bind:\n  rules:\n    - {id: bind, action: allow, endpoints: {ports: [0]}}\n", "port 0 is not allowed"},
		"sockopt alias level":     {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [socket, sol_socket], optnames: [so_mark]}}\n", "duplicate socket option level"},
		"sockopt tcp level":       {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [tcp], optnames: [so_mark]}}\n", "unsupported socket option level"},
		"sockopt missing level":   {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [ip], optnames: [so_mark]}}\n", `requires level "socket"`},
		"sockopt unused level":    {"sockopt:\n  rules:\n    - {id: sockopt, action: block, match: {levels: [socket, ip], optnames: [so_mark]}}\n", `level "ip" has no matching option name`},
		"cross-section duplicate": {"exec:\n  rules:\n    - {id: duplicate, action: block, match: {path_globs: [/tmp/tool]}}\nfile:\n  rules:\n    - {id: duplicate, action: block, match: {path_globs: [/tmp/data]}}\n", "duplicate rule id"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte("version: 1\n" + test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestPublishedExampleAndSchemaAreValid(t *testing.T) {
	t.Parallel()
	example, err := os.ReadFile("../../examples/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(example); err != nil {
		t.Fatalf("published example: %v", err)
	}
	schema, err := os.ReadFile("../../docs/policy.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(schema, &document); err != nil {
		t.Fatalf("published schema: %v", err)
	}
	if got, want := document["$schema"], "https://json-schema.org/draft/2020-12/schema"; got != want {
		t.Fatalf("$schema = %v, want %v", got, want)
	}
}

func TestParseStrictPolicy(t *testing.T) {
	t.Parallel()
	document, err := Parse([]byte(`
version: 1
dns:
  block:
    - bad.example
    - "*.blocked.example"
  allow:
    - safe.blocked.example
egress:
  default: allow
  rules:
    - id: block-metadata
      action: block
      selectors:
        uids: [1000]
        cgroup_prefixes: [/workloads]
      destinations:
        cidrs: [169.254.169.254/32]
        ports: [80]
        protocols: [tcp]
detections:
  - id: curl-metadata
    severity: warning
    events: [connection]
    match:
      directions: [outbound]
      destination_cidrs: [169.254.169.254/32]
    threshold:
      count: 3
      within: 1m
      group_by: [cgroup]
    cooldown: 5m
    message: repeated metadata access
`))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := document.Egress.Rules[0].ID, "block-metadata"; got != want {
		t.Fatalf("egress rule id = %q, want %q", got, want)
	}
	if got, want := document.DetectionRules[0].Threshold.Within.Duration, time.Minute; got != want {
		t.Fatalf("threshold window = %s, want %s", got, want)
	}
	if document.DetectionRules[0].Enabled == nil || !*document.DetectionRules[0].Enabled {
		t.Fatal("detection rule was not enabled by default")
	}
}

func TestParseRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	t.Parallel()
	for name, input := range map[string]string{
		"unknown":  "version: 1\nunknown: true\n",
		"multiple": "version: 1\n---\nversion: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse() error = nil")
			}
		})
	}
}

func TestParseRejectsInvalidOrActionPrefixedDNSEntries(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		dns  string
		want string
	}{
		"allow prefix in block list": {dns: "dns:\n  block: [allow:evil.example]\n", want: "dns.block[0]"},
		"block prefix in allow list": {dns: "dns:\n  allow: [block:safe.example]\n", want: "dns.allow[0]"},
		"invalid domain":             {dns: "dns:\n  block: [not-a-domain]\n", want: "dns.block[0]"},
		"multiline item":             {dns: "dns:\n  block: [\"evil.example\\nother.example\"]\n", want: "dns.block[0]"},
		"allow all":                  {dns: "dns:\n  allow: [\"*\"]\n", want: "dns.allow[0]"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte("version: 1\n" + test.dns))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want indexed DNS entry rejection", err)
			}
		})
	}
}

func TestMergeLocalOverlayReplacesByIDAndAddsDNS(t *testing.T) {
	t.Parallel()
	base, err := Parse([]byte(`
version: 1
dns:
  block: [remote.example]
egress:
  default: block
  rules:
    - id: service-egress
      action: block
      destinations:
        cidrs: [10.0.0.0/8]
detections:
  - id: service-signal
    severity: notice
    events: [exec]
    message: remote
`))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte(`
version: 1
disabled_rule_ids: [baseline.cloud-metadata-access]
dns:
  allow: [remote.example]
  block: [local.example]
egress:
  rules:
    - id: service-egress
      action: allow
      destinations:
        cidrs: [10.1.0.0/16]
detections:
  - id: service-signal
    severity: warning
    events: [exec]
    message: local
`))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	if got, want := bundle.Egress.Default, "block"; got != want {
		t.Fatalf("default = %q, want %q", got, want)
	}
	if got, want := bundle.Egress.Rules[0].Action, "allow"; got != want {
		t.Fatalf("overlay action = %q, want %q", got, want)
	}
	if got, want := bundle.DetectionRules[0].Message, "local"; got != want {
		t.Fatalf("overlay detection = %q, want %q", got, want)
	}
	if got := strings.Join(bundle.DNS.BlockDomains, ","); !strings.Contains(got, "local.example") {
		t.Fatalf("block domains = %q, want local domain", got)
	}
	if got := strings.Join(bundle.DNS.AllowDomains, ","); !strings.Contains(got, "remote.example") {
		t.Fatalf("allow domains = %q, want remote override", got)
	}
}

func TestMergeLocalRuleCanReplaceRemoteRuleType(t *testing.T) {
	t.Parallel()
	base, err := Parse([]byte(`
version: 1
egress:
  rules:
    - id: workload-policy
      action: block
`))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte(`
version: 1
detections:
  - id: workload-policy
    severity: notice
    events: [exec]
    message: local replacement
`))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Egress.Rules) != 0 || len(bundle.DetectionRules) != 1 {
		t.Fatalf("merged rules = egress %d, detection %d; want 0, 1", len(bundle.Egress.Rules), len(bundle.DetectionRules))
	}
}

func TestMergeEnforcementSectionsByID(t *testing.T) {
	t.Parallel()
	base, err := Parse([]byte(`
version: 1
exec:
  rules: [{id: exec-rule, action: block, match: {path_globs: [/remote/exec]}}]
file:
  rules: [{id: file-rule, action: block, match: {path_globs: [/remote/file]}}]
bind:
  default: block
  rules: [{id: bind-rule, action: block, endpoints: {ports: [22]}}]
unix:
  rules: [{id: unix-rule, action: block, match: {path_globs: [/remote/socket]}}]
sockopt:
  rules: [{id: sockopt-rule, action: block, match: {levels: [socket], optnames: [so_mark]}}]
`))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte(`
version: 1
disabled_rule_ids: [file-rule]
exec:
  rules: [{id: exec-rule, action: block, match: {path_globs: [/local/exec]}}]
bind:
  default: allow
unix:
  rules: [{id: unix-rule, action: allow, match: {path_globs: [/local/socket]}}]
sockopt:
  rules: [{id: sockopt-rule, action: allow, match: {levels: [socket], optnames: [so_mark]}}]
`))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if got := bundle.Exec.Rules[0].Match.PathGlobs[0]; got != "/local/exec" {
		t.Fatalf("exec path = %q, want local replacement", got)
	}
	if len(bundle.File.Rules) != 0 {
		t.Fatalf("file rules = %d, want disabled", len(bundle.File.Rules))
	}
	if bundle.Bind.Default != "allow" || len(bundle.Bind.Rules) != 1 {
		t.Fatalf("bind policy = %#v, want local default with remote rule", bundle.Bind)
	}
	if bundle.Unix.Rules[0].Action != "allow" || bundle.Sockopt.Rules[0].Action != "allow" {
		t.Fatalf("local replacements not applied: unix=%s sockopt=%s", bundle.Unix.Rules[0].Action, bundle.Sockopt.Rules[0].Action)
	}
}

func TestDetectionMessageByteLimit(t *testing.T) {
	t.Parallel()

	rule := DetectionRule{
		ID: "message-limit", Severity: "notice", Events: []string{"exec"},
		Message: strings.Repeat("x", MaxDetectionMessageBytes+1),
	}
	if err := rule.validate(); err == nil || !strings.Contains(err.Error(), "message length") {
		t.Fatalf("DetectionRule.validate error = %v, want message byte-limit rejection", err)
	}
}

func TestDetectionCIDRsCanonicalizeMappedPrefixesBeforeMasking(t *testing.T) {
	t.Parallel()

	if err := (DetectionMatch{DestinationCIDRs: []string{"::ffff:192.0.2.129/95"}}).validate(); err == nil || !strings.Contains(err.Error(), "ambiguous below /96") {
		t.Fatalf("below-/96 mapped detection CIDR error = %v, want ambiguity rejection", err)
	}
	if err := (DetectionMatch{DestinationCIDRs: []string{"::ffff:192.0.2.129/120"}}).validate(); err != nil {
		t.Fatalf("mapped detection subnet rejected: %v", err)
	}
}

func TestDetectionRejectsMutableOrNonCanonicalIdentitySelectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		events []string
		match  DetectionMatch
	}{
		{name: "command line", events: []string{"connection"}, match: DetectionMatch{CommandGlobs: []string{"*curl*"}}},
		{name: "cgroup path", events: []string{"connection"}, match: DetectionMatch{CgroupPrefixes: []string{"/workloads"}}},
		{name: "service", events: []string{"connection"}, match: DetectionMatch{Services: []string{"worker.service"}}},
		{name: "container", events: []string{"connection"}, match: DetectionMatch{ContainerIDs: []string{"container"}}},
		{name: "kubernetes", events: []string{"connection"}, match: DetectionMatch{KubernetesNamespace: []string{"production"}}},
		{name: "lsm label", events: []string{"connection"}, match: DetectionMatch{LSMLabels: []string{"label"}}},
		{name: "requested executable", events: []string{"exec"}, match: DetectionMatch{ExecutableGlobs: []string{"/tmp/**"}}},
		{name: "requested file", events: []string{"file_access"}, match: DetectionMatch{FilePathGlobs: []string{"/etc/shadow"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := DetectionRule{
				ID: "event-time-only", Severity: "warning", Events: test.events,
				Match: test.match, Message: "event-time identity only",
			}
			if err := rule.validate(); err == nil {
				t.Fatal("DetectionRule.validate accepted a mutable or non-canonical selector")
			}
		})
	}
}

func TestDetectionRejectsUnavailableOrCachedProcessIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		events    []string
		match     DetectionMatch
		exclude   DetectionMatch
		groupBy   []string
		wantError string
	}{
		{name: "dns uid", events: []string{"dns"}, match: DetectionMatch{UIDs: []uint32{1000}}, wantError: "cached identity"},
		{name: "blocked dns uid", events: []string{"blocked"}, match: DetectionMatch{UIDs: []uint32{1000}}, wantError: "cached identity"},
		{name: "sockops uid", events: []string{"tcp_sockops"}, match: DetectionMatch{UIDs: []uint32{1000}}, wantError: "cached identity"},
		{
			name: "inbound tcp uid", events: []string{"connection"},
			match:     DetectionMatch{Directions: []string{"inbound"}, Protocols: []string{"tcp"}, UIDs: []uint32{1000}},
			wantError: "inbound TCP",
		},
		{
			name: "broad connection uid exclusion", events: []string{"connection"},
			exclude: DetectionMatch{UIDs: []uint32{0}}, wantError: "inbound TCP",
		},
		{name: "dns cgroup grouping", events: []string{"dns"}, groupBy: []string{"cgroup"}, wantError: "cached identity"},
		{
			name: "inbound tcp executable grouping", events: []string{"connection"},
			match:   DetectionMatch{Directions: []string{"inbound"}, Protocols: []string{"tcp"}},
			groupBy: []string{"executable"}, wantError: "inbound TCP",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rule := DetectionRule{
				ID: "trusted-identity-only", Severity: "warning", Events: test.events,
				Match: test.match, Exclude: test.exclude, Message: "trusted identity",
			}
			if len(test.groupBy) > 0 {
				rule.Threshold = Threshold{
					Count: 2, Within: Duration{Duration: time.Minute}, GroupBy: test.groupBy,
				}
			}
			err := rule.validate()
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("DetectionRule.validate error = %v, want %q", err, test.wantError)
			}
		})
	}
}

func TestDetectionAcceptsContemporaneousProcessIdentity(t *testing.T) {
	t.Parallel()

	rules := []DetectionRule{
		{
			ID: "resolver-uid", Severity: "warning", Events: []string{"resolver"},
			Match: DetectionMatch{UIDs: []uint32{1000}}, Message: "resolver identity",
		},
		{
			ID: "outbound-connection-uid", Severity: "warning", Events: []string{"connection"},
			Match: DetectionMatch{Directions: []string{"outbound"}, UIDs: []uint32{1000}}, Message: "outbound identity",
		},
		{
			ID: "udp-connection-uid", Severity: "warning", Events: []string{"connection"},
			Match: DetectionMatch{Protocols: []string{"udp"}, UIDs: []uint32{1000}}, Message: "udp identity",
		},
		{
			ID: "outbound-root-exclusion", Severity: "warning", Events: []string{"connection"},
			Match: DetectionMatch{Directions: []string{"outbound"}}, Exclude: DetectionMatch{UIDs: []uint32{0}},
			Message: "safe exclusion",
		},
		{
			ID: "outbound-identity-group", Severity: "warning", Events: []string{"connection"},
			Match: DetectionMatch{Directions: []string{"outbound"}},
			Threshold: Threshold{
				Count: 2, Within: Duration{Duration: time.Minute}, GroupBy: []string{"cgroup", "executable", "uid"},
			},
			Message: "safe grouping",
		},
	}
	for _, rule := range rules {
		if err := rule.validate(); err != nil {
			t.Errorf("DetectionRule.validate rejected %q: %v", rule.ID, err)
		}
	}
}

func TestDetectionAcceptsKernelResolvedPathSelectors(t *testing.T) {
	t.Parallel()

	for _, rule := range []DetectionRule{
		{ID: "exec-path", Severity: "warning", Events: []string{"exec_blocked", "exec_would_block"}, Match: DetectionMatch{ExecutableGlobs: []string{"/tmp/**"}}, Message: "resolved exec"},
		{ID: "file-path", Severity: "warning", Events: []string{"file_blocked", "file_would_block"}, Match: DetectionMatch{FilePathGlobs: []string{"/etc/**"}}, Message: "resolved file"},
	} {
		if err := rule.validate(); err != nil {
			t.Fatalf("DetectionRule.validate rejected kernel-resolved selectors: %v", err)
		}
	}
}

func TestDetectionPathGroupingRequiresResolvedPathEvents(t *testing.T) {
	t.Parallel()

	rule := DetectionRule{
		ID: "requested-path-group", Severity: "warning", Events: []string{"file_access"},
		Threshold: Threshold{
			Count: 2, Within: Duration{Duration: time.Minute}, GroupBy: []string{"path"},
		},
		Message: "do not group requested aliases",
	}
	if err := rule.validate(); err == nil || !strings.Contains(err.Error(), "resolved-path") {
		t.Fatalf("DetectionRule.validate error = %v, want requested-path grouping rejection", err)
	}
}

func TestDetectionGroupingRejectsDuplicatesAndOversizedLists(t *testing.T) {
	t.Parallel()

	base := DetectionRule{
		ID: "grouping", Severity: "warning", Events: []string{"connection"},
		Threshold: Threshold{Count: 2, Within: Duration{Duration: time.Minute}},
		Message:   "bounded grouping",
	}
	duplicate := base
	duplicate.Threshold.GroupBy = []string{"uid", "uid"}
	if err := duplicate.validate(); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate group_by error = %v, want duplicate rejection", err)
	}
	oversized := base
	oversized.Threshold.GroupBy = make([]string, len(supportedGroupFields)+1)
	for index := range oversized.Threshold.GroupBy {
		oversized.Threshold.GroupBy[index] = "uid"
	}
	if err := oversized.validate(); err == nil || !strings.Contains(err.Error(), "count") {
		t.Fatalf("oversized group_by error = %v, want count rejection", err)
	}
}

func TestDetectionPathPatternsFitCanonicalEventIdentity(t *testing.T) {
	t.Parallel()

	for _, pattern := range []string{
		"tmp/tool",
		"/tmp/*/tool",
		"/tmp/tool?",
		"/tmp/[ab]",
		"/" + strings.Repeat("x", MaxDetectionPathStemBytes),
	} {
		if err := validateDetectionPathPattern(pattern); err == nil {
			t.Errorf("validateDetectionPathPattern(%q) accepted unsafe pattern", pattern)
		}
	}
	for _, pattern := range []string{"/tmp/tool", "/tmp/**", "/**"} {
		if err := validateDetectionPathPattern(pattern); err != nil {
			t.Errorf("validateDetectionPathPattern(%q) error = %v", pattern, err)
		}
	}
}

func TestMergeRejectsAggregateSelectorCompilationWork(t *testing.T) {
	t.Parallel()

	selectors := make([]string, MaxRuleListValues)
	for index := range selectors {
		selectors[index] = fmt.Sprintf("/workloads/%d", index)
	}
	makeRules := func(prefix string, count int) []EgressRule {
		rules := make([]EgressRule, 0, count)
		for index := range count {
			rules = append(rules, EgressRule{
				ID: prefix + fmt.Sprint(index), Action: "block",
				Selectors:    EgressSelectors{CgroupPaths: selectors},
				Destinations: EgressDestinations{CIDRs: []string{"10.0.0.0/8"}},
			})
		}
		return rules
	}
	base := Document{Version: Version, Egress: EgressPolicy{Rules: makeRules("base-", 9)}}
	overlay := Document{Version: Version, Egress: EgressPolicy{Rules: makeRules("overlay-", 8)}}
	if _, err := Merge(base, overlay); err == nil || !strings.Contains(err.Error(), "merged cgroup selector count") {
		t.Fatalf("Merge error = %v, want aggregate selector rejection", err)
	}
}

func TestBundleRejectsAggregateDetectionSampleBudget(t *testing.T) {
	t.Parallel()

	enabled := true
	rules := make([]DetectionRule, 0, 7)
	for index := range 7 {
		rules = append(rules, DetectionRule{
			ID: fmt.Sprintf("threshold-%d", index), Enabled: &enabled,
			Severity: "notice", Events: []string{"connection"}, Message: "bounded",
			Match: DetectionMatch{Directions: []string{"outbound"}},
			Threshold: Threshold{
				Count: MaxThresholdCount, Within: Duration{Duration: time.Minute},
				GroupBy: []string{"cgroup"},
			},
		})
	}
	bundle := Bundle{DetectionRules: rules}
	if err := bundle.Validate(); err == nil || !strings.Contains(err.Error(), "sample budget") {
		t.Fatalf("Bundle.Validate error = %v, want aggregate sample rejection", err)
	}
}
