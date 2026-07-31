package policy

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

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
      executable_globs: ["*/curl"]
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
disabled_rule_ids: [baseline.exec-from-shared-memory]
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
