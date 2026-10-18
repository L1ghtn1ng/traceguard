package policy

import (
	"strings"
	"testing"
)

const validSequence = `
version: 1
detection_sequences:
  - id: shell-then-egress
    severity: critical
    key: process
    within: 5m
    message: a shell connected out
    steps:
      - events: [exec]
        match: {command_globs: ["sh *"]}
      - events: [connection]
        match: {directions: [outbound]}
`

func TestParseDetectionSequence(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(validSequence))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if sequence := document.DetectionSequences[0]; len(sequence.Steps) != 2 || sequence.FinalStepRule().Events[0] != "connection" {
		t.Fatalf("sequence = %+v", sequence)
	}
}

func TestParseRejectsInvalidDetectionSequences(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct{ from, to, want string }{
		"unknown key":     {"key: process", "key: host", "key must be"},
		"long window":     {"within: 5m", "within: 2h", "within must be"},
		"no identity":     {"events: [connection]", "events: [dns]", "event-time process identity"},
		"cached identity": {"match: {directions: [outbound]}", "match: {ports: [443]}", "inbound TCP"},
		"one step": {`      - events: [connection]
        match: {directions: [outbound]}
`, "", "steps must number"},
	} {
		document := strings.Replace(validSequence, test.from, test.to, 1)
		if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}

	duplicate := validSequence + "detections:\n  - {id: shell-then-egress, severity: notice, events: [exec], message: x}\n"
	if _, err := Parse([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate rule id") {
		t.Fatalf("duplicate id error = %v", err)
	}
}

func TestMergeDisablesSequencesByID(t *testing.T) {
	t.Parallel()

	base, err := Parse([]byte(validSequence))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte("version: 1\ndisabled_rule_ids: [shell-then-egress]\n"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.DetectionSequences) != 0 {
		t.Fatalf("disabled sequence survived the merge: %+v", bundle.DetectionSequences)
	}
}
