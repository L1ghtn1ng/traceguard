package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseDetectionExceptions(t *testing.T) {
	t.Parallel()

	for name, expires := range map[string]string{"unquoted": "2026-12-31T00:00:00Z", "quoted": `"2026-12-31T01:00:00+01:00"`} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document, err := Parse([]byte(`
version: 1
detection_exceptions:
  - id: guest-agent-imds
    rules: [baseline.cloud-metadata-access]
    reason: guest agent polls instance metadata
    expires: ` + expires + `
    match: {uids: [0]}
`))
			if err != nil {
				t.Fatalf("Parse returned error: %v", err)
			}
			exception := document.DetectionExceptions[0]
			if want := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC); !exception.Expires.Equal(want) || exception.Expires.Location() != time.UTC {
				t.Fatalf("expires = %v, want %v in UTC", exception.Expires, want)
			}
			if !exception.Active(time.Date(2026, 12, 30, 0, 0, 0, 0, time.UTC)) || exception.Active(time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)) {
				t.Fatal("Active does not end at expires")
			}
		})
	}
}

func TestParseRejectsInvalidDetectionExceptions(t *testing.T) {
	t.Parallel()

	valid := "    rules: [baseline.cloud-metadata-access]\n    reason: agent\n    match: {uids: [0]}\n"
	tests := map[string]struct {
		body string
		want string
	}{
		"missing rules":   {"    reason: agent\n    match: {uids: [0]}\n", "rules must not be empty"},
		"missing reason":  {"    rules: [baseline.cloud-metadata-access]\n    match: {uids: [0]}\n", "reason must not be empty"},
		"empty match":     {"    rules: [baseline.cloud-metadata-access]\n    reason: agent\n", "match must not be empty"},
		"bad timestamp":   {valid + "    expires: tomorrow\n", "RFC 3339"},
		"bad rule id":     {"    rules: [Bad_ID]\n    reason: agent\n    match: {uids: [0]}\n", "invalid rule id"},
		"duplicate rule":  {"    rules: [a.b, a.b]\n    reason: agent\n    match: {uids: [0]}\n", "duplicate exception rule"},
		"unknown field":   {valid + "    until: 2026-01-01T00:00:00Z\n", "until"},
		"long reason":     {"    rules: [a.b]\n    reason: " + strings.Repeat("x", MaxExceptionReasonBytes+1) + "\n    match: {uids: [0]}\n", "reason length"},
		"mutable context": {"    rules: [a.b]\n    reason: agent\n    match: {services: [cron.service]}\n", "not captured at event time"},
		"long program":    {"    rules: [a.b]\n    reason: agent\n    match: {programs: [amazon-ssm-agent]}\n", "15-byte comm"},
		"bad program":     {"    rules: [a.b]\n    reason: agent\n    match: {programs: [\"ag[\"]}\n", "invalid program glob"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse([]byte("version: 1\ndetection_exceptions:\n  - id: example\n" + test.body))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse error = %v, want %q", err, test.want)
			}
		})
	}

	_, err := Parse([]byte("version: 1\ndetection_exceptions:\n  - id: example\n" + valid + "  - id: example\n" + valid))
	if err == nil || !strings.Contains(err.Error(), "duplicate detection exception id") {
		t.Fatalf("duplicate exception id error = %v", err)
	}
}

func TestMergeOverlayReplacesExceptionByID(t *testing.T) {
	t.Parallel()

	base, err := Parse([]byte(`
version: 1
detection_exceptions:
  - {id: shared, rules: [a.b], reason: base, match: {uids: [0]}}
  - {id: base-only, rules: [a.b], reason: base, match: {uids: [1]}}
`))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte(`
version: 1
detection_exceptions:
  - {id: shared, rules: [a.b], reason: overlay, match: {uids: [2]}}
`))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.DetectionExceptions) != 2 {
		t.Fatalf("exceptions = %+v, want two", bundle.DetectionExceptions)
	}
	if got := bundle.DetectionExceptions; got[0].ID != "base-only" || got[1].ID != "shared" || got[1].Reason != "overlay" {
		t.Fatalf("merged exceptions = %+v, want sorted with overlay winning", got)
	}
}

func TestProgramsAreExceptionOnly(t *testing.T) {
	t.Parallel()

	for name, document := range map[string]string{
		"rule match": `
version: 1
detections:
  - id: by-comm
    severity: notice
    events: [exec]
    match: {programs: [curl]}
    message: curl ran
`,
		"rule exclude": `
version: 1
detections:
  - id: by-comm
    severity: notice
    events: [exec]
    match: {exec_sources: [fd]}
    exclude: {programs: [runc]}
    message: fd exec
`,
	} {
		if _, err := Parse([]byte(document)); err == nil || !strings.Contains(err.Error(), "only in detection exceptions") {
			t.Errorf("%s: Parse error = %v, want an exception-only error", name, err)
		}
	}
}

func TestProgramsRequireEventTimeIdentity(t *testing.T) {
	t.Parallel()

	exception := DetectionException{ID: "x", Rules: []string{"r"}, Reason: "r", Match: DetectionMatch{Programs: []string{"agent"}}}
	if err := ValidateExceptionFor(DetectionRule{ID: "r", Events: []string{"dns"}}, exception); err == nil || !strings.Contains(err.Error(), "programs require event-time process identity") {
		t.Fatalf("dns exception error = %v", err)
	}
	if err := ValidateExceptionFor(DetectionRule{ID: "r", Events: []string{"connection"}}, exception); err == nil {
		t.Fatal("programs accepted for connection rules that may match inbound TCP")
	}
	outbound := DetectionRule{ID: "r", Events: []string{"connection"}, Match: DetectionMatch{Directions: []string{"outbound"}}}
	if err := ValidateExceptionFor(outbound, exception); err != nil {
		t.Fatalf("outbound connection exception error = %v", err)
	}
}
