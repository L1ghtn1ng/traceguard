package replay

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const archive = `{"timestamp":"2026-10-18T10:00:00Z","level":"info","message":"policy loaded","policy_sha256":"abc"}
{"timestamp":"2026-10-18T10:00:01Z","level":"info","message":"connection","event":"connection","direction":"outbound","peer_address":"169.254.169.254","peer_port":80,"socket_protocol":"tcp","kernel_uid":0,"cgroup_id":18446744073709551615,"program":"agent"}
{"timestamp":"2026-10-18T10:00:02Z","level":"info","message":"connection","event":"connection","direction":"outbound","peer_address":"169.254.169.254","peer_port":80,"socket_protocol":"tcp","kernel_uid":1000,"cgroup_id":18446744073709551614,"program":"curl"}
{"timestamp":"2026-10-18T10:00:03Z","level":"info","message":"detection-alert","event":"detection_alert","detection_rule_id":"baseline.cloud-metadata-access"}
{"timestamp":"2026-10-18T10:00:04Z","level":"info","message":"heartbeat","event":"heartbeat"}
not json
`

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunEvaluatesArchivedEventsWithBaseline(t *testing.T) {
	t.Parallel()

	var alerts bytes.Buffer
	summary, err := Run(Config{ArchivePath: writeFile(t, "events.jsonl", archive)}, &alerts)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if summary.Records != 6 || summary.Evaluated != 2 || summary.Skipped != 3 || summary.Malformed != 1 {
		t.Fatalf("summary counts = %+v", summary)
	}
	// The two connections come from different cgroups, so the per-process
	// cooldown must not merge them: 64-bit IDs have to stay exact.
	if got := summary.Alerts["baseline.cloud-metadata-access"]; got != 2 {
		t.Fatalf("metadata alerts = %d, want 2", got)
	}
	lines := strings.Split(strings.TrimSpace(alerts.String()), "\n")
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatal(err)
	}
	if record["event"] != "detection_alert" || record["source_event"] != "connection" || record["timestamp"] != "2026-10-18T10:00:01Z" {
		t.Fatalf("alert record = %v", record)
	}
}

func TestRunAppliesPolicyRulesAndExceptions(t *testing.T) {
	t.Parallel()

	policyPath := writeFile(t, "policy.yaml", `
version: 1
disabled_rule_ids: [baseline.direct-email-egress]
detection_exceptions:
  - id: root-agent
    rules: [baseline.cloud-metadata-access]
    reason: guest agent runs as root
    match: {uids: [0]}
`)
	var alerts bytes.Buffer
	summary, err := Run(Config{ArchivePath: writeFile(t, "events.jsonl", archive), PolicyPath: policyPath}, &alerts)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := summary.Alerts["baseline.cloud-metadata-access"]; got != 1 {
		t.Fatalf("metadata alerts = %d, want 1 after the root exception", got)
	}
	if len(summary.Exceptions) != 1 || summary.Exceptions[0].Suppressed != 1 {
		t.Fatalf("exceptions = %+v, want one suppression", summary.Exceptions)
	}

	var out bytes.Buffer
	if err := WriteSummary(summary, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"baseline.cloud-metadata-access  1", "root-agent", "evaluated  2"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunReadsGzipArchives(t *testing.T) {
	t.Parallel()

	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(archive)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	summary, err := Run(Config{ArchivePath: writeFile(t, "events.jsonl.1.gz", compressed.String())}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if summary.Evaluated != 2 {
		t.Fatalf("evaluated = %d, want 2", summary.Evaluated)
	}
}

func TestRunRejectsInvalidPolicy(t *testing.T) {
	t.Parallel()

	policyPath := writeFile(t, "policy.yaml", "version: 1\ndetection_exceptions:\n  - {id: x, rules: [missing], reason: r, match: {uids: [0]}}\n")
	if _, err := Run(Config{ArchivePath: writeFile(t, "events.jsonl", archive), PolicyPath: policyPath}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("Run error = %v, want unknown rule rejection", err)
	}
}

func TestConvertNumberKeepsIntegersExact(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]any{
		"18446744073709551615": uint64(18446744073709551615),
		"-3":                   int64(-3),
		"1.5":                  1.5,
	} {
		if got := convertNumber(json.Number(input)); got != want {
			t.Errorf("convertNumber(%s) = %#v, want %#v", input, got, want)
		}
	}
}
