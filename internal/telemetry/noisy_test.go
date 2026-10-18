package telemetry

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestReportNoisyRulesRanksLiveMetrics(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	for range 5 {
		registry.IncDetectionAlert("baseline.cloud-metadata-access", "warning")
	}
	registry.IncDetectionAlert("custom.odd\"rule", "notice")
	for range 3 {
		registry.IncDetectionAlert("runtime.fileless-exec", "warning")
	}
	registry.SetDetectionExceptions(1, 0, map[string]uint64{"runc-self-reexec": 40})
	server := httptest.NewServer(registry.httpHandler())
	t.Cleanup(server.Close)

	var out bytes.Buffer
	addr := strings.TrimPrefix(server.URL, "http://")
	if err := ReportNoisyRules(t.Context(), NoisyRulesConfig{MetricsAddr: addr}, &out); err != nil {
		t.Fatalf("ReportNoisyRules: %v", err)
	}
	report := out.String()
	metadata := strings.Index(report, "baseline.cloud-metadata-access")
	fileless := strings.Index(report, "runtime.fileless-exec")
	odd := strings.Index(report, `custom.odd"rule`)
	if metadata < 0 || fileless < 0 || odd < 0 || metadata > fileless || fileless > odd {
		t.Fatalf("rules not ranked busiest first:\n%s", report)
	}
	for _, want := range []string{"alerts since the daemon started", ": 9", "55.6%", "runc-self-reexec", "40"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
}

func TestReportNoisyRulesWindowCountsOnlyNewAlerts(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	for range 100 {
		registry.IncDetectionAlert("baseline.direct-email-egress", "notice")
	}
	server := httptest.NewServer(registry.httpHandler())
	t.Cleanup(server.Close)

	done := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		done <- ReportNoisyRules(t.Context(), NoisyRulesConfig{
			MetricsAddr: strings.TrimPrefix(server.URL, "http://"), Window: 200 * time.Millisecond,
		}, &out)
	}()
	time.Sleep(50 * time.Millisecond)
	registry.IncDetectionAlert("runtime.ptrace-attach", "warning")
	registry.IncDetectionAlert("runtime.ptrace-attach", "warning")
	registry.IncDetectionAlert("baseline.direct-email-egress", "notice")
	if err := <-done; err != nil {
		t.Fatalf("ReportNoisyRules: %v", err)
	}
	report := out.String()
	if !strings.Contains(report, "during the last 200ms: 3") {
		t.Fatalf("window total wrong:\n%s", report)
	}
	if strings.Index(report, "runtime.ptrace-attach") > strings.Index(report, "baseline.direct-email-egress") {
		t.Fatalf("window ranking used cumulative counts:\n%s", report)
	}
}

func TestReportNoisyRulesRejectsOtherEndpoints(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(NewRegistry().httpHandler())
	t.Cleanup(server.Close)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := ReportNoisyRules(ctx, NoisyRulesConfig{MetricsAddr: strings.TrimPrefix(server.URL, "http://")}, &bytes.Buffer{}); err == nil {
		t.Fatal("a cancelled scrape succeeded")
	}
	if _, err := ParseAlertSnapshot(strings.NewReader("some_metric 1\n")); err == nil || !strings.Contains(err.Error(), "uptime") {
		t.Fatalf("non-TraceGuard metrics error = %v", err)
	}
}

func TestParseAlertSnapshotHandlesResetsAndEscapes(t *testing.T) {
	t.Parallel()

	before, err := ParseAlertSnapshot(strings.NewReader("traceguard_uptime_seconds 10\n" +
		`traceguard_detection_alerts_total{rule_id="a",severity="warning"} 50` + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	after, err := ParseAlertSnapshot(strings.NewReader("# TYPE x counter\ntraceguard_uptime_seconds 20\n" +
		`traceguard_detection_alerts_total{rule_id="a",severity="warning"} 4` + "\n" +
		`traceguard_detection_alerts_total{rule_id="b\\\"c",severity="notice"} 2` + "\n" +
		`traceguard_detection_alerts_total{rule_id="b\\\"c",severity="warning"} 1` + "\n" +
		"garbage{ 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	report := RankNoisyRules(before, after, 10*time.Second, false)
	if len(report.Rules) != 2 || report.Rules[0].ID != "a" || report.Rules[0].Count != 4 {
		t.Fatalf("reset counter not taken as its new value: %+v", report.Rules)
	}
	if report.Rules[1].ID != `b\"c` || report.Rules[1].Count != 3 || report.Rules[1].Severity != "notice,warning" {
		t.Fatalf("escaped multi-severity rule = %+v", report.Rules[1])
	}
}
