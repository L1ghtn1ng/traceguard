package app

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/threatintel"
)

func TestFeedWatcherReappliesOnlyWhenFeedsChange(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := policyconfig.Bundle{ThreatIntel: policyconfig.ThreatIntelPolicy{Feeds: []policyconfig.ThreatIntelFeed{{
		ID: "bad", Path: path, Type: policyconfig.FeedTypeDomains,
	}}}}
	recorder, output := newTestRecorder(t)
	applied := 0
	failing := false
	watcher := &feedWatcher{
		source: func() policyconfig.Bundle { return source },
		apply: func(policyconfig.Bundle) error {
			applied++
			if failing {
				return errors.New("feed half written")
			}
			return nil
		},
		metrics: telemetry.NewRegistry(), recorder: recorder,
	}
	watcher.collect(time.Now())
	watcher.collect(time.Now())
	if applied != 0 {
		t.Fatalf("unchanged feeds were re-applied %d times", applied)
	}

	if err := os.WriteFile(path, []byte("evil.example\nworse.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	failing = true
	watcher.collect(time.Now())
	watcher.collect(time.Now())
	if applied != 2 || !strings.Contains(output.String(), "reload threat intel feeds") {
		t.Fatalf("failed reload applied %d times, want a retry on each poll; log %s", applied, output.String())
	}
	failing = false
	watcher.collect(time.Now())
	watcher.collect(time.Now())
	if applied != 3 || !strings.Contains(output.String(), "threat intel feeds reloaded") {
		t.Fatalf("successful reload applied %d times in total, want 3", applied)
	}
}

func TestEmitThreatIntelAlertsRecordsMatches(t *testing.T) {
	t.Parallel()

	feed, err := threatintel.Parse(policyconfig.ThreatIntelFeed{ID: "bad", Type: policyconfig.FeedTypeDomains, Severity: "critical"}, []byte("evil.example\n"))
	if err != nil {
		t.Fatal(err)
	}
	recorder, output := newTestRecorder(t)
	metrics := telemetry.NewRegistry()
	emitThreatIntelAlerts(threatintel.NewMatcher([]threatintel.Feed{feed}), recorder, metrics, time.Unix(1, 0), "dns", map[string]any{"domain": "c2.evil.example"})
	emitThreatIntelAlerts(nil, recorder, metrics, time.Unix(1, 0), "dns", map[string]any{"domain": "c2.evil.example"})
	for _, want := range []string{`"detection_rule_id":"threat_intel.bad"`, `"threat_intel_indicator":"evil.example"`, `"severity":"critical"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("alert record missing %s: %s", want, output.String())
		}
	}
	if !strings.Contains(metrics.Render(), `traceguard_detection_alerts_total{rule_id="threat_intel.bad",severity="critical"} 1`) {
		t.Fatalf("alert metric missing:\n%s", metrics.Render())
	}
}
