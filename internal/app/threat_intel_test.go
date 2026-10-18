package app

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
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
		refresh: func() error {
			applied++
			if failing {
				return errors.New("blocking feed exceeds policy limits")
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
	sink := alertSink{recorder: recorder, metrics: metrics}
	emitThreatIntelAlerts(threatintel.NewMatcher([]threatintel.Feed{feed}), sink, time.Unix(1, 0), "dns", map[string]any{"domain": "c2.evil.example"})
	emitThreatIntelAlerts(nil, sink, time.Unix(1, 0), "dns", map[string]any{"domain": "c2.evil.example"})
	for _, want := range []string{`"detection_rule_id":"threat_intel.bad"`, `"threat_intel_indicator":"evil.example"`, `"severity":"critical"`} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("alert record missing %s: %s", want, output.String())
		}
	}
	if !strings.Contains(metrics.Render(), `traceguard_detection_alerts_total{rule_id="threat_intel.bad",severity="critical"} 1`) {
		t.Fatalf("alert metric missing:\n%s", metrics.Render())
	}
}

func TestValidateResponseRules(t *testing.T) {
	t.Parallel()

	bundle := policyconfig.Bundle{
		DetectionSequences: []policyconfig.DetectionSequence{{ID: "web-shell-egress"}},
		ThreatIntel:        policyconfig.ThreatIntelPolicy{Feeds: []policyconfig.ThreatIntelFeed{{ID: "c2"}}},
		Responses: []policyconfig.Response{{ID: "r", Rules: []string{
			"baseline.inbound-ssh-bruteforce", "runtime.ptrace-attach", "web-shell-egress", "threat_intel.c2",
		}}},
	}
	if err := validateResponseRules(bundle); err != nil {
		t.Fatalf("known rules rejected: %v", err)
	}
	bundle.Responses[0].Rules = append(bundle.Responses[0].Rules, "typo.rule")
	if err := validateResponseRules(bundle); err == nil || !strings.Contains(err.Error(), `unknown rule "typo.rule"`) {
		t.Fatalf("unknown rule error = %v", err)
	}
}

func TestPolicyDigestIncludesFeedContents(t *testing.T) {
	t.Parallel()

	bundle := policyconfig.Bundle{DNS: blocklist.Rules{BlockDomains: []string{"example.com"}}}
	plain, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := policyDigest(bundle, ""); err != nil || digest != plain {
		t.Fatalf("digest without feeds = %q, %v; want the bundle digest %q", digest, err, plain)
	}
	first, _ := policyDigest(bundle, "bad=aa")
	second, _ := policyDigest(bundle, "bad=bb")
	if first == plain || first == second {
		t.Fatalf("feed contents did not change the digest: %q %q %q", plain, first, second)
	}
}

func TestDetectionInputsIgnoreKernelRules(t *testing.T) {
	t.Parallel()

	base := policyconfig.Bundle{DetectionRules: []policyconfig.DetectionRule{{ID: "r"}}}
	withBlocks := base
	withBlocks.DNS.BlockSuffixes = []string{"evil.example"}
	if !reflect.DeepEqual(detectionInputs(base), detectionInputs(withBlocks)) {
		t.Fatal("a blocking feed's DNS rules counted as a detection change")
	}
	changed := base
	changed.DetectionRules = []policyconfig.DetectionRule{{ID: "other"}}
	if reflect.DeepEqual(detectionInputs(base), detectionInputs(changed)) {
		t.Fatal("a changed detection rule was not a detection change")
	}
}
