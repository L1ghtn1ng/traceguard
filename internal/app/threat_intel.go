package app

import (
	"maps"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/threatintel"
)

const threatIntelPollInterval = time.Minute

// feedWatcher re-applies policy when a threat intelligence feed file changes,
// judged by its file signature so unchanged feeds are not re-read.
type feedWatcher struct {
	source     func() policyconfig.Bundle
	refresh    func() error
	metrics    *telemetry.Registry
	recorder   *eventsink.Recorder
	signatures map[string]string
}

func feedSignatures(feeds []policyconfig.ThreatIntelFeed) map[string]string {
	signatures := make(map[string]string, len(feeds))
	for _, feed := range feeds {
		signatures[feed.Path] = threatintel.Signature(feed.Path)
	}
	return signatures
}

func (w *feedWatcher) collect(time.Time) {
	source := w.source()
	current := feedSignatures(source.ThreatIntel.Feeds)
	if w.signatures == nil {
		w.signatures = current
		return
	}
	if maps.Equal(current, w.signatures) {
		return
	}
	if err := applyPolicyWithHealth(w.metrics, w.refresh); err != nil {
		// Keep the old signatures so the reload is retried.
		w.recorder.ErrorDedup("reload threat intel feeds", err, nil, policyRefreshErrorDedupeTTL)
		return
	}
	w.signatures = current
	w.recorder.Info("threat intel feeds reloaded", map[string]any{"feeds": len(source.ThreatIntel.Feeds)})
}
