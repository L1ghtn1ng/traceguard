package app

import (
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestRecordFileAuditFirstSeenCountsSuppressedRepeats(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	metrics := telemetry.NewRegistry()
	cfg := config.Config{FileAuditFirstSeen: true}
	fields := map[string]any{"event": "file_access", "requested_path": "/etc/hosts", "current_exe": "/usr/bin/cat"}
	timestamp := time.Unix(1_700_000_000, 0)
	for offset := range 3 {
		recordFileAudit(cfg, recorder, metrics, timestamp.Add(time.Duration(offset)*time.Hour), "file_access", fields)
	}
	if got := strings.Count(output.String(), `"requested_path":"/etc/hosts"`); got != 1 {
		t.Fatalf("recorded %d file audit events, want 1: %s", got, output.String())
	}
	if !strings.Contains(metrics.Render(), `traceguard_first_seen_suppressed_total{event="file_access"} 2`) {
		t.Fatalf("suppressed repeats not counted:\n%s", metrics.Render())
	}
}

func TestRecordFileAuditDefaultKeepsPeriodicRepeats(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	metrics := telemetry.NewRegistry()
	fields := map[string]any{"event": "file_access", "requested_path": "/etc/hosts", "current_exe": "/usr/bin/cat"}
	recordFileAudit(config.Config{}, recorder, metrics, time.Now(), "file_access", fields)
	if !strings.Contains(output.String(), "/etc/hosts") || strings.Contains(metrics.Render(), "first_seen") {
		t.Fatalf("default file audit recording changed: %s", output.String())
	}
}
