package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestApplyPolicyWithHealthTracksFailureAndRecovery(t *testing.T) {
	t.Parallel()

	metrics := telemetry.NewRegistry()
	wantErr := errors.New("apply failed")
	if err := applyPolicyWithHealth(metrics, func() error { return wantErr }); !errors.Is(err, wantErr) {
		t.Fatalf("applyPolicyWithHealth() error = %v, want %v", err, wantErr)
	}
	if metrics.Healthy() {
		t.Fatal("metrics stayed healthy after policy apply failure")
	}
	if rendered := metrics.Render(); !strings.Contains(rendered, `traceguard_policy_source_healthy{source="apply"} 0`) {
		t.Fatalf("metrics missing failed apply health: %s", rendered)
	}

	if err := applyPolicyWithHealth(metrics, func() error { return nil }); err != nil {
		t.Fatalf("applyPolicyWithHealth() recovery error = %v", err)
	}
	if !metrics.Healthy() {
		t.Fatal("metrics did not recover after successful policy apply")
	}
	if rendered := metrics.Render(); !strings.Contains(rendered, `traceguard_policy_source_healthy{source="apply"} 1`) {
		t.Fatalf("metrics missing recovered apply health: %s", rendered)
	}
}
