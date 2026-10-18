package detection

import (
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func metadataEvent(at int64, uid uint32) Event {
	return Event{
		Timestamp: time.Unix(at, 0),
		Name:      "connection",
		Fields: map[string]any{
			"direction": "outbound", "peer_address": "169.254.169.254", "peer_port": uint16(80),
			"protocol": "tcp", "kernel_uid": uid, "cgroup_id": uint64(uid), "program": "agent",
		},
	}
}

func metadataException(expires time.Time) policy.DetectionException {
	return policy.DetectionException{
		ID: "guest-agent-imds", Rules: []string{"baseline.cloud-metadata-access"},
		Reason: "guest agent polls instance metadata", Expires: policy.Timestamp{Time: expires},
		Match: policy.DetectionMatch{UIDs: []uint32{0}, Directions: []string{"outbound"}},
	}
}

func installExceptions(t *testing.T, exceptions ...policy.DetectionException) *Engine {
	t.Helper()
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(nil, []string{"baseline.direct-email-egress", "baseline.policy-denial-burst"}, exceptions)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	engine.Install(compiled)
	return engine
}

func TestExceptionSuppressesMatchingEventsUntilExpiry(t *testing.T) {
	t.Parallel()

	engine := installExceptions(t, metadataException(time.Unix(100, 0)))
	if alerts := engine.Evaluate(metadataEvent(10, 0)); len(alerts) != 0 {
		t.Fatalf("excepted event raised %d alerts", len(alerts))
	}
	if alerts := engine.Evaluate(metadataEvent(11, 1000)); len(alerts) != 1 {
		t.Fatalf("event outside the exception raised %d alerts, want 1", len(alerts))
	}
	if alerts := engine.Evaluate(metadataEvent(100, 0)); len(alerts) != 1 {
		t.Fatalf("event at expiry raised %d alerts, want 1", len(alerts))
	}

	statuses := engine.ExceptionStatus(time.Unix(50, 0))
	if len(statuses) != 1 || statuses[0].ID != "guest-agent-imds" || statuses[0].Expired || statuses[0].Suppressed != 1 {
		t.Fatalf("status before expiry = %+v", statuses)
	}
	if statuses := engine.ExceptionStatus(time.Unix(100, 0)); !statuses[0].Expired {
		t.Fatalf("status at expiry = %+v, want expired", statuses)
	}
}

func TestExceptionWithoutExpiryNeverExpires(t *testing.T) {
	t.Parallel()

	engine := installExceptions(t, metadataException(time.Time{}))
	if alerts := engine.Evaluate(metadataEvent(1<<40, 0)); len(alerts) != 0 {
		t.Fatalf("non-expiring exception let %d alerts through", len(alerts))
	}
	if statuses := engine.ExceptionStatus(time.Unix(1<<40, 0)); statuses[0].Expired {
		t.Fatal("exception without expires reported expired")
	}
}

func TestExceptedEventsDoNotCountTowardThresholds(t *testing.T) {
	t.Parallel()

	rule := policy.DetectionRule{
		ID: "outbound-burst", Severity: "warning", Events: []string{"connection"},
		Match:     policy.DetectionMatch{Directions: []string{"outbound"}},
		Threshold: policy.Threshold{Count: 2, Within: policy.Duration{Duration: time.Minute}, GroupBy: []string{"destination"}},
		Message:   "burst",
	}
	exception := policy.DetectionException{
		ID: "root-burst", Rules: []string{"outbound-burst"}, Reason: "root is expected",
		Match: policy.DetectionMatch{UIDs: []uint32{0}},
	}
	compiled, err := Compile([]policy.DetectionRule{rule}, []string{"baseline.cloud-metadata-access"}, []policy.DetectionException{exception})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Install(compiled)
	engine.Evaluate(metadataEvent(1, 0))
	if alerts := engine.Evaluate(metadataEvent(2, 1000)); len(alerts) != 0 {
		t.Fatalf("excepted event counted toward the threshold: %d alerts", len(alerts))
	}
	if alerts := engine.Evaluate(metadataEvent(3, 1000)); len(alerts) != 1 {
		t.Fatalf("second non-excepted event raised %d alerts, want 1", len(alerts))
	}
}

func TestInstallKeepsSuppressionCountsForRetainedExceptions(t *testing.T) {
	t.Parallel()

	engine := installExceptions(t, metadataException(time.Time{}))
	engine.Evaluate(metadataEvent(1, 0))
	engine.Evaluate(metadataEvent(2, 0))

	compiled, err := Compile(nil, nil, []policy.DetectionException{metadataException(time.Time{})})
	if err != nil {
		t.Fatal(err)
	}
	engine.Install(compiled)
	if statuses := engine.ExceptionStatus(time.Unix(3, 0)); statuses[0].Suppressed != 2 {
		t.Fatalf("suppressed after reinstall = %d, want 2", statuses[0].Suppressed)
	}
	engine.Install(CompiledRules{})
	if statuses := engine.ExceptionStatus(time.Unix(3, 0)); len(statuses) != 0 {
		t.Fatalf("removed exception still reported: %+v", statuses)
	}
}

func TestCompileRejectsInvalidExceptionReferences(t *testing.T) {
	t.Parallel()

	unknown := metadataException(time.Time{})
	unknown.Rules = []string{"no-such-rule"}
	if _, err := Compile(nil, nil, []policy.DetectionException{unknown}); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("unknown rule error = %v", err)
	}

	disabled := metadataException(time.Time{})
	if _, err := Compile(nil, []string{"baseline.cloud-metadata-access"}, []policy.DetectionException{disabled}); err != nil {
		t.Fatalf("exception for a disabled rule returned error: %v", err)
	}

	// DNS events carry no event-time process identity, so a UID exception on
	// a DNS rule could never be evaluated truthfully.
	dnsRule := policy.DetectionRule{
		ID: "dns-watch", Severity: "notice", Events: []string{"dns"}, Message: "dns",
		Match: policy.DetectionMatch{Domains: []string{"example.com"}},
	}
	byUID := policy.DetectionException{
		ID: "dns-root", Rules: []string{"dns-watch"}, Reason: "root lookups",
		Match: policy.DetectionMatch{UIDs: []uint32{0}},
	}
	if _, err := Compile([]policy.DetectionRule{dnsRule}, nil, []policy.DetectionException{byUID}); err == nil || !strings.Contains(err.Error(), "event-time process identity") {
		t.Fatalf("identity exception on DNS rule error = %v", err)
	}
}

func TestCompileValidatesExceptionsForDisabledRules(t *testing.T) {
	t.Parallel()

	// DNS events carry no event-time process identity, so this exception
	// could never be valid for the rule, enabled or not.
	enabled := false
	dnsRule := policy.DetectionRule{
		ID: "dns-watch", Enabled: &enabled, Severity: "notice", Events: []string{"dns"}, Message: "dns",
	}
	byUID := policy.DetectionException{
		ID: "dns-root", Rules: []string{"dns-watch"}, Reason: "root lookups",
		Match: policy.DetectionMatch{UIDs: []uint32{0}},
	}
	if _, err := Compile([]policy.DetectionRule{dnsRule}, nil, []policy.DetectionException{byUID}); err == nil || !strings.Contains(err.Error(), "event-time process identity") {
		t.Fatalf("exception for a disabled custom rule error = %v", err)
	}
	if _, err := Compile(nil, []string{"baseline.cloud-metadata-access"}, []policy.DetectionException{{
		ID: "dns-domains", Rules: []string{"baseline.cloud-metadata-access"}, Reason: "x",
		Match: policy.DetectionMatch{UnixPathGlobs: []string{"/run/x.sock"}},
	}}); err == nil || !strings.Contains(err.Error(), "unix_path_globs") {
		t.Fatalf("exception for a disabled baseline rule error = %v", err)
	}
}
