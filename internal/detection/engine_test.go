package detection

import (
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestBaselineRulesEnabledAndDisableable(t *testing.T) {
	t.Parallel()
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := engine.RuleCount(), 3; got != want {
		t.Fatalf("rule count = %d, want %d", got, want)
	}
	alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(1, 0),
		Name:      "exec",
		Fields: map[string]any{
			"exe": "/dev/shm/tools/payload",
		},
	})
	if got, want := len(alerts), 1; got != want {
		t.Fatalf("alert count = %d, want %d", got, want)
	}
	if got, want := alerts[0].RuleID, "baseline.exec-from-shared-memory"; got != want {
		t.Fatalf("rule id = %q, want %q", got, want)
	}

	if err := engine.Replace(nil, []string{"baseline.exec-from-shared-memory"}); err != nil {
		t.Fatal(err)
	}
	if alerts := engine.Evaluate(Event{
		Timestamp: time.Unix(2, 0),
		Name:      "exec",
		Fields:    map[string]any{"exe": "/dev/shm/payload"},
	}); len(alerts) != 0 {
		t.Fatalf("disabled baseline emitted %d alerts", len(alerts))
	}
}

func TestThresholdGroupingCooldownAndExclusion(t *testing.T) {
	t.Parallel()
	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID:       "metadata-burst",
		Enabled:  &enabled,
		Severity: "warning",
		Events:   []string{"connection"},
		Match: policy.DetectionMatch{
			DestinationCIDRs: []string{"169.254.169.254/32"},
			Ports:            []uint16{80},
		},
		Exclude: policy.DetectionMatch{
			UIDs: []uint32{0},
		},
		Threshold: policy.Threshold{
			Count:   3,
			Within:  policy.Duration{Duration: time.Minute},
			GroupBy: []string{"cgroup"},
		},
		Cooldown: policy.Duration{Duration: 5 * time.Minute},
		Message:  "metadata burst",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1000, 0)
	fields := map[string]any{
		"peer_address": "169.254.169.254",
		"peer_port":    uint16(80),
		"uid":          uint32(1000),
		"cgroup":       "/workloads/a",
	}
	for index := 0; index < 2; index++ {
		if alerts := engine.Evaluate(Event{Timestamp: base.Add(time.Duration(index) * time.Second), Name: "connection", Fields: fields}); len(alerts) != 0 {
			t.Fatalf("event %d emitted early alert", index)
		}
	}
	alerts := engine.Evaluate(Event{Timestamp: base.Add(2 * time.Second), Name: "connection", Fields: fields})
	if got, want := len(alerts), 1; got != want {
		t.Fatalf("threshold alert count = %d, want %d", got, want)
	}
	if alerts := engine.Evaluate(Event{Timestamp: base.Add(3 * time.Second), Name: "connection", Fields: fields}); len(alerts) != 0 {
		t.Fatalf("cooldown emitted %d alerts", len(alerts))
	}

	excluded := cloneFields(fields)
	excluded["uid"] = uint32(0)
	if alerts := engine.Evaluate(Event{Timestamp: base.Add(10 * time.Minute), Name: "connection", Fields: excluded}); len(alerts) != 0 {
		t.Fatalf("excluded event emitted %d alerts", len(alerts))
	}
}

func TestEngineBoundsThresholdState(t *testing.T) {
	t.Parallel()
	enabled := true
	engine, err := New([]policy.DetectionRule{{
		ID:       "bounded",
		Enabled:  &enabled,
		Severity: "notice",
		Events:   []string{"exec"},
		Threshold: policy.Threshold{
			Count:   2,
			Within:  policy.Duration{Duration: time.Minute},
			GroupBy: []string{"cgroup"},
		},
		Message: "bounded",
	}}, []string{
		"baseline.exec-from-shared-memory",
		"baseline.sensitive-auth-file-write",
		"baseline.policy-denial-burst",
	})
	if err != nil {
		t.Fatal(err)
	}
	engine.maxGroups = 4
	for index := 0; index < 20; index++ {
		engine.Evaluate(Event{
			Timestamp: time.Unix(int64(index), 0),
			Name:      "exec",
			Fields:    map[string]any{"cgroup": string(rune('a' + index))},
		})
	}
	if got := engine.StateCount(); got > 4 {
		t.Fatalf("state count = %d, want <= 4", got)
	}
}

func TestGlobsMatchAcrossPathSeparatorsAndCommandArguments(t *testing.T) {
	t.Parallel()
	if !matchGlobs([]string{"*/curl"}, "/usr/bin/curl") {
		t.Fatal("executable glob did not match nested path")
	}
	if !matchGlobs([]string{"*--data*"}, "/usr/bin/curl --data secret") {
		t.Fatal("command glob did not match command containing a path")
	}
}
