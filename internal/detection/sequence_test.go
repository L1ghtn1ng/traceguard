package detection

import (
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func shellThenEgress(key string, cooldown time.Duration) policy.DetectionSequence {
	return policy.DetectionSequence{
		ID: "shell-then-egress", Severity: "critical", Key: key,
		Within: policy.Duration{Duration: time.Minute}, Cooldown: policy.Duration{Duration: cooldown},
		Message: "a shell connected out", MITRE: policy.MITRE{Techniques: []string{"T1059.004"}},
		Steps: []policy.SequenceStep{
			{Events: []string{"exec"}, Match: policy.DetectionMatch{CommandGlobs: []string{"sh *"}}},
			{Events: []string{"connection"}, Match: policy.DetectionMatch{Directions: []string{"outbound"}}},
		},
	}
}

func sequenceEngine(t *testing.T, sequence policy.DetectionSequence, exceptions ...policy.DetectionException) *Engine {
	t.Helper()
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(policy.Bundle{
		DisabledRuleIDs:    []string{"baseline.cloud-metadata-access", "baseline.direct-email-egress", "baseline.inbound-ssh-bruteforce", "baseline.policy-denial-burst"},
		DetectionSequences: []policy.DetectionSequence{sequence}, DetectionExceptions: exceptions,
	})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	engine.Install(compiled)
	return engine
}

func sequenceEvent(at int64, name string, pid uint32, cgroup uint64, extra map[string]any) Event {
	fields := map[string]any{"pid": pid, "process_start_ticks": uint64(pid) * 10, "cgroup_id": cgroup, "kernel_uid": uint32(33)}
	for key, value := range extra {
		fields[key] = value
	}
	return Event{Timestamp: time.Unix(at, 0), Name: name, Fields: fields}
}

var (
	shellExec = map[string]any{"command_line": []string{"sh", "-c", "id"}}
	outbound  = map[string]any{"direction": "outbound"}
)

func TestSequenceAlertsWhenStepsMatchInOrderForOneProcess(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	if alerts := engine.Evaluate(sequenceEvent(1, "connection", 10, 1, outbound)); len(alerts) != 0 {
		t.Fatal("second step alone alerted")
	}
	engine.Evaluate(sequenceEvent(2, "exec", 10, 1, shellExec))
	if alerts := engine.Evaluate(sequenceEvent(3, "connection", 11, 1, outbound)); len(alerts) != 0 {
		t.Fatal("another process completed the sequence")
	}
	alerts := engine.Evaluate(sequenceEvent(4, "connection", 10, 1, outbound))
	if len(alerts) != 1 || alerts[0].ID == "" || alerts[0].RuleID != "shell-then-egress" || alerts[0].Count != 2 || alerts[0].Window != time.Minute {
		t.Fatalf("alerts = %+v", alerts)
	}
	if alerts[0].Fields["sequence_started"] != time.Unix(2, 0).UTC().Format(time.RFC3339Nano) || alerts[0].Techniques[0] != "T1059.004" {
		t.Fatalf("alert metadata = %+v", alerts[0])
	}
	if alerts := engine.Evaluate(sequenceEvent(5, "connection", 10, 1, outbound)); len(alerts) != 0 {
		t.Fatal("completed sequence alerted again without a new first step")
	}
}

func TestSequenceCgroupKeyCorrelatesAcrossProcesses(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyCgroup, 0))
	engine.Evaluate(sequenceEvent(1, "exec", 10, 7, shellExec))
	if alerts := engine.Evaluate(sequenceEvent(2, "connection", 11, 8, outbound)); len(alerts) != 0 {
		t.Fatal("another cgroup completed the sequence")
	}
	if alerts := engine.Evaluate(sequenceEvent(3, "connection", 11, 7, outbound)); len(alerts) != 1 {
		t.Fatalf("same-cgroup completion raised %d alerts, want 1", len(alerts))
	}
}

func TestSequenceExpiresAfterWindow(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	engine.Evaluate(sequenceEvent(1, "exec", 10, 1, shellExec))
	if alerts := engine.Evaluate(sequenceEvent(62, "connection", 10, 1, outbound)); len(alerts) != 0 {
		t.Fatal("step outside the window completed the sequence")
	}
}

func TestSequenceCooldownAndExceptions(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, time.Hour))
	for at, want := range []int{1, 0} {
		engine.Evaluate(sequenceEvent(int64(10*at+1), "exec", 10, 1, shellExec))
		if alerts := engine.Evaluate(sequenceEvent(int64(10*at+2), "connection", 10, 1, outbound)); len(alerts) != want {
			t.Fatalf("completion %d raised %d alerts, want %d", at+1, len(alerts), want)
		}
	}

	exception := policy.DetectionException{
		ID: "www-data", Rules: []string{"shell-then-egress"}, Reason: "expected", Match: policy.DetectionMatch{UIDs: []uint32{33}},
	}
	excepted := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0), exception)
	excepted.Evaluate(sequenceEvent(1, "exec", 10, 1, shellExec))
	if alerts := excepted.Evaluate(sequenceEvent(2, "connection", 10, 1, outbound)); len(alerts) != 0 {
		t.Fatal("excepted sequence alerted")
	}
	if statuses := excepted.ExceptionStatus(time.Unix(3, 0)); statuses[0].Suppressed != 1 {
		t.Fatalf("exception status = %+v", statuses)
	}
}

func TestSequenceStateIsBounded(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	engine.maxSequenceStates = 2
	for pid := range uint32(5) {
		engine.Evaluate(sequenceEvent(1, "exec", pid+10, 1, shellExec))
	}
	if got := len(engine.sequenceStates); got != 2 {
		t.Fatalf("sequence states = %d, want the cap of 2", got)
	}
	// Expired progress makes room again.
	engine.Evaluate(sequenceEvent(100, "exec", 99, 1, shellExec))
	if _, ok := sequenceKey("shell-then-egress", policy.SequenceKeyProcess, sequenceEvent(100, "exec", 99, 1, nil).Fields); !ok || len(engine.sequenceStates) != 1 {
		t.Fatalf("sequence states after pruning = %d, want 1", len(engine.sequenceStates))
	}
}

func TestSequenceSkipsEventsWithoutIdentity(t *testing.T) {
	t.Parallel()

	if _, ok := sequenceKey("s", policy.SequenceKeyProcess, map[string]any{"pid": uint32(1)}); ok {
		t.Fatal("process key built without process_start_ticks")
	}
	if _, ok := sequenceKey("s", policy.SequenceKeyCgroup, map[string]any{}); ok {
		t.Fatal("cgroup key built without cgroup_id")
	}
}

func TestSequenceLaterFirstStepCanComplete(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	engine.Evaluate(sequenceEvent(0, "exec", 10, 1, shellExec))
	engine.Evaluate(sequenceEvent(40, "exec", 10, 1, shellExec))
	alerts := engine.Evaluate(sequenceEvent(70, "connection", 10, 1, outbound))
	if len(alerts) != 1 || alerts[0].Fields["sequence_started"] != time.Unix(40, 0).UTC().Format(time.RFC3339Nano) {
		t.Fatalf("alerts = %+v, want one starting at the later first step", alerts)
	}
}

func TestSequenceRejectsStepsBeforeThePreviousStep(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	engine.Evaluate(sequenceEvent(10, "exec", 10, 1, shellExec))
	if alerts := engine.Evaluate(sequenceEvent(5, "connection", 10, 1, outbound)); len(alerts) != 0 {
		t.Fatalf("an earlier event completed the sequence: %+v", alerts)
	}
}

func TestSequencePruningUsesEachSequencesWindow(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	started := time.Unix(0, 0)
	engine.sequenceStates[groupKey{1}] = &sequenceState{window: time.Minute, partial: []partialMatch{{started: started, last: started, ok: true}}}
	engine.sequenceStates[groupKey{2}] = &sequenceState{window: time.Hour, partial: []partialMatch{{started: started, last: started, ok: true}}}
	engine.pruneSequenceStates(started.Add(2 * time.Minute))
	if _, short := engine.sequenceStates[groupKey{1}]; short {
		t.Fatal("a one-minute partial match outlived its window")
	}
	if _, long := engine.sequenceStates[groupKey{2}]; !long {
		t.Fatal("a one-hour partial match was pruned inside its window")
	}
}

func TestSequenceCooldownHoldsWhenRecordsAreFull(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, time.Hour))
	engine.maxSequenceStates = 1
	complete := func(at int64, pid uint32) int {
		engine.Evaluate(sequenceEvent(at, "exec", pid, 1, shellExec))
		return len(engine.Evaluate(sequenceEvent(at+1, "connection", pid, 1, outbound)))
	}
	if complete(1, 10) != 1 || complete(10, 20) != 1 {
		t.Fatal("first completions did not alert")
	}
	if got := complete(20, 20); got != 0 {
		t.Fatalf("a key in cooldown alerted %d times after the records filled", got)
	}
}

func TestSequenceSkipsNullIdentity(t *testing.T) {
	t.Parallel()

	for _, fields := range []map[string]any{
		{"pid": nil, "process_start_ticks": nil},
		{"pid": uint32(0), "process_start_ticks": uint64(0)},
	} {
		if _, ok := sequenceKey("s", policy.SequenceKeyProcess, fields); ok {
			t.Errorf("process key built from %v", fields)
		}
	}
	if _, ok := sequenceKey("s", policy.SequenceKeyCgroup, map[string]any{"cgroup_id": nil}); ok {
		t.Error("cgroup key built from a null cgroup_id")
	}
}

func TestSequenceIDsAndDisabledExceptions(t *testing.T) {
	t.Parallel()

	builtinID := shellThenEgress(policy.SequenceKeyProcess, 0)
	builtinID.ID = "baseline.cloud-metadata-access"
	if _, err := Compile(policy.Bundle{DetectionSequences: []policy.DetectionSequence{builtinID}}); err == nil || !strings.Contains(err.Error(), "built-in rule") {
		t.Fatalf("sequence with a built-in ID error = %v", err)
	}

	exception := policy.DetectionException{
		ID: "quiet", Rules: []string{"shell-then-egress"}, Reason: "kept for later", Match: policy.DetectionMatch{UIDs: []uint32{33}},
	}
	if _, err := Compile(policy.Bundle{DisabledRuleIDs: []string{"shell-then-egress"}, DetectionExceptions: []policy.DetectionException{exception}}); err != nil {
		t.Fatalf("an exception for a disabled sequence rejected the policy: %v", err)
	}

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	engine.Evaluate(sequenceEvent(1, "exec", 10, 1, shellExec))
	if got := engine.StateCount(); got < 1 {
		t.Fatalf("StateCount = %d, want the in-progress sequence counted", got)
	}
}

func TestSequencesSkipEventsNoStepUses(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	if _, used := engine.sequences[0].events["file_access"]; used {
		t.Fatal("file_access listed as a step event")
	}
	for _, name := range []string{"exec", "connection"} {
		if _, used := engine.sequences[0].events[name]; !used {
			t.Fatalf("%s missing from the step events", name)
		}
	}
}

func TestFullSequenceTablePrunesOnlyWhenSomethingCanExpire(t *testing.T) {
	t.Parallel()

	engine := sequenceEngine(t, shellThenEgress(policy.SequenceKeyProcess, 0))
	engine.maxSequenceStates = 2
	for pid := range uint32(2) {
		engine.Evaluate(sequenceEvent(1, "exec", pid+10, 1, shellExec))
	}
	engine.Evaluate(sequenceEvent(2, "exec", 99, 1, shellExec))
	if next := engine.nextProgressPrune; !next.Equal(time.Unix(1, 0).Add(time.Minute)) {
		t.Fatalf("next prune = %v, want when the oldest key expires", next)
	}
	// Before then, a full table is not walked again; after, it makes room.
	engine.Evaluate(sequenceEvent(30, "exec", 98, 1, shellExec))
	if len(engine.sequenceStates) != 2 {
		t.Fatalf("states = %d, want the full table unchanged", len(engine.sequenceStates))
	}
	engine.Evaluate(sequenceEvent(62, "exec", 97, 1, shellExec))
	if _, ok := sequenceKey("shell-then-egress", policy.SequenceKeyProcess, sequenceEvent(62, "exec", 97, 1, nil).Fields); !ok || len(engine.sequenceStates) != 1 {
		t.Fatalf("states after expiry = %d, want only the new key", len(engine.sequenceStates))
	}
}
