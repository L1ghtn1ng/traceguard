package detection

import (
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func installProfiles(t *testing.T, profiles []string, exceptions ...policy.DetectionException) *Engine {
	t.Helper()
	engine, err := New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := Compile(policy.Bundle{BuiltinProfiles: profiles, DetectionExceptions: exceptions})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}
	engine.Install(compiled)
	return engine
}

func securityEvent(at uint32, name, operation, program string, uid uint32) Event {
	return Event{Timestamp: time.Unix(int64(at), 0), Name: name, Fields: map[string]any{
		"operation": operation, "program": program, "kernel_uid": uid, "uid": uid,
		"cgroup_id": uint64(at), "pid": at, "process_start_ticks": uint64(at),
	}}
}

func TestPlatformExceptionsCompileWithEveryProfileCombination(t *testing.T) {
	t.Parallel()

	for _, profiles := range [][]string{
		{policy.ProfilePlatform},
		{policy.ProfileRuntime, policy.ProfilePlatform},
	} {
		if _, err := Compile(policy.Bundle{BuiltinProfiles: profiles}); err != nil {
			t.Fatalf("Compile(%v) returned error: %v", profiles, err)
		}
	}
	for _, exception := range PlatformExceptions() {
		if len(exception.Match.UIDs) != 1 || exception.Match.UIDs[0] != 0 {
			t.Errorf("platform exception %s is not limited to root: %v", exception.ID, exception.Match.UIDs)
		}
	}
}

func TestPlatformExceptionsSuppressOnlyRootAgents(t *testing.T) {
	t.Parallel()

	engine := installProfiles(t, []string{policy.ProfilePlatform})
	agent := metadataEvent(10, 0)
	agent.Fields["program"] = "amazon-ssm-agen"
	if alerts := engine.Evaluate(agent); len(alerts) != 0 {
		t.Fatalf("root SSM agent IMDS access raised %d alerts", len(alerts))
	}
	impostor := metadataEvent(11, 1000)
	impostor.Fields["program"] = "amazon-ssm-agen"
	if alerts := engine.Evaluate(impostor); len(alerts) != 1 {
		t.Fatalf("non-root process named like the agent raised %d alerts, want 1", len(alerts))
	}
	curl := metadataEvent(12, 0)
	curl.Fields["program"] = "curl"
	curl.Fields["cgroup_id"] = uint64(12)
	if alerts := engine.Evaluate(curl); len(alerts) != 1 {
		t.Fatalf("root curl IMDS access raised %d alerts, want 1", len(alerts))
	}
}

func TestPlatformExceptionsCoverRuntimeRulesOnlyWithRuntimeProfile(t *testing.T) {
	t.Parallel()

	engine := installProfiles(t, []string{policy.ProfileRuntime, policy.ProfilePlatform})
	for _, test := range []struct {
		event Event
		want  int
	}{
		{securityEvent(1, "namespace_change", "setns", "runc:[2:INIT]", 0), 0},
		{securityEvent(2, "namespace_change", "setns", "containerd-shim", 0), 0},
		{securityEvent(3, "namespace_change", "setns", "nsenter", 0), 1},
		{securityEvent(4, "bpf_prog_load", "", "systemd", 0), 0},
		{securityEvent(5, "bpf_prog_load", "", "bpftool", 0), 1},
	} {
		if alerts := engine.Evaluate(test.event); len(alerts) != test.want {
			t.Errorf("%s by %s raised %d alerts, want %d", test.event.Name, test.event.Fields["program"], len(alerts), test.want)
		}
	}

	reexec := Event{Timestamp: time.Unix(6, 0), Name: "exec", Fields: map[string]any{
		"exec_source": "fd", "command_line": []string{"runc", "init"}, "program": "runc", "kernel_uid": uint32(0),
		"cgroup_id": uint64(6), "pid": uint32(6),
	}}
	if alerts := engine.Evaluate(reexec); len(alerts) != 0 {
		t.Fatalf("runc init re-exec raised %d alerts", len(alerts))
	}
}

func TestPolicyExceptionReplacesPlatformException(t *testing.T) {
	t.Parallel()

	override := policy.DetectionException{
		ID: "platform.cloud-guest-agent-imds", Rules: []string{"baseline.cloud-metadata-access"},
		Reason: "only the Google agent runs here", Match: policy.DetectionMatch{UIDs: []uint32{0}, Programs: []string{"google_guest_ag"}},
	}
	engine := installProfiles(t, []string{policy.ProfilePlatform}, override)
	ssm := metadataEvent(10, 0)
	ssm.Fields["program"] = "amazon-ssm-agen"
	if alerts := engine.Evaluate(ssm); len(alerts) != 1 {
		t.Fatalf("overridden exception still suppressed the SSM agent: %d alerts", len(alerts))
	}
	statuses := engine.ExceptionStatus(time.Unix(10, 0))
	count := 0
	for _, status := range statuses {
		if status.ID == override.ID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("exception %s installed %d times, want 1", override.ID, count)
	}
}

func TestPlatformProfileOffShipsNoExceptions(t *testing.T) {
	t.Parallel()

	engine := installProfiles(t, nil)
	agent := metadataEvent(10, 0)
	agent.Fields["program"] = "amazon-ssm-agen"
	if alerts := engine.Evaluate(agent); len(alerts) != 1 {
		t.Fatalf("agent access without the platform profile raised %d alerts, want 1", len(alerts))
	}
	if statuses := engine.ExceptionStatus(time.Unix(10, 0)); len(statuses) != 0 {
		t.Fatalf("exceptions installed without the platform profile: %+v", statuses)
	}
}
