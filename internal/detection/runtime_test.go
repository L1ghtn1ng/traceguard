package detection

import (
	"slices"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestBuiltinRulesPassPolicyValidation(t *testing.T) {
	t.Parallel()

	for name, rules := range map[string][]policy.DetectionRule{"baseline": BaselineRules(), "runtime": RuntimeRules()} {
		if err := (policy.Document{Version: policy.Version, DetectionRules: rules}).Validate(); err != nil {
			t.Fatalf("%s rules fail policy validation: %v", name, err)
		}
	}
}

func TestRuntimeProfileIsOptIn(t *testing.T) {
	t.Parallel()

	baseline, err := Compile(policy.Bundle{})
	if err != nil {
		t.Fatal(err)
	}
	withRuntime, err := Compile(policy.Bundle{BuiltinProfiles: []string{policy.ProfileRuntime}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(baseline.rules), len(BaselineRules()); got != want {
		t.Fatalf("default rule count = %d, want baseline only (%d)", got, want)
	}
	if got, want := len(withRuntime.rules), len(BaselineRules())+len(RuntimeRules()); got != want {
		t.Fatalf("runtime profile rule count = %d, want %d", got, want)
	}

	exception := policy.DetectionException{
		ID: "runc", Rules: []string{"runtime.fileless-exec"}, Reason: "runc re-executes itself from a memfd",
		Match: policy.DetectionMatch{ExecSources: []string{"fd"}},
	}
	if _, err := Compile(policy.Bundle{DetectionExceptions: []policy.DetectionException{exception}}); err != nil {
		t.Fatalf("exception for a runtime rule with the profile off returned error: %v", err)
	}
}

func TestRuntimeRulesFireOnRepresentativeEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rule         string
		event        string
		fires, quiet map[string]any
	}{
		{"runtime.kernel-module-load", "module_load", map[string]any{"operation": "finit_module"}, nil},
		{"runtime.bpf-program-load", "bpf_prog_load", map[string]any{"bpf_prog_type": "kprobe"}, nil},
		{"runtime.ptrace-attach", "ptrace", map[string]any{"operation": "attach"}, map[string]any{"operation": "traceme"}},
		{"runtime.process-memory-write", "process_vm", map[string]any{"operation": "write"}, map[string]any{"operation": "read"}},
		{"runtime.fileless-exec", "exec", map[string]any{"exec_source": "fd"}, map[string]any{"exec_source": "path"}},
		{"runtime.namespace-join", "namespace_change", map[string]any{"operation": "setns"}, map[string]any{"operation": "unshare"}},
		{"runtime.sensitive-filesystem-mount", "mount", map[string]any{"mount_fstype": "debugfs"}, map[string]any{"mount_fstype": "ext4"}},
		{"runtime.sensitive-capability-request", "privilege_change",
			map[string]any{"operation": "capset", "requested_capabilities": []string{"net_raw", "sys_admin"}},
			map[string]any{"operation": "capset", "requested_capabilities": []string{"net_bind_service"}}},
	}
	if len(tests) != len(RuntimeRules()) {
		t.Fatalf("covered %d runtime rules, profile has %d", len(tests), len(RuntimeRules()))
	}
	for _, test := range tests {
		t.Run(test.rule, func(t *testing.T) {
			t.Parallel()
			compiled, err := Compile(policy.Bundle{BuiltinProfiles: []string{policy.ProfileRuntime}})
			if err != nil {
				t.Fatal(err)
			}
			engine, err := New(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			engine.Install(compiled)
			evaluate := func(fields map[string]any, cgroup uint64) []string {
				fields["cgroup_id"] = cgroup
				fields["program"] = "probe"
				var ids []string
				for _, alert := range engine.Evaluate(Event{Timestamp: time.Unix(1, 0), Name: test.event, Fields: fields}) {
					ids = append(ids, alert.RuleID)
				}
				return ids
			}
			if ids := evaluate(test.fires, 1); !slices.Contains(ids, test.rule) {
				t.Fatalf("matching event raised %v, want %s", ids, test.rule)
			}
			if test.quiet != nil {
				if ids := evaluate(test.quiet, 2); slices.Contains(ids, test.rule) {
					t.Fatalf("non-matching event raised %s", test.rule)
				}
			}
		})
	}
}

func TestAlertRecordFieldsCarryMITREAndCompliance(t *testing.T) {
	t.Parallel()

	alert := Alert{
		RuleID: "x", Tactics: []string{"TA0005"}, Techniques: []string{"T1620"}, Compliance: []string{"pci-dss:10.2.7"},
		Fields: map[string]any{"pid": 1},
	}
	fields := alert.RecordFields("exec")
	for name, want := range map[string][]string{
		"mitre_tactics": {"TA0005"}, "mitre_techniques": {"T1620"}, "compliance": {"pci-dss:10.2.7"},
	} {
		if got, ok := fields[name].([]string); !ok || !slices.Equal(got, want) {
			t.Fatalf("%s = %#v, want %v", name, fields[name], want)
		}
	}
	if _, ok := (Alert{RuleID: "y"}).RecordFields("exec")["mitre_tactics"]; ok {
		t.Fatal("alert without MITRE mapping recorded an empty mitre_tactics field")
	}
}
