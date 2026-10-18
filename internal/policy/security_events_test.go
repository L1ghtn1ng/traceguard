package policy

import (
	"strings"
	"testing"
)

func TestOperationsSelectorValidation(t *testing.T) {
	t.Parallel()

	rule := func(events, operations string) string {
		return "version: 1\ndetections:\n  - id: probe\n    severity: warning\n    message: probe\n    events: " + events +
			"\n    match: {operations: " + operations + "}\n"
	}
	if _, err := Parse([]byte(rule("[ptrace, process_vm]", "[attach, write]"))); err != nil {
		t.Fatalf("valid operations rejected: %v", err)
	}
	for name, test := range map[string]struct {
		events, operations, want string
	}{
		"event without operation":  {"[mount]", "[attach]", "require security events"},
		"operation of other event": {"[ptrace]", "[write]", `operation "write" is not carried`},
		"unknown operation":        {"[privilege_change]", "[setfsuid]", `operation "setfsuid"`},
	} {
		if _, err := Parse([]byte(rule(test.events, test.operations))); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}
