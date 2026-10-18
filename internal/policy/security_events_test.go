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

func TestExecSelectorValidation(t *testing.T) {
	t.Parallel()

	rule := func(events, match string) string {
		return "version: 1\ndetections:\n  - id: probe\n    severity: warning\n    message: probe\n    events: " + events +
			"\n    match: " + match + "\n"
	}
	if _, err := Parse([]byte(rule("[exec]", `{command_globs: ["* -c *curl*"], exec_sources: [fd]}`))); err != nil {
		t.Fatalf("valid exec selectors rejected: %v", err)
	}
	for name, test := range map[string]struct {
		events, match, want string
	}{
		"command glob on decision event": {"[exec_blocked]", `{command_globs: ["*"]}`, "command_globs require exec events"},
		"exec source on file event":      {"[file_access]", `{exec_sources: [fd]}`, "exec_sources require exec events"},
		"unknown exec source":            {"[exec]", `{exec_sources: [memory]}`, `unsupported exec source "memory"`},
		"malformed command glob":         {"[exec]", `{command_globs: ["["]}`, "invalid glob"},
	} {
		if _, err := Parse([]byte(rule(test.events, test.match))); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}
