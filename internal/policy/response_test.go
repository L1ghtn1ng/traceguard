package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseResponses(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`
version: 1
responses:
  - id: block-bruteforcer
    rules: [baseline.inbound-ssh-bruteforce]
    action: block_peer
    duration: 1h
  - id: freeze-injector
    rules: [runtime.process-memory-write, runtime.ptrace-attach]
    action: freeze_cgroup
    duration: 10m
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if got := document.Responses; len(got) != 2 || got[0].Duration.Duration != time.Hour || got[1].Action != ResponseFreezeCgroup {
		t.Fatalf("responses = %+v", got)
	}
}

func TestParseRejectsInvalidResponses(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct{ response, want string }{
		"unknown action": {"{id: r, rules: [a.b], action: kill, duration: 1m}", "action must be"},
		"no duration":    {"{id: r, rules: [a.b], action: block_peer}", "duration must be"},
		"long duration":  {"{id: r, rules: [a.b], action: block_peer, duration: 25h}", "duration must be"},
		"no rules":       {"{id: r, action: block_peer, duration: 1m}", "rules must not be empty"},
		"bad rule id":    {"{id: r, rules: [A], action: block_peer, duration: 1m}", "invalid rule id"},
	} {
		if _, err := Parse([]byte("version: 1\nresponses:\n  - " + test.response + "\n")); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}
