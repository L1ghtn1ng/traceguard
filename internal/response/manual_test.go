package response

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestManualApplyAndLift(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	h.clock.now = time.Unix(100, 0)
	if err := h.responder.Apply("cmd-1", policy.ResponseBlockPeer, "203.0.113.7", time.Hour); err != nil {
		t.Fatalf("Apply block_peer: %v", err)
	}
	peer := netip.MustParseAddr("203.0.113.7")
	if until := h.blocker.blocked[peer]; !until.Equal(time.Unix(100, 0).Add(time.Hour)) {
		t.Fatalf("block until %v, want an hour from now", until)
	}
	last := h.output.fields[len(h.output.fields)-1]
	if _, hasAlert := last["alert_id"]; last["command_id"] != "cmd-1" || hasAlert || last["response_id"] != ManualResponseID {
		t.Fatalf("applied record fields = %v, want the command id", last)
	}
	actions := h.responder.ActiveActions(10)
	if len(actions) != 1 || !actions[0].Manual || !actions[0].Applied || actions[0].Target != "203.0.113.7" {
		t.Fatalf("active actions = %+v", actions)
	}

	// A policy change does not end a manual action.
	h.responder.Configure(nil)
	if h.responder.Active() != 1 {
		t.Fatal("policy change reverted a manual action")
	}

	if err := h.responder.Lift("cmd", policy.ResponseBlockPeer, "::ffff:203.0.113.7"); err != nil {
		t.Fatalf("Lift: %v", err)
	}
	if len(h.blocker.blocked) != 0 || h.responder.Active() != 0 {
		t.Fatalf("after lift: blocked %v active %d", h.blocker.blocked, h.responder.Active())
	}
	if err := h.responder.Lift("cmd", policy.ResponseBlockPeer, "203.0.113.7"); err == nil {
		t.Fatal("Lift of an inactive action succeeded")
	}
}

// stateful gives a harness a state file, which enforced manual freezes need.
func stateful(t *testing.T) Options {
	t.Helper()
	return Options{StatePath: filepath.Join(t.TempDir(), "responses.json"), BootID: "boot-1"}
}

func TestManualApplyChecksTargetsAndMode(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, stateful(t))
	for _, test := range []struct {
		action, target string
		duration       time.Duration
		want           string
	}{
		{policy.ResponseBlockPeer, "not-an-ip", time.Hour, "IP address"},
		{policy.ResponseBlockPeer, "127.0.0.1", time.Hour, "loopback"},
		{policy.ResponseBlockPeer, "203.0.113.7", 0, "duration"},
		{policy.ResponseBlockPeer, "203.0.113.7", 25 * time.Hour, "duration"},
		{policy.ResponseFreezeCgroup, "0", time.Hour, "cgroup ID"},
		{policy.ResponseFreezeCgroup, "-4", time.Hour, "cgroup ID"},
		{"wipe_disk", "x", time.Hour, "unknown"},
	} {
		err := h.responder.Apply("cmd", test.action, test.target, test.duration)
		if err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("Apply(%s, %q, %s) = %v, want %q", test.action, test.target, test.duration, err, test.want)
		}
	}

	h.freezer.refuse = true
	if err := h.responder.Apply("cmd", policy.ResponseFreezeCgroup, "42", time.Hour); err == nil || !strings.Contains(err.Error(), "TraceGuard") {
		t.Fatalf("Apply freeze of a protected cgroup = %v, want refusal", err)
	}

	off := newHarness(ModeOff, Options{})
	if err := off.responder.Apply("cmd", policy.ResponseBlockPeer, "203.0.113.7", time.Hour); err == nil {
		t.Fatal("Apply succeeded with responses off")
	}

	dry := newHarness(ModeDryRun, Options{})
	if err := dry.responder.Apply("cmd", policy.ResponseBlockPeer, "203.0.113.7", time.Hour); err != nil {
		t.Fatalf("dry-run Apply: %v", err)
	}
	if len(dry.blocker.blocked) != 0 || dry.output.count("response would apply") != 1 {
		t.Fatalf("dry-run changed the kernel or did not record: %v %v", dry.blocker.blocked, dry.output.messages)
	}
}

func TestPolicyResponsesCarryAlertID(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	alert := alertFor("baseline.inbound-ssh-bruteforce", 100, map[string]any{"peer_address": "203.0.113.9"})
	alert.ID = "alert-123"
	h.responder.Handle(alert)
	if got := h.output.fields[len(h.output.fields)-1]["alert_id"]; got != "alert-123" {
		t.Fatalf("response record alert_id = %v, want alert-123", got)
	}
	if _, ok := h.output.fields[len(h.output.fields)-1]["command_id"]; ok {
		t.Fatal("policy response record carries a command id")
	}
}

func TestManualTargetsAreNormalised(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, stateful(t))
	if err := h.responder.Apply("cmd", policy.ResponseBlockPeer, "fe80::1%eth0", time.Hour); err == nil || !strings.Contains(err.Error(), "zone") {
		t.Fatalf("Apply of a zoned address = %v, want refusal", err)
	}
	if err := h.responder.Apply("cmd", policy.ResponseFreezeCgroup, "42", time.Hour); err != nil {
		t.Fatalf("Apply freeze: %v", err)
	}
	// A lift names the cgroup however it is written.
	if err := h.responder.Lift("cmd", policy.ResponseFreezeCgroup, " 0042 "); err != nil {
		t.Fatalf("Lift of 0042: %v", err)
	}
	if h.responder.Active() != 0 {
		t.Fatal("freeze still active after lift")
	}
}

func TestAFailedLiftIsRetriedOnTheNextTick(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, stateful(t))
	h.clock.now = time.Unix(100, 0)
	if err := h.responder.Apply("cmd", policy.ResponseFreezeCgroup, "42", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	h.freezer.thawErr = errors.New("cgroup busy")
	if err := h.responder.Lift("cmd", policy.ResponseFreezeCgroup, "42"); err == nil {
		t.Fatal("Lift succeeded although the thaw failed")
	}
	h.freezer.thawErr = nil
	h.clock.now = time.Unix(105, 0)
	h.responder.Expire(h.clock.now)
	if h.responder.Active() != 0 {
		t.Fatal("the failed lift waited for the original 24 hour deadline")
	}
}

func TestAManualFreezeNeedsRecoveryState(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	if err := h.responder.Apply("cmd", policy.ResponseFreezeCgroup, "42", time.Hour); err == nil || !strings.Contains(err.Error(), "state file") {
		t.Fatalf("Apply freeze without state = %v, want refusal", err)
	}
	if len(h.freezer.frozen) != 0 {
		t.Fatal("froze a cgroup with no way to recover it")
	}

	// The state directory disappears after start: the freeze is undone.
	options := stateful(t)
	unsaved := newHarness(ModeEnforce, options)
	if err := os.RemoveAll(filepath.Dir(options.StatePath)); err != nil {
		t.Fatal(err)
	}
	if err := unsaved.responder.Apply("cmd", policy.ResponseFreezeCgroup, "42", time.Hour); err == nil || !strings.Contains(err.Error(), "could not be saved") {
		t.Fatalf("Apply freeze with unsaved state = %v, want it refused before freezing", err)
	}
	if unsaved.freezer.freezeN != 0 {
		t.Fatal("froze before its recovery record was saved")
	}
	if len(unsaved.freezer.frozen) != 0 || unsaved.responder.Active() != 0 {
		t.Fatal("the unrecoverable freeze stayed in force")
	}
}

func TestALiftRecordsItsCommand(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	if err := h.responder.Apply("cmd-apply", policy.ResponseBlockPeer, "203.0.113.7", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := h.responder.Lift("cmd-lift", policy.ResponseBlockPeer, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	last := h.output.fields[len(h.output.fields)-1]
	if h.output.messages[len(h.output.messages)-1] != "response reverted" || last["command_id"] != "cmd-lift" {
		t.Fatalf("revert record = %v %v", h.output.messages[len(h.output.messages)-1], last)
	}
}

func TestTheRecoveryRecordExistsBeforeTheFreeze(t *testing.T) {
	t.Parallel()

	options := stateful(t)
	h := newHarness(ModeEnforce, options)
	recorded := false
	h.freezer.onFreeze = func(uint64) {
		// A crash here must leave a record the next start can thaw.
		payload, err := os.ReadFile(options.StatePath)
		var state stateFile
		recorded = err == nil && json.Unmarshal(payload, &state) == nil && len(state.Frozen) == 1 && state.Frozen[0].CgroupID == 42
	}
	if err := h.responder.Apply("cmd", policy.ResponseFreezeCgroup, "42", time.Hour); err != nil {
		t.Fatal(err)
	}
	if !recorded {
		t.Fatal("the cgroup was frozen before its recovery record was saved")
	}

	// A cgroup someone else froze gets no record, so it is never thawed by us.
	other := newHarness(ModeEnforce, stateful(t))
	other.freezer.already = true
	other.freezer.onFreeze = func(uint64) {}
	if err := other.responder.Apply("cmd", policy.ResponseFreezeCgroup, "7", time.Hour); err != nil {
		t.Fatal(err)
	}
	if other.responder.pending != nil {
		t.Fatal("a pending record was left behind")
	}
}

func TestARetriedLiftKeepsItsCommand(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, stateful(t))
	h.clock.now = time.Unix(100, 0)
	if err := h.responder.Apply("cmd-apply", policy.ResponseFreezeCgroup, "42", 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	h.freezer.thawErr = errors.New("cgroup busy")
	_ = h.responder.Lift("cmd-lift", policy.ResponseFreezeCgroup, "42")
	h.freezer.thawErr = nil
	h.clock.now = time.Unix(105, 0)
	h.responder.Expire(h.clock.now)
	last := h.output.fields[len(h.output.fields)-1]
	if h.output.messages[len(h.output.messages)-1] != "response reverted" || last["command_id"] != "cmd-lift" || last["reason"] != "lifted" {
		t.Fatalf("retried undo record = %v %v", h.output.messages[len(h.output.messages)-1], last)
	}
}
