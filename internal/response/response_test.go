package response

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

type fakeBlocker struct {
	blocked map[netip.Addr]time.Time
	err     error
	cleared int
}

func (f *fakeBlocker) BlockPeer(address netip.Addr, until time.Time) error {
	if f.err != nil {
		return f.err
	}
	f.blocked[address] = until
	return nil
}

func (f *fakeBlocker) UnblockPeer(address netip.Addr) error {
	delete(f.blocked, address)
	return nil
}

func (f *fakeBlocker) ClearPeers() error {
	f.cleared++
	clear(f.blocked)
	return nil
}

type fakeFreezer struct {
	frozen   map[string]bool
	thawErr  error
	freezeN  int
	checkN   int
	refuse   bool
	already  bool
	thawedID map[uint64]bool
}

func (f *fakeFreezer) Check(id uint64) (string, error) {
	f.checkN++
	if f.refuse {
		return "", &RefusedError{Reason: "refusing to freeze: it contains TraceGuard"}
	}
	return fmt.Sprintf("/kubepods.slice/pod-%d", id), nil
}

func (f *fakeFreezer) Freeze(id uint64) (string, bool, error) {
	f.freezeN++
	path, err := f.Check(id)
	if err != nil || f.already {
		return path, false, err
	}
	f.frozen[path] = true
	return path, true, nil
}

func (f *fakeFreezer) Thaw(id uint64, path string) error {
	if f.thawErr != nil {
		return f.thawErr
	}
	delete(f.frozen, path)
	f.thawedID[id] = true
	return nil
}

type records struct {
	messages []string
	fields   []map[string]any
}

func (r *records) record(message string, fields map[string]any) {
	r.messages = append(r.messages, message)
	r.fields = append(r.fields, fields)
}

func (r *records) count(message string) int {
	count := 0
	for _, recorded := range r.messages {
		if recorded == message {
			count++
		}
	}
	return count
}

// clock is a settable time source.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

var testResponses = []policy.Response{
	{ID: "block-scanner", Rules: []string{"baseline.inbound-ssh-bruteforce"}, Action: policy.ResponseBlockPeer, Duration: policy.Duration{Duration: time.Hour}},
	{ID: "freeze-injector", Rules: []string{"runtime.process-memory-write"}, Action: policy.ResponseFreezeCgroup, Duration: policy.Duration{Duration: 10 * time.Minute}},
}

type harness struct {
	responder *Responder
	blocker   *fakeBlocker
	freezer   *fakeFreezer
	output    *records
	clock     *clock
}

func newHarness(mode string, options Options) harness {
	h := harness{
		blocker: &fakeBlocker{blocked: map[netip.Addr]time.Time{}},
		freezer: &fakeFreezer{frozen: map[string]bool{}, thawedID: map[uint64]bool{}},
		output:  &records{}, clock: &clock{now: time.Unix(0, 0)},
	}
	options.Now = h.clock.Now
	if options.Sleep == nil {
		options.Sleep = func(time.Duration) {}
	}
	h.responder = New(mode, h.blocker, h.freezer, h.output.record, options)
	h.responder.Configure(testResponses)
	return h
}

func newTestResponder(mode string) (*Responder, *fakeBlocker, *fakeFreezer, *records) {
	h := newHarness(mode, Options{})
	return h.responder, h.blocker, h.freezer, h.output
}

func alertFor(rule string, at int64, fields map[string]any) detection.Alert {
	return detection.Alert{RuleID: rule, Timestamp: time.Unix(at, 0), Fields: fields}
}

func TestEnforceAppliesExtendsAndExpiresActions(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	responder, blocker, freezer, output := h.responder, h.blocker, h.freezer, h.output
	peer := netip.MustParseAddr("203.0.113.9")
	h.clock.now = time.Unix(100, 0)
	responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 100, map[string]any{"peer_address": "203.0.113.9"}))
	responder.Handle(alertFor("runtime.process-memory-write", 100, map[string]any{"cgroup_id": uint64(2)}))
	if until := blocker.blocked[peer]; !until.Equal(time.Unix(100, 0).Add(time.Hour)) || len(freezer.frozen) != 1 || responder.Active() != 2 {
		t.Fatalf("blocked %v frozen %v active %d", blocker.blocked, freezer.frozen, responder.Active())
	}

	h.clock.now = time.Unix(200, 0)
	responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 200, map[string]any{"peer_address": "203.0.113.9"}))
	if until := blocker.blocked[peer]; !until.Equal(time.Unix(200, 0).Add(time.Hour)) || output.count("response extended") != 1 || responder.Active() != 2 {
		t.Fatalf("repeat alert did not extend the block: until %v records %v", until, output.messages)
	}

	responder.Expire(time.Unix(100, 0).Add(10 * time.Minute))
	if len(freezer.frozen) != 0 || len(blocker.blocked) != 1 || responder.Active() != 1 {
		t.Fatalf("after freeze expiry: blocked %v frozen %v", blocker.blocked, freezer.frozen)
	}
	responder.RevertAll()
	if len(blocker.blocked) != 0 || responder.Active() != 0 || output.count("response reverted") != 2 {
		t.Fatalf("after shutdown: blocked %v records %v", blocker.blocked, output.messages)
	}
}

func TestDeadlineCountsFromWhenTheActionIsApplied(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	h.clock.now = time.Unix(10_000, 0)
	// An alert handled long after its event still gets its full duration.
	h.responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	if until := h.blocker.blocked[netip.MustParseAddr("203.0.113.9")]; !until.Equal(time.Unix(10_000, 0).Add(time.Hour)) {
		t.Fatalf("deadline = %v, want an hour after it was applied", until)
	}
}

func TestDryRunAndOffTouchNothing(t *testing.T) {
	t.Parallel()

	dryRun, blocker, freezer, output := newTestResponder(ModeDryRun)
	dryRun.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	dryRun.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)}))
	if len(blocker.blocked) != 0 || len(freezer.frozen) != 0 || output.count("response would apply") != 2 {
		t.Fatalf("dry run changed state: blocked %v frozen %v records %v", blocker.blocked, freezer.frozen, output.messages)
	}
	dryRun.RevertAll()
	if len(freezer.thawedID) != 0 {
		t.Fatalf("dry run thawed %v", freezer.thawedID)
	}

	off, _, _, offOutput := newTestResponder(ModeOff)
	off.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	off.Submit(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	if len(offOutput.messages) != 0 || off.Active() != 0 {
		t.Fatalf("off mode recorded %v", offOutput.messages)
	}
}

func TestSkipsAlertsWithoutUsableTargets(t *testing.T) {
	t.Parallel()

	responder, blocker, _, output := newTestResponder(ModeEnforce)
	for _, fields := range []map[string]any{{}, {"peer_address": "127.0.0.1"}, {"peer_address": "::"}, {"peer_address": "ff02::1"}} {
		responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, fields))
	}
	responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cached_cgroup_id": uint64(5)}))
	responder.Handle(alertFor("unrelated", 1, map[string]any{"peer_address": "203.0.113.9"}))
	if len(blocker.blocked) != 0 || output.count("response skipped") != 5 {
		t.Fatalf("blocked %v records %v", blocker.blocked, output.messages)
	}
}

func TestConfigureRevertsRemovedResponses(t *testing.T) {
	t.Parallel()

	responder, blocker, _, output := newTestResponder(ModeEnforce)
	responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	responder.Configure(testResponses[1:])
	if len(blocker.blocked) != 0 || output.count("response reverted") != 1 {
		t.Fatalf("removed response left %v", blocker.blocked)
	}
}

func TestSharedActionOutlivesOneOfItsResponses(t *testing.T) {
	t.Parallel()

	second := policy.Response{ID: "block-intel", Rules: []string{"threat_intel.c2"}, Action: policy.ResponseBlockPeer, Duration: policy.Duration{Duration: 2 * time.Hour}}
	h := newHarness(ModeEnforce, Options{})
	h.responder.Configure(append(slices.Clone(testResponses), second))
	peer := map[string]any{"peer_address": "203.0.113.9"}
	h.responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, peer))
	h.responder.Handle(alertFor("threat_intel.c2", 1, peer))

	h.responder.Configure([]policy.Response{testResponses[0]})
	if until, blocked := h.blocker.blocked[netip.MustParseAddr("203.0.113.9")]; !blocked || !until.Equal(time.Unix(0, 0).Add(time.Hour)) {
		t.Fatalf("after removing one response: blocked until %v (%t), want the remaining response's hour", until, blocked)
	}
	h.responder.Configure(nil)
	if len(h.blocker.blocked) != 0 || h.output.count("response reverted") != 1 {
		t.Fatalf("after removing both: blocked %v records %v", h.blocker.blocked, h.output.messages)
	}
}

func TestChangedResponseRevertsItsAction(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	h.responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	changed := slices.Clone(testResponses)
	changed[0].Action = policy.ResponseFreezeCgroup
	h.responder.Configure(changed)
	if len(h.blocker.blocked) != 0 || h.responder.Active() != 0 {
		t.Fatalf("changed response kept its peer block: %v", h.blocker.blocked)
	}
	if reason := h.output.fields[len(h.output.fields)-1]["reason"]; reason != "policy_changed" {
		t.Fatalf("revert reason = %v, want policy_changed", reason)
	}
}

func TestFailedThawIsRetried(t *testing.T) {
	t.Parallel()

	responder, _, freezer, output := newTestResponder(ModeEnforce)
	responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)}))
	freezer.thawErr = errors.New("busy")
	responder.Expire(time.Unix(1, 0).Add(time.Hour))
	if responder.Active() != 1 || output.count("response revert failed") != 1 {
		t.Fatalf("failed thaw was forgotten: active %d records %v", responder.Active(), output.messages)
	}
	freezer.thawErr = nil
	responder.Expire(time.Unix(1, 0).Add(time.Hour))
	if responder.Active() != 0 || len(freezer.frozen) != 0 {
		t.Fatalf("retry did not thaw: active %d frozen %v", responder.Active(), freezer.frozen)
	}
}

func TestShutdownRetriesFailedThaw(t *testing.T) {
	t.Parallel()

	sleeps := 0
	var h harness
	h = newHarness(ModeEnforce, Options{Sleep: func(time.Duration) {
		sleeps++
		h.freezer.thawErr = nil
	}})
	h.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)}))
	h.freezer.thawErr = errors.New("busy")
	h.responder.RevertAll()
	if sleeps != 1 || h.responder.Active() != 0 || len(h.freezer.frozen) != 0 {
		t.Fatalf("shutdown did not retry: sleeps %d active %d frozen %v", sleeps, h.responder.Active(), h.freezer.frozen)
	}
}

func TestRefusedFreezeIsNotRetriedUntilItsDeadline(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	h.freezer.refuse = true
	alert := alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)})
	h.responder.Handle(alert)
	h.responder.Handle(alert)
	if h.freezer.freezeN != 1 || h.output.count("response failed") != 1 || h.output.count("response skipped") != 1 {
		t.Fatalf("freezes %d records %v, want one attempt then a skip", h.freezer.freezeN, h.output.messages)
	}
	h.responder.Expire(time.Unix(0, 0).Add(time.Hour))
	h.responder.Handle(alert)
	if h.freezer.freezeN != 2 {
		t.Fatalf("freezes after the refusal expired = %d, want 2", h.freezer.freezeN)
	}
}

func TestSubmitQueuesOnlyNamedRules(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	for range queueSize {
		h.responder.Submit(alertFor("unrelated", 1, nil))
	}
	h.responder.Submit(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	if len(h.responder.queue) != 1 {
		t.Fatalf("queue holds %d alerts, want only the one a response names", len(h.responder.queue))
	}
	for range queueSize {
		h.responder.Submit(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	}
	if h.output.count("response skipped") != 1 {
		t.Fatalf("records %v, want one skip for the full queue", h.output.messages)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		h.responder.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for h.responder.Active() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if h.responder.Active() != 1 {
		t.Fatalf("Run did not apply the queued alert")
	}
}

func TestRecoverUndoesAnEarlierRun(t *testing.T) {
	t.Parallel()

	state := filepath.Join(t.TempDir(), "responses.json")
	first := newHarness(ModeEnforce, Options{StatePath: state, BootID: "boot-a"})
	first.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(7)}))
	// The first run crashes here, without RevertAll.

	again := newHarness(ModeEnforce, Options{StatePath: state, BootID: "boot-a"})
	again.blocker.blocked[netip.MustParseAddr("198.51.100.4")] = time.Unix(9_999, 0)
	again.responder.Recover()
	if !again.freezer.thawedID[7] || again.blocker.cleared != 1 || len(again.blocker.blocked) != 0 || again.responder.Active() != 0 {
		t.Fatalf("recover: thawed %v cleared %d blocked %v active %d", again.freezer.thawedID, again.blocker.cleared, again.blocker.blocked, again.responder.Active())
	}
	payload, err := os.ReadFile(state) //nolint:gosec // test path
	if err != nil || strings.Contains(string(payload), `"cgroup_id"`) {
		t.Fatalf("state after recovery = %s, %v; want no frozen cgroups", payload, err)
	}

	first.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(8)}))
	rebooted := newHarness(ModeEnforce, Options{StatePath: state, BootID: "boot-b"})
	rebooted.responder.Recover()
	if len(rebooted.freezer.thawedID) != 0 {
		t.Fatalf("a state file from another boot thawed %v", rebooted.freezer.thawedID)
	}
}

func TestBlockFailureIsRecorded(t *testing.T) {
	t.Parallel()

	responder, blocker, _, output := newTestResponder(ModeEnforce)
	blocker.err = errors.New("map full")
	responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	if responder.Active() != 0 || output.count("response failed") != 1 {
		t.Fatalf("failed block tracked: active %d records %v", responder.Active(), output.messages)
	}
}

func TestCgroupFreezerRefusesCriticalGroups(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	entries := []cgroupinfo.Entry{
		{ID: 1, Path: "/", Level: 0},
		{ID: 2, Path: "/system.slice", Level: 1},
		{ID: 3, Path: "/system.slice/traceguard.service", Level: 2},
		{ID: 4, Path: "/init.scope", Level: 1},
		{ID: 5, Path: "/kubepods.slice/pod-a", Level: 2},
		{ID: 6, Path: "/kubepods.slice", Level: 1},
	}
	for _, entry := range entries {
		directory := filepath.Join(root, entry.Path)
		if err := os.MkdirAll(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "cgroup.freeze"), []byte("0"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.controllers"), []byte("cpu memory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	self := "/system.slice/traceguard.service"
	ids := map[string]uint64{}
	for _, entry := range entries {
		ids[filepath.Join(root, entry.Path)] = entry.ID
	}
	freezer := &CgroupFreezer{
		Root: root, self: func() (string, error) { return self, nil },
		scan: func(context.Context, string) ([]cgroupinfo.Entry, error) { return entries, nil },
		id: func(path string) (uint64, error) {
			if id, ok := ids[path]; ok {
				return id, nil
			}
			return 0, fs.ErrNotExist
		},
	}
	for id, want := range map[uint64]string{1: "below a top-level slice", 2: "below a top-level slice", 3: "contains TraceGuard", 6: "below a top-level slice", 9: "no longer exists"} {
		if _, _, err := freezer.Freeze(id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Freeze(%d) error = %v, want %q", id, err, want)
		}
	}
	path, froze, err := freezer.Freeze(5)
	if err != nil || !froze || path != "/kubepods.slice/pod-a" {
		t.Fatalf("Freeze(5) = %q, %t, %v", path, froze, err)
	}
	if again, froze, err := freezer.Freeze(5); err != nil || froze || again != path {
		t.Fatalf("Freeze of a frozen cgroup = %q, %t, %v; want it left to whoever froze it", again, froze, err)
	}
	state, err := os.ReadFile(filepath.Join(root, path, "cgroup.freeze")) //nolint:gosec // test path
	if err != nil || string(state) != "1" {
		t.Fatalf("cgroup.freeze = %q, %v", state, err)
	}
	// A cgroup removed and recreated at the same path is not thawed.
	ids[filepath.Join(root, path)] = 50
	if err := freezer.Thaw(5, path); err != nil {
		t.Fatal(err)
	}
	if state, _ := os.ReadFile(filepath.Join(root, path, "cgroup.freeze")); string(state) != "1" { //nolint:gosec // test path
		t.Fatalf("thawed a replacement cgroup: cgroup.freeze = %q", state)
	}
	ids[filepath.Join(root, path)] = 5
	if err := freezer.Thaw(5, path); err != nil {
		t.Fatal(err)
	}
	if state, _ := os.ReadFile(filepath.Join(root, path, "cgroup.freeze")); string(state) != "0" { //nolint:gosec // test path
		t.Fatalf("cgroup.freeze after thaw = %q", state)
	}
	if err := freezer.Thaw(9, "/kubepods.slice/gone"); err != nil {
		t.Fatalf("thawing a removed cgroup returned %v", err)
	}

	// The daemon's cgroup is read at each freeze, so a moved daemon is
	// still protected.
	self = "/kubepods.slice/pod-a/traceguard"
	if _, _, err := freezer.Freeze(5); err == nil || !strings.Contains(err.Error(), "contains TraceGuard") {
		t.Fatalf("Freeze after the daemon moved = %v, want a refusal", err)
	}

	nested := &CgroupFreezer{Root: root, self: func() (string, error) { return "/x", nil }, scan: func(context.Context, string) ([]cgroupinfo.Entry, error) {
		return []cgroupinfo.Entry{{ID: 1, Path: "/", Level: 1}, {ID: 5, Path: "/pod-a", Level: 2}}, nil
	}}
	if _, _, err := nested.Freeze(5); err == nil || !strings.Contains(err.Error(), "cgroup v2 root") {
		t.Fatalf("non-root cgroup path error = %v", err)
	}
}

func TestSelfCgroup(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(path, []byte("0::/system.slice/traceguard.service\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if self, err := SelfCgroup(path); err != nil || self != "/system.slice/traceguard.service" {
		t.Fatalf("SelfCgroup = %q, %v", self, err)
	}
}

func TestRecoverKeepsRecordsItCannotThaw(t *testing.T) {
	t.Parallel()

	state := filepath.Join(t.TempDir(), "responses.json")
	first := newHarness(ModeEnforce, Options{StatePath: state, BootID: "boot-a"})
	first.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(7)}))

	// A start without a freezer keeps the record, also through later writes.
	output := &records{}
	noFreezer := New(ModeEnforce, &fakeBlocker{blocked: map[netip.Addr]time.Time{}}, nil, output.record,
		Options{StatePath: state, BootID: "boot-a", Sleep: func(time.Duration) {}})
	noFreezer.Recover()
	noFreezer.Configure(testResponses)
	noFreezer.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	noFreezer.RevertAll()
	if noFreezer.Active() != 0 || output.count("response revert failed") != 1 {
		t.Fatalf("records %v, want the unthawed freeze reported", output.messages)
	}

	again := newHarness(ModeEnforce, Options{StatePath: state, BootID: "boot-a"})
	again.responder.Recover()
	if !again.freezer.thawedID[7] {
		t.Fatalf("the record was lost: thawed %v", again.freezer.thawedID)
	}
}

func TestRecoverLeavesAnUnreadableStateFile(t *testing.T) {
	t.Parallel()

	state := filepath.Join(t.TempDir(), "responses.json")
	if err := os.WriteFile(state, []byte(`{"boot_id": "boot-a", "frozen": [`), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newHarness(ModeEnforce, Options{StatePath: state, BootID: "boot-a"})
	h.responder.Recover()
	h.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(8)}))
	h.responder.RevertAll()
	payload, err := os.ReadFile(state) //nolint:gosec // test path
	if err != nil || string(payload) != `{"boot_id": "boot-a", "frozen": [` || h.output.count("response state unreadable") != 1 {
		t.Fatalf("state = %q, %v; records %v; want the file left as it was and the failure reported", payload, err, h.output.messages)
	}
}

func TestThawWaitsForAMissingHierarchy(t *testing.T) {
	t.Parallel()

	freezer := &CgroupFreezer{Root: filepath.Join(t.TempDir(), "unmounted"), id: func(string) (uint64, error) { return 0, fs.ErrNotExist }}
	if err := freezer.Thaw(5, "/kubepods.slice/pod-a"); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("Thaw without a hierarchy = %v, want an error so the record is kept", err)
	}
}

func TestLocateSelfNeedsTheDaemonInItsCgroup(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	procCgroup := filepath.Join(t.TempDir(), "cgroup")
	if err := os.MkdirAll(filepath.Join(root, "system.slice", "traceguard.service"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "system.slice", "traceguard.service", "cgroup.procs"), []byte("7\n42\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for content, want := range map[string]string{
		"0::/system.slice/traceguard.service\n": "",
		// In a private cgroup namespace the daemon sees itself at the root.
		"0::/\n": "private cgroup namespace",
	} {
		if err := os.WriteFile(procCgroup, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		path, err := LocateSelf(root, procCgroup, 42)
		if want == "" && (err != nil || path != "/system.slice/traceguard.service") {
			t.Errorf("%q: locateSelf = %q, %v", content, path, err)
		}
		if want != "" && (err == nil || !strings.Contains(err.Error(), want)) {
			t.Errorf("%q: locateSelf error = %v, want %q", content, err, want)
		}
	}
}

func TestDryRunFreezeRunsTheSafetyChecks(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeDryRun, Options{})
	h.freezer.refuse = true
	h.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)}))
	if h.output.count("response would apply") != 0 || h.output.count("response failed") != 1 || h.responder.Active() != 0 || h.freezer.freezeN != 0 {
		t.Fatalf("records %v active %d freezes %d, want the refusal reported and nothing frozen", h.output.messages, h.responder.Active(), h.freezer.freezeN)
	}
}

func TestAlreadyFrozenCgroupIsLeftFrozen(t *testing.T) {
	t.Parallel()

	state := filepath.Join(t.TempDir(), "responses.json")
	h := newHarness(ModeEnforce, Options{StatePath: state, BootID: "b"})
	h.freezer.already = true
	h.responder.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)}))
	if fields := h.output.fields[len(h.output.fields)-1]; fields["already_frozen"] != true {
		t.Fatalf("applied record = %v, want already_frozen", fields)
	}
	h.responder.RevertAll()
	if len(h.freezer.thawedID) != 0 {
		t.Fatalf("thawed %v, want a freeze made by something else left alone", h.freezer.thawedID)
	}
	if payload, _ := os.ReadFile(state); strings.Contains(string(payload), `"cgroup_id"`) { //nolint:gosec // test path
		t.Fatalf("state %s records a freeze TraceGuard did not make", payload)
	}
}

func TestFailedExtensionKeepsTheRecordedDeadline(t *testing.T) {
	t.Parallel()

	h := newHarness(ModeEnforce, Options{})
	peer := map[string]any{"peer_address": "203.0.113.9"}
	h.responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, peer))
	h.blocker.err = errors.New("map busy")
	h.clock.now = time.Unix(600, 0)
	h.responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 600, peer))
	h.blocker.err = nil
	// Removing nothing still recomputes the deadline from the owners.
	h.responder.Configure(testResponses)
	h.responder.Expire(time.Unix(0, 0).Add(time.Hour))
	if h.responder.Active() != 0 {
		t.Fatalf("the block outlived the deadline its kernel entry has: active %d", h.responder.Active())
	}
}
