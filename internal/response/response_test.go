package response

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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

type fakeFreezer struct {
	frozen  map[string]bool
	thawErr error
}

func (f *fakeFreezer) Freeze(id uint64) (string, error) {
	path := fmt.Sprintf("/kubepods.slice/pod-%d", id)
	f.frozen[path] = true
	return path, nil
}

func (f *fakeFreezer) Thaw(path string) error {
	if f.thawErr != nil {
		return f.thawErr
	}
	delete(f.frozen, path)
	return nil
}

type records struct{ messages []string }

func (r *records) record(message string, _ map[string]any) { r.messages = append(r.messages, message) }

func (r *records) count(message string) int {
	count := 0
	for _, recorded := range r.messages {
		if recorded == message {
			count++
		}
	}
	return count
}

var testResponses = []policy.Response{
	{ID: "block-scanner", Rules: []string{"baseline.inbound-ssh-bruteforce"}, Action: policy.ResponseBlockPeer, Duration: policy.Duration{Duration: time.Hour}},
	{ID: "freeze-injector", Rules: []string{"runtime.process-memory-write"}, Action: policy.ResponseFreezeCgroup, Duration: policy.Duration{Duration: 10 * time.Minute}},
}

func newTestResponder(mode string) (*Responder, *fakeBlocker, *fakeFreezer, *records) {
	blocker := &fakeBlocker{blocked: map[netip.Addr]time.Time{}}
	freezer := &fakeFreezer{frozen: map[string]bool{}}
	output := &records{}
	responder := New(mode, blocker, freezer, output.record)
	responder.Configure(testResponses)
	return responder, blocker, freezer, output
}

func alertFor(rule string, at int64, fields map[string]any) detection.Alert {
	return detection.Alert{RuleID: rule, Timestamp: time.Unix(at, 0), Fields: fields}
}

func TestEnforceAppliesExtendsAndExpiresActions(t *testing.T) {
	t.Parallel()

	responder, blocker, freezer, output := newTestResponder(ModeEnforce)
	peer := netip.MustParseAddr("203.0.113.9")
	responder.Handle(alertFor("baseline.inbound-ssh-bruteforce", 100, map[string]any{"peer_address": "203.0.113.9"}))
	responder.Handle(alertFor("runtime.process-memory-write", 100, map[string]any{"cgroup_id": uint64(2)}))
	if until := blocker.blocked[peer]; !until.Equal(time.Unix(100, 0).Add(time.Hour)) || len(freezer.frozen) != 1 || responder.Active() != 2 {
		t.Fatalf("blocked %v frozen %v active %d", blocker.blocked, freezer.frozen, responder.Active())
	}

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

func TestDryRunAndOffTouchNothing(t *testing.T) {
	t.Parallel()

	dryRun, blocker, freezer, output := newTestResponder(ModeDryRun)
	dryRun.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
	dryRun.Handle(alertFor("runtime.process-memory-write", 1, map[string]any{"cgroup_id": uint64(2)}))
	if len(blocker.blocked) != 0 || len(freezer.frozen) != 0 || output.count("response would apply") != 2 {
		t.Fatalf("dry run changed state: blocked %v frozen %v records %v", blocker.blocked, freezer.frozen, output.messages)
	}
	dryRun.RevertAll()

	off, _, _, offOutput := newTestResponder(ModeOff)
	off.Handle(alertFor("baseline.inbound-ssh-bruteforce", 1, map[string]any{"peer_address": "203.0.113.9"}))
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
	freezer := &CgroupFreezer{Root: root, Self: "/system.slice/traceguard.service", scan: func(context.Context, string) ([]cgroupinfo.Entry, error) {
		return entries, nil
	}}
	for id, want := range map[uint64]string{1: "below a top-level slice", 2: "below a top-level slice", 3: "contains TraceGuard", 6: "below a top-level slice", 9: "no longer exists"} {
		if _, err := freezer.Freeze(id); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Freeze(%d) error = %v, want %q", id, err, want)
		}
	}
	path, err := freezer.Freeze(5)
	if err != nil || path != "/kubepods.slice/pod-a" {
		t.Fatalf("Freeze(5) = %q, %v", path, err)
	}
	state, err := os.ReadFile(filepath.Join(root, path, "cgroup.freeze")) //nolint:gosec // test path
	if err != nil || string(state) != "1" {
		t.Fatalf("cgroup.freeze = %q, %v", state, err)
	}
	if err := freezer.Thaw(path); err != nil {
		t.Fatal(err)
	}
	if err := freezer.Thaw("/kubepods.slice/gone"); err != nil {
		t.Fatalf("thawing a removed cgroup returned %v", err)
	}

	nested := &CgroupFreezer{Root: root, scan: func(context.Context, string) ([]cgroupinfo.Entry, error) {
		return []cgroupinfo.Entry{{ID: 1, Path: "/", Level: 1}, {ID: 5, Path: "/pod-a", Level: 2}}, nil
	}}
	if _, err := nested.Freeze(5); err == nil || !strings.Contains(err.Error(), "cgroup v2 root") {
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
