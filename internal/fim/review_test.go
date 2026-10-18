package fim

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestUnknownPathsAreNotReportedDeleted(t *testing.T) {
	t.Parallel()

	baseline := map[string]State{"/etc/a": {Type: "file"}, "/etc/sub/b": {Type: "file"}}
	for name, result := range map[string]scanResult{
		"truncated":  {states: map[string]State{}, truncated: true},
		"unreadable": {states: map[string]State{"/etc/a": {Type: "file"}}, unreadable: []string{"/etc/sub"}},
	} {
		changes, final := reconcile([]string{"/etc/a", "/etc/sub/b"}, baseline, result, func(string) bool { return true })
		if len(changes) != 0 || final["/etc/sub/b"] == nil {
			t.Errorf("%s: changes %+v final %v, want unknown entries kept", name, changes, final)
		}
	}
	changes, final := reconcile([]string{"/etc/a"}, baseline, scanResult{states: map[string]State{}}, func(string) bool { return true })
	if len(changes) != 1 || changes[0].Kind != Deleted || final["/etc/a"] != nil {
		t.Fatalf("a known absence was not reported deleted: %+v", changes)
	}
}

func TestFailedHashKeepsBaselineDigest(t *testing.T) {
	t.Parallel()

	modified := time.Unix(100, 0)
	baseline := map[string]State{"/etc/shadow": {Type: "file", Size: 10, ModTime: modified, SHA256: "aa"}}
	unreadable := scanResult{states: map[string]State{"/etc/shadow": {Type: "file", Size: 10, ModTime: modified, HashSkipped: "unreadable"}}}
	changes, final := reconcile([]string{"/etc/shadow"}, baseline, unreadable, func(string) bool { return true })
	if len(changes) != 0 || final["/etc/shadow"].SHA256 != "aa" {
		t.Fatalf("failed hash: changes %+v digest %q, want no change and the digest kept", changes, final["/etc/shadow"].SHA256)
	}
}

func TestModificationTimeChangeIsReported(t *testing.T) {
	t.Parallel()

	change, ok := diff("/etc/x", &State{Type: "file", SHA256: "aa", ModTime: time.Unix(1, 0)}, &State{Type: "file", SHA256: "aa", ModTime: time.Unix(2, 0)})
	if !ok || change.Kind != Attributes || !slices.Equal(change.Changed, []string{"mtime"}) {
		t.Fatalf("change = %+v, %t", change, ok)
	}
	if _, ok := diff("/etc", &State{Type: "directory", ModTime: time.Unix(1, 0)}, &State{Type: "directory", ModTime: time.Unix(2, 0)}); ok {
		t.Fatal("a directory mtime change was reported")
	}
}

func TestNotifyKeepsFirstDueTimeAndActor(t *testing.T) {
	t.Parallel()

	watcher := NewWatcher(t.TempDir())
	clock := time.Unix(100, 0)
	watcher.now = func() time.Time { return clock }
	watcher.Notify("/etc/x", Actor{"actor_pid": uint32(1)})
	clock = clock.Add(900 * time.Millisecond)
	watcher.Notify("/etc/x", Actor{"actor_pid": uint32(2)})
	check := watcher.pending["/etc/x"]
	if !check.due.Equal(time.Unix(100, 0).Add(settleDelay)) || check.actor["actor_pid"] != uint32(1) || !check.ambiguous {
		t.Fatalf("pending check = %+v, want the first due time and actor, marked ambiguous", check)
	}
}

func TestQueuedChecksSurviveRescans(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/hosts", "a\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/hosts"))
	watcher.Notify("/etc/hosts", Actor{"actor_program": "editor"})
	watcher.install(false, output.emit)
	if _, queued := watcher.pending["/etc/hosts"]; !queued {
		t.Fatal("a rescan discarded a queued check")
	}
}

func TestPolicyChangeReportsOnlyPathsWatchedBefore(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/a", "1\n")
	writeFile(t, root, "srv/b", "1\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/**"))
	writeFile(t, root, "etc/a", "changed\n")
	watcher.Configure(policy.FileIntegrityPolicy{Paths: []string{"/etc/**", "/srv/**"}})
	watcher.mu.Lock()
	watcher.rebuild = false
	watcher.mu.Unlock()
	watcher.install(true, output.emit)
	changes, _ := output.snapshot()
	if len(changes) != 1 || changes[0].Path != "/etc/a" || changes[0].Kind != Modified {
		t.Fatalf("changes = %+v, want only the change to a path watched before", changes)
	}
	if _, ok := watcher.baseline["/srv/b"]; !ok {
		t.Fatal("a newly watched path was not baselined")
	}
}

func TestAffectedKeysSkipsBaselineWalkForFiles(t *testing.T) {
	t.Parallel()

	baseline := map[string]State{"/usr/bin/a": {Type: "file"}, "/usr/bin/b": {Type: "file"}, "/usr/bin": {Type: "directory"}}
	if keys := affectedKeys("/usr/bin/a", baseline, newScanResult()); !slices.Equal(keys, []string{"/usr/bin/a"}) {
		t.Fatalf("file keys = %v", keys)
	}
	if keys := affectedKeys("/usr/bin", baseline, newScanResult()); len(keys) != 3 {
		t.Fatalf("directory keys = %v, want the directory and its entries", keys)
	}
}

func TestUnreadableDirectoryIsUnknown(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can read any directory")
	}

	root := t.TempDir()
	writeFile(t, root, "etc/private/key", "x\n")
	if err := os.Chmod(filepath.Join(root, "etc/private"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "etc/private"), 0o700) }) //nolint:gosec // restores a test directory for cleanup
	result := scanner{root: root, policy: watchPolicy("/etc/**"), maxSize: 1 << 20}.Baseline()
	if result.known("/etc/private/key") {
		t.Fatalf("entries of an unreadable directory are known: %+v", result)
	}
}
