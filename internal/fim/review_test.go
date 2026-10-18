package fim

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestUnreadableHashedFileIsReportedOnceAndRecheckedLater(t *testing.T) {
	t.Parallel()

	modified := time.Unix(100, 0)
	key := []string{"/etc/shadow"}
	state := func(digest, skipped string) State {
		return State{Type: "file", Size: 10, ModTime: modified, SHA256: digest, HashSkipped: skipped}
	}
	step := func(baseline map[string]State, current State) ([]Change, map[string]State) {
		changes, final := reconcile(key, baseline, scanResult{states: map[string]State{key[0]: current}}, func(string) bool { return true })
		return changes, map[string]State{key[0]: *final[key[0]]}
	}

	// Size and modification time can be preserved while content changes,
	// so a hashed file that becomes unreadable cannot count as unchanged.
	changes, baseline := step(map[string]State{key[0]: state("aa", "")}, state("", "unreadable"))
	if len(changes) != 1 || changes[0].Kind != Modified || !slices.Contains(changes[0].Changed, "content") {
		t.Fatalf("unreadable file: changes %+v, want one unverified content change", changes)
	}
	if changes, baseline = step(baseline, state("", "unreadable")); len(changes) != 0 {
		t.Fatalf("still unreadable: changes %+v, want it reported only once", changes)
	}
	if changes, _ := step(baseline, state("aa", "")); len(changes) != 0 {
		t.Fatalf("readable again, same digest: changes %+v, want none", changes)
	}
	if changes, _ := step(baseline, state("bb", "")); len(changes) != 1 || !slices.Contains(changes[0].Changed, "content") {
		t.Fatalf("readable again, new digest: changes %+v, want a content change", changes)
	}
}

func TestSymlinkedParentIsNotFollowed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "elsewhere"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "elsewhere", "secret"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "elsewhere"), filepath.Join(root, "etc", "alias")); err != nil {
		t.Fatal(err)
	}
	// The symlink itself may be recorded as a symlink, but nothing it
	// points to is read.
	for _, pattern := range []string{"/etc/alias/secret", "/etc/alias/**"} {
		s := scanner{root: root, policy: policy.FileIntegrityPolicy{Paths: []string{pattern}}, maxSize: 1 << 20}
		for path := range s.Baseline().states {
			if strings.HasPrefix(path, "/etc/alias/") {
				t.Errorf("%s: baseline read %s through the symlinked directory", pattern, path)
			}
		}
	}
}

func TestExactExclusionKeepsTheDirectorysEntries(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "ssl", "private"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "ssl", "openssl.cnf"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc", "ssl", "private", "key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := scanner{root: root, maxSize: 1 << 20, policy: policy.FileIntegrityPolicy{
		Paths: []string{"/etc/**"}, Exclude: []string{"/etc/ssl", "/etc/ssl/private/**"},
	}}
	states := s.Baseline().states
	if _, ok := states["/etc/ssl/openssl.cnf"]; !ok {
		t.Fatalf("baseline %v, want files under an exactly excluded directory kept", states)
	}
	for _, excluded := range []string{"/etc/ssl", "/etc/ssl/private", "/etc/ssl/private/key"} {
		if _, ok := states[excluded]; ok {
			t.Errorf("baseline recorded excluded %s", excluded)
		}
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

func TestUnattributedCheckBecomesAmbiguousWithoutPanicking(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/hosts", "127.0.0.1 localhost\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/hosts"))
	writeFile(t, root, "etc/hosts", "10.0.0.1 bank.example\n")
	watcher.Notify("/etc/hosts", nil)
	watcher.Notify("/etc/hosts", Actor{"actor_pid": uint32(2)})
	watcher.checkDue(time.Now().Add(settleDelay), output.emit)
	changes, actors := output.snapshot()
	if len(changes) != 1 || actors[0]["actor_ambiguous"] != true {
		t.Fatalf("changes %+v actors %v, want one ambiguous change", changes, actors)
	}
}

func TestCheckDuringPolicyChangeWaitsForRebuild(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/hosts", "127.0.0.1 localhost\n")
	watcher, output := newTestWatcher(t, root, watchPolicy("/etc/hosts"))
	writeFile(t, root, "etc/hosts", "10.0.0.1 bank.example\n")
	watcher.Notify("/etc/hosts", Actor{"actor_pid": uint32(1)})
	watcher.mu.Lock()
	watcher.rebuild = true
	watcher.mu.Unlock()
	watcher.checkDue(time.Now().Add(settleDelay), output.emit)
	watcher.mu.Lock()
	_, requeued := watcher.pending["/etc/hosts"]
	watcher.mu.Unlock()
	if changes, _ := output.snapshot(); len(changes) != 0 || !requeued {
		t.Fatalf("changes %+v requeued %t, want the check held for the rebuild", changes, requeued)
	}
}

func TestBaselineOfExactlyMaxFilesIsComplete(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/hosts", "127.0.0.1 localhost\n")
	s := scanner{root: root, policy: watchPolicy("/etc/hosts"), maxSize: 1 << 20}
	result := newScanResult()
	for index := range MaxFiles - 1 {
		result.states[fmt.Sprintf("/other/%d", index)] = State{Type: "file"}
	}
	s.record("/etc/hosts", &result)
	if result.truncated || len(result.states) != MaxFiles {
		t.Fatalf("truncated %t with %d states, want a complete baseline of exactly MaxFiles", result.truncated, len(result.states))
	}
	s.record("/etc/hosts", &result)
	if result.truncated {
		t.Fatal("rerecording a known path truncated the baseline")
	}
	s.record("/etc/passwd", &result)
	if !result.truncated {
		t.Fatal("an entry beyond MaxFiles did not truncate the baseline")
	}
}

func TestPathsForFileFindsEveryHardLink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "etc/sudoers", "root ALL=(ALL) ALL\n")
	if err := os.Link(filepath.Join(root, "etc", "sudoers"), filepath.Join(root, "etc", "sudoers.link")); err != nil {
		t.Fatal(err)
	}
	watcher, _ := newTestWatcher(t, root, watchPolicy("/etc/**"))
	state := watcher.baseline["/etc/sudoers"]
	if state.inode == 0 {
		t.Fatal("baseline recorded no inode")
	}
	if paths := watcher.PathsForFile(state.device, state.inode); !slices.Equal(slices.Sorted(slices.Values(paths)), []string{"/etc/sudoers", "/etc/sudoers.link"}) {
		t.Fatalf("PathsForFile = %v, want both names", paths)
	}
}
