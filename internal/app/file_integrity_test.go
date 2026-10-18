package app

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/fim"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestFileChangeOperationNamesMatchPolicyValidation(t *testing.T) {
	t.Parallel()

	names := []string{"rmdir"}
	for _, name := range fileChangeOperations {
		names = append(names, name)
	}
	want := slices.Clone(policyconfig.SecurityEventOperations["file_change"])
	slices.Sort(names)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("file_change operations = %v, policy accepts %v", names, want)
	}
}

func TestAppendFileChangeFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event ebpf.Event
		want  map[string]any
	}{
		{"unlink", ebpf.Event{Filename: "/etc/x", FileMode: atFDCWD}, map[string]any{"operation": "unlink"}},
		{"rmdir", ebpf.Event{Filename: "/etc/d", FileMode: atFDCWD, FileFlags: atRemoveDir}, map[string]any{
			"operation": "rmdir", "requested_flags": uint32(atRemoveDir),
		}},
		{"renameat", ebpf.Event{Operation: 1, Filename: "a", FileMode: 4, NewPath: "/etc/b"}, map[string]any{
			"operation": "rename", "requested_dirfd": int32(4), "new_path": "/etc/b",
		}},
		{"chmod", ebpf.Event{Operation: 2, Filename: "/usr/bin/x", FileMode: atFDCWD, Value: 0o104755}, map[string]any{
			"operation": "chmod", "requested_mode": "4755",
		}},
		{"chown keeps gid", ebpf.Event{Operation: 3, Filename: "/etc/x", FileMode: atFDCWD, Value: uint64(unchangedID)<<32 | 1000}, map[string]any{
			"operation": "chown", "requested_uid": uint32(1000),
		}},
		{"truncate", ebpf.Event{Operation: 4, Filename: "/var/log/x", FileMode: atFDCWD, Value: 0}, map[string]any{
			"operation": "truncate", "truncate_length": uint64(0),
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fields := map[string]any{}
			appendFileChangeFields(fields, test.event)
			test.want["requested_path"] = test.event.Filename
			test.want["path_source"] = "syscall-requested"
			if !reflect.DeepEqual(fields, test.want) {
				t.Fatalf("fields = %#v, want %#v", fields, test.want)
			}
		})
	}
}

func TestResolveRequestedPath(t *testing.T) {
	t.Parallel()

	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "42", "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/home/user", filepath.Join(procRoot, "42", "cwd")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/cron.d", filepath.Join(procRoot, "42", "fd", "7")); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		pid, dirfd uint32
		path, want string
		ok         bool
	}{
		"absolute":       {42, atFDCWD, "/etc/../etc/passwd", "/etc/passwd", true},
		"relative cwd":   {42, atFDCWD, ".ssh/authorized_keys", "/home/user/.ssh/authorized_keys", true},
		"relative dirfd": {42, 7, "job", "/etc/cron.d/job", true},
		"unknown dirfd":  {42, 9, "job", "", false},
		"gone process":   {43, atFDCWD, "x", "", false},
		"empty":          {42, atFDCWD, "", "", false},
	} {
		if got, ok := resolveRequestedPath(procRoot, test.pid, test.dirfd, test.path); got != test.want || ok != test.ok {
			t.Errorf("%s: resolveRequestedPath = %q, %t; want %q, %t", name, got, ok, test.want, test.ok)
		}
	}
}

func TestSharesMountNamespace(t *testing.T) {
	t.Parallel()

	procRoot := t.TempDir()
	for pid, namespace := range map[string]string{"self": "mnt:[1]", "42": "mnt:[1]", "43": "mnt:[2]"} {
		if err := os.MkdirAll(filepath.Join(procRoot, pid, "ns"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(namespace, filepath.Join(procRoot, pid, "ns", "mnt")); err != nil {
			t.Fatal(err)
		}
	}
	for pid, want := range map[uint32]bool{42: true, 43: false, 44: true} {
		if got := sharesMountNamespace(procRoot, pid); got != want {
			t.Errorf("sharesMountNamespace(%d) = %t, want %t", pid, got, want)
		}
	}
}

func TestWarnIntegrityWithoutAudit(t *testing.T) {
	t.Parallel()

	watched := policyconfig.FileIntegrityPolicy{Paths: []string{"/etc/**"}}
	noRescan := policyconfig.FileIntegrityPolicy{Paths: []string{"/etc/**"}, RescanInterval: &policyconfig.Duration{}}
	for name, test := range map[string]struct {
		fileAudit bool
		integrity policyconfig.FileIntegrityPolicy
		want      string
	}{
		"audit on":         {true, watched, ""},
		"integrity off":    {false, policyconfig.FileIntegrityPolicy{}, ""},
		"rescan only":      {false, watched, "only by rescan"},
		"nothing observes": {false, noRescan, "sees no file writes"},
	} {
		recorder, output := newTestRecorder(t)
		warnIntegrityWithoutAudit(config.Config{FileAudit: test.fileAudit}, test.integrity, recorder)
		logged := output.String()
		if test.want == "" && logged != "" || test.want != "" && !strings.Contains(logged, test.want) {
			t.Errorf("%s: logged %q, want %q", name, logged, test.want)
		}
	}
}

func TestIntegrityRecordFields(t *testing.T) {
	t.Parallel()

	previous := &fim.State{Type: "file", Mode: 0o755, Size: 4, ModTime: time.Unix(1, 0).UTC(), SHA256: "aa"}
	current := &fim.State{Type: "file", Mode: 0o755 | fs.ModeSetuid, UID: 0, GID: 0, Size: 4, ModTime: time.Unix(2, 0).UTC(), HashSkipped: "size"}
	fields := integrityRecordFields(fim.Change{Path: "/usr/bin/x", Kind: fim.Attributes, Changed: []string{"mode"}, Previous: previous, Current: current},
		fim.Actor{"actor_program": "chmod"})
	for key, want := range map[string]any{
		"event": "file_integrity", "path": "/usr/bin/x", "change": "attributes", "detection_source": "event",
		"mode": "4755", "previous_mode": "0755", "previous_sha256": "aa", "hash_skipped": "size", "actor_program": "chmod",
	} {
		if !reflect.DeepEqual(fields[key], want) {
			t.Errorf("%s = %#v, want %#v", key, fields[key], want)
		}
	}
	if rescan := integrityRecordFields(fim.Change{Path: "/x", Kind: fim.Deleted, Previous: previous}, nil); rescan["detection_source"] != "rescan" {
		t.Fatalf("rescan detection_source = %v", rescan["detection_source"])
	}
}

func TestNotifyIntegrityReportsWatchedWrites(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc", "cron.d"), 0o750); err != nil {
		t.Fatal(err)
	}
	watcher := fim.NewWatcher(root)
	watcher.Configure(policyconfig.FileIntegrityPolicy{Paths: []string{"/etc/cron.d/**"}})
	var mu sync.Mutex
	var changes []fim.Change
	var actors []fim.Actor
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		watcher.Run(ctx, func(change fim.Change, actor fim.Actor) {
			mu.Lock()
			defer mu.Unlock()
			changes = append(changes, change)
			actors = append(actors, actor)
		})
		close(done)
	}()
	defer func() {
		cancel()
		<-done
	}()
	waitUntil(t, func() bool { return watcher.Stats().Files == 1 })

	if err := os.WriteFile(filepath.Join(root, "etc", "cron.d", "job"), []byte("* * * * * root x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	event := ebpf.Event{Kind: ebpf.EventFileAccess, PID: 1, Filename: "/etc/cron.d/job", FileFlags: 0x41}
	notifyIntegrity(watcher, t.TempDir(), event, map[string]any{"program": "bash", "event": "file_created"})
	readOnly := ebpf.Event{Kind: ebpf.EventFileAccess, PID: 1, Filename: "/etc/cron.d/job", FileFlags: 0}
	notifyIntegrity(watcher, t.TempDir(), readOnly, map[string]any{"program": "cat"})

	waitUntil(t, func() bool { mu.Lock(); defer mu.Unlock(); return len(changes) > 0 })
	mu.Lock()
	defer mu.Unlock()
	if len(changes) != 1 || changes[0].Path != "/etc/cron.d/job" || changes[0].Kind != fim.Created {
		t.Fatalf("changes = %+v", changes)
	}
	if actors[0]["actor_program"] != "bash" || actors[0]["actor_event"] != "file_created" {
		t.Fatalf("actor = %v", actors[0])
	}
}

func waitUntil(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met before the deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
