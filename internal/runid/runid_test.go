package runid

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestIDIsHex32(t *testing.T) {
	t.Parallel()

	if len(ID) != 32 {
		t.Fatalf("ID = %q, want 32 hex characters", ID)
	}
	if first, second := newID(), newID(); first == second {
		t.Fatal("two run IDs were equal")
	}
}

func TestStartCountsRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-sequence")
	for want := uint64(1); want <= 3; want++ {
		if err := Start(path); err != nil {
			t.Fatal(err)
		}
		if Sequence != want {
			t.Fatalf("Sequence = %d, want %d", Sequence, want)
		}
	}
	firstInstall := Install
	if len(firstInstall) != 32 {
		t.Fatalf("Install = %q", firstInstall)
	}
	if err := os.WriteFile(path, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Start(path); err != nil || Sequence != 1 || Install == firstInstall {
		t.Fatalf("Start on a corrupt file = %v, Sequence %d, Install %q; want a new install from 1", err, Sequence, Install)
	}
}

func TestOverlappingStartsNeverShareANumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "run-sequence")
	got := make(chan uint64, 8)
	for range 8 {
		go func() {
			_, next, err := allocate(path)
			if err != nil {
				t.Error(err)
			}
			got <- next
		}()
	}
	seen := map[uint64]bool{}
	for range 8 {
		number := <-got
		if seen[number] {
			t.Fatalf("number %d was allocated twice", number)
		}
		seen[number] = true
	}
	if len(seen) != 8 || !seen[1] || !seen[8] {
		t.Fatalf("numbers = %v, want 1..8", seen)
	}
}

func TestALostCounterGetsANewInstall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run-sequence")
	first, _, err := allocate(path)
	if err != nil {
		t.Fatal(err)
	}
	again, _, _ := allocate(path)
	if again != first {
		t.Fatal("the install changed while the file was kept")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fresh, number, err := allocate(path)
	if err != nil || fresh == first || number != 1 {
		t.Fatalf("after loss: install %q (was %q), number %d, %v", fresh, first, number, err)
	}
}

func TestAHeldLockIsWaitedOnOnlySoLong(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.lock")
	holder, err := os.Create(path) //nolint:gosec // a test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Close() }()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	waiter, err := os.Open(path) //nolint:gosec // a test temp file
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = waiter.Close() }()
	started := time.Now()
	if err := lockWithin(waiter, 100*time.Millisecond); err == nil {
		t.Fatal("lockWithin took a lock another process holds")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("lockWithin waited %v", elapsed)
	}
	_ = unix.Flock(int(holder.Fd()), unix.LOCK_UN)
	if err := lockWithin(waiter, time.Second); err != nil {
		t.Fatalf("lockWithin after release: %v", err)
	}
}

func TestReservedNamesTheCounterFiles(t *testing.T) {
	for path, want := range map[string]bool{
		DefaultPath: true, DefaultPath + ".lock": true, "/var/lib/traceguard//run-sequence": true,
		"/var/lib/traceguard/responses.json": false, "": false,
	} {
		if got := Reserved(path); got != want {
			t.Errorf("Reserved(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestAnUnreadableCounterStartsANewInstall(t *testing.T) {
	for _, content := range []string{"5\n", "not a counter\n", strings.Repeat("z", 32) + " 4\n", strings.Repeat("a", 32) + " 18446744073709551615\n",
		strings.Repeat("a", 32) + " 9223372036854775807\n", strings.Repeat("a", 32) + " 0\n", strings.Repeat("x", 4096),
	} {
		path := filepath.Join(t.TempDir(), "run-sequence")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		install, next, err := allocate(path)
		if err != nil || next != 1 || len(install) != 32 || install == strings.Repeat("a", 32) {
			t.Fatalf("allocate(%q) = %q, %d, %v; want a new install counting from 1", content, install, next, err)
		}
		if again, count, err := allocate(path); err != nil || again != install || count != 2 {
			t.Fatalf("second allocate(%q) = %q, %d, %v", content, again, count, err)
		}
	}
}
