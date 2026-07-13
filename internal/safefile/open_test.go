package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadFileRejectsSymlinksAndOversizedFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if _, err := ReadFile(target, 4); err == nil {
		t.Fatal("ReadFile accepted oversized file")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := ReadFile(link, 8); err == nil {
		t.Fatal("ReadFile followed symlink")
	}
}

func TestReadFileRejectsFIFOWithoutBlocking(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "input.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo returned error: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(path, 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not regular") {
			t.Fatalf("ReadFile error = %v, want non-regular file rejection", err)
		}
	case <-time.After(time.Second):
		t.Fatal("ReadFile blocked while opening FIFO")
	}
}

func TestWriteFileAtomicReplacesContents(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cache", "blocklist.txt")
	if err := WriteFileAtomic(path, []byte("first"), 0o640); err != nil {
		t.Fatalf("first WriteFileAtomic: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("second"), 0o640); err != nil {
		t.Fatalf("second WriteFileAtomic: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if string(got) != "second" {
		t.Fatalf("content = %q, want second", got)
	}
}

func TestWriteFileAtomicCleansRenameTarget(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := dir + string(filepath.Separator) + "cache" + string(filepath.Separator) + "."
	if err := WriteFileAtomic(path, []byte("payload"), 0o640); err != nil {
		t.Fatalf("WriteFileAtomic with unclean path: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "cache"))
	if err != nil {
		t.Fatalf("read cleaned target: %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("content = %q, want payload", got)
	}
}
