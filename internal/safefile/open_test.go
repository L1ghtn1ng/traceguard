package safefile

import (
	"io"
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

func TestOpenAbsoluteFallsBackWhenOpenat2IsUnavailable(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(path, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("write domain file: %v", err)
	}

	file, err := openAbsolute(path, unix.O_RDONLY, 0, func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	})
	if err != nil {
		t.Fatalf("openAbsolute fallback: %v", err)
	}
	defer file.Close()
	payload, err := io.ReadAll(file)
	if err != nil {
		t.Fatalf("read fallback file: %v", err)
	}
	if string(payload) != "example.com\n" {
		t.Fatalf("fallback content = %q, want domain file content", payload)
	}
}

func TestOpenAbsoluteFallbackRejectsSymlinks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "domains.txt")
	if err := os.WriteFile(target, []byte("example.com\n"), 0o600); err != nil {
		t.Fatalf("write domain file: %v", err)
	}
	finalLink := filepath.Join(dir, "domains-link.txt")
	if err := os.Symlink(target, finalLink); err != nil {
		t.Fatalf("create final symlink: %v", err)
	}
	parentLink := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(dir, parentLink); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}

	unsupportedOpenat2 := func(int, string, *unix.OpenHow) (int, error) {
		return -1, unix.ENOSYS
	}
	for _, path := range []string{finalLink, filepath.Join(parentLink, "domains.txt")} {
		file, err := openAbsolute(path, unix.O_RDONLY, 0, unsupportedOpenat2)
		if file != nil {
			_ = file.Close()
		}
		if err == nil {
			t.Fatalf("openAbsolute fallback followed symlink in %q", path)
		}
	}
}

func TestWriteFileAtomicReplacesContents(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "cache", "policy.yaml")
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
