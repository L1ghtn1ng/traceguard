package safefile

import (
	"os"
	"path/filepath"
	"testing"
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
