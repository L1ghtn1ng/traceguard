package logging

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRotatingFileRotatesAndKeepsBackups(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "traceguard.log")

	writer, err := NewRotatingFile(path, Options{
		MaxSizeBytes: 32,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		t.Fatalf("NewRotatingFile returned error: %v", err)
	}
	defer writer.Close()

	line := bytes.Repeat([]byte("x"), 20)
	for range 8 {
		if _, err := writer.Write(append(append([]byte{}, line...), '\n')); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current log file missing: %v", err)
	}
	for idx := 1; idx <= 5; idx++ {
		rotated := rotatedPath(path, idx)
		if _, err := os.Stat(rotated); err != nil {
			t.Fatalf("rotated log %d missing: %v", idx, err)
		}
		file, err := os.Open(rotated)
		if err != nil {
			t.Fatalf("open rotated log %d: %v", idx, err)
		}
		compressed, err := gzip.NewReader(file)
		if err != nil {
			_ = file.Close()
			t.Fatalf("open rotated log %d as gzip: %v", idx, err)
		}
		content, err := io.ReadAll(compressed)
		closeErr := errors.Join(compressed.Close(), file.Close())
		if err != nil || closeErr != nil {
			t.Fatalf("read rotated log %d: %v", idx, errors.Join(err, closeErr))
		}
		if !bytes.Equal(content, append(append([]byte{}, line...), '\n')) {
			t.Fatalf("rotated log %d content = %q, want one complete line", idx, content)
		}
		if _, err := os.Stat(path + fmt.Sprintf(".%d", idx)); !os.IsNotExist(err) {
			t.Fatalf("uncompressed rotated log %d state: %v", idx, err)
		}
	}
	if _, err := os.Stat(rotatedPath(path, 6)); !os.IsNotExist(err) {
		t.Fatalf("unexpected sixth backup state: %v", err)
	}
}

func TestRotatingFileRejectsSymlinkLogPath(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, []byte("existing\n"), 0o640); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "traceguard.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink log path: %v", err)
	}

	_, err := NewRotatingFile(link, Options{
		MaxSizeBytes: 32,
		MaxBackups:   1,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err == nil {
		t.Fatal("NewRotatingFile accepted symlink log path")
	}
}

func TestRotatingFileRejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "logs-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink log directory: %v", err)
	}

	_, err := NewRotatingFile(filepath.Join(link, "traceguard.log"), Options{
		MaxSizeBytes: 32,
		MaxBackups:   1,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err == nil {
		t.Fatal("NewRotatingFile accepted symlinked log directory")
	}
}

func TestSymlinkAllowedOnlyForDefaultLogDirectory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{path: "/var/log/traceguard", want: true},
		{path: "/var/log/traceguard/", want: true},
		{path: "/var/log/traceguard-extra", want: false},
		{path: "/var/log/traceguard/subdirectory", want: false},
		{path: "/tmp/traceguard", want: false},
	}
	for _, test := range tests {
		if got := allowsLogDirectorySymlink(test.path); got != test.want {
			t.Errorf("allowsLogDirectorySymlink(%q) = %t, want %t", test.path, got, test.want)
		}
	}
}

func TestOpenDirectoryAllowsFinalSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "logs-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink directory: %v", err)
	}

	dir, err := openDirectoryAllowFinalSymlink(link)
	if err != nil {
		t.Fatalf("openDirectoryAllowFinalSymlink returned error: %v", err)
	}
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		t.Fatalf("stat opened directory: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("opened final symlink target is not a directory")
	}
}

func TestOpenDirectoryRejectsParentSymlink(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	logs := filepath.Join(target, "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	link := filepath.Join(root, "parent-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink parent: %v", err)
	}

	dir, err := openDirectoryAllowFinalSymlink(filepath.Join(link, "logs"))
	if dir != nil {
		_ = dir.Close()
	}
	if err == nil {
		t.Fatal("openDirectoryAllowFinalSymlink accepted a parent symlink")
	}
}

func TestRotatingFileDoesNotReopenAfterClose(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "traceguard.log")
	writer, err := NewRotatingFile(path, Options{MaxSizeBytes: 32, MaxBackups: 1})
	if err != nil {
		t.Fatalf("NewRotatingFile returned error: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if _, err := writer.Write([]byte("after-close\n")); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Write after Close error = %v, want os.ErrClosed", err)
	}
}

func TestRotatingFileKeepsStableDirectoryDuringRotation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	dir := filepath.Join(root, "logs")
	path := filepath.Join(dir, "traceguard.log")
	writer, err := NewRotatingFile(path, Options{MaxSizeBytes: 8, MaxBackups: 1})
	if err != nil {
		t.Fatalf("NewRotatingFile returned error: %v", err)
	}
	defer writer.Close()
	if _, err := writer.Write([]byte("first\n")); err != nil {
		t.Fatalf("first Write returned error: %v", err)
	}
	moved := filepath.Join(root, "logs-original")
	if err := os.Rename(dir, moved); err != nil {
		t.Fatalf("rename log directory: %v", err)
	}
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatalf("replace log directory: %v", err)
	}
	if _, err := writer.Write([]byte("second\n")); err != nil {
		t.Fatalf("second Write returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "traceguard.log.1.gz")); err != nil {
		t.Fatalf("rotation did not stay in original directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "traceguard.log")); !os.IsNotExist(err) {
		t.Fatalf("replacement directory was used during rotation: %v", err)
	}
}
