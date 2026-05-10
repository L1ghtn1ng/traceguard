package logging

import (
	"bytes"
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
	for i := 0; i < 8; i++ {
		if _, err := writer.Write(append(append([]byte{}, line...), '\n')); err != nil {
			t.Fatalf("Write returned error: %v", err)
		}
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current log file missing: %v", err)
	}
	for idx := 1; idx <= 5; idx++ {
		if _, err := os.Stat(rotatedPath(path, idx)); err != nil {
			t.Fatalf("rotated log %d missing: %v", idx, err)
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
