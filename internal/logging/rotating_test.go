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
