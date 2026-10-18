package policy

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseFileIntegrityDefaultsAndSettings(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte("version: 1\nfile_integrity:\n  paths: [/etc/**, /usr/bin/sudo]\n  exclude: [/etc/mtab]\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	integrity := document.FileIntegrity
	if !integrity.Enabled() || !integrity.HashEnabled() || integrity.HashLimit() != DefaultFileIntegrityHashBytes || integrity.Rescan() != time.Hour {
		t.Fatalf("defaults = enabled %t hash %t limit %d rescan %s", integrity.Enabled(), integrity.HashEnabled(), integrity.HashLimit(), integrity.Rescan())
	}

	document, err = Parse([]byte("version: 1\nfile_integrity:\n  paths: [/etc/**]\n  hash: false\n  max_hash_bytes: 1024\n  rescan_interval: 0s\n"))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if integrity := document.FileIntegrity; integrity.HashEnabled() || integrity.HashLimit() != 1024 || integrity.Rescan() != 0 {
		t.Fatalf("settings = hash %t limit %d rescan %s", integrity.HashEnabled(), integrity.HashLimit(), integrity.Rescan())
	}
	if (FileIntegrityPolicy{}).Enabled() {
		t.Fatal("empty file integrity policy reported enabled")
	}
}

func TestParseRejectsInvalidFileIntegrity(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct{ body, want string }{
		"relative path":     {"  paths: [etc/passwd]\n", "clean absolute"},
		"glob in path":      {"  paths: [/etc/*.conf]\n", "exact path or end in /**"},
		"exclude only":      {"  exclude: [/etc/mtab]\n", "exclude requires paths"},
		"duplicate path":    {"  paths: [/etc/**, /etc/**]\n", "duplicate file integrity path"},
		"oversized hashing": {"  paths: [/etc/**]\n  max_hash_bytes: 2147483648\n", "max_hash_bytes"},
		"short rescan":      {"  paths: [/etc/**]\n  rescan_interval: 10s\n", "rescan_interval"},
		"unknown field":     {"  paths: [/etc/**]\n  follow_symlinks: true\n", "follow_symlinks"},
	} {
		if _, err := Parse([]byte("version: 1\nfile_integrity:\n" + test.body)); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
}

func TestMergeFileIntegrityUnionsPathsAndPrefersOverlaySettings(t *testing.T) {
	t.Parallel()

	base, err := Parse([]byte("version: 1\nfile_integrity:\n  paths: [/etc/**]\n  max_hash_bytes: 4096\n  rescan_interval: 30m\n"))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte("version: 1\nfile_integrity:\n  paths: [/root/.ssh/**, /etc/**]\n  hash: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	integrity := bundle.FileIntegrity
	if !slices.Equal(integrity.Paths, []string{"/etc/**", "/root/.ssh/**"}) {
		t.Fatalf("paths = %v", integrity.Paths)
	}
	if integrity.HashEnabled() || integrity.HashLimit() != 4096 || integrity.Rescan() != 30*time.Minute {
		t.Fatalf("settings = hash %t limit %d rescan %s", integrity.HashEnabled(), integrity.HashLimit(), integrity.Rescan())
	}

	restore, err := Parse([]byte("version: 1\nfile_integrity:\n  paths: [/etc/**]\n  max_hash_bytes: 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err = Merge(base, restore)
	if err != nil {
		t.Fatal(err)
	}
	if limit := bundle.FileIntegrity.HashLimit(); limit != DefaultFileIntegrityHashBytes {
		t.Fatalf("overlay max_hash_bytes 0 limit = %d, want default %d", limit, DefaultFileIntegrityHashBytes)
	}
}
