package policy

import (
	"regexp"
	"testing"
)

func TestBundleDigestIgnoresDocumentFormatting(t *testing.T) {
	t.Parallel()

	compact, err := Parse([]byte("version: 1\ndns: {block: [example.com]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	spaced, err := Parse([]byte("# comment\nversion: 1\n\ndns:\n  block:\n    - example.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	compactBundle, err := Merge(compact, Document{Version: Version})
	if err != nil {
		t.Fatal(err)
	}
	spacedBundle, err := Merge(Document{Version: Version}, spaced)
	if err != nil {
		t.Fatal(err)
	}
	left, err := compactBundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	right, err := spacedBundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if left != right {
		t.Fatalf("digests differ for the same effective policy: %s != %s", left, right)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(left) {
		t.Fatalf("digest %q is not hex SHA-256", left)
	}
}

func TestBundleDigestChangesWithPolicy(t *testing.T) {
	t.Parallel()

	empty, err := Bundle{}.Digest()
	if err != nil {
		t.Fatal(err)
	}
	document, err := Parse([]byte("version: 1\ndns: {block: [example.com]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(document, Document{Version: Version})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := bundle.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if empty == changed {
		t.Fatal("digest did not change when a DNS block rule was added")
	}
}
