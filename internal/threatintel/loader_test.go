package threatintel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestLoaderKeepsLastGoodFeedAndReportsErrors(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "domains.txt")
	config := policy.ThreatIntelFeed{ID: "bad", Path: path, Type: policy.FeedTypeDomains}
	loader := NewLoader()

	feeds, err := loader.Load([]policy.ThreatIntelFeed{config})
	if err == nil || !strings.Contains(err.Error(), "empty until it can be read") || len(feeds) != 1 || len(feeds[0].Domains) != 0 {
		t.Fatalf("missing feed = %+v, %v; want an empty feed and an error", feeds, err)
	}

	if err := os.WriteFile(path, []byte("evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	feeds, err = loader.Load([]policy.ThreatIntelFeed{config})
	if err != nil || len(feeds[0].Domains) != 1 {
		t.Fatalf("created feed = %+v, %v", feeds, err)
	}

	replacement := filepath.Join(directory, "next.txt")
	if err := os.WriteFile(replacement, []byte("not a domain!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	feeds, err = loader.Load([]policy.ThreatIntelFeed{config})
	if err == nil || !strings.Contains(err.Error(), "previous contents") || len(feeds[0].Domains) != 1 || feeds[0].Domains[0] != "evil.example" {
		t.Fatalf("invalid replacement = %+v, %v; want the previous contents and an error", feeds, err)
	}
}

func TestLoaderReusesUnchangedFeeds(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte("evil.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := policy.ThreatIntelFeed{ID: "bad", Path: path, Type: policy.FeedTypeDomains}
	loader := NewLoader()
	if _, err := loader.Load([]policy.ThreatIntelFeed{config}); err != nil {
		t.Fatal(err)
	}
	signature := Signature(path)
	// Changing what the cache holds shows whether the next load re-reads.
	entry := loader.cache[path+"\x00"+policy.FeedTypeDomains]
	entry.feed.Domains = []string{"cached.example"}
	loader.cache[path+"\x00"+policy.FeedTypeDomains] = entry
	feeds, err := loader.Load([]policy.ThreatIntelFeed{config})
	if err != nil || feeds[0].Domains[0] != "cached.example" || Signature(path) != signature {
		t.Fatalf("unchanged feed was re-read: %+v, %v", feeds, err)
	}
}

func TestSignatureChangesWhenAFileIsReplaced(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	path := filepath.Join(directory, "feed")
	if err := os.WriteFile(path, []byte("a.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	before := Signature(path)
	replacement := filepath.Join(directory, "next")
	if err := os.WriteFile(replacement, []byte("b.example\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Same size and modification time, as an atomic replace may preserve.
	if err := os.Chtimes(replacement, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if Signature(path) == before {
		t.Fatal("a replaced feed kept its signature")
	}
}
