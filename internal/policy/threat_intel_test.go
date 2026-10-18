package policy

import (
	"strings"
	"testing"
	"time"
)

func TestParseThreatIntelFeeds(t *testing.T) {
	t.Parallel()

	document, err := Parse([]byte(`
version: 1
threat_intel:
  feeds:
    - {id: phishing, path: /var/lib/traceguard/feeds/phishing.txt, type: domains, block: true}
    - {id: c2, path: /var/lib/traceguard/feeds/c2.txt, type: addresses, severity: critical, cooldown: 1h}
`))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	phishing, c2 := document.ThreatIntel.Feeds[0], document.ThreatIntel.Feeds[1]
	if !phishing.Block || phishing.AlertSeverity() != "warning" || phishing.AlertCooldown() != DefaultThreatIntelCooldown || phishing.RuleID() != "threat_intel.phishing" {
		t.Fatalf("phishing defaults = %+v", phishing)
	}
	if c2.AlertSeverity() != "critical" || c2.AlertCooldown() != time.Hour {
		t.Fatalf("c2 settings = %+v", c2)
	}
}

func TestParseRejectsInvalidThreatIntelFeeds(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct{ feed, want string }{
		"relative path": {"{id: a, path: feeds/a.txt, type: domains}", "clean absolute path"},
		"unclean path":  {"{id: a, path: /var/lib/../a.txt, type: domains}", "clean absolute path"},
		"bad type":      {"{id: a, path: /a.txt, type: hashes}", "type must be"},
		"bad severity":  {"{id: a, path: /a.txt, type: domains, severity: high}", "unsupported severity"},
		"bad id":        {"{id: A, path: /a.txt, type: domains}", "invalid rule id"},
	} {
		if _, err := Parse([]byte("version: 1\nthreat_intel:\n  feeds:\n    - " + test.feed + "\n")); err == nil || !strings.Contains(err.Error(), test.want) {
			t.Errorf("%s: error = %v, want %q", name, err, test.want)
		}
	}
	duplicate := "version: 1\nthreat_intel:\n  feeds:\n    - {id: a, path: /a.txt, type: domains}\n    - {id: a, path: /b.txt, type: domains}\n"
	if _, err := Parse([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate feed id") {
		t.Fatalf("duplicate feed error = %v", err)
	}
}

func TestMergeThreatIntelOverlayReplacesFeed(t *testing.T) {
	t.Parallel()

	base, err := Parse([]byte("version: 1\nthreat_intel:\n  feeds:\n    - {id: a, path: /a.txt, type: domains, block: true}\n    - {id: b, path: /b.txt, type: addresses}\n"))
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := Parse([]byte("version: 1\nthreat_intel:\n  feeds:\n    - {id: a, path: /a.txt, type: domains}\n"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if feeds := bundle.ThreatIntel.Feeds; len(feeds) != 2 || feeds[0].ID != "a" || feeds[0].Block || feeds[1].ID != "b" {
		t.Fatalf("merged feeds = %+v", feeds)
	}
}
