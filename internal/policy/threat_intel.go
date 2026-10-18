package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	MaxThreatIntelFeeds = 32
	// MaxThreatIntelFeedIDLength keeps the egress rule IDs a blocking feed
	// generates, threat_intel.<id>.<n> with n up to 3,907 for 1,000,000
	// prefixes, within the 64-character rule ID limit.
	MaxThreatIntelFeedIDLength = 64 - len("threat_intel.") - len(".0000")
	// DefaultThreatIntelCooldown suppresses repeat alerts for one indicator
	// and cgroup.
	DefaultThreatIntelCooldown = 10 * time.Minute
)

// Threat intelligence feed types.
const (
	FeedTypeDomains   = "domains"
	FeedTypeAddresses = "addresses"
)

// ThreatIntelPolicy lists local indicator files to match events against.
type ThreatIntelPolicy struct {
	Feeds []ThreatIntelFeed `yaml:"feeds,omitempty"`
}

// ThreatIntelFeed is one local file of indicators, one per line. Operators
// fetch and verify feeds with their own tooling; TraceGuard only reads them.
type ThreatIntelFeed struct {
	ID       string    `yaml:"id"`
	Path     string    `yaml:"path"`
	Type     string    `yaml:"type"`
	Severity string    `yaml:"severity,omitempty"`
	Block    bool      `yaml:"block,omitempty"`
	Cooldown *Duration `yaml:"cooldown,omitempty"`
}

// AlertSeverity returns the feed's alert severity, warning by default.
func (f ThreatIntelFeed) AlertSeverity() string {
	if f.Severity == "" {
		return "warning"
	}
	return f.Severity
}

// AlertCooldown returns the feed's per-indicator alert cooldown.
func (f ThreatIntelFeed) AlertCooldown() time.Duration {
	if f.Cooldown == nil {
		return DefaultThreatIntelCooldown
	}
	return f.Cooldown.Duration
}

// RuleID is the detection rule ID the feed's alerts carry.
func (f ThreatIntelFeed) RuleID() string { return "threat_intel." + f.ID }

func (t ThreatIntelPolicy) validate() error {
	if len(t.Feeds) > MaxThreatIntelFeeds {
		return fmt.Errorf("feed count %d exceeds %d", len(t.Feeds), MaxThreatIntelFeeds)
	}
	ids := make(map[string]struct{}, len(t.Feeds))
	for index, feed := range t.Feeds {
		if err := validateRuleID(feed.ID); err != nil {
			return fmt.Errorf("feed %d: %w", index, err)
		}
		if len(feed.ID) > MaxThreatIntelFeedIDLength {
			return fmt.Errorf("feed %q: id is longer than %d characters", feed.ID, MaxThreatIntelFeedIDLength)
		}
		if _, exists := ids[feed.ID]; exists {
			return fmt.Errorf("duplicate feed id %q", feed.ID)
		}
		ids[feed.ID] = struct{}{}
		if !filepath.IsAbs(feed.Path) || filepath.Clean(feed.Path) != feed.Path {
			return fmt.Errorf("feed %q path must be a clean absolute path", feed.ID)
		}
		if feed.Type != FeedTypeDomains && feed.Type != FeedTypeAddresses {
			return fmt.Errorf("feed %q type must be %s or %s", feed.ID, FeedTypeDomains, FeedTypeAddresses)
		}
		if feed.Severity != "" {
			if err := validateAlertMetadata(feed.Severity, "feed", nil, MITRE{}, nil); err != nil {
				return fmt.Errorf("feed %q: %w", feed.ID, err)
			}
		}
		if feed.Cooldown != nil && feed.Cooldown.Duration < 0 {
			return fmt.Errorf("feed %q cooldown must not be negative", feed.ID)
		}
	}
	return nil
}

// mergeThreatIntel lets an overlay feed replace a base feed with the same ID.
func mergeThreatIntel(base, overlay ThreatIntelPolicy) ThreatIntelPolicy {
	merged := make(map[string]ThreatIntelFeed, len(base.Feeds)+len(overlay.Feeds))
	for _, feed := range base.Feeds {
		merged[feed.ID] = feed
	}
	for _, feed := range overlay.Feeds {
		merged[feed.ID] = feed
	}
	feeds := make([]ThreatIntelFeed, 0, len(merged))
	for _, feed := range merged {
		feeds = append(feeds, feed)
	}
	slices.SortFunc(feeds, func(left, right ThreatIntelFeed) int { return strings.Compare(left.ID, right.ID) })
	return ThreatIntelPolicy{Feeds: feeds}
}
