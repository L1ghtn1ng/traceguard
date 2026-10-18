package threatintel

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// Signature identifies a feed file's version without reading it: its inode,
// size, and modification and change times. Replacing a file by rename changes
// its inode, and rewriting it in place changes its change time, which
// userspace cannot set back.
func Signature(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "missing"
	}
	signature := fmt.Sprintf("%d:%d", info.Size(), info.ModTime().UnixNano())
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		signature += fmt.Sprintf(":%d:%d:%d.%d", stat.Dev, stat.Ino, stat.Ctim.Sec, stat.Ctim.Nsec)
	}
	return signature
}

// Loader loads feeds for the daemon. It reuses a parsed feed while its file
// is unchanged, and keeps serving the last good copy of a feed that cannot be
// read or parsed, so a missing or half-written file never takes enforcement
// down with it.
type Loader struct {
	mu    sync.Mutex
	cache map[string]cachedFeed
}

type cachedFeed struct {
	// signature is the version feed was read from.
	signature string
	feed      Feed
	// failed is the version that last could not be loaded, and err why.
	failed string
	err    error
	ok     bool
}

// NewLoader returns an empty loader.
func NewLoader() *Loader {
	return &Loader{cache: make(map[string]cachedFeed)}
}

// Load returns every configured feed, with an error for each feed that could
// not be loaded. Such a feed is its last good copy, or empty if there is none.
func (l *Loader) Load(configs []policy.ThreatIntelFeed) ([]Feed, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	loaded := make([]Feed, 0, len(configs))
	var errs []error
	cache := make(map[string]cachedFeed, len(configs))
	for _, config := range configs {
		key := config.Path + "\x00" + config.Type
		signature := Signature(config.Path)
		entry := l.cache[key]
		if !entry.ok || entry.signature != signature {
			if signature != entry.failed {
				feeds, err := Load([]policy.ThreatIntelFeed{config})
				if err == nil {
					entry = cachedFeed{signature: signature, feed: feeds[0], ok: true}
				} else {
					entry.failed, entry.err = signature, err
				}
			}
		}
		cache[key] = entry
		feed := entry.feed
		feed.Config = config
		loaded = append(loaded, feed)
		switch {
		case entry.ok && entry.signature == signature:
		case entry.ok:
			errs = append(errs, fmt.Errorf("%w; using its previous contents", entry.err))
		default:
			errs = append(errs, fmt.Errorf("%w; the feed is empty until it can be read", entry.err))
		}
	}
	l.cache = cache
	return loaded, errors.Join(errs...)
}
