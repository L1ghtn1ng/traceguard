package fim

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

const (
	// settleDelay coalesces bursts of writes to one path into one check.
	settleDelay = time.Second
	// maxPending bounds queued paths; overflow schedules a full rescan.
	maxPending = 4096
)

// Actor describes the process whose event queued a check.
type Actor map[string]any

// Stats summarizes the watcher for metrics and heartbeats.
type Stats struct {
	Files     int
	Truncated bool
	Dropped   uint64
}

type pendingCheck struct {
	actor Actor
	due   time.Time
}

// Watcher holds the baseline and checks paths it is notified about.
type Watcher struct {
	root string
	now  func() time.Time
	wake chan struct{}

	mu       sync.Mutex
	policy   policy.FileIntegrityPolicy
	rebuild  bool
	baseline map[string]State
	pending  map[string]pendingCheck
	overflow bool
	stats    Stats
}

// NewWatcher returns a watcher over root, "/" outside tests.
func NewWatcher(root string) *Watcher {
	return &Watcher{
		root: root, now: time.Now, wake: make(chan struct{}, 1),
		baseline: make(map[string]State), pending: make(map[string]pendingCheck),
	}
}

// Configure installs a policy. A changed policy rebuilds the baseline on the
// Run goroutine without reporting changes.
func (w *Watcher) Configure(integrity policy.FileIntegrityPolicy) {
	w.mu.Lock()
	changed := !reflect.DeepEqual(integrity, w.policy)
	if changed {
		w.policy = integrity
		w.rebuild = true
	}
	w.mu.Unlock()
	if changed {
		w.signal()
	}
}

// Watched reports whether a change to path could affect a watched file: the
// path is watched, or it is an ancestor of a watched path, as a renamed
// parent directory is.
func (w *Watcher) Watched(path string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.policy.Enabled() {
		return false
	}
	s := w.scannerLocked()
	if s.watched(path) {
		return true
	}
	for _, pattern := range w.policy.Paths {
		stem := strings.TrimSuffix(pattern, "/**")
		if strings.HasPrefix(stem, strings.TrimSuffix(path, "/")+"/") {
			return true
		}
	}
	return false
}

// Notify queues a check of path, attributed to actor. It never blocks.
func (w *Watcher) Notify(path string, actor Actor) {
	w.mu.Lock()
	if _, queued := w.pending[path]; !queued && len(w.pending) >= maxPending {
		w.overflow = true
		w.stats.Dropped++
		w.mu.Unlock()
		w.signal()
		return
	}
	w.pending[path] = pendingCheck{actor: actor, due: w.now().Add(settleDelay)}
	w.mu.Unlock()
}

// Stats returns the current watcher statistics.
func (w *Watcher) Stats() Stats {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stats
}

func (w *Watcher) signal() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

func (w *Watcher) scannerLocked() scanner {
	return scanner{root: w.root, policy: w.policy, maxSize: w.policy.HashLimit()}
}

// Run processes rebuilds, queued checks, and periodic rescans until ctx is
// done. emit receives each change, with a nil actor for rescan findings.
func (w *Watcher) Run(ctx context.Context, emit func(Change, Actor)) {
	ticker := time.NewTicker(settleDelay)
	defer ticker.Stop()
	nextRescan := time.Time{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.wake:
		case <-ticker.C:
		}
		w.mu.Lock()
		rebuild, overflow, interval := w.rebuild, w.overflow, w.policy.Rescan()
		w.rebuild, w.overflow = false, false
		w.mu.Unlock()

		now := w.now()
		switch {
		case rebuild:
			w.install(false, emit)
			nextRescan = nextRescanAt(now, interval)
		case overflow || (!nextRescan.IsZero() && !now.Before(nextRescan)):
			w.install(true, emit)
			nextRescan = nextRescanAt(now, interval)
		}
		w.checkDue(now, emit)
	}
}

func nextRescanAt(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

// install scans every watched path and replaces the baseline, reporting the
// differences when report is set. Queued checks are dropped because the scan
// covers them.
func (w *Watcher) install(report bool, emit func(Change, Actor)) {
	w.mu.Lock()
	s := w.scannerLocked()
	w.mu.Unlock()
	current := map[string]State{}
	truncated := false
	if s.policy.Enabled() {
		current, truncated = s.Baseline()
	}

	w.mu.Lock()
	if w.rebuild {
		// The policy changed during the scan; the next pass rebuilds.
		w.mu.Unlock()
		return
	}
	previous := w.baseline
	w.baseline = current
	w.pending = make(map[string]pendingCheck)
	w.stats.Files, w.stats.Truncated = len(current), truncated
	w.mu.Unlock()

	if report {
		for _, change := range diffSubset("/", previous, current) {
			emit(change, nil)
		}
	}
}

// checkDue rechecks queued paths whose settle delay has passed.
func (w *Watcher) checkDue(now time.Time, emit func(Change, Actor)) {
	w.mu.Lock()
	due := make(map[string]Actor)
	for path, check := range w.pending {
		if !now.Before(check.due) {
			due[path] = check.actor
			delete(w.pending, path)
		}
	}
	s := w.scannerLocked()
	w.mu.Unlock()

	for path, actor := range due {
		current := w.scanAffected(s, path)
		w.mu.Lock()
		changes := diffSubset(path, w.baseline, current)
		for _, change := range changes {
			if change.Current != nil {
				w.baseline[change.Path] = *change.Current
			} else {
				delete(w.baseline, change.Path)
			}
		}
		w.stats.Files = len(w.baseline)
		w.mu.Unlock()
		for _, change := range changes {
			emit(change, actor)
		}
	}
}

// scanAffected returns the current state of the watched files a change to
// path can affect: path itself and, for a directory, the watched entries
// beneath it.
func (w *Watcher) scanAffected(s scanner, path string) map[string]State {
	states := make(map[string]State)
	prefix := strings.TrimSuffix(path, "/") + "/"
	for _, pattern := range s.policy.Paths {
		stem, subtree := strings.CutSuffix(pattern, "/**")
		switch {
		case stem == path || strings.HasPrefix(stem, prefix):
			s.scanTree(stem, subtree, states)
		case subtree && (stem == "" || strings.HasPrefix(path, strings.TrimSuffix(stem, "/")+"/")):
			s.scanTree(path, true, states)
		}
	}
	return states
}
