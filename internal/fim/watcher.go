package fim

import (
	"context"
	"maps"
	"reflect"
	"slices"
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
	// ambiguous records that another process also touched the path before
	// the check ran, so the actor may not be the one that changed it.
	ambiguous bool
}

// Watcher holds the baseline and checks paths it is notified about.
type Watcher struct {
	root string
	now  func() time.Time
	wake chan struct{}

	mu     sync.Mutex
	policy policy.FileIntegrityPolicy
	// baselinePolicy is the policy the current baseline was scanned under.
	baselinePolicy policy.FileIntegrityPolicy
	rebuild        bool
	baseline       map[string]State
	pending        map[string]pendingCheck
	overflow       bool
	stats          Stats
}

// NewWatcher returns a watcher over root, "/" outside tests.
func NewWatcher(root string) *Watcher {
	return &Watcher{
		root: root, now: time.Now, wake: make(chan struct{}, 1),
		baseline: make(map[string]State), pending: make(map[string]pendingCheck),
	}
}

// Configure installs a policy. A changed policy rebuilds the baseline on the
// Run goroutine, reporting changes only for paths both policies watch.
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

// Enabled reports whether the installed policy watches any path.
func (w *Watcher) Enabled() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.policy.Enabled()
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
	if existing, queued := w.pending[path]; queued {
		// Keep the first due time so a busy path is still checked within the
		// settle delay, and the first actor, marking any later different one.
		if !reflect.DeepEqual(existing.actor["actor_pid"], actor["actor_pid"]) {
			existing.ambiguous = true
			w.pending[path] = existing
		}
		w.mu.Unlock()
		return
	}
	w.pending[path] = pendingCheck{actor: actor, due: w.now().Add(settleDelay)}
	w.mu.Unlock()
}

// PendingPaths lists the paths waiting for a check, sorted.
func (w *Watcher) PendingPaths() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Sorted(maps.Keys(w.pending))
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
		installed := true
		switch {
		case rebuild:
			installed = w.install(true, emit)
			nextRescan = nextRescanAt(now, interval)
		case overflow || (!nextRescan.IsZero() && !now.Before(nextRescan)):
			installed = w.install(false, emit)
			nextRescan = nextRescanAt(now, interval)
		}
		if !installed {
			// The policy changed during the scan. Queued checks wait for the
			// rebuild so they are not compared against the old baseline.
			continue
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

// install scans every watched path and replaces the baseline. A rescan
// reports every difference; a rebuild for a new policy reports only paths
// that both the old and new policy watch. Queued checks are kept: a change
// made while the scan ran may postdate what it read. install reports false
// when the policy changed during the scan.
func (w *Watcher) install(rebuild bool, emit func(Change, Actor)) bool {
	w.mu.Lock()
	s := w.scannerLocked()
	old := scanner{root: w.root, policy: w.baselinePolicy}
	w.mu.Unlock()
	result := newScanResult()
	if s.policy.Enabled() {
		result = s.Baseline()
	}

	w.mu.Lock()
	if w.rebuild {
		w.mu.Unlock()
		return false
	}
	keys := make(map[string]struct{}, len(w.baseline)+len(result.states))
	for key := range w.baseline {
		keys[key] = struct{}{}
	}
	for key := range result.states {
		keys[key] = struct{}{}
	}
	report := func(string) bool { return true }
	if rebuild {
		report = func(key string) bool { return old.watched(key) && s.watched(key) }
	}
	changes, final := reconcile(slices.Sorted(maps.Keys(keys)), w.baseline, result, report)
	baseline := make(map[string]State, len(final))
	for key, state := range final {
		if state != nil && s.watched(key) {
			baseline[key] = *state
		}
	}
	w.baseline = baseline
	w.baselinePolicy = s.policy
	w.stats.Files, w.stats.Truncated = len(baseline), result.truncated
	w.mu.Unlock()

	for _, change := range changes {
		emit(change, nil)
	}
	return true
}

// checkDue rechecks queued paths whose settle delay has passed.
func (w *Watcher) checkDue(now time.Time, emit func(Change, Actor)) {
	w.mu.Lock()
	due := make(map[string]pendingCheck)
	for path, check := range w.pending {
		if !now.Before(check.due) {
			due[path] = check
			delete(w.pending, path)
		}
	}
	s := w.scannerLocked()
	w.mu.Unlock()

	for path, check := range due {
		result := w.scanAffected(s, path)
		w.mu.Lock()
		if w.rebuild {
			// The policy changed during the scan. Requeue the check for
			// after the rebuild, so it is judged by the new policy.
			if _, queued := w.pending[path]; !queued {
				w.pending[path] = check
			}
			w.mu.Unlock()
			continue
		}
		changes, final := reconcile(affectedKeys(path, w.baseline, result), w.baseline, result, func(string) bool { return true })
		for key, state := range final {
			if state != nil {
				w.baseline[key] = *state
			} else {
				delete(w.baseline, key)
			}
		}
		w.stats.Files = len(w.baseline)
		w.mu.Unlock()
		actor := check.actor
		if check.ambiguous {
			actor = maps.Clone(actor)
			if actor == nil {
				actor = Actor{}
			}
			actor["actor_ambiguous"] = true
		}
		for _, change := range changes {
			emit(change, actor)
		}
	}
}

// scanAffected returns the current state of the watched files a change to
// path can affect: path itself and, for a directory, the watched entries
// beneath it.
func (w *Watcher) scanAffected(s scanner, path string) scanResult {
	result := newScanResult()
	prefix := strings.TrimSuffix(path, "/") + "/"
	for _, pattern := range s.policy.Paths {
		stem, subtree := strings.CutSuffix(pattern, "/**")
		switch {
		case stem == path || strings.HasPrefix(stem, prefix):
			s.scanTree(stem, subtree, &result)
		case subtree && (stem == "" || strings.HasPrefix(path, strings.TrimSuffix(stem, "/")+"/")):
			s.scanTree(path, true, &result)
		}
	}
	return result
}
