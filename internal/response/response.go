// Package response runs the reversible actions a policy attaches to
// detection rules: temporarily blocking an alert's peer address and
// temporarily freezing its acting cgroup.
//
// Every action has a deadline. It is undone when the deadline passes, when
// every response holding it is removed or changed, when TraceGuard stops, or,
// after a crash, when TraceGuard next starts. Each step is recorded.
package response

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// Modes.
const (
	ModeOff     = "off"
	ModeDryRun  = "dry-run"
	ModeEnforce = "enforce"
)

const (
	// MaxActive bounds simultaneously active actions.
	MaxActive = 1024
	// queueSize bounds alerts waiting for Run.
	queueSize = 256
	// revertAttempts and revertRetryDelay bound how long shutdown retries
	// an undo that fails.
	revertAttempts   = 3
	revertRetryDelay = time.Second
)

// PeerBlocker blocks and unblocks peer addresses in the kernel.
type PeerBlocker interface {
	BlockPeer(address netip.Addr, until time.Time) error
	UnblockPeer(address netip.Addr) error
	// ClearPeers removes every peer block, including any an earlier run
	// left in a pinned map.
	ClearPeers() error
}

// Freezer freezes and thaws cgroups by ID.
type Freezer interface {
	// Freeze freezes the cgroup and returns its path. A *RefusedError means
	// retrying cannot succeed.
	Freeze(id uint64) (string, error)
	// Thaw unfreezes the cgroup at path if it is still the cgroup with id.
	Thaw(id uint64, path string) error
}

// RefusedError reports a cgroup that will not be frozen: a protected group,
// or one that no longer exists.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return e.Reason }

// Recorder receives a record for every action step.
type Recorder func(message string, fields map[string]any)

// Options holds a responder's optional settings.
type Options struct {
	// StatePath records frozen cgroups, so a restart after a crash can
	// thaw them. Empty keeps no record.
	StatePath string
	// BootID identifies this boot. A state file from another boot is
	// ignored, because cgroup IDs do not survive a reboot.
	BootID string
	// Now and Sleep default to the time package.
	Now   func() time.Time
	Sleep func(time.Duration)
}

type actionKey struct {
	action string
	target string
}

// owner is a response holding an action, with the rule that triggered it
// and the deadline it asked for.
type owner struct {
	ruleID string
	until  time.Time
}

type active struct {
	owners map[string]owner
	// until is the latest owner deadline.
	until time.Time
	// applied reports whether the kernel or cgroupfs was changed, which
	// dry-run actions never do.
	applied    bool
	peer       netip.Addr
	cgroupID   uint64
	cgroupPath string
}

type refusal struct {
	until  time.Time
	reason string
}

// Responder applies responses to alerts.
type Responder struct {
	mode    string
	blocker PeerBlocker
	freezer Freezer
	record  Recorder
	options Options
	queue   chan detection.Alert
	// rules holds the rule IDs any response names, for Submit.
	rules atomic.Pointer[map[string]struct{}]

	mu        sync.Mutex
	responses []policy.Response
	active    map[actionKey]*active
	refused   map[actionKey]refusal
	// retained holds recorded freezes this run cannot thaw, kept in the
	// state file for the next start.
	retained []frozenCgroup
	// stateHeld stops writes to a state file that could not be read, so
	// its records survive for the next start.
	stateHeld bool
}

// New returns a responder in mode. A nil blocker or freezer makes that
// action unavailable.
func New(mode string, blocker PeerBlocker, freezer Freezer, record Recorder, options Options) *Responder {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Sleep == nil {
		options.Sleep = time.Sleep
	}
	r := &Responder{
		mode: mode, blocker: blocker, freezer: freezer, record: record, options: options,
		queue: make(chan detection.Alert, queueSize), active: make(map[actionKey]*active), refused: make(map[actionKey]refusal),
	}
	r.rules.Store(&map[string]struct{}{})
	return r
}

// Configure installs the policy's responses. An active action loses each
// response that was removed or changed, and is reverted when none remain.
func (r *Responder) Configure(responses []policy.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	previous := make(map[string]policy.Response, len(r.responses))
	for _, response := range r.responses {
		previous[response.ID] = response
	}
	current := make(map[string]policy.Response, len(responses))
	rules := make(map[string]struct{})
	for _, response := range responses {
		current[response.ID] = response
		for _, rule := range response.Rules {
			rules[rule] = struct{}{}
		}
	}
	r.responses = slices.Clone(responses)
	r.rules.Store(&rules)
	for key, action := range r.active {
		reason := ""
		remaining := make(map[string]owner, len(action.owners))
		for id, held := range action.owners {
			response, kept := current[id]
			switch {
			case !kept:
				reason = "policy_removed"
			case !reflect.DeepEqual(response, previous[id]):
				reason = "policy_changed"
			default:
				remaining[id] = held
			}
		}
		if len(remaining) == 0 && reason != "" {
			r.revertLocked(key, action, reason)
			continue
		}
		action.owners = remaining
		r.shortenLocked(key, action)
	}
	r.refused = make(map[actionKey]refusal)
}

// shortenLocked moves an action's deadline back to its latest remaining
// owner's.
func (r *Responder) shortenLocked(key actionKey, action *active) {
	var latest time.Time
	for _, held := range action.owners {
		if held.until.After(latest) {
			latest = held.until
		}
	}
	if latest.IsZero() || !latest.Before(action.until) {
		return
	}
	if key.action == policy.ResponseBlockPeer && action.applied && r.blocker != nil && latest.After(r.options.Now()) {
		if err := r.blocker.BlockPeer(action.peer, latest); err != nil {
			fields := r.actionFields(key, action, "policy_changed")
			fields["error"] = err.Error()
			r.record("response failed", fields)
			return
		}
	}
	action.until = latest
}

// Submit queues an alert for Run without blocking. An alert that finds the
// queue full is skipped and recorded.
func (r *Responder) Submit(alert detection.Alert) {
	if r.mode == ModeOff {
		return
	}
	if _, named := (*r.rules.Load())[alert.RuleID]; !named {
		return
	}
	select {
	case r.queue <- alert:
	default:
		r.record("response skipped", map[string]any{
			"event": "response", "detection_rule_id": alert.RuleID, "mode": r.mode,
			"reason": fmt.Sprintf("%d alerts are already waiting for a response", queueSize),
		})
	}
}

// Run handles submitted alerts until ctx is done, so freezing, which scans
// the cgroup hierarchy, never delays the caller.
func (r *Responder) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-r.queue:
			r.Handle(alert)
		}
	}
}

// Handle runs every response that names the alert's rule. Deadlines count
// from when the action is applied, not from the alert, so an alert handled
// late still gets its full duration.
func (r *Responder) Handle(alert detection.Alert) {
	if r.mode == ModeOff {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, response := range r.responses {
		if !slices.Contains(response.Rules, alert.RuleID) {
			continue
		}
		until := r.options.Now().Add(response.Duration.Duration)
		switch response.Action {
		case policy.ResponseBlockPeer:
			r.blockPeerLocked(response, alert, until)
		case policy.ResponseFreezeCgroup:
			r.freezeCgroupLocked(response, alert, until)
		}
	}
}

func (r *Responder) fields(response policy.Response, alert detection.Alert, target string, until time.Time) map[string]any {
	return map[string]any{
		"event": "response", "response_id": response.ID, "action": response.Action,
		"target": target, "detection_rule_id": alert.RuleID, "mode": r.mode,
		"until": until.UTC().Format(time.RFC3339Nano),
	}
}

func (r *Responder) skip(response policy.Response, alert detection.Alert, reason string) {
	fields := r.fields(response, alert, "", time.Time{})
	delete(fields, "until")
	delete(fields, "target")
	fields["reason"] = reason
	r.record("response skipped", fields)
}

func (r *Responder) blockPeerLocked(response policy.Response, alert detection.Alert, until time.Time) {
	address, ok := peerAddress(alert.Fields)
	if !ok {
		r.skip(response, alert, "the alert has no peer address")
		return
	}
	if address.IsLoopback() || address.IsUnspecified() || address.IsMulticast() {
		r.skip(response, alert, "the peer address is loopback, unspecified, or multicast")
		return
	}
	target := address.String()
	if !r.admitLocked(response, alert, policy.ResponseBlockPeer, target, until) {
		return
	}
	applied := false
	if r.mode == ModeEnforce {
		if r.blocker == nil {
			r.skip(response, alert, "peer blocking is unavailable")
			return
		}
		if err := r.blocker.BlockPeer(address, until); err != nil {
			r.failed(response, alert, target, err)
			return
		}
		applied = true
	}
	r.track(response, alert, policy.ResponseBlockPeer, target, until, &active{peer: address, applied: applied})
}

func (r *Responder) freezeCgroupLocked(response policy.Response, alert detection.Alert, until time.Time) {
	id, ok := cgroupID(alert.Fields)
	if !ok {
		r.skip(response, alert, "the alert has no event-time cgroup")
		return
	}
	target := fmt.Sprint(id)
	key := actionKey{action: policy.ResponseFreezeCgroup, target: target}
	if refused, ok := r.refused[key]; ok && r.options.Now().Before(refused.until) {
		// Retrying would rescan the cgroup hierarchy only to refuse again.
		r.skip(response, alert, refused.reason)
		return
	}
	if !r.admitLocked(response, alert, policy.ResponseFreezeCgroup, target, until) {
		return
	}
	var path string
	applied := false
	if r.mode == ModeEnforce {
		if r.freezer == nil {
			r.skip(response, alert, "cgroup freezing is unavailable")
			return
		}
		frozen, err := r.freezer.Freeze(id)
		if err != nil {
			var refused *RefusedError
			if errors.As(err, &refused) && len(r.refused) < MaxActive {
				r.refused[key] = refusal{until: until, reason: refused.Reason}
			}
			r.failed(response, alert, target, err)
			return
		}
		path, applied = frozen, true
	}
	r.track(response, alert, policy.ResponseFreezeCgroup, target, until, &active{cgroupID: id, cgroupPath: path, applied: applied})
	r.persistLocked()
}

// admitLocked adds the response to an action that is already active,
// extending it, and reports whether a new action should be applied.
func (r *Responder) admitLocked(response policy.Response, alert detection.Alert, action, target string, until time.Time) bool {
	key := actionKey{action: action, target: target}
	if existing, ok := r.active[key]; ok {
		if held, ok := existing.owners[response.ID]; !ok || until.After(held.until) {
			existing.owners[response.ID] = owner{ruleID: alert.RuleID, until: until}
		}
		if until.After(existing.until) {
			if action == policy.ResponseBlockPeer && existing.applied && r.blocker != nil {
				if err := r.blocker.BlockPeer(existing.peer, until); err != nil {
					r.failed(response, alert, target, err)
					return false
				}
			}
			existing.until = until
			r.record("response extended", r.fields(response, alert, target, until))
			if action == policy.ResponseFreezeCgroup {
				r.persistLocked()
			}
		}
		return false
	}
	if len(r.active) >= MaxActive {
		r.skip(response, alert, fmt.Sprintf("%d actions are already active", MaxActive))
		return false
	}
	return true
}

func (r *Responder) track(response policy.Response, alert detection.Alert, action, target string, until time.Time, state *active) {
	state.owners = map[string]owner{response.ID: {ruleID: alert.RuleID, until: until}}
	state.until = until
	r.active[actionKey{action: action, target: target}] = state
	message := "response applied"
	if r.mode == ModeDryRun {
		message = "response would apply"
	}
	r.record(message, r.fields(response, alert, target, until))
}

func (r *Responder) failed(response policy.Response, alert detection.Alert, target string, err error) {
	fields := r.fields(response, alert, target, time.Time{})
	delete(fields, "until")
	fields["error"] = err.Error()
	r.record("response failed", fields)
}

// Expire reverts actions whose deadline has passed, retrying undos that
// failed.
func (r *Responder) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, action := range r.active {
		if !now.Before(action.until) {
			r.revertLocked(key, action, "expired")
		}
	}
	for key, refused := range r.refused {
		if !now.Before(refused.until) {
			delete(r.refused, key)
		}
	}
}

// RevertAll undoes every active action, for shutdown. An undo that keeps
// failing is retried briefly; a freeze that still cannot be undone stays in
// the state file for the next start to thaw.
func (r *Responder) RevertAll() {
	for attempt := range revertAttempts {
		if attempt > 0 {
			r.options.Sleep(revertRetryDelay)
		}
		r.mu.Lock()
		for key, action := range r.active {
			r.revertLocked(key, action, "shutdown")
		}
		remaining := len(r.active)
		r.mu.Unlock()
		if remaining == 0 {
			return
		}
	}
}

// Active returns the number of active actions.
func (r *Responder) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

// actionFields describes an action for a revert record.
func (r *Responder) actionFields(key actionKey, action *active, reason string) map[string]any {
	ids := slices.Sorted(maps.Keys(action.owners))
	fields := map[string]any{
		"event": "response", "action": key.action, "target": key.target, "mode": r.mode, "reason": reason,
	}
	if len(ids) > 0 {
		fields["response_id"] = ids[0]
		fields["detection_rule_id"] = action.owners[ids[0]].ruleID
	}
	if len(ids) > 1 {
		fields["response_ids"] = ids
	}
	return fields
}

// revertLocked undoes an action. An action whose undo fails stays tracked so
// the next Expire retries it.
func (r *Responder) revertLocked(key actionKey, action *active, reason string) {
	fields := r.actionFields(key, action, reason)
	if action.applied {
		var err error
		switch key.action {
		case policy.ResponseBlockPeer:
			if r.blocker != nil {
				err = r.blocker.UnblockPeer(action.peer)
			}
		case policy.ResponseFreezeCgroup:
			if r.freezer != nil {
				err = r.freezer.Thaw(action.cgroupID, action.cgroupPath)
			}
		}
		if err != nil {
			fields["error"] = err.Error()
			r.record("response revert failed", fields)
			return
		}
	}
	delete(r.active, key)
	if key.action == policy.ResponseFreezeCgroup {
		r.persistLocked()
	}
	r.record("response reverted", fields)
}

func peerAddress(fields map[string]any) (netip.Addr, bool) {
	for _, name := range []string{"peer_address", "address"} {
		if text, ok := fields[name].(string); ok {
			if address, err := netip.ParseAddr(text); err == nil {
				return address.Unmap(), true
			}
		}
	}
	return netip.Addr{}, false
}

// cgroupID reads the event-time kernel cgroup ID, never a cached or /proc
// value.
func cgroupID(fields map[string]any) (uint64, bool) {
	switch id := fields["cgroup_id"].(type) {
	case uint64:
		return id, id != 0
	case float64:
		if id > 0 && id == float64(uint64(id)) {
			return uint64(id), true
		}
	}
	return 0, false
}
