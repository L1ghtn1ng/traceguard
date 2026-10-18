// Package response runs the reversible actions a policy attaches to
// detection rules: temporarily blocking an alert's peer address and
// temporarily freezing its acting cgroup.
//
// Every action has a deadline. It is undone when the deadline passes, when its
// response is removed from policy, or when TraceGuard stops, and each step is
// recorded.
package response

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
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

// MaxActive bounds simultaneously active actions.
const MaxActive = 1024

// PeerBlocker blocks and unblocks peer addresses in the kernel.
type PeerBlocker interface {
	BlockPeer(address netip.Addr, until time.Time) error
	UnblockPeer(address netip.Addr) error
}

// Freezer freezes and thaws cgroups by ID.
type Freezer interface {
	// Freeze freezes the cgroup and returns its path for Thaw.
	Freeze(id uint64) (string, error)
	Thaw(path string) error
}

// Recorder receives a record for every action step.
type Recorder func(message string, fields map[string]any)

type actionKey struct {
	action string
	target string
}

type active struct {
	responseID string
	ruleID     string
	until      time.Time
	peer       netip.Addr
	cgroupPath string
}

// Responder applies responses to alerts.
type Responder struct {
	mode    string
	blocker PeerBlocker
	freezer Freezer
	record  Recorder

	mu        sync.Mutex
	responses []policy.Response
	active    map[actionKey]*active
}

// New returns a responder in mode. A nil blocker or freezer makes that
// action unavailable.
func New(mode string, blocker PeerBlocker, freezer Freezer, record Recorder) *Responder {
	return &Responder{mode: mode, blocker: blocker, freezer: freezer, record: record, active: make(map[actionKey]*active)}
}

// Configure installs the policy's responses and reverts active actions whose
// response was removed.
func (r *Responder) Configure(responses []policy.Response) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.responses = slices.Clone(responses)
	configured := make(map[string]struct{}, len(responses))
	for _, response := range responses {
		configured[response.ID] = struct{}{}
	}
	for key, action := range r.active {
		if _, ok := configured[action.responseID]; !ok {
			r.revertLocked(key, action, "policy_removed")
		}
	}
}

// Handle runs every response that names the alert's rule.
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
		until := alert.Timestamp.Add(response.Duration.Duration)
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
	fields := r.fields(response, alert, "", alert.Timestamp)
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
	if r.mode == ModeEnforce {
		if r.blocker == nil {
			r.skip(response, alert, "peer blocking is unavailable")
			return
		}
		if err := r.blocker.BlockPeer(address, until); err != nil {
			r.failed(response, alert, target, err)
			return
		}
	}
	r.track(response, alert, policy.ResponseBlockPeer, target, until, &active{peer: address})
}

func (r *Responder) freezeCgroupLocked(response policy.Response, alert detection.Alert, until time.Time) {
	id, ok := cgroupID(alert.Fields)
	if !ok {
		r.skip(response, alert, "the alert has no event-time cgroup")
		return
	}
	target := fmt.Sprint(id)
	if !r.admitLocked(response, alert, policy.ResponseFreezeCgroup, target, until) {
		return
	}
	var path string
	if r.mode == ModeEnforce {
		if r.freezer == nil {
			r.skip(response, alert, "cgroup freezing is unavailable")
			return
		}
		frozen, err := r.freezer.Freeze(id)
		if err != nil {
			r.failed(response, alert, target, err)
			return
		}
		path = frozen
	}
	r.track(response, alert, policy.ResponseFreezeCgroup, target, until, &active{cgroupPath: path})
}

// admitLocked extends an action that is already active and reports whether a
// new one should be applied.
func (r *Responder) admitLocked(response policy.Response, alert detection.Alert, action, target string, until time.Time) bool {
	key := actionKey{action: action, target: target}
	if existing, ok := r.active[key]; ok {
		if until.After(existing.until) {
			if action == policy.ResponseBlockPeer && r.mode == ModeEnforce && r.blocker != nil {
				if err := r.blocker.BlockPeer(existing.peer, until); err != nil {
					r.failed(response, alert, target, err)
					return false
				}
			}
			existing.until = until
			r.record("response extended", r.fields(response, alert, target, until))
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
	state.responseID, state.ruleID, state.until = response.ID, alert.RuleID, until
	r.active[actionKey{action: action, target: target}] = state
	message := "response applied"
	if r.mode == ModeDryRun {
		message = "response would apply"
	}
	r.record(message, r.fields(response, alert, target, until))
}

func (r *Responder) failed(response policy.Response, alert detection.Alert, target string, err error) {
	fields := r.fields(response, alert, target, alert.Timestamp)
	delete(fields, "until")
	fields["error"] = err.Error()
	r.record("response failed", fields)
}

// Expire reverts actions whose deadline has passed.
func (r *Responder) Expire(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, action := range r.active {
		if !now.Before(action.until) {
			r.revertLocked(key, action, "expired")
		}
	}
}

// RevertAll undoes every active action, for shutdown.
func (r *Responder) RevertAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, action := range r.active {
		r.revertLocked(key, action, "shutdown")
	}
}

// Active returns the number of active actions.
func (r *Responder) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.active)
}

// revertLocked undoes an action. An action whose undo fails stays tracked so
// the next Expire retries it.
func (r *Responder) revertLocked(key actionKey, action *active, reason string) {
	fields := map[string]any{
		"event": "response", "response_id": action.responseID, "action": key.action, "target": key.target,
		"detection_rule_id": action.ruleID, "mode": r.mode, "reason": reason,
	}
	if r.mode == ModeEnforce {
		var err error
		switch key.action {
		case policy.ResponseBlockPeer:
			if r.blocker != nil {
				err = r.blocker.UnblockPeer(action.peer)
			}
		case policy.ResponseFreezeCgroup:
			if r.freezer != nil && action.cgroupPath != "" {
				err = r.freezer.Thaw(action.cgroupPath)
			}
		}
		if err != nil {
			fields["error"] = err.Error()
			r.record("response revert failed", fields)
			return
		}
	}
	delete(r.active, key)
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
