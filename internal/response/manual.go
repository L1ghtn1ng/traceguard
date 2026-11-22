package response

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// ManualResponseID owns the actions a manager command starts. Policy
// changes never end them: only their deadline, a lift, or shutdown does.
const ManualResponseID = policy.ReservedResponseID

// ActiveAction describes an action in force, for heartbeats.
type ActiveAction struct {
	Action string
	Target string
	Until  time.Time
	// Applied is false for dry-run actions, which change nothing.
	Applied bool
	// Manual reports an action a manager command started.
	Manual bool
}

// Mode returns the response mode: ModeOff, ModeDryRun or ModeEnforce.
func (r *Responder) Mode() string { return r.mode }

// ActiveActions returns up to limit active actions, soonest to end first.
func (r *Responder) ActiveActions(limit int) []ActiveAction {
	r.mu.Lock()
	defer r.mu.Unlock()
	actions := make([]ActiveAction, 0, min(len(r.active), max(limit, 0)))
	for key, action := range r.active {
		_, manual := action.owners[ManualResponseID]
		actions = append(actions, ActiveAction{
			Action: key.action, Target: key.target, Until: action.until, Applied: action.applied, Manual: manual,
		})
	}
	slices.SortFunc(actions, func(a, b ActiveAction) int {
		if order := a.Until.Compare(b.Until); order != 0 {
			return order
		}
		return strings.Compare(a.Action+"\x00"+a.Target, b.Action+"\x00"+b.Target)
	})
	if limit >= 0 && len(actions) > limit {
		actions = actions[:limit]
	}
	return actions
}

// Apply starts the action a manager command asked for: block_peer with a
// peer address, or freeze_cgroup with a kernel cgroup ID. It runs the same
// checks and records as a policy response, honors the response mode, and
// returns why it did not apply.
func (r *Responder) Apply(commandID, action, target string, duration time.Duration) error {
	if r.mode == ModeOff {
		return errors.New("responses are off on this agent")
	}
	if duration <= 0 || duration > policy.MaxResponseDuration {
		return fmt.Errorf("duration must be between 1s and %s", policy.MaxResponseDuration)
	}
	fields := map[string]any{}
	switch action {
	case policy.ResponseBlockPeer:
		address, err := parsePeer(target)
		if err != nil {
			return err
		}
		fields["peer_address"] = address.String()
	case policy.ResponseFreezeCgroup:
		id, err := strconv.ParseUint(strings.TrimSpace(target), 10, 64)
		if err != nil || id == 0 {
			return errors.New("target must be a cgroup ID")
		}
		fields["cgroup_id"] = id
	default:
		return fmt.Errorf("unknown response action %q", action)
	}
	response := policy.Response{
		ID: ManualResponseID, Rules: []string{ManualResponseID}, Action: action, Duration: policy.Duration{Duration: duration},
	}
	alert := detection.Alert{ID: commandID, RuleID: ManualResponseID, Fields: fields}

	r.mu.Lock()
	defer r.mu.Unlock()
	until := r.options.Now().Add(duration)
	if action == policy.ResponseBlockPeer {
		return r.blockPeerLocked(response, alert, until)
	}
	if r.mode == ModeEnforce && (r.options.StatePath == "" || r.stateHeld) {
		// A crash would leave the workload frozen with nothing to thaw it.
		return errors.New("refusing to freeze: no response state file can record it for recovery")
	}
	key := actionKey{action: action, target: fmt.Sprint(fields["cgroup_id"])}
	existing, adopted := r.active[key]
	var before activeSnapshot
	if adopted {
		before = snapshot(existing)
	}
	// The recovery record is saved before the cgroup is frozen.
	r.durableFreeze = true
	defer func() { r.durableFreeze = false }()
	if err := r.freezeCgroupLocked(response, alert, until); err != nil {
		return err
	}
	if adopted && r.mode == ModeEnforce {
		// This command joined a freeze already in force, perhaps one whose
		// record never saved: acknowledge it only once the record is on disk,
		// and otherwise leave the existing freeze exactly as it was.
		if err := r.persistLocked(); err != nil {
			before.restore(existing)
			fields := r.actionFields(key, existing, "state_not_saved")
			fields["command_id"] = commandID
			r.record("response extension undone", fields)
			return fmt.Errorf("refusing to extend the freeze: its recovery record could not be saved: %w", err)
		}
	}
	return nil
}

// activeSnapshot keeps what joining an action changes, to put it back.
type activeSnapshot struct {
	owners   map[string]owner
	until    time.Time
	liftedBy string
}

func snapshot(action *active) activeSnapshot {
	return activeSnapshot{owners: maps.Clone(action.owners), until: action.until, liftedBy: action.liftedBy}
}

func (s activeSnapshot) restore(action *active) {
	action.owners = s.owners
	action.until = s.until
	action.liftedBy = s.liftedBy
}

// Lift ends an active action now, whoever started it, as a manager command
// asked. An undo that fails stays tracked and is retried.
func (r *Responder) Lift(commandID, action, target string) error {
	target = strings.TrimSpace(target)
	// Normalise as Apply and policy responses do, so a lift names the key
	// the action was tracked under.
	switch action {
	case policy.ResponseBlockPeer:
		if address, err := parsePeer(target); err == nil {
			target = address.String()
		}
	case policy.ResponseFreezeCgroup:
		if id, err := strconv.ParseUint(target, 10, 64); err == nil {
			target = strconv.FormatUint(id, 10)
		}
	}
	key := actionKey{action: action, target: target}
	r.mu.Lock()
	defer r.mu.Unlock()
	active, ok := r.active[key]
	if !ok {
		return fmt.Errorf("no %s action is active for %q", action, target)
	}
	r.revertLocked(key, active, "lifted", map[string]any{"command_id": commandID})
	if still, ok := r.active[key]; ok {
		// End it now: the next Expire tick retries the undo, rather than
		// waiting for the action's original deadline.
		still.until = r.options.Now()
		still.liftedBy = commandID
		return errors.New("the undo failed; it is retried within seconds")
	}
	return nil
}

// parsePeer reads a peer address. Zoned IPv6 addresses are refused: the
// kernel block is keyed by address alone, so a zone would track a second
// action for the same entry.
func parsePeer(target string) (netip.Addr, error) {
	address, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		return netip.Addr{}, errors.New("target must be an IP address")
	}
	if address.Zone() != "" {
		return netip.Addr{}, errors.New("target must not carry an IPv6 zone")
	}
	return address.Unmap(), nil
}
