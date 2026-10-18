package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// stateFile records the cgroups TraceGuard has frozen. Peer blocks need no
// record: their kernel entries carry a deadline, and Recover clears them.
type stateFile struct {
	BootID string         `json:"boot_id"`
	Frozen []frozenCgroup `json:"frozen"`
}

type frozenCgroup struct {
	CgroupID uint64    `json:"cgroup_id"`
	Path     string    `json:"path"`
	Until    time.Time `json:"until"`
}

// BootID reads the kernel's boot ID from path, normally
// /proc/sys/kernel/random/boot_id.
func BootID(path string) (string, error) {
	payload, err := os.ReadFile(path) //nolint:gosec // fixed /proc path
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(payload)), nil
}

// Recover undoes what an earlier run left behind: every peer block, and every
// cgroup freeze its state file records for this boot. Call it once, before
// the first alert. A freeze whose thaw fails stays tracked, and the expiry
// check retries it. A record is never dropped untried: one this run cannot
// thaw stays in the state file, and a state file that cannot be read is left
// as it is, unwritten, for the next start.
func (r *Responder) Recover() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blocker != nil {
		if err := r.blocker.ClearPeers(); err != nil {
			r.record("response revert failed", map[string]any{
				"event": "response", "action": policy.ResponseBlockPeer, "mode": r.mode, "reason": "restart", "error": err.Error(),
			})
		}
	}
	records, err := r.readStateLocked()
	if err != nil {
		r.stateHeld = true
		r.record("response state unreadable", map[string]any{
			"event": "response", "path": r.options.StatePath, "error": err.Error(),
			"detail": "the file is left unchanged and not updated this run; cgroups it records stay frozen until it is fixed and TraceGuard restarts",
		})
		return
	}
	for _, frozen := range records {
		key := actionKey{action: policy.ResponseFreezeCgroup, target: fmt.Sprint(frozen.CgroupID)}
		if r.freezer == nil {
			r.retained = append(r.retained, frozen)
			r.record("response revert failed", map[string]any{
				"event": "response", "action": key.action, "target": key.target, "mode": r.mode, "reason": "restart",
				"error": "cgroup freezing is unavailable, so " + frozen.Path + " stays frozen and stays recorded for the next start",
			})
			continue
		}
		action := &active{owners: map[string]owner{}, until: r.options.Now(), applied: true, cgroupID: frozen.CgroupID, cgroupPath: frozen.Path}
		r.active[key] = action
		r.revertLocked(key, action, "restart")
	}
	r.persistLocked()
}

// readStateLocked returns the freezes recorded for this boot. A missing file
// records none; a file that cannot be read or decoded is an error.
func (r *Responder) readStateLocked() ([]frozenCgroup, error) {
	if r.options.StatePath == "" {
		return nil, nil
	}
	payload, err := os.ReadFile(r.options.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state stateFile
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, err
	}
	if state.BootID != r.options.BootID {
		return nil, nil
	}
	return state.Frozen, nil
}

// persistLocked rewrites the state file with the cgroups that are frozen,
// including recorded ones this run cannot thaw.
func (r *Responder) persistLocked() {
	if r.options.StatePath == "" || r.stateHeld {
		return
	}
	state := stateFile{BootID: r.options.BootID, Frozen: slices.Clone(r.retained)}
	for key, action := range r.active {
		if key.action == policy.ResponseFreezeCgroup && action.applied {
			state.Frozen = append(state.Frozen, frozenCgroup{CgroupID: action.cgroupID, Path: action.cgroupPath, Until: action.until})
		}
	}
	slices.SortFunc(state.Frozen, func(left, right frozenCgroup) int { return strings.Compare(left.Path, right.Path) })
	if err := writeState(r.options.StatePath, state); err != nil {
		r.record("response state not saved", map[string]any{"event": "response", "path": r.options.StatePath, "error": err.Error()})
	}
}

// writeState replaces the state file atomically, so a crash mid-write
// leaves the previous version.
func writeState(path string, state stateFile) error {
	payload, err := json.Marshal(state)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".responses-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}
