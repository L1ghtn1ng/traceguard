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
// the first alert. A freeze that cannot be thawed yet stays tracked, and the
// expiry check retries it.
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
	for _, frozen := range r.readStateLocked() {
		key := actionKey{action: policy.ResponseFreezeCgroup, target: fmt.Sprint(frozen.CgroupID)}
		action := &active{owners: map[string]owner{}, until: r.options.Now(), applied: true, cgroupID: frozen.CgroupID, cgroupPath: frozen.Path}
		if r.freezer == nil {
			r.record("response revert failed", map[string]any{
				"event": "response", "action": key.action, "target": key.target, "mode": r.mode, "reason": "restart",
				"error": "cgroup freezing is unavailable, so " + frozen.Path + " stays frozen",
			})
			continue
		}
		r.active[key] = action
		r.revertLocked(key, action, "restart")
	}
	r.persistLocked()
}

func (r *Responder) readStateLocked() []frozenCgroup {
	if r.options.StatePath == "" {
		return nil
	}
	payload, err := os.ReadFile(r.options.StatePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var state stateFile
	if err == nil {
		err = json.Unmarshal(payload, &state)
	}
	if err != nil {
		r.record("response state unreadable", map[string]any{"event": "response", "path": r.options.StatePath, "error": err.Error()})
		return nil
	}
	if state.BootID != r.options.BootID {
		return nil
	}
	return state.Frozen
}

// persistLocked rewrites the state file with the cgroups that are frozen.
func (r *Responder) persistLocked() {
	if r.options.StatePath == "" {
		return
	}
	state := stateFile{BootID: r.options.BootID, Frozen: []frozenCgroup{}}
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
