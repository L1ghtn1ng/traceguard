package app

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/fim"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

// File change operation codes mirror FILE_CHANGE_* in traceguard.c.
var fileChangeOperations = map[uint32]string{0: "unlink", 1: "rename", 2: "chmod", 3: "chown", 4: "truncate"}

const (
	atFDCWD     = 0xffffff9c // AT_FDCWD as the unsigned dirfd field carries it
	atRemoveDir = 0x200
)

// appendFileChangeFields adds a file change event's requested arguments.
func appendFileChangeFields(fields map[string]any, event ebpf.Event) {
	operation := operationName(fileChangeOperations, event.Operation)
	if operation == "unlink" && event.FileFlags&atRemoveDir != 0 {
		operation = "rmdir"
	}
	fields["operation"] = operation
	fields["requested_path"] = event.Filename
	fields["path_source"] = "syscall-requested"
	if event.FileMode != atFDCWD {
		fields["requested_dirfd"] = int32(event.FileMode) //nolint:gosec // dirfd is a signed descriptor carried in the unsigned field
	}
	if event.FileFlags != 0 {
		fields["requested_flags"] = event.FileFlags
	}
	switch operation {
	case "rename":
		fields["new_path"] = event.NewPath
	case "chmod":
		fields["requested_mode"] = fmt.Sprintf("%04o", event.Value&0o7777)
	case "chown":
		if uid := uint32(event.Value); uid != unchangedID { //nolint:gosec // the low word is the uid
			fields["requested_uid"] = uid
		}
		if gid := uint32(event.Value >> 32); gid != unchangedID {
			fields["requested_gid"] = gid
		}
	case "truncate":
		fields["truncate_length"] = event.Value
	}
}

// resolveRequestedPath turns a syscall-requested path into an absolute one,
// reading the process's working directory or dirfd from /proc for relative
// paths. It is best effort: the process may have exited or changed
// directory, and reading another user's /proc entries needs ptrace access.
func resolveRequestedPath(procRoot string, pid, dirfd uint32, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path), true
	}
	if pid == 0 {
		return "", false
	}
	base := fmt.Sprintf("%s/%d/cwd", procRoot, pid)
	if dirfd != atFDCWD {
		base = fmt.Sprintf("%s/%d/fd/%d", procRoot, pid, dirfd)
	}
	directory, err := os.Readlink(base)
	if err != nil || !filepath.IsAbs(directory) {
		return "", false
	}
	return filepath.Join(directory, path), true
}

// sharesMountNamespace reports whether pid is in the daemon's mount
// namespace. When either namespace cannot be read, it assumes it is.
func sharesMountNamespace(procRoot string, pid uint32) bool {
	process, err := os.Readlink(fmt.Sprintf("%s/%d/ns/mnt", procRoot, pid))
	if err != nil {
		return true
	}
	daemon, err := os.Readlink(procRoot + "/self/ns/mnt")
	return err != nil || process == daemon
}

// integrityActorFields are the triggering event's fields copied onto a file
// integrity change, prefixed with actor_.
var integrityActorFields = []string{
	"event", "operation", "pid", "program", "kernel_uid", "cgroup_id", "process_start_ticks",
	"current_exe", "current_cmdline", "current_cgroup", "current_container_id",
}

// notifyIntegrity queues integrity checks for the files an audit or change
// event may have modified.
func notifyIntegrity(watcher *fim.Watcher, procRoot string, event ebpf.Event, fields map[string]any) {
	var paths []string
	switch event.Kind {
	case ebpf.EventFileAccess:
		if fileAccessName(event.FileFlags) != "write" {
			return
		}
		paths = append(paths, event.Filename)
	case ebpf.EventFileChange:
		paths = append(paths, event.Filename)
		if event.NewPath != "" {
			paths = append(paths, event.NewPath)
		}
	default:
		return
	}
	if !sharesMountNamespace(procRoot, event.PID) {
		// The paths name files in the process's own mount namespace, such
		// as a container's /etc, not the host files that are watched.
		return
	}
	actor := fim.Actor{}
	for _, name := range integrityActorFields {
		if value, ok := fields[name]; ok {
			actor["actor_"+name] = value
		}
	}
	for index, requested := range paths {
		dirfd := event.FileMode
		if index == 1 {
			// A rename's destination is relative to its new dirfd.
			dirfd = uint32(event.Value) //nolint:gosec // the low word is the dirfd
		}
		if event.Kind == ebpf.EventFileAccess {
			// Open audit events carry the mode in FileMode and the dirfd
			// in Value.
			dirfd = uint32(event.Value) //nolint:gosec // the low word is the dirfd
		}
		path, ok := resolveRequestedPath(procRoot, event.PID, dirfd, requested)
		if ok && watcher.Watched(path) {
			watcher.Notify(path, actor)
		}
	}
}

// integrityRecordFields renders a change as file_integrity record fields.
func integrityRecordFields(change fim.Change, actor fim.Actor) map[string]any {
	fields := map[string]any{
		"event":            "file_integrity",
		"path":             change.Path,
		"change":           change.Kind,
		"detection_source": "event",
	}
	if len(change.Changed) > 0 {
		fields["changed"] = change.Changed
	}
	if actor == nil {
		fields["detection_source"] = "rescan"
	}
	for key, value := range actor {
		fields[key] = value
	}
	addIntegrityState(fields, "", change.Current)
	addIntegrityState(fields, "previous_", change.Previous)
	return fields
}

func addIntegrityState(fields map[string]any, prefix string, state *fim.State) {
	if state == nil {
		return
	}
	fields[prefix+"file_type"] = state.Type
	fields[prefix+"mode"] = fmt.Sprintf("%04o", uint32(state.Mode.Perm())|specialModeBits(state))
	fields[prefix+"owner_uid"] = state.UID
	fields[prefix+"owner_gid"] = state.GID
	fields[prefix+"size"] = state.Size
	fields[prefix+"mtime"] = state.ModTime.Format(time.RFC3339Nano)
	if state.SHA256 != "" {
		fields[prefix+"sha256"] = state.SHA256
	} else {
		fields[prefix+"hash_skipped"] = state.HashSkipped
	}
	if state.LinkTarget != "" {
		fields[prefix+"link_target"] = state.LinkTarget
	}
}

// specialModeBits renders setuid, setgid, and sticky as their octal digits.
func specialModeBits(state *fim.State) uint32 {
	var bits uint32
	if state.Mode&os.ModeSetuid != 0 {
		bits |= 0o4000
	}
	if state.Mode&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	if state.Mode&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return bits
}

// newIntegrityEmitter records each change, counts it, and evaluates
// detections against it.
func newIntegrityEmitter(recorder *eventsink.Recorder, metrics *telemetry.Registry, detector *detection.Engine) func(fim.Change, fim.Actor) {
	return func(change fim.Change, actor fim.Actor) {
		fields := integrityRecordFields(change, actor)
		now := time.Now().UTC()
		metrics.IncFileIntegrityChange(change.Kind)
		recorder.InfoAt(now, "file_integrity", fields)
		emitDetectionAlerts(detector, recorder, metrics, now, "file_integrity", fields)
	}
}

// integrityStatsWatcher publishes watcher statistics and records a truncated
// baseline once per truncation.
type integrityStatsWatcher struct {
	watcher   *fim.Watcher
	metrics   *telemetry.Registry
	recorder  *eventsink.Recorder
	truncated bool
}

func (w *integrityStatsWatcher) collect(time.Time) {
	stats := w.watcher.Stats()
	w.metrics.SetFileIntegrityStats(stats.Files, stats.Truncated, stats.Dropped)
	if stats.Truncated && !w.truncated {
		w.recorder.Error("file integrity baseline truncated", nil, map[string]any{"max_files": fim.MaxFiles})
	}
	w.truncated = stats.Truncated
}

// warnIntegrityWithoutAudit records that, with file auditing off, writes
// through open files reach file integrity only through rescans.
func warnIntegrityWithoutAudit(cfg config.Config, integrity policyconfig.FileIntegrityPolicy, recorder *eventsink.Recorder) {
	if cfg.FileAudit || !integrity.Enabled() {
		return
	}
	fields := map[string]any{"rescan_interval": integrity.Rescan().String()}
	if integrity.Rescan() == 0 {
		recorder.Error("file integrity sees no file writes: file audit and rescans are both disabled", nil, fields)
		return
	}
	recorder.Error("file integrity finds file writes only by rescan because file audit is disabled", nil, fields)
}
