package app

import (
	"bufio"
	"context"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/response"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

// maxHeartbeatResponses bounds the active responses one heartbeat lists.
const maxHeartbeatResponses = 64

// heartbeatStatus gathers the self-health a heartbeat reports, so collectors
// can spot config drift, degraded hooks, and stuck agents across a fleet
// without a central manager.
type heartbeatStatus struct {
	started          time.Time
	mode             string
	policyDigest     func() string
	unavailableHooks []string
	ringBuffer       *ringBufferWatcher
	detector         *detection.Engine
	healthy          func() bool

	// The fields below are optional; empty or nil ones are left out.
	runID         string
	runSequence   uint64
	install       string
	version       string
	kernelRelease string
	osName        string
	responseMode  string
	commands      bool
	// remoteDigest returns the SHA-256 of the remote policy document in
	// use, so a policy server can tell whether the agent took its policy.
	remoteDigest func() string
	export       func() telemetry.EventExportStatus
	responses    func(limit int) []response.ActiveAction
}

func (s heartbeatStatus) fields(now time.Time) map[string]any {
	dropped, unread := s.ringBuffer.status()
	hooks := s.unavailableHooks
	if hooks == nil {
		hooks = []string{}
	}
	expired := []string{}
	exceptions := s.detector.ExceptionStatus(now)
	for _, exception := range exceptions {
		if exception.Expired {
			expired = append(expired, exception.ID)
		}
	}
	fields := map[string]any{
		"event":                        "heartbeat",
		"policy_sha256":                s.policyDigest(),
		"policy_mode":                  s.mode,
		"uptime_seconds":               int64(now.Sub(s.started).Seconds()),
		"healthy":                      s.healthy(),
		"unavailable_hooks":            hooks,
		"ringbuf_dropped_events":       dropped,
		"ringbuf_unread_bytes":         unread,
		"ringbuf_degraded":             s.ringBuffer.isDegraded(),
		"detection_rules":              s.detector.RuleCount(),
		"detection_state_groups":       s.detector.StateCount(),
		"detection_exceptions":         len(exceptions),
		"expired_detection_exceptions": expired,
	}
	for name, value := range map[string]string{
		"run_id":        s.runID,
		"agent_version": s.version, "kernel_release": s.kernelRelease, "os_name": s.osName, "response_mode": s.responseMode,
	} {
		if value != "" {
			fields[name] = value
		}
	}
	if s.responseMode != "" {
		fields["commands_enabled"] = s.commands
	}
	if s.runSequence > 0 {
		fields["run_seq"] = s.runSequence
		fields["install_id"] = s.install
	}
	if s.remoteDigest != nil {
		if digest := s.remoteDigest(); digest != "" {
			fields["policy_remote_sha256"] = digest
		}
	}
	if s.export != nil {
		export := s.export()
		fields["export_dropped_records"] = export.Dropped + export.DroppedPriority
		fields["export_dropped_alerts"] = export.DroppedPriority
		fields["export_rejected_batches"] = export.Rejected
		fields["export_spool_batches"] = export.SpoolFiles
		fields["export_queue_depth"] = export.QueueDepth
	}
	if s.responses != nil {
		// One more than the limit tells whether the list was cut short.
		actions := s.responses(maxHeartbeatResponses + 1)
		truncated := len(actions) > maxHeartbeatResponses
		if truncated {
			actions = actions[:maxHeartbeatResponses]
		}
		listed := make([]any, 0, len(actions))
		for _, action := range actions {
			listed = append(listed, map[string]any{
				"action": action.Action, "target": action.Target, "applied": action.Applied, "manual": action.Manual,
				"until": action.Until.UTC().Format(time.RFC3339),
			})
		}
		fields["active_responses"] = listed
		if truncated {
			fields["active_responses_truncated"] = true
		}
	}
	return fields
}

// osPrettyName reads PRETTY_NAME from an os-release file, or "" when it
// cannot.
func osPrettyName(path string) string {
	file, err := os.Open(path) //nolint:gosec // a fixed system path
	if err != nil {
		return ""
	}
	defer func() { _ = file.Close() }()
	scanner := bufio.NewScanner(io.LimitReader(file, 64<<10))
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || strings.TrimSpace(name) != "PRETTY_NAME" {
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else {
			value = strings.Trim(value, `"'`)
		}
		if len(value) > 128 {
			value = value[:128]
		}
		return value
	}
	return ""
}

// runHeartbeat records a heartbeat immediately and then every interval.
func runHeartbeat(ctx context.Context, interval time.Duration, recorder *eventsink.Recorder, status heartbeatStatus) {
	recorder.Info("heartbeat", status.fields(time.Now()))
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			recorder.Info("heartbeat", status.fields(now))
		}
	}
}
