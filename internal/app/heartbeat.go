package app

import (
	"context"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
)

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
	return map[string]any{
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
