package app

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func newTestHeartbeatStatus(t *testing.T, hooks []string) heartbeatStatus {
	t.Helper()
	recorder, _ := newTestRecorder(t)
	detector, err := detection.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	source := &fakeRingBufferStats{stats: ebpfmonitor.RingBufferStats{UnreadBytes: 1264, Drops: map[uint32]uint64{ebpfmonitor.EventDNS: 2}}}
	watcher := newRingBufferWatcher(source, telemetry.NewRegistry(), recorder, 0)
	watcher.collect()
	source.stats.Drops = map[uint32]uint64{ebpfmonitor.EventDNS: 9}
	watcher.collect()
	return heartbeatStatus{
		started: time.Unix(1000, 0), mode: "block",
		policyDigest:     func() string { return "abc123" },
		unavailableHooks: hooks, ringBuffer: watcher, detector: detector,
		healthy: func() bool { return true },
	}
}

func TestHeartbeatFieldsReportSelfHealth(t *testing.T) {
	t.Parallel()

	status := newTestHeartbeatStatus(t, []string{"lsm-exec", "sockops"})
	fields := status.fields(time.Unix(1090, 0))
	want := map[string]any{
		"event":                        "heartbeat",
		"policy_sha256":                "abc123",
		"policy_mode":                  "block",
		"uptime_seconds":               int64(90),
		"healthy":                      true,
		"unavailable_hooks":            []string{"lsm-exec", "sockops"},
		"ringbuf_dropped_events":       uint64(7),
		"ringbuf_unread_bytes":         1264,
		"ringbuf_degraded":             false,
		"detection_rules":              len(detection.BaselineRules()),
		"detection_state_groups":       0,
		"detection_exceptions":         0,
		"expired_detection_exceptions": []string{},
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("heartbeat fields = %#v, want %#v", fields, want)
	}
}

func TestHeartbeatReportsEmptyHookListAsArray(t *testing.T) {
	t.Parallel()

	fields := newTestHeartbeatStatus(t, nil).fields(time.Unix(1000, 0))
	if hooks, ok := fields["unavailable_hooks"].([]string); !ok || hooks == nil || len(hooks) != 0 {
		t.Fatalf("unavailable_hooks = %#v, want empty non-nil list", fields["unavailable_hooks"])
	}
}

func TestRunHeartbeatEmitsImmediatelyAndStops(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	status := newTestHeartbeatStatus(t, nil)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		runHeartbeat(ctx, time.Hour, recorder, status)
		close(done)
	}()
	deadline := time.After(time.Second)
	for !strings.Contains(output.String(), `"message":"heartbeat"`) {
		select {
		case <-deadline:
			t.Fatal("no heartbeat recorded at startup")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("runHeartbeat did not stop on cancellation")
	}
}
