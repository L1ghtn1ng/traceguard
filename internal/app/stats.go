package app

import (
	"context"
	"maps"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

const programStatsPollInterval = 15 * time.Second

func collectProgramStats(monitor *ebpf.Monitor, metrics *telemetry.Registry, recorder *eventsink.Recorder) {
	stats, err := monitor.ProgramStats()
	for program, values := range stats {
		metrics.SetEBPFProgramStats(program, values.Runtime, values.RunCount, values.RecursionMisses)
	}
	if err != nil {
		recorder.ErrorDedup("collect eBPF program statistics", err, nil, programStatsPollInterval)
	}
}

func runProgramStats(ctx context.Context, monitor *ebpf.Monitor, metrics *telemetry.Registry, recorder *eventsink.Recorder) {
	ticker := time.NewTicker(programStatsPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collectProgramStats(monitor, metrics, recorder)
		}
	}
}

const ringBufferStatsPollInterval = 5 * time.Second

type ringBufferStatsSource interface {
	RingBufferStats() (ebpf.RingBufferStats, error)
}

// ringBufferWatcher publishes ring buffer occupancy and drop counters, and
// records an error when drops grow. The first collection only establishes the
// baseline, so drops already counted in adopted pinned maps are exported but
// not reported as new loss.
type ringBufferWatcher struct {
	source   ringBufferStatsSource
	metrics  *telemetry.Registry
	recorder *eventsink.Recorder

	mu       sync.Mutex
	baseline map[uint32]uint64
	dropped  uint64
	unread   int
}

func newRingBufferWatcher(source ringBufferStatsSource, metrics *telemetry.Registry, recorder *eventsink.Recorder) *ringBufferWatcher {
	return &ringBufferWatcher{source: source, metrics: metrics, recorder: recorder}
}

func (w *ringBufferWatcher) collect() {
	stats, err := w.source.RingBufferStats()
	if err != nil {
		w.recorder.ErrorDedup("collect eBPF ring buffer statistics", err, nil, time.Minute)
	}

	w.mu.Lock()
	first := w.baseline == nil
	next := make(map[uint32]uint64, len(stats.Drops))
	maps.Copy(next, w.baseline)
	byName := make(map[string]uint64, len(stats.Drops))
	fields := make(map[string]any)
	var total uint64
	for kind, dropped := range stats.Drops {
		name := eventKindName(kind)
		byName[name] = dropped
		next[kind] = dropped
		if !first && dropped > w.baseline[kind] {
			delta := dropped - w.baseline[kind]
			// Event sinks bound nested values, so keep per-kind counts flat.
			fields["dropped_"+name] = delta
			total += delta
		}
	}
	w.baseline = next
	w.dropped += total
	w.unread = stats.UnreadBytes
	w.mu.Unlock()

	w.metrics.SetRingBufferStats(stats.SizeBytes, stats.UnreadBytes, byName)
	if total > 0 {
		fields["dropped_events"] = total
		fields["ringbuf_size_bytes"] = stats.SizeBytes
		fields["ringbuf_unread_bytes"] = stats.UnreadBytes
		w.recorder.Error("eBPF ring buffer full; events dropped", nil, fields)
	}
}

// status returns events dropped since the baseline and the unread bytes seen
// by the most recent collection.
func (w *ringBufferWatcher) status() (dropped uint64, unreadBytes int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dropped, w.unread
}

// runEvery calls collect at each interval until ctx is done.
func runEvery(ctx context.Context, interval time.Duration, collect func(time.Time)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			collect(now)
		}
	}
}

// exceptionWatcher publishes detection exception metrics and records each
// exception's expiry once.
type exceptionWatcher struct {
	detector *detection.Engine
	metrics  *telemetry.Registry
	recorder *eventsink.Recorder
	expired  map[string]struct{}
}

func newExceptionWatcher(detector *detection.Engine, metrics *telemetry.Registry, recorder *eventsink.Recorder) *exceptionWatcher {
	return &exceptionWatcher{detector: detector, metrics: metrics, recorder: recorder, expired: make(map[string]struct{})}
}

func (w *exceptionWatcher) collect(now time.Time) {
	statuses := w.detector.ExceptionStatus(now)
	suppressed := make(map[string]uint64, len(statuses))
	expired := make(map[string]struct{})
	active := 0
	for _, status := range statuses {
		suppressed[status.ID] = status.Suppressed
		if !status.Expired {
			active++
			continue
		}
		expired[status.ID] = struct{}{}
		if _, reported := w.expired[status.ID]; !reported {
			w.recorder.Info("detection exception expired", map[string]any{
				"exception_id": status.ID, "suppressed_events": status.Suppressed,
			})
		}
	}
	w.expired = expired
	w.metrics.SetDetectionExceptions(active, len(expired), suppressed)
}
