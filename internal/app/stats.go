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

// ringBufferHealthComponent names the ring buffer in
// traceguard_component_healthy.
const ringBufferHealthComponent = "ringbuf"

// ringBufferWatcher publishes ring buffer occupancy and drop counters, and
// records an error when drops grow. A kind's first successful reading only
// establishes its baseline, so drops already counted in adopted pinned maps,
// or before a failed read, are exported but not reported as new loss.
//
// With a positive unhealthyDropRate, the watcher also marks health degraded
// while drops between two collections exceed that many events per second,
// and restores it after a collection at or below the rate.
type ringBufferWatcher struct {
	source            ringBufferStatsSource
	metrics           *telemetry.Registry
	recorder          *eventsink.Recorder
	unhealthyDropRate float64

	mu        sync.Mutex
	baseline  map[uint32]uint64
	dropped   uint64
	unread    int
	collected time.Time
	degraded  bool
}

func newRingBufferWatcher(source ringBufferStatsSource, metrics *telemetry.Registry, recorder *eventsink.Recorder, unhealthyDropRate float64) *ringBufferWatcher {
	if unhealthyDropRate > 0 {
		metrics.SetComponentHealthy(ringBufferHealthComponent, true)
	}
	return &ringBufferWatcher{source: source, metrics: metrics, recorder: recorder, unhealthyDropRate: unhealthyDropRate}
}

func (w *ringBufferWatcher) collect() {
	w.collectAt(time.Now())
}

func (w *ringBufferWatcher) collectAt(now time.Time) {
	stats, err := w.source.RingBufferStats()
	if err != nil {
		w.recorder.ErrorDedup("collect eBPF ring buffer statistics", err, nil, time.Minute)
	}

	w.mu.Lock()
	next := make(map[uint32]uint64, len(stats.Drops))
	maps.Copy(next, w.baseline)
	fields := make(map[string]any)
	var total uint64
	for kind, dropped := range stats.Drops {
		name := eventKindName(kind)
		next[kind] = dropped
		if baseline, seen := w.baseline[kind]; seen && dropped > baseline {
			delta := dropped - baseline
			// Event sinks bound nested values, so keep per-kind counts flat.
			fields["dropped_"+name] = delta
			total += delta
		}
	}
	w.baseline = next
	w.dropped += total
	w.unread = stats.UnreadBytes
	rate, transition := w.updateHealthLocked(now, total)
	w.mu.Unlock()

	// Report every kind's latest good reading, so a kind whose lookup failed
	// this time keeps its series instead of vanishing.
	byName := make(map[string]uint64, len(next))
	for kind, dropped := range next {
		byName[eventKindName(kind)] = dropped
	}
	w.metrics.SetRingBufferStats(stats.SizeBytes, stats.UnreadBytes, byName)
	if total > 0 {
		fields["dropped_events"] = total
		fields["ringbuf_size_bytes"] = stats.SizeBytes
		fields["ringbuf_unread_bytes"] = stats.UnreadBytes
		w.recorder.Error("eBPF ring buffer full; events dropped", nil, fields)
	}
	switch transition {
	case healthDegraded:
		w.metrics.SetComponentHealthy(ringBufferHealthComponent, false)
		w.recorder.Error("eBPF ring buffer drop rate above threshold; health degraded", nil, map[string]any{
			"drop_rate": rate, "unhealthy_drop_rate": w.unhealthyDropRate, "ringbuf_size_bytes": stats.SizeBytes,
		})
	case healthRestored:
		w.metrics.SetComponentHealthy(ringBufferHealthComponent, true)
		w.recorder.Info("eBPF ring buffer drop rate back within threshold; health restored", map[string]any{
			"drop_rate": rate, "unhealthy_drop_rate": w.unhealthyDropRate,
		})
	case healthUnchanged:
	}
}

type healthTransition uint8

const (
	healthUnchanged healthTransition = iota
	healthDegraded
	healthRestored
)

// updateHealthLocked compares the drop rate since the previous collection
// with the threshold. The first collection only starts the interval.
func (w *ringBufferWatcher) updateHealthLocked(now time.Time, dropped uint64) (float64, healthTransition) {
	if w.unhealthyDropRate <= 0 {
		return 0, healthUnchanged
	}
	previous := w.collected
	w.collected = now
	elapsed := now.Sub(previous).Seconds()
	if previous.IsZero() || elapsed <= 0 {
		return 0, healthUnchanged
	}
	rate := float64(dropped) / elapsed
	degraded := rate > w.unhealthyDropRate
	if degraded == w.degraded {
		return rate, healthUnchanged
	}
	w.degraded = degraded
	if degraded {
		return rate, healthDegraded
	}
	return rate, healthRestored
}

// status returns events dropped since the baseline and the unread bytes seen
// by the most recent collection.
func (w *ringBufferWatcher) status() (dropped uint64, unreadBytes int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dropped, w.unread
}

// isDegraded reports whether the drop rate last exceeded the threshold.
func (w *ringBufferWatcher) isDegraded() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.degraded
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
