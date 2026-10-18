package app

import (
	"context"
	"maps"
	"time"

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

// collectRingBufferStats publishes ring buffer occupancy and drop counters,
// and records an error when drops grew since previous. A nil previous only
// establishes the baseline, so drops already counted in adopted pinned maps
// are exported but not reported as new loss. It returns the next baseline.
func collectRingBufferStats(source ringBufferStatsSource, metrics *telemetry.Registry, recorder *eventsink.Recorder, previous map[uint32]uint64) map[uint32]uint64 {
	stats, err := source.RingBufferStats()
	if err != nil {
		recorder.ErrorDedup("collect eBPF ring buffer statistics", err, nil, time.Minute)
	}
	byName := make(map[string]uint64, len(stats.Drops))
	next := make(map[uint32]uint64, len(stats.Drops))
	maps.Copy(next, previous)
	fields := make(map[string]any)
	var total uint64
	for kind, dropped := range stats.Drops {
		name := eventKindName(kind)
		byName[name] = dropped
		next[kind] = dropped
		if previous != nil && dropped > previous[kind] {
			delta := dropped - previous[kind]
			// Event sinks bound nested values, so keep per-kind counts flat.
			fields["dropped_"+name] = delta
			total += delta
		}
	}
	metrics.SetRingBufferStats(stats.SizeBytes, stats.UnreadBytes, byName)
	if total > 0 {
		fields["dropped_events"] = total
		fields["ringbuf_size_bytes"] = stats.SizeBytes
		fields["ringbuf_unread_bytes"] = stats.UnreadBytes
		recorder.Error("eBPF ring buffer full; events dropped", nil, fields)
	}
	return next
}

func runRingBufferStats(ctx context.Context, source ringBufferStatsSource, metrics *telemetry.Registry, recorder *eventsink.Recorder, baseline map[uint32]uint64) {
	ticker := time.NewTicker(ringBufferStatsPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			baseline = collectRingBufferStats(source, metrics, recorder, baseline)
		}
	}
}
