package app

import (
	"context"
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
