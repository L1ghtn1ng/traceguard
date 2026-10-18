package app

import (
	"sync"
	"sync/atomic"
	"time"
)

// maxPendingDetections bounds events held while the first policy loads.
const maxPendingDetections = 8192

type pendingDetection struct {
	timestamp time.Time
	name      string
	fields    map[string]any
}

// detectionGate holds detection until the configured policy is installed.
// The ring buffer is read before the policy loads, so without the gate
// events read during a slow load would be judged by rules the policy
// disables, and counted toward thresholds that installing it resets.
type detectionGate struct {
	evaluate func(time.Time, string, map[string]any)

	armed   atomic.Bool
	mu      sync.Mutex
	pending []pendingDetection
	dropped int
}

func newDetectionGate(evaluate func(time.Time, string, map[string]any)) *detectionGate {
	return &detectionGate{evaluate: evaluate}
}

// submit evaluates an event, or holds it until arm while the policy loads.
func (g *detectionGate) submit(timestamp time.Time, name string, fields map[string]any) {
	if g.armed.Load() {
		g.evaluate(timestamp, name, fields)
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.armed.Load() {
		g.evaluate(timestamp, name, fields)
		return
	}
	if len(g.pending) >= maxPendingDetections {
		g.dropped++
		return
	}
	g.pending = append(g.pending, pendingDetection{timestamp: timestamp, name: name, fields: fields})
}

// arm evaluates held events in order against the now-installed policy and
// passes later events straight through. It returns how many events were not
// held because the buffer was full.
func (g *detectionGate) arm() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, held := range g.pending {
		g.evaluate(held.timestamp, held.name, held.fields)
	}
	g.pending = nil
	g.armed.Store(true)
	return g.dropped
}
