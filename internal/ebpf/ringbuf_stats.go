package ebpf

import (
	"errors"
	"fmt"
	"math"
)

// eventKindMax mirrors EVENT_KIND_MAX in traceguard.c; ringbuf_drops holds
// one per-CPU counter for every kind from 0 through this value.
const eventKindMax = EventPrivilegeChange

// RingBufferStats is a point-in-time view of the shared event ring buffer.
type RingBufferStats struct {
	// SizeBytes is the ring buffer data capacity. It is zero once the
	// reader has been closed.
	SizeBytes int
	// UnreadBytes is the data the kernel has committed that userspace has
	// not consumed yet.
	UnreadBytes int
	// Drops holds cumulative events lost because bpf_ringbuf_reserve found
	// the ring buffer full, keyed by event kind.
	Drops map[uint32]uint64
}

type perCPULookup interface {
	Lookup(key, valueOut any) error
}

// RingBufferStats reads ring buffer occupancy and per-kind drop counters.
// It is safe to call concurrently with Run and after the reader has closed.
func (m *Monitor) RingBufferStats() (RingBufferStats, error) {
	var stats RingBufferStats
	m.readerMu.Lock()
	if m.reader != nil && !m.readerClosed {
		stats.SizeBytes = m.reader.BufferSize()
		stats.UnreadBytes = m.reader.AvailableBytes()
	}
	m.readerMu.Unlock()
	if m.objects.RingbufDrops == nil {
		return stats, errors.New("ring buffer drop counters are unavailable")
	}
	drops, err := readRingBufferDrops(m.objects.RingbufDrops)
	stats.Drops = drops
	return stats, err
}

func readRingBufferDrops(counters perCPULookup) (map[uint32]uint64, error) {
	drops := make(map[uint32]uint64, eventKindMax)
	var errs []error
	for kind := EventDNS; kind <= eventKindMax; kind++ {
		var perCPU []uint64
		if err := counters.Lookup(kind, &perCPU); err != nil {
			errs = append(errs, fmt.Errorf("read ring buffer drops for event kind %d: %w", kind, err))
			continue
		}
		drops[kind] = sumPerCPU(perCPU)
	}
	return drops, errors.Join(errs...)
}

func sumPerCPU(values []uint64) uint64 {
	var total uint64
	for _, value := range values {
		if value > math.MaxUint64-total {
			return math.MaxUint64
		}
		total += value
	}
	return total
}
