package ebpf

import (
	"errors"
	"fmt"
	"math/bits"
	"os"
	"time"

	"github.com/cilium/ebpf"
)

// loadConstants are read-only BPF globals fixed when a collection is loaded.
type loadConstants struct {
	connectionDedupeWindow time.Duration
	// connectionDedupeMinBytes enables TCP lifecycle deduplication, keeping
	// closes that moved at least this many bytes; zero disables it.
	connectionDedupeMinBytes uint64
	// ringBufferSize replaces the events ring buffer's compiled-in size when
	// non-zero. The kernel requires a power-of-two multiple of the page size.
	ringBufferSize uint32
}

func (c loadConstants) apply(spec *ebpf.CollectionSpec) error {
	if c.connectionDedupeWindow < 0 {
		return errors.New("connection dedupe window must not be negative")
	}
	window, ok := spec.Variables["connection_dedupe_window_ns"]
	if !ok {
		return errors.New("eBPF object lacks connection_dedupe_window_ns")
	}
	if err := window.Set(uint64(c.connectionDedupeWindow)); err != nil {
		return fmt.Errorf("set connection dedupe window: %w", err)
	}
	minBytes, ok := spec.Variables["connection_dedupe_min_bytes"]
	if !ok {
		return errors.New("eBPF object lacks connection_dedupe_min_bytes")
	}
	if err := minBytes.Set(c.connectionDedupeMinBytes); err != nil {
		return fmt.Errorf("set connection dedupe minimum bytes: %w", err)
	}
	if c.ringBufferSize != 0 {
		if err := validRingBufferSize(c.ringBufferSize); err != nil {
			return err
		}
		events, ok := spec.Maps["events"]
		if !ok {
			return errors.New("eBPF object lacks the events ring buffer")
		}
		events.MaxEntries = c.ringBufferSize
	}
	return nil
}

func validRingBufferSize(size uint32) error {
	page := os.Getpagesize()
	if bits.OnesCount32(size) != 1 || page <= 0 || uint64(size)%uint64(page) != 0 {
		return fmt.Errorf("ring buffer size %d must be a power of two and a multiple of the %d-byte page size", size, page)
	}
	return nil
}

// specLoader wraps a generated spec loader so every collection loaded from it
// carries these constants.
func (c loadConstants) specLoader(load func() (*ebpf.CollectionSpec, error)) func() (*ebpf.CollectionSpec, error) {
	return func() (*ebpf.CollectionSpec, error) {
		spec, err := load()
		if err != nil {
			return nil, err
		}
		if err := c.apply(spec); err != nil {
			return nil, err
		}
		return spec, nil
	}
}
