package ebpf

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

// loadConstants are read-only BPF globals fixed when a collection is loaded.
type loadConstants struct {
	connectionDedupeWindow time.Duration
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
