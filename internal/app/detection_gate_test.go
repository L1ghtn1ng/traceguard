package app

import (
	"slices"
	"sync"
	"testing"
	"time"
)

func TestDetectionGateHoldsEventsUntilArmed(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var evaluated []string
	gate := newDetectionGate(func(_ time.Time, name string, _ map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		evaluated = append(evaluated, name)
	})
	gate.submit(time.Unix(1, 0), "first", nil)
	gate.submit(time.Unix(2, 0), "second", nil)
	if len(evaluated) != 0 {
		t.Fatalf("events evaluated before the policy was installed: %v", evaluated)
	}
	if dropped := gate.arm(); dropped != 0 {
		t.Fatalf("arm dropped %d events", dropped)
	}
	gate.submit(time.Unix(3, 0), "third", nil)
	if !slices.Equal(evaluated, []string{"first", "second", "third"}) {
		t.Fatalf("evaluated = %v, want held events in order then live events", evaluated)
	}
}

func TestDetectionGateCountsOverflow(t *testing.T) {
	t.Parallel()

	count := 0
	gate := newDetectionGate(func(time.Time, string, map[string]any) { count++ })
	for range maxPendingDetections + 3 {
		gate.submit(time.Unix(1, 0), "event", nil)
	}
	if dropped := gate.arm(); dropped != 3 || count != maxPendingDetections {
		t.Fatalf("dropped = %d evaluated = %d, want 3 and %d", dropped, count, maxPendingDetections)
	}
}

func TestDetectionGateIsSafeDuringArm(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	count := 0
	gate := newDetectionGate(func(time.Time, string, map[string]any) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 500 {
				gate.submit(time.Unix(1, 0), "event", nil)
			}
		})
	}
	gate.arm()
	wg.Wait()
	if count != 2000 {
		t.Fatalf("evaluated %d events, want every one of 2000", count)
	}
}
