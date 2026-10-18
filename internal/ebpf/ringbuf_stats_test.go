package ebpf

import (
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type fakePerCPULookup struct {
	values map[uint32][]uint64
	errs   map[uint32]error
}

func (f fakePerCPULookup) Lookup(key, valueOut any) error {
	kind, ok := key.(uint32)
	if !ok {
		return fmt.Errorf("key type %T, want uint32", key)
	}
	out, ok := valueOut.(*[]uint64)
	if !ok {
		return fmt.Errorf("value type %T, want *[]uint64", valueOut)
	}
	if err := f.errs[kind]; err != nil {
		return err
	}
	*out = append([]uint64(nil), f.values[kind]...)
	return nil
}

func TestReadRingBufferDropsSumsEveryCPUForEveryKind(t *testing.T) {
	t.Parallel()

	drops, err := readRingBufferDrops(fakePerCPULookup{values: map[uint32][]uint64{
		EventDNS:        {1, 2, 3},
		EventFileAccess: {0, 7},
		EventSockOps:    {5},
	}})
	if err != nil {
		t.Fatalf("readRingBufferDrops returned error: %v", err)
	}
	if got, want := len(drops), int(eventKindMax); got != want {
		t.Fatalf("drop kinds = %d, want every event kind (%d)", got, want)
	}
	for kind, want := range map[uint32]uint64{EventDNS: 6, EventFileAccess: 7, EventSockOps: 5, EventExec: 0} {
		if got := drops[kind]; got != want {
			t.Errorf("drops[%d] = %d, want %d", kind, got, want)
		}
	}
	if _, ok := drops[0]; ok {
		t.Error("drops include unused kind 0")
	}
}

func TestReadRingBufferDropsKeepsReadableKindsOnError(t *testing.T) {
	t.Parallel()

	lookupErr := errors.New("lookup failed")
	drops, err := readRingBufferDrops(fakePerCPULookup{
		values: map[uint32][]uint64{EventDNS: {4}},
		errs:   map[uint32]error{EventExec: lookupErr},
	})
	if !errors.Is(err, lookupErr) {
		t.Fatalf("error = %v, want wrapped lookup error", err)
	}
	if got := drops[EventDNS]; got != 4 {
		t.Fatalf("drops[dns] = %d, want 4", got)
	}
	if _, ok := drops[EventExec]; ok {
		t.Fatal("unreadable kind reported a drop value")
	}
}

func TestSumPerCPUSaturates(t *testing.T) {
	t.Parallel()

	if got := sumPerCPU([]uint64{math.MaxUint64 - 1, 5}); got != math.MaxUint64 {
		t.Fatalf("sumPerCPU overflow = %d, want saturation", got)
	}
	if got := sumPerCPU(nil); got != 0 {
		t.Fatalf("sumPerCPU(nil) = %d, want 0", got)
	}
}

func TestRingBufferStatsWithoutReaderOrCounters(t *testing.T) {
	t.Parallel()

	stats, err := (&Monitor{readerClosed: true}).RingBufferStats()
	if err == nil {
		t.Fatal("RingBufferStats without drop counters returned nil error")
	}
	if stats.SizeBytes != 0 || stats.UnreadBytes != 0 || stats.Drops != nil {
		t.Fatalf("stats = %#v, want zero value", stats)
	}
}

func TestRingBufferDropMapCoversEveryEventKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{"default", loadTraceguard}, {"dns-compat", loadTraceguardDNSCompat},
		{"recvmsg-compat", loadTraceguardRecvmsgCompat}, {"dns-recvmsg-compat", loadTraceguardDNSRecvmsgCompat},
		{"linux71", loadTraceguardLinux71}, {"linux71-dns-compat", loadTraceguardLinux71DNSCompat},
		{"linux71-recvmsg-compat", loadTraceguardLinux71RecvmsgCompat}, {"linux71-dns-recvmsg-compat", loadTraceguardLinux71DNSRecvmsgCompat},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			spec, err := test.load()
			if err != nil {
				t.Fatal(err)
			}
			drops := spec.Maps["ringbuf_drops"]
			if drops == nil || drops.Type != ebpf.PerCPUArray || drops.KeySize != 4 || drops.ValueSize != 8 || drops.MaxEntries != eventKindMax+1 {
				t.Fatalf("ringbuf_drops = %#v, want per-CPU uint64 counters for kinds 0..%d", drops, eventKindMax)
			}
		})
	}
}

func TestBPFRingBufferReservationsCountDrops(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("bpf/traceguard.c")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if got := strings.Count(text, "bpf_ringbuf_reserve("); got != 1 {
		t.Fatalf("bpf_ringbuf_reserve call sites = %d, want only the counting reserve_event helper", got)
	}
	if !strings.Contains(text, "#define EVENT_KIND_MAX EVENT_PRIVILEGE_CHANGE") {
		t.Fatal("EVENT_KIND_MAX no longer tracks the last event kind; update eventKindMax with it")
	}
	kinds := 0
	for _, define := range regexp.MustCompile(`(?m)^#define (EVENT_[A-Z_]+) \d+$`).FindAllStringSubmatch(text, -1) {
		if !strings.HasPrefix(define[1], "EVENT_SOURCE_") {
			kinds++
		}
	}
	if kinds != int(eventKindMax) {
		t.Fatalf("numeric event kinds = %d, want %d covered by ringbuf_drops", kinds, eventKindMax)
	}
}
