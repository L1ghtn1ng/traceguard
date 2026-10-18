//go:build linux && ebpfintegration

package ebpf

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func TestFullRingBufferCountsDroppedEventsForIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("RemoveMemlock returned error: %v", err)
	}
	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	retainIntegrationProgram(spec, "trace_dns")
	// One page holds only a handful of events, so an unread buffer fills fast.
	spec.Maps["events"].MaxEntries = uint32(os.Getpagesize())
	var objects struct {
		TraceDns       *ebpf.Program `ebpf:"trace_dns"`
		Events         *ebpf.Map     `ebpf:"events"`
		RingbufDrops   *ebpf.Map     `ebpf:"ringbuf_drops"`
		Settings       *ebpf.Map     `ebpf:"settings"`
		PolicySelector *ebpf.Map     `ebpf:"policy_selector"`
	}
	if err := spec.LoadAndAssign(&objects, newCollectionOptions()); err != nil {
		fatalVerifierError(t, "LoadAndAssign", err)
	}
	defer objects.TraceDns.Close()
	defer objects.Events.Close()
	defer objects.RingbufDrops.Close()
	defer objects.Settings.Close()
	defer objects.PolicySelector.Close()
	publishIntegrationSettings(t, objects.Settings, objects.PolicySelector, 0, 1, runtimeSettings{})

	const queries = 32
	packet := ipv4DNSQuestionPacket([]byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}, false)
	for range queries {
		if result, _, err := objects.TraceDns.Test(packet); err != nil {
			t.Fatalf("test DNS packet: %v", err)
		} else if result != 1 {
			t.Fatalf("observe result = %d, want 1", result)
		}
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		t.Fatalf("NewReader returned error: %v", err)
	}
	defer reader.Close()
	reader.SetDeadline(time.Now().Add(100 * time.Millisecond))
	delivered := 0
	for {
		if _, err := reader.Read(); err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("Read returned error: %v", err)
			}
			break
		}
		delivered++
	}

	drops, err := readRingBufferDrops(objects.RingbufDrops)
	if err != nil {
		t.Fatalf("readRingBufferDrops returned error: %v", err)
	}
	if drops[EventDNS] == 0 {
		t.Fatalf("dns drops = 0 after %d queries into a one-page buffer (%d delivered)", queries, delivered)
	}
	if got := uint64(delivered) + drops[EventDNS]; got != queries {
		t.Fatalf("delivered %d + dropped %d = %d, want every query accounted for (%d)", delivered, drops[EventDNS], got, queries)
	}
	for kind, dropped := range drops {
		if kind != EventDNS && dropped != 0 {
			t.Errorf("drops[%d] = %d, want 0 for kinds that were not emitted", kind, dropped)
		}
	}
}
