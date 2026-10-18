package ebpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestResponsePeerKeyMatchesKernelLayout(t *testing.T) {
	t.Parallel()

	if got := binary.Size(responsePeerKey{}); got != 20 {
		t.Fatalf("responsePeerKey size = %d, want 20", got)
	}
	v4, err := newResponsePeerKey(netip.MustParseAddr("::ffff:203.0.113.9"))
	if err != nil {
		t.Fatal(err)
	}
	if v4.Family != familyIPv4 || v4.Addr != [16]byte{203, 0, 113, 9} {
		t.Fatalf("IPv4-mapped key = %+v, want unmapped IPv4", v4)
	}
	v6, err := newResponsePeerKey(netip.MustParseAddr("2001:db8::1"))
	if err != nil {
		t.Fatal(err)
	}
	if v6.Family != familyIPv6 || v6.Addr != netip.MustParseAddr("2001:db8::1").As16() {
		t.Fatalf("IPv6 key = %+v", v6)
	}
	if _, err := newResponsePeerKey(netip.Addr{}); err == nil {
		t.Fatal("invalid address produced a key")
	}
}

func TestMonotonicDeadlineRejectsPastDeadlines(t *testing.T) {
	t.Parallel()

	now := time.Now()
	if _, err := monotonicDeadline(now.Add(-time.Second), now); err == nil {
		t.Fatal("past deadline accepted")
	}
	deadline, err := monotonicDeadline(now.Add(time.Hour), now)
	if err != nil || deadline < uint64(time.Hour) {
		t.Fatalf("deadline = %d, %v", deadline, err)
	}
}

func TestResponseMapsMatchKernelLayout(t *testing.T) {
	t.Parallel()

	spec, err := loadTraceguard()
	if err != nil {
		t.Fatal(err)
	}
	if peers := spec.Maps["response_peers"]; peers == nil || peers.Type != ebpf.Hash || peers.KeySize != 20 || peers.ValueSize != 8 || peers.MaxEntries != 4096 {
		t.Fatalf("response_peers = %#v", peers)
	}
	if drops := spec.Maps["response_peer_drops"]; drops == nil || drops.Type != ebpf.PerCPUArray || drops.MaxEntries != 2 {
		t.Fatalf("response_peer_drops = %#v", drops)
	}
}
