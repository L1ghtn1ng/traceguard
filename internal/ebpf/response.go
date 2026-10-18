package ebpf

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// familyIPv4 and familyIPv6 mirror FAMILY_IPV4 and FAMILY_IPV6.
const (
	familyIPv4 = 4
	familyIPv6 = 6
)

// responsePeerKey mirrors struct response_peer_key in traceguard.c.
type responsePeerKey struct {
	Family uint8
	_      [3]uint8
	Addr   [16]byte
}

func newResponsePeerKey(address netip.Addr) (responsePeerKey, error) {
	address = address.Unmap()
	var key responsePeerKey
	switch {
	case address.Is4():
		key.Family = familyIPv4
		ip := address.As4()
		copy(key.Addr[:], ip[:])
	case address.Is6():
		key.Family = familyIPv6
		key.Addr = address.As16()
	default:
		return responsePeerKey{}, fmt.Errorf("invalid peer address %v", address)
	}
	return key, nil
}

// monotonicDeadline converts a wall-clock deadline to the CLOCK_MONOTONIC
// nanoseconds bpf_ktime_get_ns compares against.
func monotonicDeadline(until time.Time, now time.Time) (uint64, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, fmt.Errorf("read monotonic clock: %w", err)
	}
	remaining := until.Sub(now)
	if remaining <= 0 {
		return 0, errors.New("peer block deadline has passed")
	}
	return uint64(ts.Nano()) + uint64(remaining), nil //nolint:gosec // both are positive nanosecond counts
}

// BlockPeer drops cgroup traffic to and from address until the deadline.
func (m *Monitor) BlockPeer(address netip.Addr, until time.Time) error {
	if m.objects.ResponsePeers == nil {
		return errors.New("response peer map is unavailable")
	}
	key, err := newResponsePeerKey(address)
	if err != nil {
		return err
	}
	deadline, err := monotonicDeadline(until, time.Now())
	if err != nil {
		return err
	}
	if err := m.objects.ResponsePeers.Put(key, deadline); err != nil {
		return fmt.Errorf("block peer %v: %w", address, err)
	}
	return nil
}

// UnblockPeer removes a peer block. Removing an absent block is not an error.
func (m *Monitor) UnblockPeer(address netip.Addr) error {
	if m.objects.ResponsePeers == nil {
		return errors.New("response peer map is unavailable")
	}
	key, err := newResponsePeerKey(address)
	if err != nil {
		return err
	}
	if err := m.objects.ResponsePeers.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("unblock peer %v: %w", address, err)
	}
	return nil
}

// ResponsePeerDrops returns packets dropped by peer blocks, by direction.
func (m *Monitor) ResponsePeerDrops() (egress, ingress uint64, err error) {
	if m.objects.ResponsePeerDrops == nil {
		return 0, 0, errors.New("response drop counters are unavailable")
	}
	for index, target := range []*uint64{&egress, &ingress} {
		var perCPU []uint64
		if err := m.objects.ResponsePeerDrops.Lookup(uint32(index), &perCPU); err != nil {
			return 0, 0, fmt.Errorf("read response drops: %w", err)
		}
		*target = sumPerCPU(perCPU)
	}
	return egress, ingress, nil
}
