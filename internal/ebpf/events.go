package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	commSize            = 16
	domainSize          = 256
	maxDNSWireNameBytes = 255
	filenameSize        = 256
	timestampOffsetTTL  = time.Second
)

type timestampOffsetCache struct {
	mu          sync.Mutex
	offsetNS    int64
	refreshedAt time.Time
	initialized bool
	now         func() time.Time
	bootNowNS   func() (int64, error)
}

var eventTimestampOffsets = timestampOffsetCache{
	now:       func() time.Time { return time.Now().UTC() },
	bootNowNS: readBootTimeNS,
}

const (
	EventDNS uint32 = iota + 1
	EventBlocked
	EventExec
	EventResolver
	EventResolverBlocked
	EventConnection
	EventFileAccess
)

type rawEvent struct {
	TimestampNS  uint64
	Kind         uint32
	PID          uint32
	Comm         [commSize]byte
	Domain       [domainSize]byte
	Filename     [filenameSize]byte
	Transport    uint8
	Family       uint8
	SocketProto  uint8
	Attribution  uint8
	SocketHook   uint8
	Direction    uint8
	Port         uint16
	LocalPort    uint16
	CPad         uint16
	FileFlags    uint32
	FileMode     uint32
	KernelUID    uint32
	EventSource  uint32
	FeatureSet   uint32
	UIDSource    uint32
	CPad2        uint32
	CgroupID     uint64
	SocketCookie uint64
	Addr         [16]byte
	LocalAddr    [16]byte
}

type Event struct {
	Timestamp        time.Time
	Kind             uint32
	PID              uint32
	Comm             string
	Domain           string
	Filename         string
	Transport        string
	Address          string
	Port             uint16
	LocalAddress     string
	LocalPort        uint16
	FileFlags        uint32
	FileMode         uint32
	KernelUID        uint32
	CgroupID         uint64
	SocketCookie     uint64
	Attribution      string
	Direction        string
	SocketHook       string
	SocketFamily     string
	SocketProtocol   string
	EventSource      string
	KernelFeatureSet string
	UIDSource        string
}

func decodeEvent(record []byte) (Event, error) {
	return decodeEventWithByteOrder(record, binary.NativeEndian)
}

func decodeEventWithByteOrder(record []byte, byteOrder binary.ByteOrder) (Event, error) {
	var raw rawEvent
	if err := binary.Read(bytes.NewReader(record), byteOrder, &raw); err != nil {
		return Event{}, fmt.Errorf("decode raw event: %w", err)
	}
	if raw.TimestampNS > math.MaxInt64 {
		return Event{}, fmt.Errorf("event timestamp %d exceeds int64 nanosecond range", raw.TimestampNS)
	}
	timestamp, err := eventTimestamp(raw.TimestampNS)
	if err != nil {
		return Event{}, err
	}

	return Event{
		Timestamp:        timestamp,
		Kind:             raw.Kind,
		PID:              raw.PID,
		Comm:             zeroTerminated(raw.Comm[:]),
		Domain:           decodeQName(raw.Domain[:]),
		Filename:         zeroTerminated(raw.Filename[:]),
		Transport:        transportName(raw.Transport),
		Address:          decodeAddress(raw.Family, raw.Addr),
		Port:             raw.Port,
		LocalAddress:     decodeAddress(raw.Family, raw.LocalAddr),
		LocalPort:        raw.LocalPort,
		FileFlags:        raw.FileFlags,
		FileMode:         raw.FileMode,
		KernelUID:        raw.KernelUID,
		CgroupID:         raw.CgroupID,
		SocketCookie:     raw.SocketCookie,
		Attribution:      attributionName(raw.Attribution),
		Direction:        directionName(raw.Direction),
		SocketHook:       socketHookName(raw.SocketHook),
		SocketFamily:     socketFamilyName(raw.Family),
		SocketProtocol:   socketProtocolName(raw.SocketProto),
		EventSource:      eventSourceName(raw.EventSource),
		KernelFeatureSet: kernelFeatureSetName(raw.FeatureSet),
		UIDSource:        uidSourceName(raw.UIDSource),
	}, nil
}

func eventTimestamp(timestampNS uint64) (time.Time, error) {
	offsetNS, err := eventTimestampOffsets.offset()
	if err != nil {
		return time.Time{}, err
	}
	return eventTimestampWithOffset(timestampNS, offsetNS)
}

func (c *timestampOffsetCache) offset() (int64, error) {
	checkedAt := c.now().UTC()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.initialized && !checkedAt.Before(c.refreshedAt) && checkedAt.Sub(c.refreshedAt) < timestampOffsetTTL {
		return c.offsetNS, nil
	}

	bootNowNS, err := c.bootNowNS()
	if err != nil {
		return 0, err
	}
	refreshedAt := c.now().UTC()
	offsetNS, err := timestampOffsetAt(refreshedAt, bootNowNS)
	if err != nil {
		return 0, err
	}
	c.offsetNS = offsetNS
	c.refreshedAt = refreshedAt
	c.initialized = true
	return offsetNS, nil
}

func readBootTimeNS() (int64, error) {
	var boot unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &boot); err != nil {
		return 0, fmt.Errorf("read CLOCK_BOOTTIME: %w", err)
	}
	return unix.TimespecToNsec(boot), nil
}

func eventTimestampAt(timestampNS uint64, wallNow time.Time, bootNowNS int64) (time.Time, error) {
	if timestampNS > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("event timestamp %d exceeds int64 nanosecond range", timestampNS)
	}
	offsetNS, err := timestampOffsetAt(wallNow, bootNowNS)
	if err != nil {
		return time.Time{}, err
	}
	return eventTimestampWithOffset(timestampNS, offsetNS)
}

func timestampOffsetAt(wallNow time.Time, bootNowNS int64) (int64, error) {
	if bootNowNS < 0 {
		return 0, fmt.Errorf("CLOCK_BOOTTIME returned negative value %d", bootNowNS)
	}
	wallNowNS := wallNow.UnixNano()
	if wallNowNS < bootNowNS {
		return 0, fmt.Errorf("invalid wall-clock-to-BOOTTIME offset: wall clock %d precedes boot time %d", wallNowNS, bootNowNS)
	}
	return wallNowNS - bootNowNS, nil
}

func eventTimestampWithOffset(timestampNS uint64, offsetNS int64) (time.Time, error) {
	if timestampNS > math.MaxInt64 {
		return time.Time{}, fmt.Errorf("event timestamp %d exceeds int64 nanosecond range", timestampNS)
	}
	if offsetNS < 0 {
		return time.Time{}, fmt.Errorf("invalid wall-clock-to-BOOTTIME offset %d", offsetNS)
	}
	if int64(timestampNS) > math.MaxInt64-offsetNS {
		return time.Time{}, fmt.Errorf("event timestamp %d with offset %d exceeds int64 nanosecond range", timestampNS, offsetNS)
	}
	return time.Unix(0, int64(timestampNS)+offsetNS).UTC(), nil
}

func zeroTerminated(data []byte) string {
	idx := bytes.IndexByte(data, 0)
	if idx == -1 {
		idx = len(data)
	}
	return string(data[:idx])
}

func transportName(proto uint8) string {
	switch proto {
	case 1:
		return "udp"
	case 2:
		return "tcp"
	case 3:
		return "dot"
	case 4:
		return "doh"
	default:
		return "unknown"
	}
}

func decodeQName(raw []byte) string {
	if len(raw) == 0 || raw[0] == 0 {
		return ""
	}

	parts := make([]string, 0, 8)
	for offset := 0; offset < len(raw); {
		labelLen := int(raw[offset])
		offset++

		if labelLen == 0 {
			break
		}
		if labelLen > 63 || offset+labelLen > len(raw) {
			return ""
		}

		parts = append(parts, string(raw[offset:offset+labelLen]))
		offset += labelLen
	}

	return strings.Join(parts, ".")
}

func decodeAddress(family uint8, raw [16]byte) string {
	switch family {
	case 4:
		if bytes.Equal(raw[:4], make([]byte, 4)) {
			return ""
		}
		return net.IP(raw[:4]).String()
	case 6:
		if bytes.Equal(raw[:], make([]byte, 16)) {
			return ""
		}
		return net.IP(raw[:]).String()
	default:
		return ""
	}
}

func socketFamilyName(family uint8) string {
	switch family {
	case 4:
		return "ipv4"
	case 6:
		return "ipv6"
	default:
		return ""
	}
}

func socketProtocolName(proto uint8) string {
	switch proto {
	case 1:
		return "udp"
	case 2:
		return "tcp"
	default:
		return ""
	}
}

func attributionName(code uint8) string {
	switch code {
	case 1:
		return "kernel-skb"
	case 2:
		return "kernel-sendmsg"
	case 3:
		return "kernel-connect"
	case 4:
		return "kernel-recvmsg"
	case 5:
		return "kernel-ingress"
	default:
		return ""
	}
}

func directionName(code uint8) string {
	switch code {
	case 1:
		return "inbound"
	case 2:
		return "outbound"
	default:
		return ""
	}
}

func socketHookName(code uint8) string {
	switch code {
	case 1:
		return "cgroup_skb"
	case 2:
		return "cgroup_sendmsg4"
	case 3:
		return "cgroup_sendmsg6"
	case 4:
		return "cgroup_connect4"
	case 5:
		return "cgroup_connect6"
	case 6:
		return "cgroup_skb_ingress"
	case 7:
		return "cgroup_recvmsg4"
	case 8:
		return "cgroup_recvmsg6"
	case 9:
		return "cgroup_post_bind4"
	case 10:
		return "cgroup_post_bind6"
	default:
		return ""
	}
}

func eventSourceName(code uint32) string {
	switch code {
	case 1:
		return "syscall-tracepoint"
	case 2:
		return "cgroup-skb"
	case 3:
		return "cgroup-sock-addr"
	case 4:
		return "cgroup-sock"
	default:
		return ""
	}
}

func kernelFeatureSetName(code uint32) string {
	switch code {
	case 1:
		return "legacy"
	case 2:
		return "linux71"
	default:
		return ""
	}
}

func uidSourceName(code uint32) string {
	switch code {
	case 1:
		return "kernel"
	default:
		return ""
	}
}
