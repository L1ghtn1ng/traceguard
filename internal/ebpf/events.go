package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"strings"
	"time"
)

const (
	commSize     = 16
	domainSize   = 256
	filenameSize = 256
)

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
	var raw rawEvent
	if err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("decode raw event: %w", err)
	}
	if raw.TimestampNS > math.MaxInt64 {
		return Event{}, fmt.Errorf("event timestamp %d exceeds int64 nanosecond range", raw.TimestampNS)
	}

	return Event{
		Timestamp:        time.Unix(0, int64(raw.TimestampNS)).UTC(),
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

func zeroTerminated(data []byte) string {
	idx := bytes.IndexByte(data, 0)
	if idx == -1 {
		idx = len(data)
	}
	return strings.TrimSpace(string(data[:idx]))
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
