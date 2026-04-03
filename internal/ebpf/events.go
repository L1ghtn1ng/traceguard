package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
)

type rawEvent struct {
	TimestampNS uint64
	Kind        uint32
	PID         uint32
	Comm        [commSize]byte
	Domain      [domainSize]byte
	Filename    [filenameSize]byte
	Transport   uint8
	Family      uint8
	SocketProto uint8
	Attribution uint8
	SocketHook  uint8
	_           uint8
	Port        uint16
	Addr        [16]byte
}

type Event struct {
	Timestamp      time.Time
	Kind           uint32
	PID            uint32
	Comm           string
	Domain         string
	Filename       string
	Transport      string
	Address        string
	Port           uint16
	Attribution    string
	SocketHook     string
	SocketFamily   string
	SocketProtocol string
}

func decodeEvent(record []byte) (Event, error) {
	var raw rawEvent
	if err := binary.Read(bytes.NewReader(record), binary.LittleEndian, &raw); err != nil {
		return Event{}, fmt.Errorf("decode raw event: %w", err)
	}

	return Event{
		Timestamp:      time.Unix(0, int64(raw.TimestampNS)).UTC(),
		Kind:           raw.Kind,
		PID:            raw.PID,
		Comm:           zeroTerminated(raw.Comm[:]),
		Domain:         decodeQName(raw.Domain[:]),
		Filename:       zeroTerminated(raw.Filename[:]),
		Transport:      transportName(raw.Transport),
		Address:        decodeAddress(raw.Family, raw.Addr),
		Port:           raw.Port,
		Attribution:    attributionName(raw.Attribution),
		SocketHook:     socketHookName(raw.SocketHook),
		SocketFamily:   socketFamilyName(raw.Family),
		SocketProtocol: socketProtocolName(raw.SocketProto),
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
		return net.IP(raw[:4]).String()
	case 6:
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
	default:
		return ""
	}
}
