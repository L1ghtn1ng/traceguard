package ebpf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEncodeAndDecodeDomainKey(t *testing.T) {
	t.Parallel()

	key, err := encodeDomainKey("Api.Example.COM")
	if err != nil {
		t.Fatalf("encodeDomainKey returned error: %v", err)
	}

	got := decodeQName(key.Domain[:])
	want := "api.example.com"
	if got != want {
		t.Fatalf("decodeQName returned %q, want %q", got, want)
	}
}

func TestEncodeDomainKeyRejectsInvalidDomains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		domain string
	}{
		{name: "empty", domain: ""},
		{name: "empty label", domain: "example..com"},
		{name: "label too long", domain: string(bytes.Repeat([]byte("a"), 64)) + ".com"},
		{name: "domain too long", domain: string(bytes.Repeat([]byte("a."), 128)) + "com"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := encodeDomainKey(tt.domain); err == nil {
				t.Fatalf("encodeDomainKey(%q) returned nil error", tt.domain)
			}
		})
	}
}

func TestEncodeDomainSuffixKey(t *testing.T) {
	t.Parallel()

	key, err := encodeDomainSuffixKey("Example.COM")
	if err != nil {
		t.Fatalf("encodeDomainSuffixKey returned error: %v", err)
	}
	exact, err := encodeDomainKey("example.com")
	if err != nil {
		t.Fatalf("encodeDomainKey returned error: %v", err)
	}

	var hash uint64 = 14695981039346656037
	var length uint16
	for _, value := range exact.Domain {
		hash ^= uint64(value)
		hash *= 1099511628211
		length++
		if value == 0 {
			break
		}
	}
	if key.Hash != hash || key.Length != length {
		t.Fatalf("suffix key = {hash:%d length:%d}, want {hash:%d length:%d}", key.Hash, key.Length, hash, length)
	}
}

func TestDecodeQNameRejectsMalformedWireNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "root", raw: []byte{0}},
		{name: "label too long", raw: append([]byte{64}, bytes.Repeat([]byte("a"), 64)...)},
		{name: "truncated label", raw: []byte{7, 'e', 'x'}},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := decodeQName(tt.raw); got != "" {
				t.Fatalf("decodeQName(%v) = %q, want empty", tt.raw, got)
			}
		})
	}
}

func TestDecodeAddressAndEnumNamesHandleUnknownValues(t *testing.T) {
	t.Parallel()

	if got := decodeAddress(9, [16]byte{1, 2, 3, 4}); got != "" {
		t.Fatalf("decodeAddress unknown family = %q, want empty", got)
	}
	if got := decodeAddress(4, [16]byte{}); got != "" {
		t.Fatalf("decodeAddress zero IPv4 = %q, want empty", got)
	}
	if got := decodeAddress(6, [16]byte{}); got != "" {
		t.Fatalf("decodeAddress zero IPv6 = %q, want empty", got)
	}
	if got := transportName(99); got != "unknown" {
		t.Fatalf("transportName unknown = %q, want unknown", got)
	}
	if got := attributionName(99); got != "" {
		t.Fatalf("attributionName unknown = %q, want empty", got)
	}
	if got := directionName(99); got != "" {
		t.Fatalf("directionName unknown = %q, want empty", got)
	}
	if got := socketHookName(99); got != "" {
		t.Fatalf("socketHookName unknown = %q, want empty", got)
	}
}

func TestDecodeEventSocketMetadata(t *testing.T) {
	t.Parallel()

	var raw rawEvent
	raw.Kind = EventDNS
	raw.PID = 42
	raw.Transport = 1
	raw.Family = 4
	raw.SocketProto = 1
	raw.Attribution = 2
	raw.SocketHook = 2
	raw.Port = 53
	copy(raw.Comm[:], "curl")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write returned error: %v", err)
	}

	event, err := decodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decodeEvent returned error: %v", err)
	}
	if event.Attribution != "kernel-sendmsg" {
		t.Fatalf("Attribution = %q, want kernel-sendmsg", event.Attribution)
	}
	if event.SocketHook != "cgroup_sendmsg4" {
		t.Fatalf("SocketHook = %q, want cgroup_sendmsg4", event.SocketHook)
	}
	if event.SocketFamily != "ipv4" {
		t.Fatalf("SocketFamily = %q, want ipv4", event.SocketFamily)
	}
	if event.SocketProtocol != "udp" {
		t.Fatalf("SocketProtocol = %q, want udp", event.SocketProtocol)
	}
}

func TestDecodeConnectionEvent(t *testing.T) {
	t.Parallel()

	var raw rawEvent
	raw.Kind = EventConnection
	raw.PID = 99
	raw.Transport = 2
	raw.Family = 4
	raw.SocketProto = 2
	raw.Attribution = 5
	raw.SocketHook = 6
	raw.Direction = 1
	raw.Port = 443
	raw.LocalPort = 8443
	raw.Addr = [16]byte{203, 0, 113, 5}
	raw.LocalAddr = [16]byte{10, 0, 0, 10}
	copy(raw.Comm[:], "nginx")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, raw); err != nil {
		t.Fatalf("binary.Write returned error: %v", err)
	}

	event, err := decodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decodeEvent returned error: %v", err)
	}
	if event.Direction != "inbound" {
		t.Fatalf("Direction = %q, want inbound", event.Direction)
	}
	if event.Address != "203.0.113.5" {
		t.Fatalf("Address = %q, want 203.0.113.5", event.Address)
	}
	if event.LocalAddress != "10.0.0.10" {
		t.Fatalf("LocalAddress = %q, want 10.0.0.10", event.LocalAddress)
	}
	if event.LocalPort != 8443 {
		t.Fatalf("LocalPort = %d, want 8443", event.LocalPort)
	}
	if event.Attribution != "kernel-ingress" {
		t.Fatalf("Attribution = %q, want kernel-ingress", event.Attribution)
	}
	if event.SocketHook != "cgroup_skb_ingress" {
		t.Fatalf("SocketHook = %q, want cgroup_skb_ingress", event.SocketHook)
	}
}

func TestDecodeFileAccessEvent(t *testing.T) {
	t.Parallel()

	record := make([]byte, binary.Size(rawEvent{}))
	writeLE := func(offset int, value any) {
		t.Helper()
		buf := bytes.NewBuffer(record[offset:offset])
		if err := binary.Write(buf, binary.LittleEndian, value); err != nil {
			t.Fatalf("binary.Write returned error: %v", err)
		}
	}

	writeLE(8, uint32(EventFileAccess))
	writeLE(12, uint32(123))
	copy(record[16:32], "cat")
	copy(record[288:544], "/etc/passwd")
	writeLE(556, uint16(0x40))
	writeLE(560, uint32(0o600))

	event, err := decodeEvent(record)
	if err != nil {
		t.Fatalf("decodeEvent returned error: %v", err)
	}
	if event.Kind != EventFileAccess {
		t.Fatalf("Kind = %d, want %d", event.Kind, EventFileAccess)
	}
	if event.Filename != "/etc/passwd" {
		t.Fatalf("Filename = %q, want /etc/passwd", event.Filename)
	}
	if event.FileFlags != 0x40 {
		t.Fatalf("FileFlags = %#x, want 0x40", event.FileFlags)
	}
	if event.FileMode != 0o600 {
		t.Fatalf("FileMode = %#o, want 0600", event.FileMode)
	}
}

func TestRawEventSizeMatchesBPFEvent(t *testing.T) {
	t.Parallel()

	if got, want := binary.Size(rawEvent{}), 600; got != want {
		t.Fatalf("rawEvent size = %d, want BPF struct event size %d", got, want)
	}
}
