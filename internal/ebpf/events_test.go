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
