package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestEventTimestampAtConvertsBootClockToWallTime(t *testing.T) {
	t.Parallel()

	wallNow := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	got, err := eventTimestampAt(uint64((2*time.Hour - time.Second).Nanoseconds()), wallNow, (2 * time.Hour).Nanoseconds())
	if err != nil {
		t.Fatalf("eventTimestampAt returned error: %v", err)
	}
	if want := wallNow.Add(-time.Second); !got.Equal(want) {
		t.Fatalf("timestamp = %s, want %s", got, want)
	}
}

func TestTimestampOffsetCacheReusesAndRefreshesOffset(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC)
	bootNowNS := (2 * time.Hour).Nanoseconds()
	clockReads := 0
	cache := timestampOffsetCache{
		now: func() time.Time { return now },
		bootNowNS: func() (int64, error) {
			clockReads++
			return bootNowNS, nil
		},
	}

	first, err := cache.offset()
	if err != nil {
		t.Fatalf("first offset returned error: %v", err)
	}
	now = now.Add(500 * time.Millisecond)
	bootNowNS = (24 * time.Hour).Nanoseconds()
	second, err := cache.offset()
	if err != nil {
		t.Fatalf("cached offset returned error: %v", err)
	}
	if second != first || clockReads != 1 {
		t.Fatalf("cached offset = %d with %d clock reads, want %d with 1 read", second, clockReads, first)
	}

	now = now.Add(500 * time.Millisecond)
	bootNowNS = (2*time.Hour + time.Second).Nanoseconds()
	refreshed, err := cache.offset()
	if err != nil {
		t.Fatalf("refreshed offset returned error: %v", err)
	}
	if refreshed != first || clockReads != 2 {
		t.Fatalf("refreshed offset = %d with %d clock reads, want %d with 2 reads", refreshed, clockReads, first)
	}
}

func TestTimestampOffsetCacheReturnsClockError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("clock unavailable")
	clockReads := 0
	cache := timestampOffsetCache{
		now: func() time.Time { return time.Date(2026, time.July, 10, 12, 0, 0, 0, time.UTC) },
		bootNowNS: func() (int64, error) {
			clockReads++
			if clockReads == 1 {
				return 0, wantErr
			}
			return (2 * time.Hour).Nanoseconds(), nil
		},
	}
	if _, err := cache.offset(); !errors.Is(err, wantErr) {
		t.Fatalf("offset error = %v, want %v", err, wantErr)
	}
	if _, err := cache.offset(); err != nil {
		t.Fatalf("offset did not retry after initialization error: %v", err)
	}
	if clockReads != 2 {
		t.Fatalf("clock reads = %d, want 2", clockReads)
	}
}

func TestEventTimestampRejectsInvalidOffsetAndRange(t *testing.T) {
	t.Parallel()

	if _, err := eventTimestampWithOffset(0, -1); err == nil {
		t.Fatal("eventTimestampWithOffset accepted a negative offset")
	}
	if _, err := eventTimestampWithOffset(math.MaxInt64, 1); err == nil {
		t.Fatal("eventTimestampWithOffset accepted an overflowing timestamp")
	}
	if _, err := eventTimestampAt(0, time.Unix(0, 0), 1); err == nil {
		t.Fatal("eventTimestampAt accepted wall time before CLOCK_BOOTTIME")
	}
}

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
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if _, err := encodeDomainKey(tt.domain); err == nil {
				t.Fatalf("encodeDomainKey(%q) returned nil error", tt.domain)
			}
		})
	}
}

func TestEncodeDomainKeyEnforcesDNSWireLength(t *testing.T) {
	t.Parallel()

	legal := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	if _, err := encodeDomainKey(legal); err != nil {
		t.Fatalf("encodeDomainKey rejected 255-byte wire name: %v", err)
	}
	illegal := legal + "e"
	if _, err := encodeDomainKey(illegal); err == nil {
		t.Fatal("encodeDomainKey accepted 256-byte wire name")
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

func TestValidateEnforcedSuffixKeyRejectsUnsupportedWireLength(t *testing.T) {
	t.Parallel()

	tooLong, err := encodeDomainSuffixKey(strings.Repeat("a", 63) + ".com")
	if err != nil {
		t.Fatalf("encodeDomainSuffixKey returned error: %v", err)
	}
	if err := validateEnforcedSuffixKey(tooLong); err == nil || !strings.Contains(err.Error(), "exceeds enforced suffix limit") {
		t.Fatalf("validateEnforcedSuffixKey error = %v, want enforced-limit error", err)
	}

	manyLabels, err := encodeDomainSuffixKey(strings.Repeat("a.", 19) + "a")
	if err != nil {
		t.Fatalf("encodeDomainSuffixKey returned error: %v", err)
	}
	if err := validateEnforcedSuffixKey(manyLabels); err != nil {
		t.Fatalf("validateEnforcedSuffixKey rejected a short wire name with many labels: %v", err)
	}
}

func TestEncodeEndpoint4KeyUsesNativeByteOrder(t *testing.T) {
	t.Parallel()

	ip := []byte{1, 2, 3, 4}
	key := encodeEndpoint4Key(ip, 853, 3)
	if got := binary.NativeEndian.AppendUint32(nil, key.Addr); !bytes.Equal(got, ip) {
		t.Fatalf("serialized endpoint address = %v, want %v", got, ip)
	}
	if key.Port != 853 || key.Transport != 3 {
		t.Fatalf("endpoint metadata = port:%d transport:%d", key.Port, key.Transport)
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
	if got := eventSourceName(99); got != "" {
		t.Fatalf("eventSourceName unknown = %q, want empty", got)
	}
	if got := kernelFeatureSetName(99); got != "" {
		t.Fatalf("kernelFeatureSetName unknown = %q, want empty", got)
	}
	if got := uidSourceName(99); got != "" {
		t.Fatalf("uidSourceName unknown = %q, want empty", got)
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
	if err := binary.Write(&buf, binary.NativeEndian, raw); err != nil {
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

func TestDecodeEventSupportsBigEndianRecords(t *testing.T) {
	t.Parallel()

	raw := rawEvent{
		TimestampNS:  123,
		Kind:         EventConnection,
		PID:          0x01020304,
		Port:         0x1234,
		LocalPort:    0x5678,
		CgroupID:     0x0102030405060708,
		SocketCookie: 0x1112131415161718,
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, raw); err != nil {
		t.Fatalf("binary.Write returned error: %v", err)
	}

	event, err := decodeEventWithByteOrder(buf.Bytes(), binary.BigEndian)
	if err != nil {
		t.Fatalf("decodeEventWithByteOrder returned error: %v", err)
	}
	if event.PID != raw.PID || event.Port != raw.Port || event.LocalPort != raw.LocalPort || event.CgroupID != raw.CgroupID || event.SocketCookie != raw.SocketCookie {
		t.Fatalf("decoded multi-byte fields = %#v, want pid=%#x port=%#x local_port=%#x cgroup=%#x cookie=%#x", event, raw.PID, raw.Port, raw.LocalPort, raw.CgroupID, raw.SocketCookie)
	}
}

func TestZeroTerminatedPreservesWhitespace(t *testing.T) {
	t.Parallel()

	if got, want := zeroTerminated([]byte(" report \x00ignored")), " report "; got != want {
		t.Fatalf("zeroTerminated = %q, want %q", got, want)
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
	if err := binary.Write(&buf, binary.NativeEndian, raw); err != nil {
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

	var raw rawEvent
	raw.Kind = EventFileAccess
	raw.PID = 123
	raw.FileFlags = 0x40
	raw.FileMode = 0o600
	copy(raw.Comm[:], "cat")
	copy(raw.Filename[:], "/etc/passwd")

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, raw); err != nil {
		t.Fatalf("binary.Write returned error: %v", err)
	}

	event, err := decodeEvent(buf.Bytes())
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

func TestDecodeKernelFeatureMetadata(t *testing.T) {
	t.Parallel()

	var raw rawEvent
	raw.Kind = EventDNS
	raw.FeatureSet = 2
	raw.EventSource = 2
	raw.UIDSource = 1
	raw.KernelUID = 1000
	raw.CgroupID = 12345
	raw.SocketCookie = 67890

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, raw); err != nil {
		t.Fatalf("binary.Write returned error: %v", err)
	}

	event, err := decodeEvent(buf.Bytes())
	if err != nil {
		t.Fatalf("decodeEvent returned error: %v", err)
	}
	if event.KernelFeatureSet != "linux71" {
		t.Fatalf("KernelFeatureSet = %q, want linux71", event.KernelFeatureSet)
	}
	if event.EventSource != "cgroup-skb" {
		t.Fatalf("EventSource = %q, want cgroup-skb", event.EventSource)
	}
	if event.UIDSource != "kernel" {
		t.Fatalf("UIDSource = %q, want kernel", event.UIDSource)
	}
	if event.KernelUID != 1000 || event.CgroupID != 12345 || event.SocketCookie != 67890 {
		t.Fatalf("kernel metadata = uid:%d cgroup:%d cookie:%d", event.KernelUID, event.CgroupID, event.SocketCookie)
	}
}

func TestRawEventSizeMatchesBPFEvent(t *testing.T) {
	t.Parallel()

	if got, want := binary.Size(rawEvent{}), 632; got != want {
		t.Fatalf("rawEvent size = %d, want BPF struct event size %d", got, want)
	}
}
