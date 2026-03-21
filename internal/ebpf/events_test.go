package ebpf

import "testing"

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
