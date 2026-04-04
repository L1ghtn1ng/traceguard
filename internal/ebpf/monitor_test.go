package ebpf

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
)

func TestParseKernelRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		release string
		major   int
		minor   int
		ok      bool
	}{
		{release: "6.12.80", major: 6, minor: 12, ok: true},
		{release: "6.12.0-custom", major: 6, minor: 12, ok: true},
		{release: "6.18.21", major: 6, minor: 18, ok: true},
		{release: "7.0.0-rc6", major: 7, minor: 0, ok: true},
		{release: "garbage", ok: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.release, func(t *testing.T) {
			t.Parallel()

			major, minor, ok := parseKernelRelease(tc.release)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && (major != tc.major || minor != tc.minor) {
				t.Fatalf("version = %d.%d, want %d.%d", major, minor, tc.major, tc.minor)
			}
		})
	}
}

func TestIsLinux612x(t *testing.T) {
	t.Parallel()

	if !isLinux612x("6.12.80") {
		t.Fatal("isLinux612x rejected 6.12.x")
	}
	if isLinux612x("6.18.21") {
		t.Fatal("isLinux612x accepted non-6.12 kernel")
	}
}

func TestIsDNSHelperVerifierError(t *testing.T) {
	t.Parallel()

	err := errors.New("field TraceDns: program trace_dns: load program: invalid argument: program of this type cannot use helper bpf_get_current_comm#16")
	if !isDNSHelperVerifierError(err) {
		t.Fatal("isDNSHelperVerifierError rejected helper-verifier failure")
	}
	if isDNSHelperVerifierError(errors.New("some other verifier error")) {
		t.Fatal("isDNSHelperVerifierError matched unrelated error")
	}
}

func TestIsRecvmsgContextVerifierError(t *testing.T) {
	t.Parallel()

	err := errors.New("field TraceRecvmsg4: program trace_recvmsg4: load program: permission denied: invalid bpf_context access off=40 size=4")
	if !isRecvmsgContextVerifierError(err) {
		t.Fatal("isRecvmsgContextVerifierError rejected recvmsg context failure")
	}
	if isRecvmsgContextVerifierError(errors.New("some other verifier error")) {
		t.Fatal("isRecvmsgContextVerifierError matched unrelated error")
	}
}

func TestCIDRKeyBinarySizes(t *testing.T) {
	t.Parallel()

	if got := binary.Size(endpoint4CIDRKey{}); got != 12 {
		t.Fatalf("endpoint4CIDRKey binary size = %d, want 12", got)
	}
	if got := binary.Size(endpoint6CIDRKey{}); got != 24 {
		t.Fatalf("endpoint6CIDRKey binary size = %d, want 24", got)
	}
}

func TestCIDRKeySizesMatchCollectionSpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		loadSpec func() (*ebpf.CollectionSpec, error)
	}{
		{name: "default", loadSpec: loadTraceguard},
		{name: "dns-compat", loadSpec: loadTraceguardDNSCompat},
		{name: "recvmsg-compat", loadSpec: loadTraceguardRecvmsgCompat},
		{name: "dns-recvmsg-compat", loadSpec: loadTraceguardDNSRecvmsgCompat},
	}

	const (
		endpoint4CIDRKeySize = uint32(12)
		endpoint6CIDRKeySize = uint32(24)
	)

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spec, err := tc.loadSpec()
			if err != nil {
				t.Fatalf("load spec: %v", err)
			}

			assertMapKeySize(t, spec, "endpoint4_cidr_rules", endpoint4CIDRKeySize)
			assertMapKeySize(t, spec, "endpoint4_cidr_allow_rules", endpoint4CIDRKeySize)
			assertMapKeySize(t, spec, "endpoint6_cidr_rules", endpoint6CIDRKeySize)
			assertMapKeySize(t, spec, "endpoint6_cidr_allow_rules", endpoint6CIDRKeySize)
		})
	}
}

func assertMapKeySize(t *testing.T, spec *ebpf.CollectionSpec, mapName string, want uint32) {
	t.Helper()

	mapSpec, ok := spec.Maps[mapName]
	if !ok {
		t.Fatalf("map %q not found in collection spec", mapName)
	}
	if mapSpec.KeySize != want {
		t.Fatalf("%s key size = %d, want %d", mapName, mapSpec.KeySize, want)
	}
}
