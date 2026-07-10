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
		{release: "7.1.1-arch1-1", major: 7, minor: 1, ok: true},
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

func TestPolicySlotValuePreservesActiveSlot(t *testing.T) {
	t.Parallel()

	if got, remove := policySlotValue(0b01, true, 1); got != 0b11 || remove {
		t.Fatalf("add inactive slot = %02b, remove=%v; want 11,false", got, remove)
	}
	if got, remove := policySlotValue(0b11, false, 1); got != 0b01 || remove {
		t.Fatalf("clear inactive slot = %02b, remove=%v; want 01,false", got, remove)
	}
	if got, remove := policySlotValue(0b10, false, 1); got != 0 || !remove {
		t.Fatalf("clear only slot = %02b, remove=%v; want 00,true", got, remove)
	}
}

func TestRuntimeSettingsKeepsKernelABISize(t *testing.T) {
	t.Parallel()

	if got := binary.Size(runtimeSettings{}); got != 8 {
		t.Fatalf("runtimeSettings size = %d, want 8", got)
	}
}

func TestIsKernelAtLeast(t *testing.T) {
	t.Parallel()

	tests := []struct {
		release string
		want    bool
	}{
		{release: "7.1.0", want: true},
		{release: "7.1.1-custom", want: true},
		{release: "7.2.0", want: true},
		{release: "8.0.0", want: true},
		{release: "7.0.13", want: false},
		{release: "6.18.36", want: false},
		{release: "garbage", want: false},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.release, func(t *testing.T) {
			t.Parallel()

			if got := isKernelAtLeast(tc.release, 7, 1); got != tc.want {
				t.Fatalf("isKernelAtLeast(%q, 7, 1) = %v, want %v", tc.release, got, tc.want)
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

func TestValidateKernelReleaseEnforces612Floor(t *testing.T) {
	t.Parallel()

	if err := validateKernelRelease("6.12.0"); err != nil {
		t.Fatalf("validateKernelRelease rejected 6.12: %v", err)
	}
	if err := validateKernelRelease("6.11.9"); !errors.Is(err, ErrUnsupportedKernel) {
		t.Fatalf("validateKernelRelease error = %v, want ErrUnsupportedKernel", err)
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

func TestLoadLinux71MonitorObjectsWithSelectsCompatVariants(t *testing.T) {
	t.Parallel()

	dnsErr := errors.New("field TraceDns: program trace_dns: load program: invalid argument: program of this type cannot use helper bpf_get_current_comm#16")
	recvmsgErr := errors.New("field TraceRecvmsg4: program trace_recvmsg4: load program: permission denied: invalid bpf_context access off=40 size=4")
	dnsRecvmsgErr := errors.New("field TraceDns: program trace_dns: load program: invalid argument: program of this type cannot use helper bpf_get_current_comm#16; field TraceRecvmsg4: program trace_recvmsg4: load program: permission denied: invalid bpf_context access off=40 size=4")

	tests := []struct {
		name       string
		loaders    monitorVariantLoaders
		wantObject string
	}{
		{
			name:       "default",
			loaders:    fakeLinux71Loaders(nil, errors.New("unused"), errors.New("unused"), errors.New("unused")),
			wantObject: "traceguardLinux71",
		},
		{
			name:       "dns compat",
			loaders:    fakeLinux71Loaders(dnsErr, nil, errors.New("unused"), errors.New("unused")),
			wantObject: "traceguardLinux71DNSCompat",
		},
		{
			name:       "recvmsg compat",
			loaders:    fakeLinux71Loaders(recvmsgErr, errors.New("unused"), nil, errors.New("unused")),
			wantObject: "traceguardLinux71RecvmsgCompat",
		},
		{
			name:       "combined compat",
			loaders:    fakeLinux71Loaders(dnsErr, recvmsgErr, errors.New("unused"), nil),
			wantObject: "traceguardLinux71DNSRecvmsgCompat",
		},
		{
			name:       "recvmsg then dns compat",
			loaders:    fakeLinux71Loaders(recvmsgErr, errors.New("unused"), dnsErr, nil),
			wantObject: "traceguardLinux71DNSRecvmsgCompat",
		},
		{
			name:       "combined direct default error",
			loaders:    fakeLinux71Loaders(dnsRecvmsgErr, errors.New("unused"), errors.New("unused"), nil),
			wantObject: "traceguardLinux71DNSRecvmsgCompat",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, features, err := loadLinux71MonitorObjectsWith(nil, KernelFeatures{KernelAtLeast71: true}, tc.loaders)
			if err != nil {
				t.Fatalf("loadLinux71MonitorObjectsWith returned error: %v", err)
			}
			if !features.EnhancedTelemetry {
				t.Fatal("EnhancedTelemetry = false, want true")
			}
			if features.SelectedFeatureSet != kernelFeatureSetLinux71 {
				t.Fatalf("SelectedFeatureSet = %q, want %q", features.SelectedFeatureSet, kernelFeatureSetLinux71)
			}
			if features.SelectedObject != tc.wantObject {
				t.Fatalf("SelectedObject = %q, want %q", features.SelectedObject, tc.wantObject)
			}
		})
	}
}

func fakeLinux71Loaders(defaultErr, dnsErr, recvmsgErr, dnsRecvmsgErr error) monitorVariantLoaders {
	return monitorVariantLoaders{
		defaultVariant:   fakeVariantLoader(defaultErr),
		dnsCompat:        fakeVariantLoader(dnsErr),
		recvmsgCompat:    fakeVariantLoader(recvmsgErr),
		dnsRecvmsgCompat: fakeVariantLoader(dnsRecvmsgErr),
	}
}

func fakeVariantLoader(err error) func(*ebpf.CollectionOptions) (monitorObjects, error) {
	return func(*ebpf.CollectionOptions) (monitorObjects, error) {
		return monitorObjects{}, err
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
		{name: "linux71", loadSpec: loadTraceguardLinux71},
		{name: "linux71-dns-compat", loadSpec: loadTraceguardLinux71DNSCompat},
		{name: "linux71-recvmsg-compat", loadSpec: loadTraceguardLinux71RecvmsgCompat},
		{name: "linux71-dns-recvmsg-compat", loadSpec: loadTraceguardLinux71DNSRecvmsgCompat},
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
