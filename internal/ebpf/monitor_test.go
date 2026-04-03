package ebpf

import (
	"errors"
	"testing"
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
