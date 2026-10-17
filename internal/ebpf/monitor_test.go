package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type testCloser struct {
	id       int
	closed   *[]int
	closeErr error
}

func (c *testCloser) Close() error {
	*c.closed = append(*c.closed, c.id)
	return c.closeErr
}

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

	if got := binary.Size(runtimeSettings{}); got != pinSettingsSize {
		t.Fatalf("runtimeSettings size = %d, want %d", got, pinSettingsSize)
	}
	if got := binary.Size(domainSuffixKey{}); got != 16 {
		t.Fatalf("domainSuffixKey size = %d, want 16", got)
	}
	if got := binary.Size(egress4Key{}); got != 28 {
		t.Fatalf("egress4Key size = %d, want 28", got)
	}
	if got := binary.Size(egress6Key{}); got != 40 {
		t.Fatalf("egress6Key size = %d, want 40", got)
	}
	if got := binary.Size(pathLPMKey{}); got != 260 {
		t.Fatalf("pathLPMKey size = %d, want 260", got)
	}
	if got := binary.Size(sockoptKey{}); got != 24 {
		t.Fatalf("sockoptKey size = %d, want 24", got)
	}
	if got := binary.Size(ruleNameKey{}); got != 8 {
		t.Fatalf("ruleNameKey size = %d, want 8", got)
	}
	if got := binary.Size(ruleNameValue{}); got != maxPolicyRuleIDBytes+1 {
		t.Fatalf("ruleNameValue size = %d, want %d", got, maxPolicyRuleIDBytes+1)
	}
	if got := binary.Size(pinMetadata{}); got != pinMetadataSize {
		t.Fatalf("pinMetadata size = %d, want %d", got, pinMetadataSize)
	}
}

func TestBPFVerdictHelpersKeepExpectedPolarity(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("bpf/traceguard.c")
	if err != nil {
		t.Fatalf("read eBPF source: %v", err)
	}
	normalized := strings.Join(strings.Fields(string(source)), " ")
	for name, contract := range map[string]string{
		"LSM MAC":          "static __always_inline int lsm_mac_verdict(__u8 deny) { return deny ? -TRACEGUARD_EPERM : 0; }",
		"cgroup sock_addr": "static __always_inline int cgroup_verdict(__u8 deny) { return deny ? 0 : 1; }",
	} {
		if !strings.Contains(normalized, contract) {
			t.Errorf("%s verdict helper no longer has the required polarity", name)
		}
	}
}

func TestBPFProcessIdentityUsesThreadGroupLeaderStartTime(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("bpf/traceguard.c")
	if err != nil {
		t.Fatalf("read eBPF source: %v", err)
	}
	normalized := strings.Join(strings.Fields(string(source)), " ")
	for _, contract := range []string{
		"__builtin_preserve_access_index(&task->group_leader)",
		"__builtin_preserve_access_index(&group_leader->start_boottime)",
	} {
		if !strings.Contains(normalized, contract) {
			t.Errorf("process identity no longer reads the thread-group leader: missing %q", contract)
		}
	}
	if strings.Contains(normalized, "__builtin_preserve_access_index(&task->start_boottime)") {
		t.Error("process identity reads the current thread start time instead of its thread-group leader")
	}
}

func TestBPFEventIdentityMarksPathTruncationAndCapturesCurrentSocketIdentity(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("bpf/traceguard.c")
	if err != nil {
		t.Fatalf("read eBPF source: %v", err)
	}
	normalized := strings.Join(strings.Fields(string(source)), " ")
	for _, contract := range []string{
		"event->file_mode |= PATH_EVENT_FLAG_TRUNCATED",
		"#define UID_SOURCE_SOCKET_CACHE 2",
		"event->kernel_uid = (__u32)bpf_get_current_uid_gid()",
		"event->uid_source = UID_SOURCE_KERNEL",
		"event->uid_source = UID_SOURCE_SOCKET_CACHE",
		"event->cgroup_id = bpf_get_current_cgroup_id()",
		"init_event_base(event, EVENT_SOCKOPS, TRANSPORT_TCP, EVENT_SOURCE_SOCKOPS)",
	} {
		if !strings.Contains(normalized, contract) {
			t.Errorf("eBPF event identity contract is missing %q", contract)
		}
	}
}

func TestBPFCgroupAncestorBoundMatchesUserspaceValidation(t *testing.T) {
	t.Parallel()

	source, err := os.ReadFile("bpf/traceguard.c")
	if err != nil {
		t.Fatalf("read eBPF source: %v", err)
	}
	contract := fmt.Sprintf("#define MAX_CGROUP_ANCESTORS %d", cgroupinfo.MaxAncestorLookupLevels)
	if !strings.Contains(string(source), contract) {
		t.Fatalf("eBPF source is missing userspace ancestor bound %q", contract)
	}
}

func TestPolicySelectorRoundTripAndValidation(t *testing.T) {
	t.Parallel()

	selector := encodePolicySelector(1, 42)
	slot, generation, ok := decodePolicySelector(selector)
	if !ok || slot != 1 || generation != 42 {
		t.Fatalf("decoded selector = %d/%d/%t, want 1/42/true", slot, generation, ok)
	}
	if _, _, ok := decodePolicySelector(encodePolicySelector(2, 42)); ok {
		t.Fatal("selector accepted invalid policy slot 2")
	}
}

func TestEncodeRuleNamesPreservesCompleteBoundedIdentifiers(t *testing.T) {
	t.Parallel()

	longest := strings.Repeat("a", maxPolicyRuleIDBytes)
	encoded, err := encodeRuleNames(map[uint32]string{17: longest})
	if err != nil {
		t.Fatal(err)
	}
	value := encoded[17]
	if got := zeroTerminated(value.Name[:]); got != longest {
		t.Fatalf("encoded rule name = %q, want %q", got, longest)
	}
	for _, test := range []struct {
		name  string
		rules map[uint32]string
	}{
		{name: "reserved number", rules: map[uint32]string{0: "rule"}},
		{name: "empty name", rules: map[uint32]string{1: ""}},
		{name: "embedded NUL", rules: map[uint32]string{1: "rule\x00hidden"}},
		{name: "oversized name", rules: map[uint32]string{1: longest + "b"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := encodeRuleNames(test.rules); err == nil {
				t.Fatal("encodeRuleNames accepted invalid input")
			}
		})
	}
}

func TestDaemonIdentityPreservesExactProcessCoordinates(t *testing.T) {
	t.Parallel()

	identity := daemonProcessIdentity{TGID: 42, StartTicks: 1000}
	if identity.TGID != 42 || identity.StartTicks != 1000 {
		t.Fatalf("daemon identity = %#v, want exact TGID and start ticks", identity)
	}
}

func TestReadProcessStartTimeHandlesParenthesesInComm(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "stat")
	payload := "42 (daemon ) worker) S " + strings.Repeat("0 ", 18) + "12345 0\n"
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	start, err := readProcessStartTime(path)
	if err != nil {
		t.Fatal(err)
	}
	if start != 12345 {
		t.Fatalf("start time = %d, want 12345", start)
	}
}

func TestPolicyLimitsMatchKernelMapCapacities(t *testing.T) {
	t.Parallel()

	spec, err := loadTraceguard()
	if err != nil {
		t.Fatalf("loadTraceguard returned error: %v", err)
	}
	if got, want := spec.Maps["blocklist"].MaxEntries, uint32(2*blocklistMaxEntries); got != want {
		t.Fatalf("blocklist map capacity = %d, want two policy slots (%d)", got, want)
	}
	if got, want := spec.Maps["endpoint4_rules"].MaxEntries, uint32(2*endpointMaxEntries); got != want {
		t.Fatalf("endpoint map capacity = %d, want two policy slots (%d)", got, want)
	}
	for _, name := range []string{
		"block_suffixes", "egress4_allow_rules", "egress4_block_rules", "egress6_allow_rules", "egress6_block_rules",
		"exec_allow_paths", "exec_block_paths", "file_allow_paths", "file_block_paths", "unix_allow_paths", "unix_block_paths",
		"bind4_allow_rules", "bind4_block_rules", "bind6_allow_rules", "bind6_block_rules", "sockopt_allow", "sockopt_block",
	} {
		if got, want := spec.Maps[name].MaxEntries, uint32(2*egressMaxEntries); got != want {
			t.Fatalf("%s map capacity = %d, want two policy slots (%d)", name, got, want)
		}
	}
	if readers := spec.Maps["policy_readers"]; readers == nil || readers.Type != ebpf.PerCPUArray || readers.MaxEntries != 2 || readers.ValueSize != 8 {
		t.Fatalf("policy reader map = %#v, want two per-CPU uint64 counters", readers)
	}
	if settings := spec.Maps["settings"]; settings == nil || settings.ValueSize != pinSettingsSize {
		t.Fatalf("settings map = %#v, want value size %d", settings, pinSettingsSize)
	}
	if settings := spec.Maps["settings"]; settings == nil || settings.Type != ebpf.Array || settings.MaxEntries != 2 {
		t.Fatalf("settings map = %#v, want two immutable array slots", settings)
	}
	if selector := spec.Maps["policy_selector"]; selector == nil || selector.Type != ebpf.Hash || selector.MaxEntries != 1 || selector.ValueSize != 8 {
		t.Fatalf("policy selector map = %#v, want one RCU-replaced uint64 hash entry", selector)
	}
	if identity := spec.Maps["daemon_identity"]; identity == nil || identity.Type != ebpf.Hash || identity.MaxEntries != 1 || identity.ValueSize != 16 {
		t.Fatalf("daemon identity map = %#v, want one exact RCU-replaced process identity", identity)
	}
	if names := spec.Maps["rule_names"]; names == nil || names.Type != ebpf.Hash || names.MaxEntries != 2*policyMaxEntries || names.KeySize != 8 || names.ValueSize != maxPolicyRuleIDBytes+1 {
		t.Fatalf("rule name map = %#v, want two complete policy slots", names)
	}
	if socketInfo := spec.Maps["socket_info"]; socketInfo == nil || socketInfo.ValueSize != 40 {
		t.Fatalf("socket_info map = %#v, want 40-byte generation-bound values", socketInfo)
	}
	if listenerInfo := spec.Maps["listener_info"]; listenerInfo == nil || listenerInfo.ValueSize != 40 {
		t.Fatalf("listener_info map = %#v, want 40-byte generation-bound values", listenerInfo)
	}
}

func TestPinnedModeKeepsLSMLinksLifecycleBound(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	linksDir := filepath.Join(root, "links")
	if err := os.MkdirAll(linksDir, 0o700); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(linksDir, "lsm_exec")
	if err := os.WriteFile(stale, []byte("stale pin"), 0o600); err != nil {
		t.Fatal(err)
	}
	closed := []int{}
	attachCalls := 0
	links, state := attachOptionalPrograms("/sys/fs/cgroup", Options{PinEBPF: true, PinPath: root}, optionalPrograms{
		LSMExec: &ebpf.Program{},
	}, attachmentFunctions{
		attachLSM: func(link.LSMOptions) (io.Closer, error) {
			attachCalls++
			return &testCloser{id: 1, closed: &closed}, nil
		},
	})
	if attachCalls != 1 || !state.LSMExecAttached || len(links) != 1 {
		t.Fatalf("LSM attach result = calls:%d state:%+v links:%d", attachCalls, state, len(links))
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale persistent LSM link was not removed: %v", err)
	}
	if err := links[0].Close(); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedObjectsContainOptionalEnforcementHooks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		load func() (*ebpf.CollectionSpec, error)
	}{
		{"default", loadTraceguard}, {"dns-compat", loadTraceguardDNSCompat},
		{"recvmsg-compat", loadTraceguardRecvmsgCompat}, {"dns-recvmsg-compat", loadTraceguardDNSRecvmsgCompat},
		{"linux71", loadTraceguardLinux71}, {"linux71-dns-compat", loadTraceguardLinux71DNSCompat},
		{"linux71-recvmsg-compat", loadTraceguardLinux71RecvmsgCompat}, {"linux71-dns-recvmsg-compat", loadTraceguardLinux71DNSRecvmsgCompat},
	}
	wantSections := map[string]string{
		"lsm_bprm_check_security": "lsm/bprm_check_security",
		"lsm_file_open":           "lsm/file_open", "trace_bind4": "cgroup/bind4", "trace_bind6": "cgroup/bind6",
		"trace_connect_unix": "cgroup/connect_unix", "trace_sendmsg_unix": "cgroup/sendmsg_unix",
		"trace_recvmsg_unix": "cgroup/recvmsg_unix", "trace_setsockopt": "cgroup/setsockopt", "trace_sockops": "sockops",
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			spec, err := test.load()
			if err != nil {
				t.Fatal(err)
			}
			for name, section := range wantSections {
				program := spec.Programs[name]
				if program == nil || program.SectionName != section {
					t.Errorf("program %s section = %v, want %s", name, program, section)
				}
			}
			if path := spec.Maps["lsm_path_buf"]; path == nil || path.Type != ebpf.TaskStorage {
				t.Errorf("lsm_path_buf = %#v, want task storage", path)
			}
		})
	}
}

func TestLinux71ObjectsIncludeEnhancedTelemetryHelpers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		loadSpec func() (*ebpf.CollectionSpec, error)
	}{
		{name: "default", loadSpec: loadTraceguardLinux71},
		{name: "dns compat", loadSpec: loadTraceguardLinux71DNSCompat},
		{name: "recvmsg compat", loadSpec: loadTraceguardLinux71RecvmsgCompat},
		{name: "dns recvmsg compat", loadSpec: loadTraceguardLinux71DNSRecvmsgCompat},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			spec, err := tc.loadSpec()
			if err != nil {
				t.Fatalf("load spec: %v", err)
			}
			for _, helper := range []asm.BuiltinFunc{
				asm.FnGetCurrentUidGid,
				asm.FnGetCurrentCgroupId,
				asm.FnGetSocketCookie,
			} {
				if !collectionUsesHelper(spec, helper) {
					t.Errorf("generated object does not call %s", helper)
				}
			}
		})
	}
}

func collectionUsesHelper(spec *ebpf.CollectionSpec, helper asm.BuiltinFunc) bool {
	for _, program := range spec.Programs {
		for _, instruction := range program.Instructions {
			if instruction.IsBuiltinCall() && instruction.Constant == int64(helper) {
				return true
			}
		}
	}
	return false
}

func TestDomainSuffixPolicySlotsProduceDistinctKeys(t *testing.T) {
	t.Parallel()

	key, err := encodeDomainSuffixKey("example.com")
	if err != nil {
		t.Fatalf("encodeDomainSuffixKey returned error: %v", err)
	}
	other := key
	other.Slot = 1
	if key == other {
		t.Fatal("policy slot did not change the suffix map key")
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

func TestVerifierErrorClassifiersInspectTypedLogs(t *testing.T) {
	t.Parallel()

	dnsErr := fmt.Errorf("field TraceDns: %w", &ebpf.VerifierError{
		Cause: errors.New("invalid argument"),
		Log:   []string{"program of this type cannot use helper bpf_get_current_comm#16"},
	})
	if !isDNSHelperVerifierError(dnsErr) {
		t.Fatal("isDNSHelperVerifierError rejected typed verifier log")
	}

	recvmsgErr := fmt.Errorf("field TraceRecvmsg4: %w", &ebpf.VerifierError{
		Cause: errors.New("permission denied"),
		Log:   []string{"invalid bpf_context access off=40 size=4"},
	})
	if !isRecvmsgContextVerifierError(recvmsgErr) {
		t.Fatal("isRecvmsgContextVerifierError rejected typed verifier log")
	}
}

func TestAttachMonitorProgramsRollsBackInReverseOrder(t *testing.T) {
	t.Parallel()

	var closed []int
	calls := 0
	functions := attachmentFunctions{
		attachCgroup: func(_ link.CgroupOptions) (io.Closer, error) {
			calls++
			if calls == 4 {
				return nil, errors.New("attach failed")
			}
			return &testCloser{id: calls, closed: &closed}, nil
		},
		attachTracepoint: func(string, string, *ebpf.Program) (io.Closer, error) {
			t.Fatal("tracepoint attach called after cgroup failure")
			return nil, errors.New("unexpected tracepoint attach")
		},
	}

	links, err := attachMonitorPrograms("/sys/fs/cgroup", Options{}, monitorObjects{}, functions)
	if err == nil || !strings.Contains(err.Error(), "attach failed") {
		t.Fatalf("attachMonitorPrograms error = %v, want attach failure", err)
	}
	if links != nil {
		t.Fatalf("links = %v, want nil", links)
	}
	if !slices.Equal(closed, []int{3, 2, 1}) {
		t.Fatalf("close order = %v, want [3 2 1]", closed)
	}
}

func TestCloseReaderOnCancelStopsWhenRunFinishes(t *testing.T) {
	t.Parallel()

	var closed []int
	reader := &testCloser{id: 1, closed: &closed}
	finished := make(chan struct{})
	done := make(chan struct{})
	go func() {
		closeReaderOnCancel(context.Background(), reader, finished)
		close(done)
	}()
	close(finished)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closeReaderOnCancel leaked after Run finished")
	}
	if len(closed) != 0 {
		t.Fatalf("reader closed after normal Run completion: %v", closed)
	}
}

func TestCloseReaderOnCancelClosesReader(t *testing.T) {
	t.Parallel()

	var closed []int
	reader := &testCloser{id: 1, closed: &closed}
	finished := make(chan struct{})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		closeReaderOnCancel(ctx, reader, finished)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closeReaderOnCancel did not react to cancellation")
	}
	if !slices.Equal(closed, []int{1}) {
		t.Fatalf("closed readers = %v, want [1]", closed)
	}
}

func TestShouldTryDNSRecvmsgCompatChecksEveryFailure(t *testing.T) {
	t.Parallel()

	dnsErr := errors.New("field TraceDns: program trace_dns: load program: invalid argument: program of this type cannot use helper bpf_get_current_comm#16")
	otherErr := errors.New("field TraceRecvmsg4: unrelated verifier failure")
	if !shouldTryDNSRecvmsgCompat(otherErr, dnsErr) {
		t.Fatal("shouldTryDNSRecvmsgCompat ignored DNS failure from recvmsg compat load")
	}
	if shouldTryDNSRecvmsgCompat(otherErr, nil) {
		t.Fatal("shouldTryDNSRecvmsgCompat matched unrelated failures")
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
