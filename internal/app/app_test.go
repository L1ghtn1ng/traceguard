package app

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
)

func TestDefaultBaselinesUseEventTimeConnectionFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		fields map[string]any
		wantID string
	}{
		{
			name: "cloud metadata",
			fields: map[string]any{
				"direction": "outbound", "peer_address": "169.254.169.254", "peer_port": uint16(80),
			},
			wantID: "baseline.cloud-metadata-access",
		},
		{
			name: "direct email",
			fields: map[string]any{
				"direction": "outbound", "peer_address": "198.51.100.10", "peer_port": uint16(25), "socket_protocol": "tcp",
			},
			wantID: "baseline.direct-email-egress",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			engine, err := detection.New(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			alerts := engine.Evaluate(detection.Event{
				Timestamp: time.Unix(1, 0), Name: "connection", Fields: test.fields,
			})
			if len(alerts) != 1 || alerts[0].RuleID != test.wantID {
				t.Fatalf("alerts = %#v, want %q", alerts, test.wantID)
			}
		})
	}
}

type recordingProcessCache struct {
	calls []string
}

func (c *recordingProcessCache) LookupAt(pid uint32, comm string, startTime uint64) (processinfo.Metadata, bool) {
	c.calls = append(c.calls, fmt.Sprintf("lookup:%d:%s:%d", pid, comm, startTime))
	return processinfo.Metadata{PID: pid, Comm: "old"}, true
}

func (c *recordingProcessCache) Invalidate(pid uint32) {
	c.calls = append(c.calls, fmt.Sprintf("invalidate:%d", pid))
}

func TestExecProcessLookupInvalidatesAfterEnrichment(t *testing.T) {
	t.Parallel()

	cache := &recordingProcessCache{}
	process, hit := lookupProcessForEvent(cache, ebpfmonitor.Event{
		Kind: ebpfmonitor.EventExec,
		PID:  42,
		Comm: "old",
	})

	if !hit || process.Comm != "old" {
		t.Fatalf("lookup result = %#v, %v; want old metadata cache hit", process, hit)
	}
	wantCalls := []string{"lookup:42:old:0", "invalidate:42"}
	if !reflect.DeepEqual(cache.calls, wantCalls) {
		t.Fatalf("cache calls = %v, want %v", cache.calls, wantCalls)
	}
}

func TestIsPermissionErrorMatchesWrappedEBPFError(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("attach execve tracepoint: %w", ebpfmonitor.ErrInsufficientPrivileges)
	if !IsPermissionError(err) {
		t.Fatal("IsPermissionError did not match wrapped privilege error")
	}
}

func TestIsPermissionErrorRejectsOtherErrors(t *testing.T) {
	t.Parallel()

	if IsPermissionError(fmt.Errorf("some other error")) {
		t.Fatal("IsPermissionError matched unrelated error")
	}
}

func TestValidateRulesForModeAllowsAllowSuffixRulesInBlockMode(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		AllowSuffixes: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("validateRulesForMode rejected suffix allow in block mode: %v", err)
	}
}

func TestValidateRulesForModeAllowsBlockSuffixRulesInBlockMode(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		BlockSuffixes: []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("validateRulesForMode rejected suffix block in block mode: %v", err)
	}
}

func TestValidateRulesForModeAllowsDenyAllWithExactExceptions(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		BlockAllDomains:   true,
		BlockAllResolvers: true,
		AllowDomains:      []string{"resolver.example.com"},
	})
	if err != nil {
		t.Fatalf("validateRulesForMode returned error: %v", err)
	}
}

func TestPolicyMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  config.Config
		want string
	}{
		{name: "observe", cfg: config.Config{}, want: "observe"},
		{name: "dry run", cfg: config.Config{DryRun: true}, want: "dry_run"},
		{name: "block", cfg: config.Config{Block: true}, want: "block"},
		{name: "block dry run", cfg: config.Config{Block: true, DryRun: true}, want: "dry_run"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := policyMode(tt.cfg); got != tt.want {
				t.Fatalf("policyMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPolicyRuleCounts(t *testing.T) {
	t.Parallel()

	got := policyRuleCounts(blocklist.Rules{
		BlockDomains:       []string{"bad.example"},
		AllowDomains:       []string{"good.example"},
		BlockSuffixes:      []string{"bad.test"},
		AllowSuffixes:      []string{"good.test"},
		BlockEndpointCIDRs: []blocklist.EndpointCIDR{{}},
		AllowEndpointCIDRs: []blocklist.EndpointCIDR{{}, {}},
	}, 3, 4)

	want := map[string]int{
		"block|domain":        1,
		"allow|domain":        1,
		"block|suffix":        1,
		"allow|suffix":        1,
		"block|endpoint":      3,
		"allow|endpoint":      4,
		"block|endpoint_cidr": 1,
		"allow|endpoint_cidr": 2,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policyRuleCounts() = %#v, want %#v", got, want)
	}
}

func TestAppendSocketFieldsPreservesEventTimeAttribution(t *testing.T) {
	t.Parallel()

	fields := map[string]any{}
	appendSocketFields(fields, ebpfmonitor.Event{
		Kind:           ebpfmonitor.EventDNS,
		Attribution:    "kernel-sendmsg",
		SocketHook:     "cgroup_sendmsg4",
		SocketFamily:   "ipv4",
		SocketProtocol: "udp",
	})

	want := map[string]any{
		"attribution":     "kernel-sendmsg",
		"socket_hook":     "cgroup_sendmsg4",
		"socket_family":   "ipv4",
		"socket_protocol": "udp",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("fields = %#v, want %#v", fields, want)
	}
}

func TestAppendEventIdentityFieldsSeparatesKernelAndCachedIdentity(t *testing.T) {
	t.Parallel()

	kernelFields := map[string]any{}
	appendEventIdentityFields(kernelFields, ebpfmonitor.Event{
		Comm: "curl", KernelUID: 1000, CgroupID: 42, ProcessStartTime: 99, UIDSource: "kernel",
	})
	wantKernel := map[string]any{
		"program": "curl", "uid": uint32(1000), "kernel_uid": uint32(1000),
		"cgroup_id": uint64(42), "process_start_ticks": uint64(99), "uid_source": "kernel",
	}
	if !reflect.DeepEqual(kernelFields, wantKernel) {
		t.Fatalf("kernel fields = %#v, want %#v", kernelFields, wantKernel)
	}

	cachedFields := map[string]any{}
	appendEventIdentityFields(cachedFields, ebpfmonitor.Event{
		Comm: "old", KernelUID: 1001, CgroupID: 43, ProcessStartTime: 100, UIDSource: "socket-cache",
	})
	wantCached := map[string]any{
		"cached_program": "old", "cached_uid": uint32(1001), "cached_cgroup_id": uint64(43),
		"cached_process_start_ticks": uint64(100), "identity_source": "socket-cache",
	}
	if !reflect.DeepEqual(cachedFields, wantCached) {
		t.Fatalf("cached fields = %#v, want %#v", cachedFields, wantCached)
	}
	for _, securityField := range []string{"program", "uid", "kernel_uid", "cgroup_id", "process_start_ticks"} {
		if _, exists := cachedFields[securityField]; exists {
			t.Errorf("cached identity leaked into detection field %q", securityField)
		}
	}
}

func TestAppendSocketFieldsSkipsExecEvents(t *testing.T) {
	t.Parallel()

	fields := map[string]any{}
	appendSocketFields(fields, ebpfmonitor.Event{
		Kind:           ebpfmonitor.EventExec,
		Attribution:    "kernel-skb",
		SocketHook:     "cgroup_skb",
		SocketFamily:   "ipv4",
		SocketProtocol: "udp",
	})

	if len(fields) != 0 {
		t.Fatalf("fields = %#v, want empty", fields)
	}
}

func TestAppendSocketFieldsSupportsConnectionEvents(t *testing.T) {
	t.Parallel()

	fields := map[string]any{}
	appendSocketFields(fields, ebpfmonitor.Event{
		Kind:           ebpfmonitor.EventConnection,
		Attribution:    "kernel-ingress",
		SocketHook:     "cgroup_skb_ingress",
		SocketFamily:   "ipv4",
		SocketProtocol: "tcp",
	})

	want := map[string]any{
		"attribution":     "kernel-ingress",
		"socket_hook":     "cgroup_skb_ingress",
		"socket_family":   "ipv4",
		"socket_protocol": "tcp",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("fields = %#v, want %#v", fields, want)
	}
}

func TestResolveExecutablePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event ebpfmonitor.Event
		want  string
	}{
		{
			name:  "blocked exec uses kernel resolved filename",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventExecBlocked, PID: 100, Filename: "/usr/bin/new"},
			want:  "/usr/bin/new",
		},
		{
			name:  "observed exec syscall path is not canonical",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventExec, PID: 100, Filename: "/usr/bin/requested"},
			want:  "",
		},
		{
			name:  "non exec event does not substitute proc metadata",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventDNS, PID: 100, Filename: "/usr/bin/ignored"},
			want:  "",
		},
		{
			name:  "does not derive identity from cmdline",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventResolver, PID: 100},
			want:  "",
		},
		{
			name:  "pid zero stays empty",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventConnection, PID: 0},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := resolveExecutablePath(tt.event); got != tt.want {
				t.Fatalf("resolveExecutablePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEventKindNameAndSocketAwareness(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		kind        uint32
		wantName    string
		wantSockets bool
	}{
		{name: "dns", kind: ebpfmonitor.EventDNS, wantName: "dns", wantSockets: true},
		{name: "blocked", kind: ebpfmonitor.EventBlocked, wantName: "blocked", wantSockets: true},
		{name: "exec", kind: ebpfmonitor.EventExec, wantName: "exec", wantSockets: false},
		{name: "resolver", kind: ebpfmonitor.EventResolver, wantName: "resolver", wantSockets: true},
		{name: "resolver blocked", kind: ebpfmonitor.EventResolverBlocked, wantName: "resolver_blocked", wantSockets: true},
		{name: "connection", kind: ebpfmonitor.EventConnection, wantName: "connection", wantSockets: true},
		{name: "file access", kind: ebpfmonitor.EventFileAccess, wantName: "file_access", wantSockets: false},
		{name: "egress blocked", kind: ebpfmonitor.EventEgressBlocked, wantName: "egress_blocked", wantSockets: true},
		{name: "egress would block", kind: ebpfmonitor.EventEgressWouldBlock, wantName: "egress_would_block", wantSockets: true},
		{name: "exec blocked", kind: ebpfmonitor.EventExecBlocked, wantName: "exec_blocked", wantSockets: false},
		{name: "exec would block", kind: ebpfmonitor.EventExecWouldBlock, wantName: "exec_would_block", wantSockets: false},
		{name: "file blocked", kind: ebpfmonitor.EventFileBlocked, wantName: "file_blocked", wantSockets: false},
		{name: "bind blocked", kind: ebpfmonitor.EventBindBlocked, wantName: "bind_blocked", wantSockets: true},
		{name: "unix blocked", kind: ebpfmonitor.EventUnixBlocked, wantName: "unix_blocked", wantSockets: true},
		{name: "sockopt blocked", kind: ebpfmonitor.EventSockoptBlocked, wantName: "sockopt_blocked", wantSockets: true},
		{name: "sockops", kind: ebpfmonitor.EventSockOps, wantName: "tcp_sockops", wantSockets: true},
		{name: "unknown", kind: 99, wantName: "unknown", wantSockets: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := eventKindName(tt.kind); got != tt.wantName {
				t.Fatalf("eventKindName(%d) = %q, want %q", tt.kind, got, tt.wantName)
			}
			if got := isSocketAwareEvent(tt.kind); got != tt.wantSockets {
				t.Fatalf("isSocketAwareEvent(%d) = %v, want %v", tt.kind, got, tt.wantSockets)
			}
		})
	}
}

func TestFileAccessName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags uint32
		want  string
	}{
		{name: "read only", flags: 0, want: "read"},
		{name: "write only", flags: 0x1, want: "write"},
		{name: "read write", flags: 0x2, want: "write"},
		{name: "create", flags: 0x40, want: "write"},
		{name: "truncate", flags: 0x200, want: "write"},
		{name: "unknown", flags: 1 << 31, want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := fileAccessName(tt.flags); got != tt.want {
				t.Fatalf("fileAccessName(%#x) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}

func TestFileAuditEventName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags uint32
		want  string
	}{
		{name: "read only", flags: 0, want: "file_access"},
		{name: "write only", flags: 0x1, want: "file_access"},
		{name: "create", flags: 0x40, want: "file_created"},
		{name: "creat syscall", flags: 01101, want: "file_created"},
		{name: "unknown", flags: 1 << 31, want: "file_access"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := fileAuditEventName(tt.flags); got != tt.want {
				t.Fatalf("fileAuditEventName(%#x) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}
