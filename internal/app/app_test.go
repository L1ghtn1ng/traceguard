package app

import (
	"fmt"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
)

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

func TestValidateRulesForModeRejectsBlockSuffixRulesInBlockMode(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		BlockSuffixes: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("validateRulesForMode accepted suffix block in block mode")
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
		tt := tt
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

func TestAppendSocketFieldsPrefersProcAttribution(t *testing.T) {
	t.Parallel()

	fields := map[string]any{}
	appendSocketFields(fields, ebpfmonitor.Event{
		Kind:           ebpfmonitor.EventDNS,
		Attribution:    "kernel-sendmsg",
		SocketHook:     "cgroup_sendmsg4",
		SocketFamily:   "ipv4",
		SocketProtocol: "udp",
	}, processinfo.Metadata{Source: processinfo.SourceProc})

	want := map[string]any{
		"attribution":     "proc",
		"socket_hook":     "cgroup_sendmsg4",
		"socket_family":   "ipv4",
		"socket_protocol": "udp",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("fields = %#v, want %#v", fields, want)
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
	}, processinfo.Metadata{})

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
	}, processinfo.Metadata{})

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
		name    string
		event   ebpfmonitor.Event
		process processinfo.Metadata
		want    string
	}{
		{
			name:  "exec event prefers filename",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventExec, PID: 100, Filename: "/usr/bin/new"},
			process: processinfo.Metadata{
				Exe:     "/usr/bin/old",
				Cmdline: []string{"/usr/bin/fallback"},
			},
			want: "/usr/bin/new",
		},
		{
			name:  "non exec event prefers proc exe",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventDNS, PID: 100, Filename: "/usr/bin/ignored"},
			process: processinfo.Metadata{
				Exe:     "/usr/bin/curl",
				Cmdline: []string{"/usr/bin/fallback"},
			},
			want: "/usr/bin/curl",
		},
		{
			name:  "falls back to absolute cmdline",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventResolver, PID: 100},
			process: processinfo.Metadata{
				Cmdline: []string{"/usr/bin/dig", "@1.1.1.1"},
			},
			want: "/usr/bin/dig",
		},
		{
			name:  "rejects relative cmdline fallback",
			event: ebpfmonitor.Event{Kind: ebpfmonitor.EventBlocked, PID: 100},
			process: processinfo.Metadata{
				Cmdline: []string{"curl", "https://example.com"},
			},
			want: "",
		},
		{
			name:    "pid zero stays empty",
			event:   ebpfmonitor.Event{Kind: ebpfmonitor.EventConnection, PID: 0},
			process: processinfo.Metadata{Exe: "/usr/bin/sshd"},
			want:    "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := resolveExecutablePath(tt.event, tt.process); got != tt.want {
				t.Fatalf("resolveExecutablePath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolverHostUsesAtomicIndex(t *testing.T) {
	t.Parallel()

	var index atomic.Pointer[map[string]string]
	if got := resolverHost(&index, ebpfmonitor.Event{Transport: "doh", Address: "1.1.1.1", Port: 443}); got != "" {
		t.Fatalf("resolverHost without index = %q, want empty", got)
	}

	current := map[string]string{
		resolverIndexKey("doh", "1.1.1.1", 443): "cloudflare-dns.com",
	}
	index.Store(&current)
	if got := resolverHost(&index, ebpfmonitor.Event{Transport: "doh", Address: "1.1.1.1", Port: 443}); got != "cloudflare-dns.com" {
		t.Fatalf("resolverHost = %q, want cloudflare-dns.com", got)
	}
	if got := resolverHost(&index, ebpfmonitor.Event{Transport: "dot", Address: "1.1.1.1", Port: 853}); got != "" {
		t.Fatalf("resolverHost for missing endpoint = %q, want empty", got)
	}
}

func TestPolicyDecisionHelpers(t *testing.T) {
	t.Parallel()

	var pointer atomic.Pointer[blocklist.Policy]
	if got := domainDecision(&pointer, "example.com"); got != blocklist.DecisionNone {
		t.Fatalf("domainDecision without policy = %q, want %q", got, blocklist.DecisionNone)
	}
	if got := endpointDecision(&pointer, "doh", "1.1.1.1", 443); got != blocklist.DecisionNone {
		t.Fatalf("endpointDecision without policy = %q, want %q", got, blocklist.DecisionNone)
	}

	policy := blocklist.NewPolicy(blocklist.Rules{
		BlockDomains: []string{"blocked.example"},
		AllowDomains: []string{"allowed.example"},
	}, []blocklist.ResolvedEndpoint{{
		Kind: blocklist.EndpointKindDoH,
		Host: "resolver.example",
		Port: 443,
		IP:   []byte{9, 9, 9, 9},
	}}, nil)
	pointer.Store(policy)

	if got := domainDecision(&pointer, "blocked.example"); got != blocklist.DecisionBlock {
		t.Fatalf("domainDecision(blocked.example) = %q, want %q", got, blocklist.DecisionBlock)
	}
	if got := domainDecision(&pointer, "allowed.example"); got != blocklist.DecisionAllow {
		t.Fatalf("domainDecision(allowed.example) = %q, want %q", got, blocklist.DecisionAllow)
	}
	if got := endpointDecision(&pointer, "doh", "9.9.9.9", 443); got != blocklist.DecisionBlock {
		t.Fatalf("endpointDecision(9.9.9.9) = %q, want %q", got, blocklist.DecisionBlock)
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
		{name: "unknown", kind: 99, wantName: "unknown", wantSockets: false},
	}

	for _, tt := range tests {
		tt := tt
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
		tt := tt
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
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := fileAuditEventName(tt.flags); got != tt.want {
				t.Fatalf("fileAuditEventName(%#x) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}
