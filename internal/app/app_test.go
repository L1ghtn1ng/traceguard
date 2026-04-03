package app

import (
	"fmt"
	"reflect"
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

func TestValidateRulesForModeRejectsSuffixRulesInBlockMode(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		AllowSuffixes: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("validateRulesForMode accepted suffix allow in block mode")
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
