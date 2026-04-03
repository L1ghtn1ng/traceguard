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
