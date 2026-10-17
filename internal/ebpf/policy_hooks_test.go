package ebpf

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateEnforcementHooksRequiresHostWideLSMScopeAndAttach(t *testing.T) {
	t.Parallel()
	policy := PolicyConfig{Exec: PathPolicyConfig{Enabled: true}}
	monitor := Monitor{cgroupPath: "/sys/fs/cgroup/workload", attachState: AttachState{LSMExecAttached: true}}
	if err := monitor.validateEnforcementHooks(policy); err == nil || !strings.Contains(err.Error(), "host-wide") {
		t.Fatalf("slice-scoped LSM error = %v", err)
	}
	monitor.cgroupPath = "/sys/fs/cgroup"
	monitor.attachState.LSMExecAttached = false
	if err := monitor.validateEnforcementHooks(policy); err == nil || !strings.Contains(err.Error(), "not attached") {
		t.Fatalf("missing LSM error = %v", err)
	}
	monitor.attachState.LSMExecAttached = true
	if err := monitor.validateEnforcementHooks(policy); err != nil {
		t.Fatalf("ready LSM policy rejected: %v", err)
	}
	monitor.daemonNamespaceErr = errors.New("daemon runs outside the host pid namespace")
	if err := monitor.validateEnforcementHooks(policy); err == nil || !strings.Contains(err.Error(), "host PID") {
		t.Fatalf("namespaced daemon LSM error = %v", err)
	}
}

func TestHostNamespaceErrorRequiresInitNamespaces(t *testing.T) {
	t.Parallel()
	if err := hostNamespaceError(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("hostNamespaceError() accepted an unreadable pid namespace")
	}
	// Any regular file has an inode that is not the init namespace inode.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pid"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := hostNamespaceError(dir); err == nil || !strings.Contains(err.Error(), "pid namespace") {
		t.Fatalf("hostNamespaceError() = %v, want pid namespace error", err)
	}
}

func TestValidateEnforcementHooksUsesRequiredBindFamiliesAndUnixOperations(t *testing.T) {
	t.Parallel()
	v4Policy := EgressPolicyConfig{Enabled: true, Rules: []EgressRuleConfig{{
		ID: "v4", Action: "block", CIDRs: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
	}}}
	monitor := Monitor{cgroupPath: "/sys/fs/cgroup", attachState: AttachState{Bind4Attached: true}}
	// IPv4-mapped and dual-stack wildcard binds reach IPv4 policy through bind6.
	if err := monitor.validateEnforcementHooks(PolicyConfig{Bind: v4Policy}); err == nil || !strings.Contains(err.Error(), "bind6") {
		t.Fatalf("IPv4-only bind policy without bind6 error = %v", err)
	}
	monitor.attachState.Bind6Attached = true
	if err := monitor.validateEnforcementHooks(PolicyConfig{Bind: v4Policy}); err != nil {
		t.Fatalf("IPv4-only bind policy rejected with both hooks: %v", err)
	}
	v6Policy := EgressPolicyConfig{Enabled: true, Rules: []EgressRuleConfig{{
		ID: "v6", Action: "block", CIDRs: []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}}}
	if err := (&Monitor{cgroupPath: "/sys/fs/cgroup", attachState: AttachState{Bind6Attached: true}}).validateEnforcementHooks(PolicyConfig{Bind: v6Policy}); err != nil {
		t.Fatalf("IPv6-only bind policy required bind4: %v", err)
	}
	monitor.attachState.Bind6Attached = false

	// recvmsg is audit-only, so a recvmsg-only policy needs no attachment.
	unixPolicy := PathPolicyConfig{Enabled: true, Rules: []PathRuleConfig{{ID: "recv", Action: "block", AccessOrOps: []uint8{unixOpRecvmsg}}}}
	if err := monitor.validateEnforcementHooks(PolicyConfig{Unix: unixPolicy}); err != nil {
		t.Fatalf("recvmsg-only unix policy rejected: %v", err)
	}
	unixPolicy.Rules[0].AccessOrOps = []uint8{unixOpConnect, unixOpRecvmsg}
	if err := monitor.validateEnforcementHooks(PolicyConfig{Unix: unixPolicy}); err == nil || !strings.Contains(err.Error(), "connect") {
		t.Fatalf("missing connect hook error = %v", err)
	}
	monitor.attachState.UnixConnectAttached = true
	if err := monitor.validateEnforcementHooks(PolicyConfig{Unix: unixPolicy}); err != nil {
		t.Fatalf("connect+recvmsg unix policy rejected without recvmsg hook: %v", err)
	}
}
