package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestUnpinRemovesOnlyScopedAbsoluteDirectory(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "traceguard")
	if err := os.MkdirAll(filepath.Join(root, "maps"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "maps", "marker"), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unpinPinPath(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("pin root still exists or stat failed unexpectedly: %v", err)
	}
}

func TestUnpinnedModeRejectsExistingTraceGuardPins(t *testing.T) {
	t.Parallel()

	root := filepath.Join(t.TempDir(), "traceguard")
	if err := os.MkdirAll(filepath.Join(root, "links"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := rejectPinnedStateInUnpinnedMode(Options{PinPath: root})
	if err == nil || !strings.Contains(err.Error(), "traceguard -unpin") {
		t.Fatalf("unpinned preflight error = %v, want explicit unpin guidance", err)
	}
	if err := rejectPinnedStateInUnpinnedMode(Options{PinEBPF: true, PinPath: root}); err != nil {
		t.Fatalf("pinned mode rejected its own pin root: %v", err)
	}
	if err := rejectPinnedStateInUnpinnedMode(Options{PinPath: filepath.Join(t.TempDir(), "traceguard")}); err != nil {
		t.Fatalf("unpinned mode rejected an absent pin root: %v", err)
	}
}

func TestPinnedMapSetIncludesAtomicPolicyState(t *testing.T) {
	t.Parallel()

	dummy := &ebpf.Map{}
	handles := monitorMapHandles(monitorObjects{
		Settings: dummy, PolicySelector: dummy, PolicyReaders: dummy,
		DaemonIdentity: dummy, RuleNames: dummy, RingbufDrops: dummy,
	}, optionalPrograms{})
	for _, name := range []string{"settings", "policy_selector", "policy_readers", "daemon_identity", "rule_names", "ringbuf_drops"} {
		if handles[name] != dummy {
			t.Errorf("pinned handle %q = %p, want policy map %p", name, handles[name], dummy)
		}
	}
}

func TestUnpinRejectsBroadOrRelativePaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"", ".", "traceguard", "/", "/sys/fs/bpf", t.TempDir()} {
		if err := unpinPinPath(path); err == nil || !strings.Contains(err.Error(), "refuse unsafe") {
			t.Errorf("unpinPinPath(%q) error = %v, want unsafe-path rejection", path, err)
		}
	}
	if err := Unpin(filepath.Join(t.TempDir(), "traceguard")); err == nil || !strings.Contains(err.Error(), "refuse unsafe") {
		t.Errorf("Unpin(custom path) error = %v, want default-path-only rejection", err)
	}
}

func TestPinMetadataObjectNameAndSanitization(t *testing.T) {
	t.Parallel()
	metadata := pinMetadata{}
	copy(metadata.Object[:], "traceguardLinux71DNSCompat")
	if got := pinnedObjectName(&metadata); got != "traceguardLinux71DNSCompat" {
		t.Fatalf("pinned object = %q", got)
	}
	if got := sanitizePinName("DNS cgroup/egress-link"); got != "dns_cgroup_egress_link" {
		t.Fatalf("sanitized name = %q", got)
	}
}

func TestPinnedCgroupTargetValidationRejectsWrongIdentityOrAttachType(t *testing.T) {
	t.Parallel()

	if err := validateCgroupLinkTarget(42, 7, 42, 7); err != nil {
		t.Fatalf("matching target rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		id     uint64
		attach uint32
	}{
		{name: "wrong cgroup", id: 43, attach: 7},
		{name: "wrong attach", id: 42, attach: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateCgroupLinkTarget(test.id, test.attach, 42, 7); err == nil {
				t.Fatal("mismatched pinned target was accepted")
			}
		})
	}
}

func TestRemoveFreshPinsOnlyRemovesUncommittedPinSet(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "traceguard")
	if err := os.MkdirAll(filepath.Join(root, "maps"), 0o700); err != nil {
		t.Fatal(err)
	}

	committed := &Monitor{freshPinPath: root}
	committed.KeepPins()
	if err := committed.RemoveFreshPins(); err != nil {
		t.Fatalf("RemoveFreshPins() after KeepPins error = %v", err)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("committed pin set was removed: %v", err)
	}

	failed := &Monitor{freshPinPath: root}
	if err := failed.RemoveFreshPins(); err != nil {
		t.Fatalf("RemoveFreshPins() error = %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("fresh pin set still exists after failed startup: %v", err)
	}
}

type filePinner struct {
	content string
	err     error
}

func (p filePinner) Pin(path string) error {
	if p.err != nil {
		return p.err
	}
	return os.WriteFile(path, []byte(p.content), 0o600)
}

func TestReplacePinnedMapSwapsOnlyAfterPinning(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replacePinnedMap(path, filePinner{err: errors.New("pin failed")}); err == nil {
		t.Fatal("a failed pin was reported as replaced")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "old" { //nolint:gosec // path is rooted in t.TempDir
		t.Fatalf("failed replacement changed the old pin: %q, %v", got, err)
	}

	if err := os.WriteFile(stagedPinPath(path), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := replacePinnedMap(path, filePinner{content: "new"}); err != nil {
		t.Fatalf("replacePinnedMap: %v", err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "new" { //nolint:gosec // path is rooted in t.TempDir
		t.Fatalf("pin after replacement = %q, %v; want new", got, err)
	}
	if _, err := os.Stat(stagedPinPath(path)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staged pin left behind: %v", err)
	}
}

func TestStagedPinPathIsAValidBPFFSName(t *testing.T) {
	t.Parallel()

	// bpffs refuses to create any name containing a dot.
	if name := filepath.Base(stagedPinPath("/sys/fs/bpf/traceguard/maps/events")); strings.Contains(name, ".") {
		t.Fatalf("staged pin name %q contains a dot", name)
	}
}
