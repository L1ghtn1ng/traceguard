package processinfo

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCacheLookupReadsProcMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeProcEntry(t, root, 100, "status", "Name:\tcurl\nPPid:\t42\nUid:\t1000\t1000\t1000\t1000\n")
	writeProcEntry(t, root, 100, "stat", statWithStartTime("curl", 1000))
	writeProcEntry(t, root, 100, "cmdline", "/usr/bin/curl\x00https://example.com\x00")
	writeProcEntry(t, root, 100, "cgroup", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n")
	writeProcEntry(t, root, 100, filepath.Join("attr", "current"), "system_u:system_r:traceguard_t:s0\n")
	writeProcSymlink(t, root, 100, "exe", "/usr/bin/curl")
	writeProcEntry(t, root, 42, "status", "Name:\tbash\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n")
	writeProcEntry(t, root, 42, "stat", statWithStartTime("bash", 500))

	cache := NewCache(root, time.Minute)
	metadata, hit := cache.Lookup(100, "fallback")
	if hit {
		t.Fatal("first lookup unexpectedly hit cache")
	}
	if metadata.Comm != "curl" {
		t.Fatalf("Comm = %q, want curl", metadata.Comm)
	}
	if metadata.Source != SourceProc {
		t.Fatalf("Source = %q, want %q", metadata.Source, SourceProc)
	}
	if metadata.PPID != 42 {
		t.Fatalf("PPID = %d, want 42", metadata.PPID)
	}
	if metadata.UID != 1000 {
		t.Fatalf("UID = %d, want 1000", metadata.UID)
	}
	if len(metadata.Cmdline) != 2 || metadata.Cmdline[0] != "/usr/bin/curl" {
		t.Fatalf("Cmdline = %v, want curl command line", metadata.Cmdline)
	}
	if metadata.Exe != "/usr/bin/curl" {
		t.Fatalf("Exe = %q, want /usr/bin/curl", metadata.Exe)
	}
	if metadata.ParentComm != "bash" {
		t.Fatalf("ParentComm = %q, want bash", metadata.ParentComm)
	}
	if metadata.Service != "cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope" {
		t.Fatalf("Service = %q, unexpected", metadata.Service)
	}
	if metadata.Container != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("Container = %q, unexpected", metadata.Container)
	}
	if metadata.PodUID != "12345678-1234-1234-1234-123456789abc" {
		t.Fatalf("PodUID = %q, unexpected", metadata.PodUID)
	}
	if metadata.Runtime != "containerd" {
		t.Fatalf("Runtime = %q, unexpected", metadata.Runtime)
	}
	if metadata.SELinux != "system_u:system_r:traceguard_t:s0" {
		t.Fatalf("SELinux = %q, unexpected", metadata.SELinux)
	}
	if metadata.LSMSource != "selinux" {
		t.Fatalf("LSMSource = %q, want selinux", metadata.LSMSource)
	}

	_, hit = cache.Lookup(100, "fallback")
	if !hit {
		t.Fatal("second lookup did not hit cache")
	}
}

func TestCacheLookupKeepsFallbackWithoutStatusName(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeProcEntry(t, root, 100, "status", "PPid:\t42\nUid:\t1000\t1000\t1000\t1000\n")
	writeProcEntry(t, root, 100, "stat", statWithStartTime("fallback", 1000))

	cache := NewCache(root, time.Minute)
	metadata, _ := cache.Lookup(100, "fallback")
	if metadata.Comm != "fallback" {
		t.Fatalf("Comm = %q, want fallback", metadata.Comm)
	}
	if metadata.Source != SourceFallback {
		t.Fatalf("Source = %q, want %q", metadata.Source, SourceFallback)
	}
}

func TestCacheLookupRefreshesAfterPIDReuse(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeProcEntry(t, root, 100, "status", "Name:\tcurl\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n")
	writeProcEntry(t, root, 100, "stat", statWithStartTime("curl", 1000))

	cache := NewCache(root, time.Minute)
	first, hit := cache.Lookup(100, "fallback")
	if hit {
		t.Fatal("first lookup unexpectedly hit cache")
	}
	if first.Comm != "curl" {
		t.Fatalf("first Comm = %q, want curl", first.Comm)
	}

	writeProcEntry(t, root, 100, "status", "Name:\tbash\nPPid:\t1\nUid:\t1001\t1001\t1001\t1001\n")
	writeProcEntry(t, root, 100, "stat", statWithStartTime("bash", 2000))
	cache.now = func() time.Time { return time.Now().Add(processIdentityRecheckInterval) }
	second, hit := cache.Lookup(100, "fallback")
	if hit {
		t.Fatal("lookup after PID reuse unexpectedly hit cache")
	}
	if second.Comm != "bash" || second.UID != 1001 {
		t.Fatalf("second metadata = %+v, want refreshed bash metadata", second)
	}
}

func TestParseCmdline(t *testing.T) {
	t.Parallel()

	got := parseCmdline([]byte("python3\x00script.py\x00--flag\x00"))
	want := []string{"python3", "script.py", "--flag"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("parseCmdline = %v, want %v", got, want)
	}
}

func TestParseCgroup(t *testing.T) {
	t.Parallel()

	path, service, container, podUID, runtime := parseCgroup([]byte("0::/kubepods.slice/pod12345678_1234_1234_1234_123456789abc/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n"))
	if path == "" || service == "" || container == "" || podUID == "" || runtime == "" {
		t.Fatalf("parseCgroup returned empty values path=%q service=%q container=%q podUID=%q runtime=%q", path, service, container, podUID, runtime)
	}
}

func TestCacheLookupSkipsImmediateIdentityRecheck(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeProcEntry(t, root, 100, "status", "Name:\tcurl\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n")
	writeProcEntry(t, root, 100, "stat", statWithStartTime("curl", 1000))

	now := time.Date(2026, time.June, 7, 12, 0, 0, 0, time.UTC)
	cache := NewCache(root, time.Minute)
	cache.now = func() time.Time { return now }
	if _, hit := cache.Lookup(100, "fallback"); hit {
		t.Fatal("first lookup unexpectedly hit cache")
	}

	if err := os.Remove(filepath.Join(root, "100", "stat")); err != nil {
		t.Fatalf("remove stat: %v", err)
	}
	if _, hit := cache.Lookup(100, "fallback"); !hit {
		t.Fatal("immediate second lookup did not hit cache")
	}

	now = now.Add(processIdentityRecheckInterval)
	if _, hit := cache.Lookup(100, "fallback"); hit {
		t.Fatal("lookup after recheck interval unexpectedly hit cache")
	}
}

func TestExtractContainerID(t *testing.T) {
	t.Parallel()

	got := extractContainerID("/kubepods/cri-containerd-ABCDEFABCDEFABCDEFABCDEFABCDEFAB.scope")
	if want := "abcdefabcdefabcdefabcdefabcdefab"; got != want {
		t.Fatalf("extractContainerID = %q, want %q", got, want)
	}
}

func TestExtractPodUID(t *testing.T) {
	t.Parallel()

	got := extractPodUID("/kubepods.slice/kubepods-pod12345678_1234_1234_1234_123456789ABC.slice")
	if want := "12345678-1234-1234-1234-123456789abc"; got != want {
		t.Fatalf("extractPodUID = %q, want %q", got, want)
	}
}

func TestParseAppArmorLabel(t *testing.T) {
	t.Parallel()

	profile, mode := parseAppArmorLabel("traceguard-default (enforce)")
	if profile != "traceguard-default" || mode != "enforce" {
		t.Fatalf("parseAppArmorLabel returned profile=%q mode=%q", profile, mode)
	}
}

func writeProcEntry(t *testing.T, root string, pid uint32, name, content string) {
	t.Helper()

	procDir := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", procDir, err)
	}
	path := filepath.Join(procDir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func writeProcSymlink(t *testing.T, root string, pid uint32, name, target string) {
	t.Helper()

	procDir := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", procDir, err)
	}
	if err := os.Symlink(target, filepath.Join(procDir, name)); err != nil {
		t.Fatalf("symlink %s -> %s: %v", name, target, err)
	}
}

func statWithStartTime(comm string, startTime uint64) string {
	return "100 (" + comm + ") S 1 1 1 0 -1 0 0 0 0 0 0 0 0 20 0 1 0 0 " + strconv.FormatUint(startTime, 10) + " 0 0\n"
}
