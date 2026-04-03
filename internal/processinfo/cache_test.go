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
	writeProcEntry(t, root, 100, "cmdline", "/usr/bin/curl\x00https://example.com\x00")
	writeProcEntry(t, root, 100, "cgroup", "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod12345678_1234_1234_1234_123456789abc.slice/cri-containerd-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.scope\n")
	writeProcEntry(t, root, 42, "status", "Name:\tbash\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n")

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

	_, hit = cache.Lookup(100, "fallback")
	if !hit {
		t.Fatal("second lookup did not hit cache")
	}
}

func TestCacheLookupKeepsFallbackWithoutStatusName(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeProcEntry(t, root, 100, "status", "PPid:\t42\nUid:\t1000\t1000\t1000\t1000\n")

	cache := NewCache(root, time.Minute)
	metadata, _ := cache.Lookup(100, "fallback")
	if metadata.Comm != "fallback" {
		t.Fatalf("Comm = %q, want fallback", metadata.Comm)
	}
	if metadata.Source != SourceFallback {
		t.Fatalf("Source = %q, want %q", metadata.Source, SourceFallback)
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

	path, service, container, podUID, runtime := parseCgroup([]byte("0::/kubepods.slice/pod12345678_1234_1234_1234_123456789abc/cri-containerd-abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef.scope\n"))
	if path == "" || service == "" || container == "" || podUID == "" || runtime == "" {
		t.Fatalf("parseCgroup returned empty values path=%q service=%q container=%q podUID=%q runtime=%q", path, service, container, podUID, runtime)
	}
}

func writeProcEntry(t *testing.T, root string, pid uint32, name, content string) {
	t.Helper()

	procDir := filepath.Join(root, strconv.Itoa(int(pid)))
	if err := os.MkdirAll(procDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", procDir, err)
	}
	if err := os.WriteFile(filepath.Join(procDir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}
