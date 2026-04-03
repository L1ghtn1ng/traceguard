package processinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Metadata struct {
	PID           uint32
	Comm          string
	Source        string
	Exe           string
	Cmdline       []string
	UID           uint32
	PPID          uint32
	ParentComm    string
	ParentExe     string
	ParentCmdline []string
	CgroupPath    string
	Service       string
	Container     string
	PodUID        string
	Runtime       string
}

const (
	SourceFallback = "fallback"
	SourceProc     = "proc"
)

type Cache struct {
	mu      sync.Mutex
	root    string
	ttl     time.Duration
	now     func() time.Time
	entries map[uint32]cacheEntry
}

type cacheEntry struct {
	expiresAt time.Time
	metadata  Metadata
}

func NewCache(root string, ttl time.Duration) *Cache {
	if root == "" {
		root = "/proc"
	}
	return &Cache{
		root:    root,
		ttl:     ttl,
		now:     time.Now,
		entries: make(map[uint32]cacheEntry),
	}
}

func (c *Cache) Lookup(pid uint32, fallbackComm string) (Metadata, bool) {
	now := c.now()

	c.mu.Lock()
	entry, ok := c.entries[pid]
	if ok && now.Before(entry.expiresAt) {
		c.mu.Unlock()
		return entry.metadata, true
	}
	c.mu.Unlock()

	metadata := c.readMetadata(pid, fallbackComm)

	c.mu.Lock()
	c.entries[pid] = cacheEntry{
		expiresAt: now.Add(c.ttl),
		metadata:  metadata,
	}
	c.mu.Unlock()

	return metadata, false
}

func (c *Cache) Invalidate(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, pid)
}

func (c *Cache) readMetadata(pid uint32, fallbackComm string) Metadata {
	metadata := Metadata{
		PID:    pid,
		Comm:   fallbackComm,
		Source: SourceFallback,
	}

	status := c.readStatus(pid)
	if status.Name != "" {
		metadata.Comm = status.Name
		metadata.Source = SourceProc
	}
	metadata.UID = status.UID
	metadata.PPID = status.PPID

	if exe, err := os.Readlink(c.procPath(pid, "exe")); err == nil {
		metadata.Exe = exe
	}
	if cmdline, err := os.ReadFile(c.procPath(pid, "cmdline")); err == nil {
		metadata.Cmdline = parseCmdline(cmdline)
	}
	if cgroup, err := os.ReadFile(c.procPath(pid, "cgroup")); err == nil {
		metadata.CgroupPath, metadata.Service, metadata.Container, metadata.PodUID, metadata.Runtime = parseCgroup(cgroup)
	}

	if metadata.PPID != 0 {
		parentStatus := c.readStatus(metadata.PPID)
		metadata.ParentComm = parentStatus.Name
		if exe, err := os.Readlink(c.procPath(metadata.PPID, "exe")); err == nil {
			metadata.ParentExe = exe
		}
		if cmdline, err := os.ReadFile(c.procPath(metadata.PPID, "cmdline")); err == nil {
			metadata.ParentCmdline = parseCmdline(cmdline)
		}
	}

	return metadata
}

type statusSnapshot struct {
	Name string
	PPID uint32
	UID  uint32
}

func (c *Cache) readStatus(pid uint32) statusSnapshot {
	file, err := os.Open(c.procPath(pid, "status"))
	if err != nil {
		return statusSnapshot{}
	}
	defer file.Close()

	snapshot, err := parseStatus(file)
	if err != nil {
		return statusSnapshot{}
	}
	return snapshot
}

func (c *Cache) procPath(pid uint32, name string) string {
	return filepath.Join(c.root, strconv.FormatUint(uint64(pid), 10), name)
}

func parseStatus(r io.Reader) (statusSnapshot, error) {
	var snapshot statusSnapshot
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Name:"):
			snapshot.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "PPid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
			if parsed, err := strconv.ParseUint(value, 10, 32); err == nil {
				snapshot.PPID = uint32(parsed)
			}
		case strings.HasPrefix(line, "Uid:"):
			value := strings.TrimSpace(strings.TrimPrefix(line, "Uid:"))
			fields := strings.Fields(value)
			if len(fields) == 0 {
				continue
			}
			if parsed, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
				snapshot.UID = uint32(parsed)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return statusSnapshot{}, fmt.Errorf("scan status: %w", err)
	}
	return snapshot, nil
}

func parseCmdline(raw []byte) []string {
	trimmed := strings.TrimRight(string(raw), "\x00")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "\x00")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func ValidateRoot(root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("proc root is not a directory")
	}
	return nil
}

var containerPattern = regexp.MustCompile(`(?i)([a-f0-9]{64}|[a-f0-9]{32})`)
var podPattern = regexp.MustCompile(`(?i)pod([0-9a-f_]{8}[-_][0-9a-f_]{4}[-_][0-9a-f_]{4}[-_][0-9a-f_]{4}[-_][0-9a-f_]{12})`)

func parseCgroup(raw []byte) (path, service, container, podUID, runtime string) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		candidate := strings.TrimSpace(parts[2])
		if candidate == "" {
			continue
		}
		path = candidate
		if service == "" {
			service = extractService(candidate)
		}
		if container == "" {
			container = extractContainerID(candidate)
		}
		if podUID == "" {
			podUID = extractPodUID(candidate)
		}
		if runtime == "" {
			runtime = extractRuntime(candidate)
		}
	}
	return path, service, container, podUID, runtime
}

func extractService(path string) string {
	for _, part := range strings.Split(path, "/") {
		if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
			return part
		}
	}
	return ""
}

func extractContainerID(path string) string {
	match := containerPattern.FindString(path)
	return strings.ToLower(match)
}

func extractPodUID(path string) string {
	match := podPattern.FindStringSubmatch(path)
	if len(match) != 2 {
		return ""
	}
	return strings.ReplaceAll(strings.ToLower(match[1]), "_", "-")
}

func extractRuntime(path string) string {
	switch {
	case strings.Contains(path, "cri-containerd"), strings.Contains(path, "containerd"):
		return "containerd"
	case strings.Contains(path, "crio"):
		return "cri-o"
	case strings.Contains(path, "docker"):
		return "docker"
	case strings.Contains(path, "libpod"):
		return "podman"
	default:
		return ""
	}
}
