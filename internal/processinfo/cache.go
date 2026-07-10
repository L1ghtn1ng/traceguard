package processinfo

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Metadata struct {
	PID          uint32
	StartTime    uint64
	Comm         string
	Source       string
	Exe          string
	Cmdline      []string
	UID          uint32
	PPID         uint32
	ParentComm   string
	ParentExe    string
	CgroupPath   string
	Service      string
	Container    string
	PodUID       string
	Runtime      string
	LSMLabel     string
	LSMSource    string
	SELinux      string
	AppArmor     string
	AppArmorMode string
}

const (
	SourceFallback = "fallback"
	SourceProc     = "proc"

	processCachePruneInterval = time.Minute
	maxProcessCacheEntries    = 4096
)

type Cache struct {
	mu          sync.Mutex
	root        string
	ttl         time.Duration
	now         func() time.Time
	nextPruneAt time.Time
	entries     map[uint32]cacheEntry
	sequence    uint64
	usePidfds   bool
}

type cacheEntry struct {
	expiresAt time.Time
	metadata  Metadata
	pidfd     int
	lastUsed  uint64
}

func NewCache(root string, ttl time.Duration) *Cache {
	if root == "" {
		root = "/proc"
	}
	return &Cache{
		root:      root,
		ttl:       ttl,
		now:       time.Now,
		entries:   make(map[uint32]cacheEntry),
		usePidfds: root == "/proc",
	}
}

func (c *Cache) Lookup(pid uint32, fallbackComm string) (Metadata, bool) {
	now := c.now()

	c.mu.Lock()
	entry, ok := c.entries[pid]
	if ok && now.Before(entry.expiresAt) {
		if (entry.pidfd >= 0 && pidfdAlive(entry.pidfd)) || (entry.pidfd < 0 && c.sameProcess(pid, entry.metadata.StartTime)) {
			c.sequence++
			entry.lastUsed = c.sequence
			c.entries[pid] = entry
			c.mu.Unlock()
			return entry.metadata, true
		}
	}
	if ok {
		c.closeEntry(entry)
		delete(c.entries, pid)
	}
	c.mu.Unlock()

	pidfd := -1
	if c.usePidfds {
		if fd, err := unix.PidfdOpen(int(pid), 0); err == nil {
			pidfd = fd
		}
	}
	metadata := c.readMetadata(pid, fallbackComm)
	if pidfd >= 0 && !pidfdAlive(pidfd) {
		_ = unix.Close(pidfd)
		pidfd = -1
		metadata = Metadata{PID: pid, Comm: fallbackComm, Source: SourceFallback}
	}

	c.mu.Lock()
	c.pruneExpiredLocked(now)
	c.evictLRULocked()
	c.sequence++
	c.storeEntryLocked(pid, cacheEntry{
		expiresAt: now.Add(c.ttl),
		metadata:  metadata,
		pidfd:     pidfd,
		lastUsed:  c.sequence,
	})
	c.mu.Unlock()

	return metadata, false
}

func (c *Cache) storeEntryLocked(pid uint32, entry cacheEntry) {
	if existing, ok := c.entries[pid]; ok {
		c.closeEntry(existing)
	}
	c.entries[pid] = entry
}

func (c *Cache) Invalidate(pid uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[pid]; ok {
		c.closeEntry(entry)
	}
	delete(c.entries, pid)
}

func (c *Cache) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for pid, entry := range c.entries {
		c.closeEntry(entry)
		delete(c.entries, pid)
	}
	return nil
}

func (c *Cache) pruneExpiredLocked(now time.Time) {
	if !c.nextPruneAt.IsZero() && now.Before(c.nextPruneAt) {
		return
	}
	for pid, entry := range c.entries {
		if !now.Before(entry.expiresAt) {
			c.closeEntry(entry)
			delete(c.entries, pid)
		}
	}
	c.nextPruneAt = now.Add(processCachePruneInterval)
}

func (c *Cache) evictLRULocked() {
	for len(c.entries) >= maxProcessCacheEntries {
		var oldestPID uint32
		var oldest cacheEntry
		first := true
		for pid, entry := range c.entries {
			if first || entry.lastUsed < oldest.lastUsed {
				oldestPID, oldest, first = pid, entry, false
			}
		}
		c.closeEntry(oldest)
		delete(c.entries, oldestPID)
	}
}

func (c *Cache) closeEntry(entry cacheEntry) {
	if entry.pidfd >= 0 {
		_ = unix.Close(entry.pidfd)
	}
}

func pidfdAlive(fd int) bool {
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(poll, 0)
	return err == nil && n == 0
}

func (c *Cache) readMetadata(pid uint32, fallbackComm string) Metadata {
	metadata := Metadata{
		PID:    pid,
		Comm:   fallbackComm,
		Source: SourceFallback,
	}

	startTime := c.readStartTime(pid)
	if startTime == 0 {
		return metadata
	}
	status := c.readStatus(pid)
	if status.Name != "" {
		metadata.Comm = status.Name
		metadata.Source = SourceProc
	}
	metadata.UID = status.UID
	metadata.PPID = status.PPID
	metadata.StartTime = startTime

	if exe, err := os.Readlink(c.procPath(pid, "exe")); err == nil {
		metadata.Exe = exe
	}
	if cmdline, err := os.ReadFile(c.procPath(pid, "cmdline")); err == nil {
		metadata.Cmdline = parseCmdline(cmdline)
	}
	if cgroup, err := os.ReadFile(c.procPath(pid, "cgroup")); err == nil {
		metadata.CgroupPath, metadata.Service, metadata.Container, metadata.PodUID, metadata.Runtime = parseCgroup(cgroup)
	}
	metadata.LSMLabel, metadata.LSMSource, metadata.SELinux, metadata.AppArmor, metadata.AppArmorMode = c.readLSMMetadata(pid)

	if metadata.PPID != 0 {
		parentStatus := c.readStatus(metadata.PPID)
		metadata.ParentComm = parentStatus.Name
		if exe, err := os.Readlink(c.procPath(metadata.PPID, "exe")); err == nil {
			metadata.ParentExe = exe
		}
	}
	if currentStartTime := c.readStartTime(pid); currentStartTime == 0 || currentStartTime != startTime {
		return Metadata{PID: pid, Comm: fallbackComm, Source: SourceFallback}
	}

	return metadata
}

func (c *Cache) sameProcess(pid uint32, cachedStartTime uint64) bool {
	if cachedStartTime == 0 {
		return false
	}
	return c.readStartTime(pid) == cachedStartTime
}

func (c *Cache) readLSMMetadata(pid uint32) (label, source, selinux, apparmor, apparmorMode string) {
	var apparmorLabel string
	if raw, err := os.ReadFile(c.procPath(pid, "attr", "apparmor", "current")); err == nil {
		apparmor, apparmorMode = parseAppArmorLabel(string(raw))
		if apparmor != "" {
			apparmorLabel = strings.TrimSpace(string(raw))
		}
	}

	raw, err := os.ReadFile(c.procPath(pid, "attr", "current"))
	if err != nil {
		if apparmorLabel != "" {
			return apparmorLabel, "apparmor", selinux, apparmor, apparmorMode
		}
		return label, source, selinux, apparmor, apparmorMode
	}
	current := strings.TrimSpace(string(raw))
	if current == "" {
		if apparmorLabel != "" {
			return apparmorLabel, "apparmor", selinux, apparmor, apparmorMode
		}
		return label, source, selinux, apparmor, apparmorMode
	}
	label = current
	if looksLikeSELinuxContext(current) {
		selinux = current
		source = "selinux"
		return label, source, selinux, apparmor, apparmorMode
	}
	if apparmor == "" {
		apparmor, apparmorMode = parseAppArmorLabel(current)
	}
	if apparmor != "" {
		source = "apparmor"
	}
	return label, source, selinux, apparmor, apparmorMode
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

func (c *Cache) readStartTime(pid uint32) uint64 {
	raw, err := os.ReadFile(c.procPath(pid, "stat"))
	if err != nil {
		return 0
	}
	startTime, err := parseStatStartTime(string(raw))
	if err != nil {
		return 0
	}
	return startTime
}

func (c *Cache) procPath(pid uint32, names ...string) string {
	pidString := strconv.FormatUint(uint64(pid), 10)
	size := len(c.root) + 1 + len(pidString)
	for _, name := range names {
		size += 1 + len(name)
	}

	var builder strings.Builder
	builder.Grow(size)
	builder.WriteString(c.root)
	if c.root[len(c.root)-1] != os.PathSeparator {
		builder.WriteByte(os.PathSeparator)
	}
	builder.WriteString(pidString)
	for _, name := range names {
		if name == "" {
			continue
		}
		builder.WriteByte(os.PathSeparator)
		builder.WriteString(name)
	}
	return builder.String()
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

func parseStatStartTime(raw string) (uint64, error) {
	raw = strings.TrimSpace(raw)
	closeComm := strings.LastIndex(raw, ")")
	if closeComm == -1 || closeComm+2 >= len(raw) {
		return 0, errors.New("malformed stat")
	}
	fields := strings.Fields(raw[closeComm+2:])
	if len(fields) < 20 {
		return 0, errors.New("stat missing starttime")
	}
	return strconv.ParseUint(fields[19], 10, 64)
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

func parseCgroup(raw []byte) (path, service, container, podUID, runtime string) {
	lines := strings.SplitSeq(strings.TrimSpace(string(raw)), "\n")
	for line := range lines {
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
	for part := range strings.SplitSeq(path, "/") {
		if strings.HasSuffix(part, ".service") || strings.HasSuffix(part, ".scope") {
			return part
		}
	}
	return ""
}

func extractContainerID(path string) string {
	for i := 0; i < len(path); i++ {
		if !isHex(path[i]) {
			continue
		}
		j := i + 1
		for j < len(path) && isHex(path[j]) {
			j++
		}
		switch j - i {
		case 64, 32:
			return strings.ToLower(path[i:j])
		}
		i = j
	}
	return ""
}

func extractPodUID(path string) string {
	for i := 0; i+3 < len(path); i++ {
		if !strings.EqualFold(path[i:i+3], "pod") {
			continue
		}
		start := i + 3
		end := start + 36
		if end > len(path) || !isPodUID(path[start:end]) {
			continue
		}
		return strings.ReplaceAll(strings.ToLower(path[start:end]), "_", "-")
	}
	return ""
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

func looksLikeSELinuxContext(value string) bool {
	parts := strings.Split(value, ":")
	return len(parts) >= 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

func parseAppArmorLabel(value string) (profile, mode string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ""
	}
	open := strings.LastIndex(value, " (")
	if open == -1 || !strings.HasSuffix(value, ")") {
		return value, ""
	}
	profile = strings.TrimSpace(value[:open])
	mode = strings.TrimSuffix(value[open+2:], ")")
	return profile, strings.TrimSpace(mode)
}

func isHex(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F'
}

func isPodUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for i := 0; i < len(value); i++ {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' && value[i] != '_' {
				return false
			}
		default:
			if !isHex(value[i]) {
				return false
			}
		}
	}
	return true
}
