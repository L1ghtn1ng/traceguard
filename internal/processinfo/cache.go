package processinfo

import (
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type Metadata struct {
	PID              uint32
	StartTime        uint64
	Comm             string
	Source           string
	Exe              string
	Cmdline          []string
	CmdlineTruncated bool
	UID              uint32
	PPID             uint32
	ParentComm       string
	ParentExe        string
	CgroupPath       string
	Service          string
	Container        string
	PodUID           string
	Runtime          string
	LSMLabel         string
	LSMSource        string
	SELinux          string
	AppArmor         string
	AppArmorMode     string
}

const (
	SourceFallback = "fallback"
	SourceProc     = "proc"

	processCachePruneInterval = time.Minute
	maxProcessCacheEntries    = 4096
	maxProcessCmdlineBytes    = 8 << 10
	maxProcessCmdlineArgs     = 128
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
	return c.LookupAt(pid, fallbackComm, 0)
}

// LookupAt enriches an event only when /proc still represents the task
// generation captured by the kernel. A zero expected start time keeps the
// generic Lookup behavior for non-event callers.
func (c *Cache) LookupAt(pid uint32, fallbackComm string, expectedStartTime uint64) (Metadata, bool) {
	now := c.now()

	c.mu.Lock()
	entry, ok := c.entries[pid]
	if ok && now.Before(entry.expiresAt) && (expectedStartTime == 0 || entry.metadata.StartTime == expectedStartTime) {
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
	if expectedStartTime != 0 && metadata.StartTime != expectedStartTime {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return Metadata{PID: pid, Comm: fallbackComm, Source: SourceFallback}, false
	}
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
	if fd < 0 || fd > math.MaxInt32 {
		return false
	}
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
	if cmdline, truncated, err := readFilePrefix(c.procPath(pid, "cmdline"), maxProcessCmdlineBytes); err == nil {
		metadata.Cmdline, metadata.CmdlineTruncated = parseCmdline(cmdline)
		metadata.CmdlineTruncated = metadata.CmdlineTruncated || truncated
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

func readFilePrefix(path string, maxBytes int64) (payload []byte, truncated bool, readErr error) {
	file, err := os.Open(path) //nolint:gosec // procfs path built from a numeric PID and constant names
	if err != nil {
		return nil, false, err
	}
	defer func() {
		readErr = errors.Join(readErr, file.Close())
	}()
	payload, err = io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(payload)) > maxBytes {
		return payload[:maxBytes], true, nil
	}
	return payload, false, nil
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
