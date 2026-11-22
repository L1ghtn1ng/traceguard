package eventsink

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"golang.org/x/sys/unix"
)

// Export scopes, chosen with Config.ExportEvents.
const (
	// ExportEventsAll sends every record, for collectors that keep full
	// telemetry.
	ExportEventsAll = "all"
	// ExportEventsAlerts sends only records someone may need to act on:
	// detection alerts, enforcement blocks and would-blocks, responses,
	// commands, errors, heartbeats and agent lifecycle records.
	ExportEventsAlerts = "alerts"
)

const (
	// rejectedDirName holds batches the collector refused outright, beneath
	// the spool directory, so they stop holding back newer batches but stay
	// available for inspection.
	rejectedDirName   = "rejected"
	maxRejectedFiles  = 100
	maxRejectedBytes  = 64 << 20
	maxRetryAfterHold = 10 * time.Minute
	// maxTooLargeRetries bounds how often a spooled batch refused with 413
	// and Retry-After is retried before it is set aside.
	maxTooLargeRetries = 3
)

// exportSpillSize bounds priority records waiting for the spill writer.
const exportSpillSize = 4096

var (
	// errExportHeld marks a batch kept back during a Retry-After pause.
	errExportHeld = errors.New("export paused at the collector's request")
)

// closeSpill stops the spill writer once no more records can arrive.
func (e *exportSink) closeSpill() {
	if e.spill != nil {
		e.spillOnce.Do(func() { close(e.spill) })
	}
}

// errPermanentRejection marks a reply that retrying the same payload cannot
// change: the collector understood the request and refused its content.
var errPermanentRejection = errors.New("collector rejected the batch")

// statusError reports a non-2xx export reply.
type statusError struct {
	code       int
	status     string
	retryAfter time.Duration
	// retryHint reports a valid Retry-After, even one that asks for no wait.
	retryHint bool
}

func (e *statusError) Error() string { return fmt.Sprintf("unexpected status %s", e.status) }

// Is lets errors.Is(err, errPermanentRejection) find replies that must not
// be retried. Authentication failures, throttling and server errors stay
// retryable: they can clear without the payload changing.
func (e *statusError) Is(target error) bool {
	// A refusal that says when to come back, such as a 413 while a
	// collector's limit is lowered, is temporary.
	return target == errPermanentRejection && permanentStatus(e.code) && !e.retryHint
}

func permanentStatus(code int) bool {
	switch code {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

// validRetryAfter reports whether a Retry-After header is delay-seconds or
// an HTTP-date, whatever wait it asks for.
func validRetryAfter(value string) bool {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return seconds >= 0
	}
	_, err := http.ParseTime(value)
	return err == nil
}

// parseRetryAfter reads a Retry-After header as delay-seconds or an
// HTTP-date, bounded to maxRetryAfterHold. Anything else is ignored.
func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var delay time.Duration
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds <= 0 {
			return 0
		}
		if seconds > int64(maxRetryAfterHold/time.Second) {
			return maxRetryAfterHold
		}
		delay = time.Duration(seconds) * time.Second
	} else if at, err := http.ParseTime(value); err == nil {
		delay = at.Sub(now)
	}
	return min(max(delay, 0), maxRetryAfterHold)
}

// isPriorityRecord reports whether a record is one someone may need to act
// on. These are exported under ExportEventsAlerts and are kept ahead of
// routine telemetry when the export queue is full.
func isPriorityRecord(entry record) bool {
	if strings.EqualFold(entry.Level, "error") {
		return true
	}
	if isBlockedRecord(entry) || entry.Message == "would-block" || strings.HasPrefix(entry.Message, "would-block-") {
		return true
	}
	event, _ := entry.Fields["event"].(string)
	switch event {
	case "heartbeat", "detection_alert", "response", "command", "agent_stopping":
		return true
	}
	return event == "blocked" || strings.HasSuffix(event, "_blocked") || strings.HasSuffix(event, "_would_block")
}

// openRejectedDir opens, creating it on first use, the directory beneath the
// spool that holds rejected batches.
func (s *spoolStore) openRejectedDir() (*os.File, error) {
	if s.dir == nil {
		return nil, errors.New("export spool is closed")
	}
	parent := int(s.dir.Fd())
	if err := unix.Mkdirat(parent, rejectedDirName, 0o750); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	return safefile.OpenBeneath(parent, rejectedDirName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
}

// rejectedUsage counts the files and bytes already set aside.
func rejectedUsage(dirfd int) (int, int64, error) {
	dir, err := safefile.OpenBeneath(dirfd, ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return 0, 0, err
	}
	var total int64
	count := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		// Stat through the directory descriptor: DirEntry.Info resolves
		// names against the working directory for a directory opened
		// relative to a descriptor.
		var stat unix.Stat_t
		if err := unix.Fstatat(dirfd, entry.Name(), &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return 0, 0, err
		}
		count++
		total += stat.Size
	}
	return count, total, nil
}

// reject moves a spooled file aside. When the rejected directory is full the
// file is deleted instead, and discarded reports that.
func (s *spoolStore) reject(file string, size int64) (discarded bool, err error) {
	rejected, err := s.openRejectedDir()
	if err != nil {
		return false, err
	}
	defer func() { _ = rejected.Close() }()
	dirfd := int(rejected.Fd())
	count, total, err := rejectedUsage(dirfd)
	if err != nil {
		return false, err
	}
	if count >= maxRejectedFiles || total+size > maxRejectedBytes {
		return true, unix.Unlinkat(int(s.dir.Fd()), file, 0)
	}
	if err := unix.Renameat(int(s.dir.Fd()), file, dirfd, file); err != nil {
		return false, err
	}
	return false, unix.Fsync(dirfd)
}

// writeRejected stores a live batch the collector refused, without first
// placing it in the spool.
func (s *spoolStore) writeRejected(payload []byte) (discarded bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rejected, err := s.openRejectedDir()
	if err != nil {
		return false, err
	}
	defer func() { _ = rejected.Close() }()
	dirfd := int(rejected.Fd())
	count, total, err := rejectedUsage(dirfd)
	if err != nil {
		return false, err
	}
	if count >= maxRejectedFiles || total+int64(len(payload)) > maxRejectedBytes {
		return true, nil
	}
	name, err := spoolFilename()
	if err != nil {
		return false, err
	}
	return false, writeFileBeneath(dirfd, name+s.suffix, payload)
}

// writeFileBeneath durably writes payload to name in the directory dirfd,
// through a temporary file so a crash never leaves a partial entry.
func writeFileBeneath(dirfd int, name string, payload []byte) error {
	tempName := name + ".tmp"
	temp, err := safefile.OpenBeneath(dirfd, tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_ = unix.Unlinkat(dirfd, tempName, 0)
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		return fail(err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fail(err)
	}
	if err := temp.Close(); err != nil {
		return fail(err)
	}
	if err := unix.Renameat(dirfd, tempName, dirfd, name); err != nil {
		return fail(err)
	}
	return unix.Fsync(dirfd)
}
