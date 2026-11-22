// Package runid names this run of the agent, so a collector can tell a
// restart from records of one run that arrive out of order, and an older run
// from a newer one.
package runid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"golang.org/x/sys/unix"
)

// DefaultPath keeps the counter in TraceGuard's own state directory, apart
// from any configurable file, so it neither moves with nor collides with one.
const DefaultPath = "/var/lib/traceguard/run-sequence"

// lockWait bounds how long Start waits for another start to release the
// counter, so a stalled process cannot hold this one back from monitoring.
const lockWait = 5 * time.Second

// Reserved reports whether path is one of the counter's own files, which no
// configurable file may use.
func Reserved(path string) bool {
	clean := filepath.Clean(path)
	return clean == DefaultPath || clean == DefaultPath+".lock"
}

// ID is random per process start: 16 bytes in hex.
var ID = newID()

// Sequence counts this agent's runs, kept on disk by Start; 0 when unknown.
var Sequence uint64

// Install names the counter file itself: random, made with the file. A new
// one means the counter started again (a reinstall, or lost state), so a
// collector must not judge the new count against the old one.
var Install string

func newID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand does not fail on supported platforms; a fixed value
		// still works, it only loses restart detection.
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(raw[:])
}

// Start increments the run counter kept in path and sets Sequence. A lock
// on path.lock serialises overlapping starts, so two runs never share a
// number. On any error Sequence stays 0, which collectors treat as unknown.
func Start(path string) error {
	if path == "" {
		return nil
	}
	install, next, err := allocate(path)
	if err != nil {
		return err
	}
	Install, Sequence = install, next
	return nil
}

// allocate takes the next number from the counter in path, under the lock,
// with the install ID the file carries. The file holds "<install> <count>".
func allocate(path string) (string, uint64, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", 0, err
	}
	lock, err := os.OpenFile(path+".lock", os.O_RDWR|os.O_CREATE, 0o600) //nolint:gosec // a fixed state path
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = lock.Close() }()
	if err := lockWithin(lock, lockWait); err != nil {
		return "", 0, err
	}
	defer func() { _ = unix.Flock(int(lock.Fd()), unix.LOCK_UN) }()
	install, previous := newID(), uint64(0)
	payload, err := safefile.ReadFile(path, 128)
	switch {
	case err == nil:
		// A file that does not parse starts a new install, counting from 1:
		// a collector sees the new install ID and starts its count over,
		// where refusing the file would leave every later run uncounted.
		if known, count, ok := parseCounter(payload); ok {
			install, previous = known, count
		}
	case errors.Is(err, safefile.ErrTooLarge):
		// No valid counter is that long: start a new install, as above.
	case !errors.Is(err, os.ErrNotExist):
		return "", 0, err
	}
	next := previous + 1
	if err := safefile.WriteFileAtomic(path, []byte(install+" "+strconv.FormatUint(next, 10)+"\n"), 0o600); err != nil {
		return "", 0, err
	}
	return install, next, nil
}

// lockWithin takes an exclusive lock on file, giving up after wait.
func lockWithin(file *os.File, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return err
		}
		if time.Now().After(deadline) {
			return errors.New("run sequence file is locked by another process")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// parseCounter reads "<install> <count>".
func parseCounter(payload []byte) (string, uint64, bool) {
	fields := strings.Fields(string(payload))
	if len(fields) != 2 || len(fields[0]) != 32 {
		return "", 0, false
	}
	if _, err := hex.DecodeString(fields[0]); err != nil {
		return "", 0, false
	}
	// The writer never stores 0, and collectors keep counts as signed
	// 64-bit numbers, so the next count must fit one.
	count, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || count == 0 || count >= math.MaxInt64 {
		return "", 0, false
	}
	return strings.ToLower(fields[0]), count, true
}
