package eventsink

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type archiveSink struct {
	writer  *logging.RotatingFile
	mu      sync.Mutex
	metrics *telemetry.Registry
}

func newArchiveSink(path string, metrics *telemetry.Registry) (*archiveSink, error) {
	writer, err := logging.NewRotatingFile(path, logging.Options{
		MaxSizeBytes: 1 << 30,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize event archive: %w", err)
	}
	return &archiveSink{writer: writer, metrics: metrics}, nil
}

func (a *archiveSink) Write(entry record) error {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		a.metrics.IncEventArchive("error")
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.writer.Write(append(payload, '\n')); err != nil {
		a.metrics.IncEventArchive("error")
		return err
	}
	a.metrics.IncEventArchive("success")
	return nil
}

func (a *archiveSink) Close() error {
	return a.writer.Close()
}

type blockedSink struct {
	writer *logging.RotatingFile
	mu     sync.Mutex
}

func newBlockedSink(path string) (*blockedSink, error) {
	writer, err := logging.NewRotatingFile(path, logging.Options{
		MaxSizeBytes: 1 << 30,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize blocked event log: %w", err)
	}
	return &blockedSink{writer: writer}, nil
}

func (b *blockedSink) Write(entry record) error {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		return err
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	_, err = b.writer.Write(append(payload, '\n'))
	return err
}

func (b *blockedSink) Close() error {
	return b.writer.Close()
}

func isBlockedRecord(entry record) bool {
	return entry.Message == "blocked" || strings.HasPrefix(entry.Message, "blocked-")
}

type domainSink struct {
	writer    *logging.RotatingFile
	mu        sync.Mutex
	seen      map[string]struct{}
	seenOrder []string
	seenNext  int
	seenLimit int
}

func newDomainSink(path string) (*domainSink, error) {
	writer, err := logging.NewRotatingFile(path, logging.Options{
		MaxSizeBytes: 1 << 30,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize domain log: %w", err)
	}

	sink := &domainSink{
		writer:    writer,
		seen:      make(map[string]struct{}),
		seenLimit: maxRememberedDomains,
	}
	if err := sink.loadSeen(path, 5); err != nil {
		_ = writer.Close()
		return nil, err
	}
	return sink, nil
}

func (d *domainSink) Write(entry record) error {
	value, ok := entry.Fields["domain"].(string)
	if !ok {
		return nil
	}
	domain := normalizeDomainLogValue(value)
	if domain == "" {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[domain]; ok {
		return nil
	}
	if _, err := d.writer.Write([]byte(entry.Timestamp + "\t" + domain + "\n")); err != nil {
		return err
	}
	d.rememberDomain(domain)
	return nil
}

func (d *domainSink) rememberDomain(domain string) {
	if d.seenLimit <= 0 {
		return
	}
	if _, ok := d.seen[domain]; ok {
		return
	}
	if len(d.seenOrder) < d.seenLimit {
		d.seenOrder = append(d.seenOrder, domain)
		d.seen[domain] = struct{}{}
		return
	}

	evicted := d.seenOrder[d.seenNext]
	delete(d.seen, evicted)
	d.seenOrder[d.seenNext] = domain
	d.seenNext = (d.seenNext + 1) % d.seenLimit
	d.seen[domain] = struct{}{}
}

func (d *domainSink) Close() error {
	return d.writer.Close()
}

func (d *domainSink) loadSeen(path string, backups int) error {
	for idx := backups; idx >= 0; idx-- {
		current := path
		if idx > 0 {
			current = fmt.Sprintf("%s.%d", path, idx)
		}
		if err := d.loadSeenFile(current); err != nil {
			return err
		}
	}
	return nil
}

func (d *domainSink) loadSeenFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat domain log %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("domain log %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("domain log %q is not a regular file", path)
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open domain log %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if domain := domainFromLogLine(scanner.Text()); domain != "" {
			d.rememberDomain(domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read domain log %q: %w", path, err)
	}
	return nil
}

func domainFromLogLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	timestamp, domain, ok := strings.Cut(line, "\t")
	if !ok || timestamp == "" {
		return ""
	}
	if _, err := time.Parse(time.RFC3339Nano, timestamp); err != nil {
		return ""
	}
	return normalizeDomainLogValue(domain)
}

func normalizeDomainLogValue(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if !validDomainLogValue(domain) {
		return ""
	}
	return domain
}

func validDomainLogValue(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}

	labelLen := 0
	for idx := 0; idx < len(domain); idx++ {
		ch := domain[idx]
		if ch == '.' {
			if labelLen == 0 || labelLen > 63 {
				return false
			}
			labelLen = 0
			continue
		}
		if !validDomainLogChar(ch) {
			return false
		}
		labelLen++
	}
	return labelLen > 0 && labelLen <= 63
}

func validDomainLogChar(ch byte) bool {
	return ch >= 'a' && ch <= 'z' ||
		ch >= '0' && ch <= '9' ||
		ch == '-' ||
		ch == '_'
}
