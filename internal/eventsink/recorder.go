package eventsink

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"golang.org/x/sys/unix"
)

const (
	exportQueueSize      = 1024
	exportReplayInterval = 15 * time.Second
	exportShutdownFlush  = 10 * time.Second
	exportBatchSize      = 50
	exportFlushEvery     = 5 * time.Second
	syslogQueueSize      = 1024
	syslogShutdownFlush  = 10 * time.Second
	dedupePruneInterval  = time.Minute
	maxDedupeStates      = 65536
	maxRememberedDomains = 65536
	maxSpoolFiles        = 10000
	maxSpoolBytes        = 256 * 1024 * 1024
	maxSpoolPayloadBytes = 1024 * 1024
)

var exportSpoolPath = "/var/lib/traceguard/export-spool"

type Config struct {
	ArchivePath         string
	BlockedPath         string
	DomainsPath         string
	ExportURL           string
	ExportAuthorization string
	ExportSpool         bool
	ExportCAPath        string
	ExportClientCert    string
	ExportClientKey     string
	SyslogURL           string
	SyslogFacility      string
	SyslogTag           string
	SyslogTimeout       time.Duration
	SyslogCAPath        string
}

type Recorder struct {
	mu       sync.RWMutex
	closed   bool
	logger   *logging.Logger
	archive  *archiveSink
	blocked  *blockedSink
	domains  *domainSink
	exporter *exportSink
	syslog   *syslogSink
	now      func() time.Time
	metrics  *telemetry.Registry

	dedupeMu     sync.Mutex
	errorStates  map[string]errorDedupeState
	infoStates   map[string]errorDedupeState
	changeStates map[string]string
	nextPruneAt  time.Time
}

type record struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"-"`
}

type errorDedupeState struct {
	lastEmitted     time.Time
	expiresAt       time.Time
	suppressedCount uint64
}

func NewRecorder(ctx context.Context, logger *logging.Logger, metrics *telemetry.Registry, cfg Config) (*Recorder, error) {
	recorder := &Recorder{
		logger:       logger,
		metrics:      metrics,
		now:          time.Now,
		errorStates:  make(map[string]errorDedupeState),
		infoStates:   make(map[string]errorDedupeState),
		changeStates: make(map[string]string),
	}
	if strings.TrimSpace(cfg.ArchivePath) != "" {
		archive, err := newArchiveSink(cfg.ArchivePath, metrics)
		if err != nil {
			return nil, err
		}
		recorder.archive = archive
	}
	if strings.TrimSpace(cfg.BlockedPath) != "" {
		blocked, err := newBlockedSink(cfg.BlockedPath)
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		recorder.blocked = blocked
	}
	if strings.TrimSpace(cfg.DomainsPath) != "" {
		domains, err := newDomainSink(cfg.DomainsPath)
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		recorder.domains = domains
	}
	if strings.TrimSpace(cfg.ExportURL) != "" {
		exporter, err := newExportSink(ctx, cfg, metrics)
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		recorder.exporter = exporter
	}
	if strings.TrimSpace(cfg.SyslogURL) != "" {
		syslog, err := newSyslogSink(ctx, cfg, metrics)
		if err != nil {
			_ = recorder.Close()
			return nil, err
		}
		recorder.syslog = syslog
	}
	return recorder, nil
}

func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var errs []error
	if r.archive != nil {
		errs = append(errs, r.archive.Close())
	}
	if r.blocked != nil {
		errs = append(errs, r.blocked.Close())
	}
	if r.domains != nil {
		errs = append(errs, r.domains.Close())
	}
	if r.exporter != nil {
		errs = append(errs, r.exporter.Close())
	}
	if r.syslog != nil {
		errs = append(errs, r.syslog.Close())
	}
	return errors.Join(errs...)
}

func (r *Recorder) Info(msg string, fields map[string]any) {
	r.emit("info", msg, fields)
}

func (r *Recorder) InfoAt(timestamp time.Time, msg string, fields map[string]any) {
	r.emitAt("info", msg, fields, timestamp.UTC())
}

func (r *Recorder) InfoDedup(msg string, fields map[string]any, ttl time.Duration) {
	r.infoDedupWithKey(msg, fields, ttl, fingerprintRecord("info", msg, fields), r.now().UTC())
}

func (r *Recorder) InfoDedupFileAudit(msg string, fields map[string]any, ttl time.Duration) {
	r.infoDedupWithKey(msg, fields, ttl, fingerprintFileAuditRecord(msg, fields), r.now().UTC())
}

func (r *Recorder) InfoDedupFileAuditAt(timestamp time.Time, msg string, fields map[string]any, ttl time.Duration) {
	r.infoDedupWithKey(msg, fields, ttl, fingerprintFileAuditRecord(msg, fields), timestamp.UTC())
}

func (r *Recorder) infoDedupWithKey(msg string, fields map[string]any, ttl time.Duration, key string, timestamp time.Time) {
	if ttl <= 0 {
		r.emitAt("info", msg, fields, timestamp)
		return
	}

	now := r.now().UTC()

	r.dedupeMu.Lock()
	state := r.infoStates[key]
	r.pruneDedupeStatesLocked(now)
	if !state.lastEmitted.IsZero() && now.Sub(state.lastEmitted) < ttl {
		state.suppressedCount++
		state.expiresAt = state.lastEmitted.Add(ttl)
		r.infoStates[key] = state
		limitDedupeStates(r.infoStates, key)
		r.dedupeMu.Unlock()
		return
	}
	suppressedCount := state.suppressedCount
	r.infoStates[key] = errorDedupeState{lastEmitted: now, expiresAt: now.Add(ttl)}
	limitDedupeStates(r.infoStates, key)
	r.dedupeMu.Unlock()

	if suppressedCount > 0 {
		merged := cloneFields(fields)
		merged["suppressed_count"] = suppressedCount
		r.emitAt("info", msg, merged, timestamp)
		return
	}
	r.emitAt("info", msg, fields, timestamp)
}

func (r *Recorder) Error(msg string, err error, fields map[string]any) {
	merged := cloneFields(fields)
	if err != nil {
		merged["error"] = err.Error()
	}
	r.emit("error", msg, merged)
}

func (r *Recorder) ErrorDedup(msg string, err error, fields map[string]any, ttl time.Duration) {
	merged := cloneFields(fields)
	if err != nil {
		merged["error"] = err.Error()
	}
	if ttl <= 0 {
		r.emit("error", msg, merged)
		return
	}

	now := r.now().UTC()
	key := msg + "\x00" + fmt.Sprint(merged["error"])

	r.dedupeMu.Lock()
	state := r.errorStates[key]
	r.pruneDedupeStatesLocked(now)
	if !state.lastEmitted.IsZero() && now.Sub(state.lastEmitted) < ttl {
		state.suppressedCount++
		state.expiresAt = state.lastEmitted.Add(ttl)
		r.errorStates[key] = state
		limitDedupeStates(r.errorStates, key)
		r.dedupeMu.Unlock()
		return
	}
	suppressedCount := state.suppressedCount
	r.errorStates[key] = errorDedupeState{lastEmitted: now, expiresAt: now.Add(ttl)}
	limitDedupeStates(r.errorStates, key)
	r.dedupeMu.Unlock()

	if suppressedCount > 0 {
		merged["suppressed_count"] = suppressedCount
	}
	r.emitAt("error", msg, merged, now)
}

func (r *Recorder) pruneDedupeStatesLocked(now time.Time) {
	if !r.nextPruneAt.IsZero() && now.Before(r.nextPruneAt) {
		return
	}
	pruneExpiredDedupeStates(r.infoStates, now)
	pruneExpiredDedupeStates(r.errorStates, now)
	r.nextPruneAt = now.Add(dedupePruneInterval)
}

func pruneExpiredDedupeStates(states map[string]errorDedupeState, now time.Time) {
	for key, state := range states {
		if !state.expiresAt.After(now) {
			delete(states, key)
		}
	}
}

func limitDedupeStates(states map[string]errorDedupeState, preserve string) {
	for len(states) > maxDedupeStates {
		for key := range states {
			if key == preserve {
				continue
			}
			delete(states, key)
			break
		}
	}
}

func limitChangeStates(states map[string]string, preserve string) {
	for len(states) > maxDedupeStates {
		for key := range states {
			if key == preserve {
				continue
			}
			delete(states, key)
			break
		}
	}
}

func (r *Recorder) InfoIfChanged(msg string, fields map[string]any) bool {
	fingerprint := fingerprintRecord("info", msg, fields)

	r.dedupeMu.Lock()
	if r.changeStates[msg] == fingerprint {
		r.dedupeMu.Unlock()
		return false
	}
	r.changeStates[msg] = fingerprint
	limitChangeStates(r.changeStates, msg)
	r.dedupeMu.Unlock()

	r.emit("info", msg, fields)
	return true
}

func (r *Recorder) emit(level, msg string, fields map[string]any) {
	r.emitAt(level, msg, fields, r.now().UTC())
}

func (r *Recorder) emitAt(level, msg string, fields map[string]any, timestamp time.Time) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return
	}
	if fields == nil {
		fields = map[string]any{}
	}
	if err := r.logger.LogAt(timestamp, level, msg, fields); err != nil {
		r.metrics.SetEventSinkHealthy("primary", false)
	} else {
		r.metrics.SetEventSinkHealthy("primary", true)
	}

	entry := record{
		Timestamp: timestamp.Format(time.RFC3339Nano),
		Level:     level,
		Message:   msg,
		Fields:    cloneFields(fields),
	}
	if r.archive != nil {
		if err := r.archive.Write(entry); err != nil {
			r.metrics.SetEventSinkHealthy("archive", false)
		} else {
			r.metrics.SetEventSinkHealthy("archive", true)
		}
	}
	if r.blocked != nil && isBlockedRecord(entry) {
		if err := r.blocked.Write(entry); err != nil {
			r.metrics.SetEventSinkHealthy("blocked", false)
		} else {
			r.metrics.SetEventSinkHealthy("blocked", true)
		}
	}
	if r.domains != nil {
		if err := r.domains.Write(entry); err != nil {
			r.metrics.SetEventSinkHealthy("domains", false)
		} else {
			r.metrics.SetEventSinkHealthy("domains", true)
		}
	}
	if r.exporter != nil {
		r.exporter.Enqueue(entry)
	}
	if r.syslog != nil {
		r.syslog.Enqueue(entry)
	}
}

func fingerprintRecord(level, msg string, fields map[string]any) string {
	payload, err := json.Marshal(struct {
		Level   string         `json:"level"`
		Message string         `json:"message"`
		Fields  map[string]any `json:"fields"`
	}{
		Level:   level,
		Message: msg,
		Fields:  cloneFields(fields),
	})
	if err != nil {
		return fmt.Sprintf("%s|%s|%v", level, msg, fields)
	}
	return string(payload)
}

func fingerprintFileAuditRecord(msg string, fields map[string]any) string {
	stable := make(map[string]any, 20)
	for _, key := range []string{
		"event",
		"path",
		"file_access",
		"file_flags",
		"file_mode",
		"program",
		"exe",
		"cmdline",
		"uid",
		"cgroup",
		"service",
		"container_id",
		"pod_uid",
		"runtime",
		"lsm_label",
		"lsm_source",
		"selinux_context",
		"apparmor_profile",
		"apparmor_mode",
		"k8s_namespace",
		"k8s_pod",
		"k8s_node",
		"k8s_service_account",
		"k8s_owner_kind",
		"k8s_owner",
		"k8s_app",
	} {
		if value, ok := fields[key]; ok {
			stable[key] = value
		}
	}
	if fileAuditProcessAttributionIncomplete(fields) {
		for _, key := range []string{"pid", "ppid"} {
			if value, ok := fields[key]; ok {
				stable[key] = value
			}
		}
	}
	return fingerprintRecord("info", msg, stable)
}

func fileAuditProcessAttributionIncomplete(fields map[string]any) bool {
	return !hasNonEmptyField(fields, "exe") && !hasNonEmptyField(fields, "cmdline")
}

func hasNonEmptyField(fields map[string]any, key string) bool {
	value, ok := fields[key]
	if !ok || value == nil {
		return false
	}
	switch typed := value.(type) {
	case string:
		return typed != ""
	case []string:
		return len(typed) > 0
	case []any:
		return len(typed) > 0
	default:
		return true
	}
}

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

type exportSink struct {
	client        *http.Client
	target        string
	authorization string
	queue         chan json.RawMessage
	metrics       *telemetry.Registry
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	spool         *spoolStore
}

func newExportSink(ctx context.Context, cfg Config, metrics *telemetry.Registry) (*exportSink, error) {
	parsed, err := neturl.Parse(cfg.ExportURL)
	if err != nil {
		return nil, fmt.Errorf("parse export url: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("export url must use https://")
	}

	sinkCtx, cancel := context.WithCancel(ctx)
	transport, err := newExportTransport(cfg)
	if err != nil {
		cancel()
		return nil, err
	}

	var spool *spoolStore
	if cfg.ExportSpool {
		spool, err = newSpoolStore(exportSpoolPath)
		if err != nil {
			cancel()
			return nil, err
		}
	}

	sink := &exportSink{
		client: &http.Client{
			Timeout:       20 * time.Second,
			Transport:     transport,
			CheckRedirect: checkHTTPSRedirect,
		},
		target:        parsed.String(),
		authorization: strings.TrimSpace(cfg.ExportAuthorization),
		queue:         make(chan json.RawMessage, exportQueueSize),
		metrics:       metrics,
		cancel:        cancel,
		spool:         spool,
	}
	sink.updateQueueDepth()
	sink.updateSpoolFiles()
	sink.wg.Go(func() {
		sink.run(sinkCtx)
	})
	return sink, nil
}

func (e *exportSink) Enqueue(entry record) {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		e.metrics.IncEventExport("error")
		return
	}
	select {
	case e.queue <- payload:
		e.metrics.IncEventExport("queued")
		e.updateQueueDepth()
	default:
		e.metrics.IncEventExport("dropped")
		e.metrics.SetEventExportLastError()
		e.updateQueueDepth()
	}
}

func (e *exportSink) run(ctx context.Context) {
	flushTicker := time.NewTicker(exportFlushEvery)
	defer flushTicker.Stop()
	replayTicker := time.NewTicker(exportReplayInterval)
	defer replayTicker.Stop()

	batch := make([]json.RawMessage, 0, exportBatchSize)
	flush := func(flushCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		if err := e.sendBatch(flushCtx, batch); err != nil {
			e.metrics.IncEventExport("error")
			e.metrics.SetEventExportLastError()
			if e.spool != nil {
				if spoolErr := e.spool.Write(batch); spoolErr == nil {
					e.metrics.IncEventExport("spooled")
					e.updateSpoolFiles()
				} else {
					e.metrics.IncEventExport("spool_error")
					e.metrics.SetEventExportLastError()
				}
			}
		} else {
			e.metrics.IncEventExport("success")
			e.metrics.SetEventExportLastSuccess()
		}
		batch = batch[:0]
	}
	shutdown := func() {
		for {
			select {
			case payload := <-e.queue:
				batch = append(batch, payload)
				e.updateQueueDepth()
			default:
				shutdownCtx, cancel := context.WithTimeout(context.Background(), exportShutdownFlush)
				defer cancel()
				// The worker context is already canceled during Close; use a short
				// independent context so the final batch can be delivered or spooled.
				flush(shutdownCtx)
				return
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			shutdown()
			return
		case payload := <-e.queue:
			batch = append(batch, payload)
			e.updateQueueDepth()
			if len(batch) >= exportBatchSize {
				flush(ctx)
			}
		case <-flushTicker.C:
			flush(ctx)
		case <-replayTicker.C:
			if e.spool == nil {
				continue
			}
			_ = e.spool.Replay(func(payload []byte) error {
				if err := e.sendPayload(ctx, payload); err != nil {
					e.metrics.IncEventExport("replay_error")
					e.metrics.SetEventExportLastError()
					return err
				}
				e.metrics.IncEventExport("replayed")
				e.metrics.SetEventExportLastSuccess()
				return nil
			})
			e.updateSpoolFiles()
		}
	}
}

func (e *exportSink) updateQueueDepth() {
	e.metrics.SetEventExportQueueDepth(len(e.queue))
}

func (e *exportSink) updateSpoolFiles() {
	if e.spool == nil {
		e.metrics.SetEventExportSpoolFiles(0)
		return
	}
	files, err := e.spool.files()
	if err != nil {
		e.metrics.SetEventExportLastError()
		return
	}
	e.metrics.SetEventExportSpoolFiles(len(files))
}

func (e *exportSink) sendBatch(ctx context.Context, batch []json.RawMessage) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	return e.sendPayload(ctx, payload)
}

func (e *exportSink) sendPayload(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.authorization != "" {
		req.Header.Set("Authorization", e.authorization)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

type syslogSink struct {
	mu         sync.Mutex
	closed     bool
	network    string
	address    string
	serverName string
	facility   int
	tag        string
	timeout    time.Duration
	tlsConfig  *tls.Config
	queue      chan []byte
	metrics    *telemetry.Registry
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	hostname   string
}

func newSyslogSink(ctx context.Context, cfg Config, metrics *telemetry.Registry) (*syslogSink, error) {
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.SyslogURL))
	if err != nil {
		return nil, fmt.Errorf("parse event syslog url: %w", err)
	}
	network, tlsEnabled, err := syslogNetwork(parsed.Scheme)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" || port == "" {
		return nil, errors.New("event syslog url must include host and port")
	}
	facility, ok := syslogFacilityCode(cfg.SyslogFacility)
	if !ok {
		return nil, fmt.Errorf("unsupported event syslog facility %q", cfg.SyslogFacility)
	}
	tag := strings.TrimSpace(cfg.SyslogTag)
	if tag == "" || strings.ContainsAny(tag, " \t\r\n") {
		return nil, errors.New("event syslog tag must be non-empty and must not contain whitespace")
	}
	if cfg.SyslogTimeout <= 0 {
		return nil, errors.New("event syslog timeout must be positive")
	}

	var tlsConfig *tls.Config
	if tlsEnabled {
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		if strings.TrimSpace(cfg.SyslogCAPath) != "" {
			pem, err := os.ReadFile(cfg.SyslogCAPath)
			if err != nil {
				return nil, fmt.Errorf("read event syslog ca: %w", err)
			}
			if !rootCAs.AppendCertsFromPEM(pem) {
				return nil, errors.New("append event syslog ca: no certificates found")
			}
		}
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
			ServerName: host,
		}
	}

	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "-"
	}
	sinkCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	sink := &syslogSink{
		network:    network,
		address:    net.JoinHostPort(host, port),
		serverName: host,
		facility:   facility,
		tag:        tag,
		timeout:    cfg.SyslogTimeout,
		tlsConfig:  tlsConfig,
		queue:      make(chan []byte, syslogQueueSize),
		metrics:    metrics,
		cancel:     cancel,
		hostname:   sanitizeSyslogToken(hostname),
	}
	sink.wg.Go(func() {
		sink.run(sinkCtx)
	})
	return sink, nil
}

func (s *syslogSink) Enqueue(entry record) {
	payload, err := s.message(entry)
	if err != nil {
		s.metrics.IncEventSyslog("error")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.metrics.IncEventSyslog("dropped")
		return
	}
	select {
	case s.queue <- payload:
		s.metrics.IncEventSyslog("queued")
	default:
		s.metrics.IncEventSyslog("dropped")
	}
}

func (s *syslogSink) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-s.queue:
			if !ok {
				return
			}
			if err := s.send(payload); err != nil {
				s.metrics.IncEventSyslog("error")
				continue
			}
			s.metrics.IncEventSyslog("success")
		}
	}
}

func (s *syslogSink) send(payload []byte) error {
	dialer := &net.Dialer{Timeout: s.timeout}
	var conn net.Conn
	var err error
	if s.tlsConfig != nil {
		conn, err = tls.DialWithDialer(dialer, s.network, s.address, s.tlsConfig)
	} else {
		conn, err = dialer.Dial(s.network, s.address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	if s.network == "tcp" {
		payload = fmt.Appendf(nil, "%d %s", len(payload), payload)
	}
	_, err = conn.Write(payload)
	return err
}

func (s *syslogSink) message(entry record) ([]byte, error) {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		return nil, err
	}
	priority := s.facility*8 + syslogSeverity(entry.Level)
	timestamp := strings.TrimSpace(entry.Timestamp)
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	message := fmt.Sprintf("<%d>1 %s %s %s - - - %s", priority, timestamp, s.hostname, s.tag, payload)
	return []byte(message), nil
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(syslogShutdownFlush):
		s.cancel()
		<-done
	}
	s.cancel()
	return nil
}

func syslogNetwork(scheme string) (network string, tlsEnabled bool, err error) {
	switch scheme {
	case "syslog+udp":
		return "udp", false, nil
	case "syslog+tcp":
		return "tcp", false, nil
	case "syslog+tls":
		return "tcp", true, nil
	default:
		return "", false, errors.New("event syslog url must use syslog+udp://, syslog+tcp://, or syslog+tls://")
	}
}

func syslogFacilityCode(facility string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(facility)) {
	case "kern":
		return 0, true
	case "user":
		return 1, true
	case "mail":
		return 2, true
	case "daemon":
		return 3, true
	case "auth":
		return 4, true
	case "syslog":
		return 5, true
	case "lpr":
		return 6, true
	case "news":
		return 7, true
	case "uucp":
		return 8, true
	case "cron":
		return 9, true
	case "authpriv":
		return 10, true
	case "ftp":
		return 11, true
	case "local0":
		return 16, true
	case "local1":
		return 17, true
	case "local2":
		return 18, true
	case "local3":
		return 19, true
	case "local4":
		return 20, true
	case "local5":
		return 21, true
	case "local6":
		return 22, true
	case "local7":
		return 23, true
	default:
		return 0, false
	}
}

func syslogSeverity(level string) int {
	if strings.EqualFold(strings.TrimSpace(level), "error") {
		return 3
	}
	return 6
}

func sanitizeSyslogToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return "-"
	}
	return value
}

func newExportTransport(cfg Config) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if strings.TrimSpace(cfg.ExportCAPath) != "" {
		pem, err := os.ReadFile(cfg.ExportCAPath)
		if err != nil {
			return nil, fmt.Errorf("read event export ca: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("append event export ca: no certificates found")
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}
	if strings.TrimSpace(cfg.ExportClientCert) != "" || strings.TrimSpace(cfg.ExportClientKey) != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ExportClientCert, cfg.ExportClientKey)
		if err != nil {
			return nil, fmt.Errorf("load event export client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}, nil
}

func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL == nil || req.URL.Scheme != "https" {
		return errors.New("redirect target must use https")
	}
	if len(via) == 0 || via[0].URL == nil || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return errors.New("redirect target must use the original origin")
	}
	return nil
}

func (e *exportSink) Close() error {
	e.cancel()
	e.wg.Wait()
	if e.spool != nil {
		return e.spool.Close()
	}
	return nil
}

type spoolStore struct {
	dir *os.File
	mu  sync.Mutex
}

func newSpoolStore(path string) (*spoolStore, error) {
	cleaned := filepath.Clean(path)
	if err := os.MkdirAll(cleaned, 0o750); err != nil {
		return nil, fmt.Errorf("create export spool directory: %w", err)
	}
	dir, err := safefile.OpenAbsolute(cleaned, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("export spool directory %q must not traverse symlinks: %w", cleaned, err)
	}
	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("stat export spool directory: %w", err)
	}
	if !info.IsDir() {
		_ = dir.Close()
		return nil, fmt.Errorf("export spool directory %q is not a directory", cleaned)
	}
	return &spoolStore{dir: dir}, nil
}

func (s *spoolStore) Write(batch []json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.files()
	if err != nil {
		return err
	}
	if len(existing) >= maxSpoolFiles {
		return fmt.Errorf("export spool capacity exceeded")
	}

	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	if len(payload) > maxSpoolPayloadBytes {
		return fmt.Errorf("export spool payload exceeds %d bytes", maxSpoolPayloadBytes)
	}
	usage, err := s.usage(existing)
	if err != nil {
		return err
	}
	if usage+int64(len(payload)) > maxSpoolBytes {
		return fmt.Errorf("export spool byte capacity exceeded")
	}

	name, err := spoolFilename()
	if err != nil {
		return err
	}
	tempName := name + ".tmp"
	finalName := name + ".json"
	temp, err := safefile.OpenBeneath(int(s.dir.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	if err := unix.Renameat(int(s.dir.Fd()), tempName, int(s.dir.Fd()), finalName); err != nil {
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	return unix.Fsync(int(s.dir.Fd()))
}

func (s *spoolStore) usage(files []string) (int64, error) {
	var total int64
	for _, file := range files {
		entry, err := safefile.OpenBeneath(int(s.dir.Fd()), file, unix.O_RDONLY, 0)
		if err != nil {
			return 0, err
		}
		info, err := entry.Stat()
		_ = entry.Close()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("spool entry %q is not a regular file", file)
		}
		total += info.Size()
		if total > maxSpoolBytes {
			return total, nil
		}
	}
	return total, nil
}

func (s *spoolStore) Replay(send func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := s.files()
	if err != nil {
		return err
	}
	for _, file := range files {
		payload, err := safefile.ReadFileBeneath(int(s.dir.Fd()), file, maxSpoolPayloadBytes)
		if err != nil {
			return err
		}
		if err := send(payload); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(s.dir.Fd()), file, 0); err != nil {
			return err
		}
	}
	return nil
}

func (s *spoolStore) files() ([]string, error) {
	dir, err := safefile.OpenBeneath(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !filepath.IsLocal(entry.Name()) {
			continue
		}
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	return out, nil
}

func (s *spoolStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return nil
	}
	err := s.dir.Close()
	s.dir = nil
	return err
}

func marshalSingleRecord(entry record) (json.RawMessage, error) {
	payload := make(map[string]any, len(entry.Fields)+3)
	payload["timestamp"] = entry.Timestamp
	payload["level"] = entry.Level
	payload["message"] = entry.Message
	for key, value := range entry.Fields {
		if key == "timestamp" || key == "level" || key == "message" {
			continue
		}
		payload[key] = value
	}
	return json.Marshal(payload)
}

func cloneFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(fields))
	maps.Copy(cloned, fields)
	return cloned
}

func spoolFilename() (string, error) {
	var randBytes [6]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(randBytes[:])), nil
}
