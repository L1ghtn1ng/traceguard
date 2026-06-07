package eventsink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

const (
	exportQueueSize      = 1024
	exportReplayInterval = 15 * time.Second
	exportShutdownFlush  = 10 * time.Second
	exportBatchSize      = 50
	exportFlushEvery     = 5 * time.Second
	syslogQueueSize      = 1024
	maxSpoolFiles        = 10000
	maxSpoolBytes        = 256 * 1024 * 1024
	maxSpoolPayloadBytes = 1024 * 1024
)

var exportSpoolPath = "/var/lib/traceguard/export-spool"

type Config struct {
	ArchivePath         string
	BlockedPath         string
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
	logger   *logging.Logger
	archive  *archiveSink
	blocked  *blockedSink
	exporter *exportSink
	syslog   *syslogSink
	now      func() time.Time

	dedupeMu     sync.Mutex
	errorStates  map[string]errorDedupeState
	infoStates   map[string]errorDedupeState
	changeStates map[string]string
}

type record struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"-"`
}

type errorDedupeState struct {
	lastEmitted     time.Time
	suppressedCount uint64
}

func NewRecorder(ctx context.Context, logger *logging.Logger, metrics *telemetry.Registry, cfg Config) (*Recorder, error) {
	recorder := &Recorder{
		logger:       logger,
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
			if recorder.archive != nil {
				_ = recorder.archive.Close()
			}
			return nil, err
		}
		recorder.blocked = blocked
	}
	if strings.TrimSpace(cfg.ExportURL) != "" {
		exporter, err := newExportSink(ctx, cfg, metrics)
		if err != nil {
			if recorder.archive != nil {
				_ = recorder.archive.Close()
			}
			if recorder.blocked != nil {
				_ = recorder.blocked.Close()
			}
			return nil, err
		}
		recorder.exporter = exporter
	}
	if strings.TrimSpace(cfg.SyslogURL) != "" {
		syslog, err := newSyslogSink(ctx, cfg, metrics)
		if err != nil {
			if recorder.archive != nil {
				_ = recorder.archive.Close()
			}
			if recorder.blocked != nil {
				_ = recorder.blocked.Close()
			}
			if recorder.exporter != nil {
				_ = recorder.exporter.Close()
			}
			return nil, err
		}
		recorder.syslog = syslog
	}
	return recorder, nil
}

func (r *Recorder) Close() error {
	var errs []error
	if r.archive != nil {
		errs = append(errs, r.archive.Close())
	}
	if r.blocked != nil {
		errs = append(errs, r.blocked.Close())
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

func (r *Recorder) InfoDedup(msg string, fields map[string]any, ttl time.Duration) {
	r.infoDedupWithKey(msg, fields, ttl, fingerprintRecord("info", msg, fields))
}

func (r *Recorder) InfoDedupFileAudit(msg string, fields map[string]any, ttl time.Duration) {
	r.infoDedupWithKey(msg, fields, ttl, fingerprintFileAuditRecord(msg, fields))
}

func (r *Recorder) infoDedupWithKey(msg string, fields map[string]any, ttl time.Duration, key string) {
	if ttl <= 0 {
		r.emit("info", msg, fields)
		return
	}

	now := r.now().UTC()

	r.dedupeMu.Lock()
	state := r.infoStates[key]
	if !state.lastEmitted.IsZero() && now.Sub(state.lastEmitted) < ttl {
		state.suppressedCount++
		r.infoStates[key] = state
		r.dedupeMu.Unlock()
		return
	}
	suppressedCount := state.suppressedCount
	r.infoStates[key] = errorDedupeState{lastEmitted: now}
	r.dedupeMu.Unlock()

	if suppressedCount > 0 {
		merged := cloneFields(fields)
		merged["suppressed_count"] = suppressedCount
		r.emitAt("info", msg, merged, now)
		return
	}
	r.emitAt("info", msg, fields, now)
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
	if !state.lastEmitted.IsZero() && now.Sub(state.lastEmitted) < ttl {
		state.suppressedCount++
		r.errorStates[key] = state
		r.dedupeMu.Unlock()
		return
	}
	suppressedCount := state.suppressedCount
	r.errorStates[key] = errorDedupeState{lastEmitted: now}
	r.dedupeMu.Unlock()

	if suppressedCount > 0 {
		merged["suppressed_count"] = suppressedCount
	}
	r.emitAt("error", msg, merged, now)
}

func (r *Recorder) InfoIfChanged(msg string, fields map[string]any) bool {
	fingerprint := fingerprintRecord("info", msg, fields)

	r.dedupeMu.Lock()
	if r.changeStates[msg] == fingerprint {
		r.dedupeMu.Unlock()
		return false
	}
	r.changeStates[msg] = fingerprint
	r.dedupeMu.Unlock()

	r.emit("info", msg, fields)
	return true
}

func (r *Recorder) emit(level, msg string, fields map[string]any) {
	r.emitAt(level, msg, fields, r.now().UTC())
}

func (r *Recorder) emitAt(level, msg string, fields map[string]any, timestamp time.Time) {
	if fields == nil {
		fields = map[string]any{}
	}
	r.logger.Log(level, msg, fields)

	entry := record{
		Timestamp: timestamp.Format(time.RFC3339Nano),
		Level:     level,
		Message:   msg,
		Fields:    cloneFields(fields),
	}
	if r.archive != nil {
		r.archive.Write(entry)
	}
	if r.blocked != nil && isBlockedRecord(entry) {
		r.blocked.Write(entry)
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

func (a *archiveSink) Write(entry record) {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		a.metrics.IncEventArchive("error")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.writer.Write(append(payload, '\n')); err != nil {
		a.metrics.IncEventArchive("error")
		return
	}
	a.metrics.IncEventArchive("success")
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

func (b *blockedSink) Write(entry record) {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	_, _ = b.writer.Write(append(payload, '\n'))
}

func (b *blockedSink) Close() error {
	return b.writer.Close()
}

func isBlockedRecord(entry record) bool {
	return entry.Message == "blocked" || strings.HasPrefix(entry.Message, "blocked-")
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
			Timeout:   20 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL == nil || req.URL.Scheme != "https" {
					return errors.New("redirect target must use https")
				}
				return nil
			},
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
	sink.wg.Add(1)
	go func() {
		defer sink.wg.Done()
		sink.run(sinkCtx)
	}()
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
	sinkCtx, cancel := context.WithCancel(ctx)
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
	sink.wg.Add(1)
	go func() {
		defer sink.wg.Done()
		sink.run(sinkCtx)
	}()
	return sink, nil
}

func (s *syslogSink) Enqueue(entry record) {
	payload, err := s.message(entry)
	if err != nil {
		s.metrics.IncEventSyslog("error")
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
		case payload := <-s.queue:
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
		payload = []byte(fmt.Sprintf("%d %s", len(payload), payload))
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
	s.cancel()
	s.wg.Wait()
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

func (e *exportSink) Close() error {
	e.cancel()
	e.wg.Wait()
	return nil
}

type spoolStore struct {
	dir string
	mu  sync.Mutex
}

func newSpoolStore(path string) (*spoolStore, error) {
	cleaned := filepath.Clean(path)
	if err := os.MkdirAll(cleaned, 0o750); err != nil {
		return nil, fmt.Errorf("create export spool directory: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return nil, fmt.Errorf("resolve export spool directory: %w", err)
	}
	if filepath.Clean(resolved) != cleaned {
		return nil, fmt.Errorf("export spool directory %q must not traverse symlinks", cleaned)
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return nil, fmt.Errorf("stat export spool directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("export spool directory %q is not a directory", cleaned)
	}
	return &spoolStore{dir: cleaned}, nil
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
	tempPath := filepath.Join(s.dir, name+".tmp")
	finalPath := filepath.Join(s.dir, name+".json")
	if err := os.WriteFile(tempPath, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func (s *spoolStore) usage(files []string) (int64, error) {
	var total int64
	for _, file := range files {
		path := filepath.Join(s.dir, file)
		if err := rejectSymlink(path); err != nil {
			return 0, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return 0, err
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
		path := filepath.Join(s.dir, file)
		if err := rejectSymlink(path); err != nil {
			return err
		}
		// #nosec G304 -- file is from this spool directory listing, filtered to local .json names, and symlinks are rejected.
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := send(payload); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(s.dir, file)); err != nil {
			return err
		}
	}
	return nil
}

func (s *spoolStore) files() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
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

func marshalSingleRecord(entry record) (json.RawMessage, error) {
	payload := make(map[string]any, len(entry.Fields)+3)
	payload["timestamp"] = entry.Timestamp
	payload["level"] = entry.Level
	payload["message"] = entry.Message
	for key, value := range entry.Fields {
		payload[key] = value
	}
	return json.Marshal(payload)
}

func cloneFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(fields))
	for key, value := range fields {
		cloned[key] = value
	}
	return cloned
}

func spoolFilename() (string, error) {
	var randBytes [6]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(randBytes[:])), nil
}

func rejectSymlink(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("path %q must not be a symlink", path)
	}
	return nil
}
