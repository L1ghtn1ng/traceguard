package eventsink

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
