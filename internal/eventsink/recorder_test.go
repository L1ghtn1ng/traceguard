package eventsink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestRecorderWritesArchive(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "traceguard.log")
	logWriter, err := logging.NewRotatingFile(logPath, logging.Options{
		MaxSizeBytes: 1 << 20,
		MaxBackups:   2,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		t.Fatalf("NewRotatingFile returned error: %v", err)
	}
	defer logWriter.Close()

	logger, err := logging.NewLogger(logWriter, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	archivePath := filepath.Join(t.TempDir(), "events.jsonl")
	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{
		ArchivePath: archivePath,
	})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	defer recorder.Close()

	recorder.Info("dns", map[string]any{
		"domain":  "example.com",
		"program": "curl",
	})

	content, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	text := string(content)
	for _, want := range []string{`"message":"dns"`, `"domain":"example.com"`, `"program":"curl"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("archive missing %q in %q", want, text)
		}
	}
}

func TestRecorderInfoAtUsesEventOccurrenceTimestamp(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	timestamp := time.Date(2026, time.July, 10, 12, 34, 56, 123, time.UTC)
	recorder.InfoAt(timestamp, "dns", map[string]any{"domain": "example.com"})
	lines := decodeLogLines(t, buffer)
	if len(lines) != 1 || lines[0]["timestamp"] != timestamp.Format(time.RFC3339Nano) {
		t.Fatalf("recorded timestamp = %#v, want %s", lines, timestamp.Format(time.RFC3339Nano))
	}
}

func TestRecorderMarksHealthUnhealthyOnLocalSinkFailure(t *testing.T) {
	t.Parallel()

	logger, err := logging.NewLogger(io.Discard, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	metrics := telemetry.NewRegistry()
	recorder, err := NewRecorder(t.Context(), logger, metrics, Config{ArchivePath: filepath.Join(t.TempDir(), "events.jsonl")})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	defer recorder.Close()
	if err := recorder.archive.writer.Close(); err != nil {
		t.Fatalf("close archive writer: %v", err)
	}
	recorder.Info("dns", map[string]any{"domain": "example.com"})
	if metrics.Healthy() {
		t.Fatal("local archive failure did not mark health unhealthy")
	}
}

func TestRecorderWritesBlockedLogForBlockedEventsOnly(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger, err := logging.NewLogger(&buffer, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	blockedPath := filepath.Join(t.TempDir(), "blocked.log")
	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{
		BlockedPath: blockedPath,
	})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	defer recorder.Close()

	recorder.Info("dns", map[string]any{"domain": "allowed.example"})
	recorder.Info("would-block", map[string]any{"domain": "dry-run.example", "policy": "block"})
	recorder.Info("blocked", map[string]any{"domain": "blocked.example", "policy": "block"})
	recorder.Info("blocked-doh", map[string]any{"endpoint": "dns.example", "policy": "block"})

	content, err := os.ReadFile(blockedPath)
	if err != nil {
		t.Fatalf("ReadFile blocked log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) != 2 {
		t.Fatalf("blocked log line count = %d, want 2; content=%q", len(lines), content)
	}

	var first map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("json.Unmarshal first blocked line: %v", err)
	}
	if first["message"] != "blocked" || first["domain"] != "blocked.example" || first["policy"] != "block" {
		t.Fatalf("first blocked line = %#v, want blocked domain record", first)
	}

	var second map[string]any
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("json.Unmarshal second blocked line: %v", err)
	}
	if second["message"] != "blocked-doh" || second["endpoint"] != "dns.example" || second["policy"] != "block" {
		t.Fatalf("second blocked line = %#v, want blocked resolver record", second)
	}
}

func TestRecorderWritesUniqueDomainsLog(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	logger, err := logging.NewLogger(&buffer, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	domainsPath := filepath.Join(t.TempDir(), "domains.log")
	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{
		DomainsPath: domainsPath,
	})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	defer recorder.Close()

	now := time.Date(2026, time.June, 7, 9, 30, 0, 123, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.Info("dns", map[string]any{"domain": "Example.COM."})
	recorder.Info("dns", map[string]any{"domain": "example.com"})
	recorder.Info("would-block", map[string]any{"domain": "blocked.example", "policy": "block"})
	recorder.Info("blocked", map[string]any{"domain": "BLOCKED.EXAMPLE.", "policy": "block"})
	recorder.Info("blocked-doh", map[string]any{"endpoint": "dns.example", "policy": "block"})
	recorder.Info("dns", map[string]any{"domain": ""})
	recorder.Info("dns", map[string]any{"domain": 123})
	recorder.Info("dns", map[string]any{"domain": "evil.example\nforged.example"})
	recorder.Info("dns", map[string]any{"domain": "evil.example\tforged.example"})
	recorder.Info("dns", map[string]any{"domain": "bad..example"})
	recorder.Info("dns", map[string]any{"domain": "_dmarc.example"})

	lines := readDomainLogLines(t, domainsPath)
	if len(lines) != 3 {
		t.Fatalf("domain log line count = %d, want 3; content=%q", len(lines), strings.Join(lines, "\n"))
	}
	if lines[0] != "2026-06-07T09:30:00.000000123Z\texample.com" {
		t.Fatalf("first domain log line = %q, want timestamped example.com", lines[0])
	}
	if lines[1] != "2026-06-07T09:30:00.000000123Z\tblocked.example" {
		t.Fatalf("second domain log line = %q, want timestamped blocked.example", lines[1])
	}
	if lines[2] != "2026-06-07T09:30:00.000000123Z\t_dmarc.example" {
		t.Fatalf("third domain log line = %q, want timestamped _dmarc.example", lines[2])
	}
}

func TestRecorderLoadsExistingDomainsLogForDedup(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	domainsPath := filepath.Join(dir, "domains.log")
	if err := os.WriteFile(domainsPath, []byte("2026-06-07T09:00:00Z\texisting.example\n"), 0o640); err != nil {
		t.Fatalf("write domains log: %v", err)
	}
	if err := os.WriteFile(domainsPath+".1", []byte("2026-06-07T08:00:00Z\trotated.example\n"), 0o640); err != nil {
		t.Fatalf("write rotated domains log: %v", err)
	}
	if err := os.WriteFile(domainsPath+".2", []byte("forged.example\n2026-06-07T07:01:00Z\talso\tbad\n"), 0o640); err != nil {
		t.Fatalf("write malformed rotated domains log: %v", err)
	}

	var buffer bytes.Buffer
	logger, err := logging.NewLogger(&buffer, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{
		DomainsPath: domainsPath,
	})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	defer recorder.Close()

	now := time.Date(2026, time.June, 7, 10, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.Info("dns", map[string]any{"domain": "existing.example"})
	recorder.Info("dns", map[string]any{"domain": "rotated.example"})
	recorder.Info("dns", map[string]any{"domain": "forged.example"})
	recorder.Info("dns", map[string]any{"domain": "bad"})
	recorder.Info("dns", map[string]any{"domain": "new.example"})

	lines := readDomainLogLines(t, domainsPath)
	if len(lines) != 4 {
		t.Fatalf("current domain log line count = %d, want 4; content=%q", len(lines), strings.Join(lines, "\n"))
	}
	if lines[0] != "2026-06-07T09:00:00Z\texisting.example" {
		t.Fatalf("first current domain log line changed: %q", lines[0])
	}
	if lines[1] != "2026-06-07T10:00:00Z\tforged.example" {
		t.Fatalf("second current domain log line = %q, want forged.example appended", lines[1])
	}
	if lines[2] != "2026-06-07T10:00:00Z\tbad" {
		t.Fatalf("third current domain log line = %q, want bad appended", lines[2])
	}
	if lines[3] != "2026-06-07T10:00:00Z\tnew.example" {
		t.Fatalf("fourth current domain log line = %q, want new.example appended", lines[3])
	}
}

func TestDomainSinkBoundsRememberedDomains(t *testing.T) {
	t.Parallel()

	sink := &domainSink{
		seen:      make(map[string]struct{}),
		seenLimit: 2,
	}
	sink.rememberDomain("first.example")
	sink.rememberDomain("second.example")
	sink.rememberDomain("third.example")

	if len(sink.seen) != 2 {
		t.Fatalf("remembered domain count = %d, want 2", len(sink.seen))
	}
	if _, ok := sink.seen["first.example"]; ok {
		t.Fatal("oldest remembered domain was not evicted")
	}
	if _, ok := sink.seen["second.example"]; !ok {
		t.Fatal("second remembered domain was unexpectedly evicted")
	}
	if _, ok := sink.seen["third.example"]; !ok {
		t.Fatal("newest remembered domain was unexpectedly evicted")
	}
}

func TestRecorderErrorDedupSuppressesRepeatedErrors(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)

	now = now.Add(2 * time.Minute)
	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)

	now = now.Add(3 * time.Minute)
	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if _, ok := lines[0]["suppressed_count"]; ok {
		t.Fatalf("first log line unexpectedly had suppressed_count: %#v", lines[0])
	}
	if got := lines[1]["suppressed_count"]; got != float64(1) {
		t.Fatalf("suppressed_count = %#v, want 1", got)
	}
}

func TestRecorderErrorDedupEmitsDifferentErrors(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)
	now = now.Add(time.Minute)
	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("401 Unauthorized"), nil, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[1]["error"]; got != "401 Unauthorized" {
		t.Fatalf("second error = %#v, want 401 Unauthorized", got)
	}
}

func TestRecorderPrunesExpiredDedupeStates(t *testing.T) {
	t.Parallel()

	recorder, _ := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.InfoDedup("first-info", map[string]any{"path": "/tmp/first"}, 5*time.Minute)
	recorder.ErrorDedup("first-error", errors.New("first"), nil, 5*time.Minute)
	if len(recorder.infoStates) != 1 || len(recorder.errorStates) != 1 {
		t.Fatalf("initial dedupe state counts = info %d, error %d; want 1 each", len(recorder.infoStates), len(recorder.errorStates))
	}

	now = now.Add(6 * time.Minute)
	recorder.InfoDedup("second-info", map[string]any{"path": "/tmp/second"}, 5*time.Minute)
	if len(recorder.infoStates) != 1 {
		t.Fatalf("info dedupe state count after expiry = %d, want 1", len(recorder.infoStates))
	}
	if len(recorder.errorStates) != 0 {
		t.Fatalf("error dedupe state count after expiry = %d, want 0", len(recorder.errorStates))
	}
}

func TestLimitDedupeStatesBoundsCardinality(t *testing.T) {
	t.Parallel()

	states := make(map[string]errorDedupeState, maxDedupeStates+1)
	for idx := 0; idx <= maxDedupeStates; idx++ {
		states[strconv.Itoa(idx)] = errorDedupeState{}
	}
	const preserve = "65536"
	limitDedupeStates(states, preserve)

	if len(states) != maxDedupeStates {
		t.Fatalf("dedupe state count = %d, want %d", len(states), maxDedupeStates)
	}
	if _, ok := states[preserve]; !ok {
		t.Fatalf("current dedupe state %q was evicted", preserve)
	}
}

func TestRecorderInfoIfChangedSuppressesUnchangedPayload(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)

	if !recorder.InfoIfChanged("policy loaded", map[string]any{
		"block_domains": 1,
		"source":        "https://example.test/blocklist.txt",
	}) {
		t.Fatal("InfoIfChanged did not emit initial policy snapshot")
	}
	if recorder.InfoIfChanged("policy loaded", map[string]any{
		"source":        "https://example.test/blocklist.txt",
		"block_domains": 1,
	}) {
		t.Fatal("InfoIfChanged emitted unchanged policy snapshot")
	}
	if !recorder.InfoIfChanged("policy loaded", map[string]any{
		"block_domains": 2,
		"source":        "https://example.test/blocklist.txt",
	}) {
		t.Fatal("InfoIfChanged suppressed changed policy snapshot")
	}

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[0]["block_domains"]; got != float64(1) {
		t.Fatalf("first block_domains = %#v, want 1", got)
	}
	if got := lines[1]["block_domains"]; got != float64(2) {
		t.Fatalf("second block_domains = %#v, want 2", got)
	}
}

func TestRecorderInfoIfChangedBoundsChangeStates(t *testing.T) {
	t.Parallel()

	recorder, _ := newTestRecorder(t)
	for idx := range maxDedupeStates {
		recorder.changeStates[strconv.Itoa(idx)] = "existing"
	}
	const current = "current policy"
	if !recorder.InfoIfChanged(current, map[string]any{"revision": 1}) {
		t.Fatal("InfoIfChanged did not emit the current message")
	}
	if len(recorder.changeStates) != maxDedupeStates {
		t.Fatalf("change state count = %d, want %d", len(recorder.changeStates), maxDedupeStates)
	}
	if _, ok := recorder.changeStates[current]; !ok {
		t.Fatalf("current change state %q was evicted", current)
	}
}

func TestRecorderInfoDedupSuppressesRepeatedPayload(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	fields := map[string]any{
		"event":            "file_access",
		"path":             "/etc/passwd",
		"file_access":      "read",
		"selinux_context":  "system_u:system_r:user_t:s0",
		"apparmor_profile": "traceguard-default",
		"apparmor_mode":    "enforce",
		"lsm_source":       "apparmor",
		"program":          "cat",
		"pid":              123,
		"uid":              1000,
	}

	recorder.InfoDedup("file_access", fields, 5*time.Minute)
	now = now.Add(time.Minute)
	recorder.InfoDedup("file_access", fields, 5*time.Minute)
	now = now.Add(5 * time.Minute)
	recorder.InfoDedup("file_access", fields, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if _, ok := lines[0]["suppressed_count"]; ok {
		t.Fatalf("first log line unexpectedly had suppressed_count: %#v", lines[0])
	}
	if got := lines[1]["suppressed_count"]; got != float64(1) {
		t.Fatalf("suppressed_count = %#v, want 1", got)
	}
}

func TestRecorderInfoDedupEmitsChangedPayload(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.InfoDedup("file_access", map[string]any{
		"path":        "/etc/passwd",
		"file_access": "read",
	}, 5*time.Minute)
	now = now.Add(time.Minute)
	recorder.InfoDedup("file_access", map[string]any{
		"path":        "/etc/shadow",
		"file_access": "read",
	}, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[1]["path"]; got != "/etc/shadow" {
		t.Fatalf("second path = %#v, want /etc/shadow", got)
	}
}

func TestRecorderFileAuditDedupSuppressesAppArmorAcrossPIDChurn(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	fields := map[string]any{
		"event":            "file_access",
		"path":             "/etc/passwd",
		"file_access":      "read",
		"file_flags":       uint32(0),
		"file_mode":        uint32(0),
		"program":          "cat",
		"exe":              "/usr/bin/cat",
		"uid":              uint32(1000),
		"pid":              uint32(100),
		"ppid":             uint32(10),
		"parent_program":   "bash",
		"parent_exe":       "/usr/bin/bash",
		"lsm_label":        "traceguard-default (enforce)",
		"lsm_source":       "apparmor",
		"apparmor_profile": "traceguard-default",
		"apparmor_mode":    "enforce",
	}

	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)
	now = now.Add(time.Minute)
	fields["pid"] = uint32(101)
	fields["ppid"] = uint32(11)
	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)
	now = now.Add(5 * time.Minute)
	fields["pid"] = uint32(102)
	fields["ppid"] = uint32(12)
	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[1]["suppressed_count"]; got != float64(1) {
		t.Fatalf("suppressed_count = %#v, want 1", got)
	}
	if got := lines[1]["pid"]; got != float64(102) {
		t.Fatalf("second emitted pid = %#v, want latest pid 102", got)
	}
}

func TestRecorderFileAuditDedupEmitsChangedAppArmorLabel(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	fields := map[string]any{
		"event":            "file_access",
		"path":             "/etc/passwd",
		"file_access":      "read",
		"program":          "cat",
		"exe":              "/usr/bin/cat",
		"uid":              uint32(1000),
		"pid":              uint32(100),
		"lsm_label":        "traceguard-default (enforce)",
		"lsm_source":       "apparmor",
		"apparmor_profile": "traceguard-default",
		"apparmor_mode":    "enforce",
	}

	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)
	now = now.Add(time.Minute)
	fields["pid"] = uint32(101)
	fields["lsm_label"] = "traceguard-audit (complain)"
	fields["apparmor_profile"] = "traceguard-audit"
	fields["apparmor_mode"] = "complain"
	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[1]["apparmor_profile"]; got != "traceguard-audit" {
		t.Fatalf("second apparmor_profile = %#v, want changed profile", got)
	}
}

func TestRecorderFileAuditDedupEmitsChangedCmdline(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	fields := map[string]any{
		"event":       "file_access",
		"path":        "/etc/app/config.yaml",
		"file_access": "read",
		"program":     "python",
		"exe":         "/usr/bin/python",
		"cmdline":     []string{"/usr/bin/python", "script_a.py"},
		"uid":         uint32(1000),
		"pid":         uint32(100),
	}

	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)
	now = now.Add(time.Minute)
	fields["pid"] = uint32(101)
	fields["cmdline"] = []string{"/usr/bin/python", "script_b.py"}
	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	cmdline, ok := lines[1]["cmdline"].([]any)
	if !ok || len(cmdline) != 2 || cmdline[1] != "script_b.py" {
		t.Fatalf("second cmdline = %#v, want script_b.py", lines[1]["cmdline"])
	}
}

func TestRecorderFileAuditDedupKeepsPIDForFallbackMetadata(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	fields := map[string]any{
		"event":       "file_access",
		"path":        "/etc/passwd",
		"file_access": "read",
		"file_flags":  uint32(0),
		"file_mode":   uint32(0),
		"program":     "cat",
		"uid":         uint32(0),
		"pid":         uint32(100),
		"ppid":        uint32(0),
	}

	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)
	now = now.Add(time.Minute)
	fields["pid"] = uint32(101)
	recorder.InfoDedupFileAudit("file_access", fields, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[1]["pid"]; got != float64(101) {
		t.Fatalf("second emitted pid = %#v, want fallback pid 101", got)
	}
}

func TestExportSinkSendsJSONBatchWithAuthorization(t *testing.T) {
	t.Parallel()

	requests := make(chan struct {
		auth string
		body []byte
	}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- struct {
			auth string
			body []byte
		}{
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink, err := newExportSink(context.Background(), Config{
		ExportURL:           server.URL,
		ExportAuthorization: "Bearer token",
	}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	defer sink.Close()
	if transport, ok := sink.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	batch := []json.RawMessage{
		mustMarshalRecord(t, record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "one"}),
		mustMarshalRecord(t, record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "two"}),
	}
	if err := sink.sendBatch(context.Background(), batch); err != nil {
		t.Fatalf("sendBatch returned error: %v", err)
	}

	select {
	case req := <-requests:
		if req.auth != "Bearer token" {
			t.Fatalf("auth header = %q, want Bearer token", req.auth)
		}
		var payload []map[string]any
		if err := json.Unmarshal(req.body, &payload); err != nil {
			t.Fatalf("json.Unmarshal returned error: %v", err)
		}
		if len(payload) != 2 {
			t.Fatalf("batch len = %d, want 2", len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for export request")
	}
}

func TestExportSinkKeepsLateEventsUntilClose(t *testing.T) {
	t.Parallel()

	requests := make(chan []byte, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sink, err := newExportSink(ctx, Config{ExportURL: server.URL}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	if transport, ok := sink.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	cancel()
	time.Sleep(20 * time.Millisecond)
	sink.Enqueue(record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "late"})
	if err := sink.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case payload := <-requests:
		if !bytes.Contains(payload, []byte(`"message":"late"`)) {
			t.Fatalf("export payload = %s, want late event", payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for late export event")
	}
}

func TestExportRedirectsStayOnOriginalOrigin(t *testing.T) {
	t.Parallel()

	original, err := http.NewRequest(http.MethodPost, "https://collector.example.test/v1/events", nil)
	if err != nil {
		t.Fatalf("create original request: %v", err)
	}
	tests := []struct {
		name    string
		target  string
		via     []*http.Request
		wantErr bool
	}{
		{name: "same origin", target: "https://collector.example.test/v2/events", via: []*http.Request{original}},
		{name: "different host", target: "https://other.example.test/v2/events", via: []*http.Request{original}, wantErr: true},
		{name: "different port", target: "https://collector.example.test:8443/v2/events", via: []*http.Request{original}, wantErr: true},
		{name: "downgrade", target: "http://collector.example.test/v2/events", via: []*http.Request{original}, wantErr: true},
		{name: "missing origin", target: "https://collector.example.test/v2/events", wantErr: true},
		{name: "too many", target: "https://collector.example.test/v2/events", via: []*http.Request{original, original, original, original, original}, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			redirect, err := http.NewRequest(http.MethodPost, test.target, nil)
			if err != nil {
				t.Fatalf("create redirect request: %v", err)
			}
			if err := checkHTTPSRedirect(redirect, test.via); (err != nil) != test.wantErr {
				t.Fatalf("checkHTTPSRedirect() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestNewExportSinkLoadsClientCertificate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath, keyPath := writeClientCertificate(t, tempDir)
	caPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caPath, encodeServerCertPEM(t, httptest.NewTLSServer(http.NotFoundHandler())), 0o644); err != nil {
		t.Fatalf("WriteFile ca: %v", err)
	}

	sink, err := newExportSink(context.Background(), Config{
		ExportURL:        "https://127.0.0.1:6443",
		ExportCAPath:     caPath,
		ExportClientCert: certPath,
		ExportClientKey:  keyPath,
	}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	defer sink.Close()

	transport, ok := sink.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T, want *http.Transport", sink.client.Transport)
	}
	if transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("TLSClientConfig certificates = %d, want 1", len(transport.TLSClientConfig.Certificates))
	}
}

func TestExportSinkSpoolsAndReplays(t *testing.T) {
	var failMode atomic.Bool
	failMode.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	spoolDir := filepath.Join(t.TempDir(), "spool")
	originalSpoolPath := exportSpoolPath
	exportSpoolPath = spoolDir
	t.Cleanup(func() { exportSpoolPath = originalSpoolPath })
	metrics := telemetry.NewRegistry()
	sink, err := newExportSink(context.Background(), Config{
		ExportURL:   server.URL,
		ExportSpool: true,
	}, metrics)
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	defer sink.Close()
	if transport, ok := sink.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	batch := []json.RawMessage{
		mustMarshalRecord(t, record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "spool"}),
	}
	if err := sink.sendBatch(context.Background(), batch); err == nil {
		t.Fatal("sendBatch returned nil, want server failure")
	}
	metrics.SetEventExportLastError()
	if err := sink.spool.Write(batch); err != nil {
		t.Fatalf("spool.Write returned error: %v", err)
	}
	sink.updateSpoolFiles()

	deadline := time.Now().Add(5 * time.Second)
	for {
		files, err := os.ReadDir(spoolDir)
		if err == nil && len(files) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for spool file")
		}
		time.Sleep(20 * time.Millisecond)
	}
	rendered := metrics.Render()
	if !strings.Contains(rendered, `traceguard_event_export_spool_files 1`) {
		t.Fatalf("metrics missing spool file count after failed export in %q", rendered)
	}
	if !strings.Contains(rendered, `traceguard_event_export_last_error_timestamp_seconds`) {
		t.Fatalf("metrics missing last export error timestamp in %q", rendered)
	}

	failMode.Store(false)
	if err := sink.spool.Replay(func(payload []byte) error {
		if err := sink.sendPayload(context.Background(), payload); err != nil {
			metrics.SetEventExportLastError()
			return err
		}
		metrics.SetEventExportLastSuccess()
		return nil
	}); err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}
	sink.updateSpoolFiles()

	files, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected empty spool after replay, got %d files", len(files))
	}
	rendered = metrics.Render()
	if !strings.Contains(rendered, `traceguard_event_export_spool_files 0`) {
		t.Fatalf("metrics missing empty spool file count after replay in %q", rendered)
	}
	if !strings.Contains(rendered, `traceguard_event_export_last_success_timestamp_seconds`) {
		t.Fatalf("metrics missing last export success timestamp in %q", rendered)
	}
}

func TestNewSpoolStoreRejectsSymlinkedDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	link := filepath.Join(root, "spool-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink spool directory: %v", err)
	}

	_, err := newSpoolStore(link)
	if err == nil || !strings.Contains(err.Error(), "must not traverse symlinks") {
		t.Fatalf("newSpoolStore error = %v, want symlink traversal rejection", err)
	}
}

func TestSpoolStoreRejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	store, err := newSpoolStore(t.TempDir())
	if err != nil {
		t.Fatalf("newSpoolStore returned error: %v", err)
	}
	oversized := json.RawMessage(`"` + strings.Repeat("a", maxSpoolPayloadBytes) + `"`)

	err = store.Write([]json.RawMessage{oversized})
	if err == nil || !strings.Contains(err.Error(), "payload exceeds") {
		t.Fatalf("Write error = %v, want payload size rejection", err)
	}
	files, readErr := store.files()
	if readErr != nil {
		t.Fatalf("files returned error: %v", readErr)
	}
	if len(files) != 0 {
		t.Fatalf("spool files = %d, want 0 after oversized write", len(files))
	}
}

func TestSpoolStoreRejectsByteCapacityExceeded(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := newSpoolStore(dir)
	if err != nil {
		t.Fatalf("newSpoolStore returned error: %v", err)
	}
	existing := filepath.Join(dir, "existing.json")
	file, err := os.Create(existing)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if err := file.Truncate(maxSpoolBytes); err != nil {
		_ = file.Close()
		t.Fatalf("Truncate returned error: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	err = store.Write([]json.RawMessage{json.RawMessage(`{"message":"new"}`)})
	if err == nil || !strings.Contains(err.Error(), "byte capacity exceeded") {
		t.Fatalf("Write error = %v, want byte capacity rejection", err)
	}
}

func TestExportSinkCloseDrainsQueuedEvents(t *testing.T) {
	t.Parallel()

	requests := make(chan []byte, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- body
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink, err := newExportSink(context.Background(), Config{
		ExportURL: server.URL,
	}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	if transport, ok := sink.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	sink.Enqueue(record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "queued"})
	if err := sink.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}

	select {
	case body := <-requests:
		if !strings.Contains(string(body), `"message":"queued"`) {
			t.Fatalf("export body = %s, want queued event", body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for close flush request")
	}
}

func TestRecorderExportsEventsToUDPSyslog(t *testing.T) {
	t.Parallel()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	defer packetConn.Close()

	received := make(chan string, 1)
	go func() {
		buffer := make([]byte, 4096)
		_ = packetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _, err := packetConn.ReadFrom(buffer)
		if err != nil {
			received <- "ERROR: " + err.Error()
			return
		}
		received <- string(buffer[:n])
	}()

	recorder, err := newSyslogTestRecorder(t, Config{
		SyslogURL:      "syslog+udp://" + packetConn.LocalAddr().String(),
		SyslogFacility: "local0",
		SyslogTag:      "traceguard",
		SyslogTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("newSyslogTestRecorder returned error: %v", err)
	}
	defer recorder.Close()

	recorder.Info("dns", map[string]any{"domain": "example.com"})

	select {
	case message := <-received:
		if strings.HasPrefix(message, "ERROR: ") {
			t.Fatal(message)
		}
		if !strings.Contains(message, `<134>1 `) || !strings.Contains(message, ` traceguard - - - {`) || !strings.Contains(message, `"message":"dns"`) || !strings.Contains(message, `"domain":"example.com"`) {
			t.Fatalf("syslog message = %q, want RFC5424 envelope with JSON event", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for syslog datagram")
	}
}

func TestRecorderCloseDrainsQueuedSyslog(t *testing.T) {
	t.Parallel()

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	defer packetConn.Close()
	recorder, err := newSyslogTestRecorder(t, Config{
		SyslogURL:      "syslog+udp://" + packetConn.LocalAddr().String(),
		SyslogFacility: "local0",
		SyslogTag:      "traceguard",
		SyslogTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("newSyslogTestRecorder returned error: %v", err)
	}
	recorder.Info("dns", map[string]any{"domain": "queued.example"})
	if err := recorder.Close(); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	buffer := make([]byte, 4096)
	_ = packetConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := packetConn.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom after Close: %v", err)
	}
	if !strings.Contains(string(buffer[:n]), `"domain":"queued.example"`) {
		t.Fatalf("syslog payload = %q, want queued event", buffer[:n])
	}
}

func TestRecorderExportsEventsToTCPSyslog(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- "ERROR: " + err.Error()
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 4096)
		n, err := conn.Read(buffer)
		if err != nil {
			received <- "ERROR: " + err.Error()
			return
		}
		received <- string(buffer[:n])
	}()

	recorder, err := newSyslogTestRecorder(t, Config{
		SyslogURL:      "syslog+tcp://" + listener.Addr().String(),
		SyslogFacility: "local1",
		SyslogTag:      "traceguard",
		SyslogTimeout:  time.Second,
	})
	if err != nil {
		t.Fatalf("newSyslogTestRecorder returned error: %v", err)
	}
	defer recorder.Close()

	recorder.Error("export", errors.New("boom"), nil)

	select {
	case message := <-received:
		if strings.HasPrefix(message, "ERROR: ") {
			t.Fatal(message)
		}
		parts := strings.SplitN(message, " ", 2)
		if len(parts) != 2 || parts[0] == "" {
			t.Fatalf("tcp syslog message = %q, want octet-counted frame", message)
		}
		if !strings.Contains(parts[1], `<139>1 `) || !strings.Contains(parts[1], `"message":"export"`) || !strings.Contains(parts[1], `"error":"boom"`) {
			t.Fatalf("tcp syslog frame = %q, want RFC5424 error event", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for syslog tcp frame")
	}
}

func newTestRecorder(t *testing.T) (*Recorder, *bytes.Buffer) {
	t.Helper()

	var buffer bytes.Buffer
	logger, err := logging.NewLogger(&buffer, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = recorder.Close()
	})
	return recorder, &buffer
}

func newSyslogTestRecorder(t *testing.T, cfg Config) (*Recorder, error) {
	t.Helper()

	logger, err := logging.NewLogger(io.Discard, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	return NewRecorder(context.Background(), logger, telemetry.NewRegistry(), cfg)
}

func decodeLogLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}

	decoded := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("json.Unmarshal returned error: %v", err)
		}
		decoded = append(decoded, entry)
	}
	return decoded
}

func readDomainLogLines(t *testing.T, path string) []string {
	t.Helper()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile domain log: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

func mustMarshalRecord(t *testing.T, entry record) json.RawMessage {
	t.Helper()
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		t.Fatalf("marshalSingleRecord returned error: %v", err)
	}
	return payload
}

func TestMarshalSingleRecordProtectsReservedFields(t *testing.T) {
	t.Parallel()

	payload := mustMarshalRecord(t, record{
		Timestamp: "2026-07-10T12:00:00Z",
		Level:     "info",
		Message:   "dns",
		Fields: map[string]any{
			"timestamp": "forged",
			"level":     "forged",
			"message":   "forged",
		},
	})
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if decoded["timestamp"] != "2026-07-10T12:00:00Z" || decoded["level"] != "info" || decoded["message"] != "dns" {
		t.Fatalf("reserved fields were overwritten: %#v", decoded)
	}
}

func writeClientCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "traceguard-client",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey returned error: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	return certPath, keyPath
}

func encodeServerCertPEM(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	defer server.Close()

	if server.Certificate() == nil {
		t.Fatal("server certificate is nil")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
}
