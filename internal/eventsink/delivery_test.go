package eventsink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/runid"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestIsPriorityRecord(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name  string
		entry record
		want  bool
	}{
		{"detection alert", record{Level: "info", Message: "x", Fields: map[string]any{"event": "detection_alert"}}, true},
		{"heartbeat", record{Level: "info", Message: "heartbeat", Fields: map[string]any{"event": "heartbeat"}}, true},
		{"response", record{Level: "info", Message: "response applied", Fields: map[string]any{"event": "response"}}, true},
		{"command", record{Level: "info", Message: "manager command", Fields: map[string]any{"event": "command"}}, true},
		{"stopping", record{Level: "info", Message: "agent stopping", Fields: map[string]any{"event": "agent_stopping"}}, true},
		{"error", record{Level: "error", Message: "reload policy", Fields: map[string]any{}}, true},
		{"exec blocked", record{Level: "info", Message: "exec_blocked", Fields: map[string]any{"event": "exec_blocked"}}, true},
		{"egress would block", record{Level: "info", Message: "egress_would_block", Fields: map[string]any{"event": "egress_would_block"}}, true},
		{"dns blocked", record{Level: "info", Message: "blocked", Fields: map[string]any{"event": "blocked"}}, true},
		{"resolver blocked", record{Level: "info", Message: "blocked-udp", Fields: map[string]any{"event": "resolver_blocked"}}, true},
		{"dns would block", record{Level: "info", Message: "would-block", Fields: map[string]any{"event": "dns"}}, true},
		{"resolver would block", record{Level: "info", Message: "would-block-udp", Fields: map[string]any{"event": "resolver"}}, true},
		{"dns", record{Level: "info", Message: "dns", Fields: map[string]any{"event": "dns"}}, false},
		{"exec", record{Level: "info", Message: "exec", Fields: map[string]any{"event": "exec"}}, false},
		{"policy loaded", record{Level: "info", Message: "policy loaded", Fields: map[string]any{}}, false},
	} {
		if got := isPriorityRecord(test.entry); got != test.want {
			t.Errorf("%s: isPriorityRecord = %t, want %t", test.name, got, test.want)
		}
	}
}

func TestParseRetryAfter(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	for _, test := range []struct {
		value string
		want  time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"30", 30 * time.Second},
		{"86400", maxRetryAfterHold},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
		{"soon", 0},
	} {
		if got := parseRetryAfter(test.value, now); got != test.want {
			t.Errorf("parseRetryAfter(%q) = %s, want %s", test.value, got, test.want)
		}
	}
}

func TestStatusErrorClassifiesPermanentRejections(t *testing.T) {
	t.Parallel()

	temporary := &statusError{code: http.StatusRequestEntityTooLarge, status: "413", retryAfter: time.Minute, retryHint: true}
	if errors.Is(temporary, errPermanentRejection) {
		t.Error("a 413 with Retry-After was treated as permanent")
	}
	// Retry-After: 0 is still a valid hint to retry.
	if !validRetryAfter("0") || validRetryAfter("soon") || !validRetryAfter(time.Now().UTC().Format(http.TimeFormat)) {
		t.Error("validRetryAfter misjudged a header")
	}
	for code, permanent := range map[int]bool{
		http.StatusBadRequest: true, http.StatusRequestEntityTooLarge: true, http.StatusUnsupportedMediaType: true,
		http.StatusUnprocessableEntity: true, http.StatusUnauthorized: false, http.StatusForbidden: false,
		http.StatusNotFound: false, http.StatusTooManyRequests: false, http.StatusBadGateway: false,
	} {
		err := error(&statusError{code: code, status: http.StatusText(code)})
		if got := errors.Is(err, errPermanentRejection); got != permanent {
			t.Errorf("status %d permanent = %t, want %t", code, got, permanent)
		}
	}
}

func newTestSpool(t *testing.T) *spoolStore {
	t.Helper()
	spool, err := newSpoolStore(filepath.Join(t.TempDir(), "spool"), SchemaTraceGuard)
	if err != nil {
		t.Fatalf("newSpoolStore: %v", err)
	}
	closeTestResource(t, spool)
	return spool
}

func spooledRecords(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	total := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		payload, err := os.ReadFile(filepath.Join(dir, entry.Name())) //nolint:gosec // a test temp directory
		if err != nil {
			t.Fatal(err)
		}
		var batch []json.RawMessage
		if err := json.Unmarshal(payload, &batch); err != nil {
			t.Fatalf("spool file %s: %v", entry.Name(), err)
		}
		total += len(batch)
	}
	return total
}

func TestExportFilterAlertsDropsRoutineTelemetry(t *testing.T) {
	t.Parallel()

	encode, _ := newRecordEncoder(SchemaTraceGuard)
	sink := &exportSink{
		events: ExportEventsAlerts, encode: encode, metrics: telemetry.NewRegistry(),
		priority: make(chan json.RawMessage, 4), queue: make(chan json.RawMessage, 4),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	sink.Enqueue(record{Timestamp: now, Level: "info", Message: "dns", Fields: map[string]any{"event": "dns"}})
	sink.Enqueue(record{Timestamp: now, Level: "info", Message: "alert", Fields: map[string]any{"event": "detection_alert"}})
	if len(sink.queue) != 0 || len(sink.priority) != 1 {
		t.Fatalf("queue %d priority %d, want 0 and 1", len(sink.queue), len(sink.priority))
	}

	sink.events = ExportEventsAll
	sink.Enqueue(record{Timestamp: now, Level: "info", Message: "dns", Fields: map[string]any{"event": "dns"}})
	if len(sink.queue) != 1 {
		t.Fatalf("queue %d, want routine record queued under all", len(sink.queue))
	}
}

func TestNewExportSinkRejectsUnknownExportEvents(t *testing.T) {
	t.Parallel()

	sink, err := newExportSink(context.Background(), Config{ExportURL: "https://collector.example", ExportEvents: "some"}, telemetry.NewRegistry())
	if err == nil {
		closeTestResource(t, sink)
		t.Fatal("newExportSink accepted export events \"some\"")
	}
}

func TestPriorityOverflowSpillsToSpool(t *testing.T) {
	t.Parallel()

	encode, _ := newRecordEncoder(SchemaTraceGuard)
	metrics := telemetry.NewRegistry()
	spool := newTestSpool(t)
	sink := &exportSink{
		events: ExportEventsAll, encode: encode, metrics: metrics, spool: spool,
		priority: make(chan json.RawMessage, 1), queue: make(chan json.RawMessage, 1),
		spill: make(chan json.RawMessage, 2),
	}
	var done sync.WaitGroup
	done.Go(sink.runSpill)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	alert := record{Timestamp: now, Level: "info", Message: "alert", Fields: map[string]any{"event": "detection_alert"}}
	// No worker drains the queues, as when it is stalled on a slow
	// collector: the first alert queues, the rest spill.
	for range 3 {
		sink.Enqueue(alert)
	}
	// Routine telemetry beyond the queue is still dropped.
	routine := record{Timestamp: now, Level: "info", Message: "dns", Fields: map[string]any{"event": "dns"}}
	sink.Enqueue(routine)
	sink.Enqueue(routine)
	sink.closeSpill()
	done.Wait()

	if got := spooledRecords(t, spool.dir.Name()); got != 2 {
		t.Fatalf("spooled %d alerts, want 2", got)
	}
	status := metrics.EventExportStatus()
	if status.DroppedPriority != 0 || status.Dropped != 1 {
		t.Fatalf("dropped %d priority %d, want 1 routine and no alerts", status.Dropped, status.DroppedPriority)
	}
}

func TestPriorityOverflowWithoutSpoolCountsDroppedAlerts(t *testing.T) {
	t.Parallel()

	encode, _ := newRecordEncoder(SchemaTraceGuard)
	metrics := telemetry.NewRegistry()
	sink := &exportSink{
		events: ExportEventsAll, encode: encode, metrics: metrics,
		priority: make(chan json.RawMessage, 1), queue: make(chan json.RawMessage, 1),
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for range 3 {
		sink.Enqueue(record{Timestamp: now, Level: "info", Message: "alert", Fields: map[string]any{"event": "detection_alert"}})
	}
	if got := metrics.EventExportStatus().DroppedPriority; got != 2 {
		t.Fatalf("dropped alerts = %d, want 2", got)
	}
}

func TestReplayMovesRejectedBatchAsideAndContinues(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), `"message":"poison"`) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	metrics := telemetry.NewRegistry()
	sink, err := newExportSink(context.Background(), Config{ExportURL: server.URL}, metrics)
	if err != nil {
		t.Fatalf("newExportSink: %v", err)
	}
	closeTestResource(t, sink)
	trustTestServer(t, sink, server)
	sink.spool = newTestSpool(t)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Spool file names sort by time, so the poison batch is replayed first.
	for _, message := range []string{"poison", "good"} {
		if err := sink.spool.Write([]json.RawMessage{mustMarshalRecord(t, record{Timestamp: now, Level: "info", Message: message})}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	sink.replayBudget = 5 * time.Second
	sink.replay(context.Background())

	spoolDir := sink.spool.dir.Name()
	if got := spooledRecords(t, spoolDir); got != 0 {
		t.Fatalf("spool still holds %d records, want the good batch sent and the poison set aside", got)
	}
	if got := spooledRecords(t, filepath.Join(spoolDir, rejectedDirName)); got != 1 {
		t.Fatalf("rejected directory holds %d records, want 1", got)
	}
	if got := metrics.EventExportStatus().Rejected; got != 1 {
		t.Fatalf("rejected count = %d, want 1", got)
	}
}

func TestRejectedBatchesAreBounded(t *testing.T) {
	t.Parallel()

	spool := newTestSpool(t)
	payload := []byte(`[{"message":"x"}]`)
	for range maxRejectedFiles {
		if discarded, err := spool.writeRejected(payload); err != nil || discarded {
			t.Fatalf("writeRejected = %t, %v", discarded, err)
		}
	}
	discarded, err := spool.writeRejected(payload)
	if err != nil || !discarded {
		t.Fatalf("writeRejected past the limit = %t, %v; want discarded", discarded, err)
	}
	entries, err := os.ReadDir(filepath.Join(spool.dir.Name(), rejectedDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != maxRejectedFiles {
		t.Fatalf("rejected files = %d, want %d", len(entries), maxRejectedFiles)
	}
}

func TestRetryAfterHoldsSendsAndReplay(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer server.Close()

	sink, err := newExportSink(context.Background(), Config{ExportURL: server.URL}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink: %v", err)
	}
	closeTestResource(t, sink)
	trustTestServer(t, sink, server)
	sink.spool = newTestSpool(t)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	err = sink.sendBatch(context.Background(), []json.RawMessage{mustMarshalRecord(t, record{Timestamp: now, Level: "info", Message: "one"})})
	if errors.Is(err, errPermanentRejection) || err == nil {
		t.Fatalf("sendBatch error = %v, want a retryable failure", err)
	}
	sink.noteRetryAfter(err)
	if until := time.Until(sink.holdUntil); until < 100*time.Second || until > 120*time.Second {
		t.Fatalf("hold = %s, want about two minutes", until)
	}
	if err := sink.spool.Write([]json.RawMessage{mustMarshalRecord(t, record{Timestamp: now, Level: "info", Message: "two"})}); err != nil {
		t.Fatal(err)
	}
	sink.replay(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if requests != 1 {
		t.Fatalf("collector saw %d requests, want replay held after Retry-After", requests)
	}
}

func TestMixedBatchesStayWithinTheBatchSize(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	sizes := []int{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch []json.RawMessage
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &batch)
		mu.Lock()
		sizes = append(sizes, len(batch))
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	metrics := telemetry.NewRegistry()
	sink, err := newExportSink(context.Background(), Config{ExportURL: server.URL}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	trustTestServer(t, sink, server)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	// Fill both queues before the worker can drain them in step.
	for range 3 * exportBatchSize {
		sink.Enqueue(record{Timestamp: now, Level: "info", Message: "alert", Fields: map[string]any{"event": "detection_alert"}})
		sink.Enqueue(record{Timestamp: now, Level: "info", Message: "dns", Fields: map[string]any{"event": "dns"}})
	}
	// Close cancels a send in flight, so let delivery finish first.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		mu.Lock()
		delivered := 0
		for _, size := range sizes {
			delivered += size
		}
		mu.Unlock()
		if delivered >= 6*exportBatchSize {
			break
		}
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	total := 0
	for _, size := range sizes {
		if size > exportBatchSize {
			t.Fatalf("batch of %d records, want at most %d", size, exportBatchSize)
		}
		total += size
	}
	if total != 6*exportBatchSize {
		t.Fatalf("collector received %d records in %v, want %d; metrics %s", total, sizes, 6*exportBatchSize, metrics.Render())
	}
}

func TestBatchesThatCannotBeSentOrSpooledAreCountedAsLost(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	metrics := telemetry.NewRegistry()
	sink, err := newExportSink(context.Background(), Config{ExportURL: server.URL}, metrics)
	if err != nil {
		t.Fatal(err)
	}
	trustTestServer(t, sink, server)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	sink.Enqueue(record{Timestamp: now, Level: "info", Message: "alert", Fields: map[string]any{"event": "detection_alert"}})
	sink.Enqueue(record{Timestamp: now, Level: "info", Message: "dns", Fields: map[string]any{"event": "dns"}})
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	status := metrics.EventExportStatus()
	if status.DroppedPriority != 1 || status.Dropped != 1 {
		t.Fatalf("lost alerts %d routine %d, want 1 and 1 with no spool", status.DroppedPriority, status.Dropped)
	}
}

func TestARejectedBatchThatCannotBeMovedIsDeleted(t *testing.T) {
	t.Parallel()

	spool := newTestSpool(t)
	// A regular file where the rejected directory should be.
	if err := os.WriteFile(filepath.Join(spool.dir.Name(), rejectedDirName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := spool.Write([]json.RawMessage{json.RawMessage(`{"message":"poison"}`)}); err != nil {
		t.Fatal(err)
	}
	discarded := 0
	err := spool.replayUntil(time.Time{}, func(string, []byte) error {
		return &statusError{code: http.StatusBadRequest, status: "400 Bad Request"}
	}, func(gone bool) {
		if gone {
			discarded++
		}
	})
	if err != nil {
		t.Fatalf("replayUntil = %v", err)
	}
	files, err := spool.files()
	if err != nil {
		t.Fatal(err)
	}
	if discarded != 1 || len(files) != 0 {
		t.Fatalf("discarded %d, spool files %v; want the batch deleted", discarded, files)
	}
}

func TestExportClientWaitsForLongPolls(t *testing.T) {
	t.Parallel()

	client, _, err := ExportClient(Config{})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.ResponseHeaderTimeout != 0 || client.Timeout != 0 {
		t.Fatalf("command client header timeout %v, overall %v; want neither", transport.ResponseHeaderTimeout, client.Timeout)
	}
}

func TestABatchStillTooLargeAfterRetriesIsSetAside(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()
	// No background worker: the test drives replay itself.
	sink := &exportSink{client: server.Client(), target: server.URL, metrics: telemetry.NewRegistry(), drainTimeout: time.Second}
	sink.spool = newTestSpool(t)
	if err := sink.spool.Write([]json.RawMessage{mustMarshalRecord(t, record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "big"})}); err != nil {
		t.Fatal(err)
	}
	sink.replayBudget = 5 * time.Second
	for attempt := range maxTooLargeRetries {
		sink.holdUntil = time.Time{}
		sink.replay(context.Background())
		files, _ := sink.spool.files()
		if want := attempt < maxTooLargeRetries-1; (len(files) == 1) != want {
			t.Fatalf("after try %d spool has %d files", attempt+1, len(files))
		}
	}
	if got := spooledRecords(t, filepath.Join(sink.spool.dir.Name(), rejectedDirName)); got != 1 {
		t.Fatalf("rejected directory holds %d records, want the batch set aside", got)
	}
}

func TestARetryAfterPauseIsNotASpoolError(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
	}))
	defer server.Close()
	metrics := telemetry.NewRegistry()
	sink := &exportSink{client: server.Client(), target: server.URL, metrics: metrics, drainTimeout: time.Second, replayBudget: 5 * time.Second}
	sink.spool = newTestSpool(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, message := range []string{"one", "two"} {
		if err := sink.spool.Write([]json.RawMessage{mustMarshalRecord(t, record{Timestamp: now, Level: "info", Message: message})}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
	// The first file reaches its last allowed 413 and is set aside; the
	// reply's Retry-After then pauses the pass before the second file.
	for range maxTooLargeRetries {
		sink.holdUntil = time.Time{}
		sink.replay(context.Background())
	}
	files, err := sink.spool.files()
	if err != nil || len(files) != 1 {
		t.Fatalf("spool files = %v, %v; want the second batch kept for later", files, err)
	}
	if rendered := metrics.Render(); strings.Contains(rendered, `status="spool_error"`) {
		t.Fatalf("a Retry-After pause counted as a spool error:\n%s", rendered)
	}
}

func TestBatchesSayWhetherTheyAreLiveOrReplayed(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var seen, runs []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get(DeliveryHeader))
		runs = append(runs, r.Header.Get(RunHeader))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Built without its worker, so nothing but this test sends.
	sink := &exportSink{
		client: server.Client(), target: server.URL, metrics: telemetry.NewRegistry(), spool: newTestSpool(t),
		drainTimeout: time.Second, replayBudget: 10 * time.Second,
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := sink.sendBatch(context.Background(), []json.RawMessage{mustMarshalRecord(t, record{Timestamp: now, Level: "info", Message: "live"})}); err != nil {
		t.Fatal(err)
	}
	if err := sink.spool.Write([]json.RawMessage{mustMarshalRecord(t, record{Timestamp: now, Level: "info", Message: "old"})}); err != nil {
		t.Fatal(err)
	}
	sink.replay(context.Background())
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 || seen[0] != "live" || seen[1] != "replay" {
		t.Fatalf("delivery headers = %q, want live then replay", seen)
	}
	if runs[0] != runid.ID || runs[1] != runid.ID {
		t.Fatalf("run headers = %q, want this process's run ID %q", runs, runid.ID)
	}
}
