package eventsink

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestNewRecordEncoderSelectsSchema(t *testing.T) {
	t.Parallel()

	entry := record{Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: "exec", Hostname: "h", Fields: map[string]any{"event": "exec"}}
	for schema, wantKey := range map[string]string{"": "event", SchemaTraceGuard: "event", SchemaOCSF: "class_uid"} {
		encode, err := newRecordEncoder(schema)
		if err != nil {
			t.Fatalf("newRecordEncoder(%q) returned error: %v", schema, err)
		}
		payload, err := encode(entry)
		if err != nil {
			t.Fatal(err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(payload, &decoded); err != nil {
			t.Fatal(err)
		}
		if _, ok := decoded[wantKey]; !ok {
			t.Errorf("schema %q payload %s lacks %q", schema, payload, wantKey)
		}
	}
	if _, err := newRecordEncoder("ecs"); err == nil || !strings.Contains(err.Error(), "unsupported event schema") {
		t.Fatalf("unknown schema error = %v", err)
	}
}

func TestMarshalOCSFRecordDropsUnmappedFieldsWhenOversized(t *testing.T) {
	t.Parallel()

	fields := map[string]any{"event": "exec"}
	for index := range 40 {
		fields[strings.Repeat("k", 4)+string(rune('a'+index%26))+string(rune('a'+index/26))] = strings.Repeat("v", 1000)
	}
	payload, err := marshalOCSFRecord(record{Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: "exec", Fields: fields})
	if err != nil {
		t.Fatalf("marshalOCSFRecord returned error: %v", err)
	}
	if len(payload) > maxSerializedRecordBytes {
		t.Fatalf("payload is %d bytes, over the %d limit", len(payload), maxSerializedRecordBytes)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if unmapped, _ := decoded["unmapped"].(map[string]any); unmapped["telemetry_truncated"] != true {
		t.Fatalf("unmapped = %v, want a truncation marker", decoded["unmapped"])
	}
	if decoded["class_uid"] != float64(1007) {
		t.Fatalf("class_uid = %v, want the event still classified", decoded["class_uid"])
	}
}

func TestSyslogUDPBoundsOCSFRecords(t *testing.T) {
	t.Parallel()

	payload, err := marshalUDPRecord(record{
		Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: strings.Repeat("m", 3000), Hostname: "h",
		Fields: map[string]any{"event": "exec", "detail": strings.Repeat("d", 3000)},
	}, 2048, marshalOCSFRecord)
	if err != nil {
		t.Fatalf("marshalUDPRecord returned error: %v", err)
	}
	if len(payload) > 2048 || !strings.Contains(string(payload), `"class_uid"`) {
		t.Fatalf("bounded OCSF datagram is %d bytes: %s", len(payload), payload)
	}
}

func TestMarshalOCSFRecordShortensOversizedMappedAttributes(t *testing.T) {
	t.Parallel()

	techniques := make([]any, 0, 600)
	for index := range 600 {
		techniques = append(techniques, fmt.Sprintf("T%04d.%03d", 1000+index, index))
	}
	fields := map[string]any{
		"event": "detection_alert", "alert_id": "a1", "detection_rule_id": "custom.noisy", "severity": "error",
		"detection_message": strings.Repeat("t", 4000), "mitre_techniques": techniques,
	}
	payload, err := marshalOCSFRecord(record{Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: "detection-alert", Fields: fields})
	if err != nil {
		t.Fatalf("marshalOCSFRecord returned error: %v", err)
	}
	if len(payload) > maxSerializedRecordBytes {
		t.Fatalf("payload is %d bytes, over the %d limit", len(payload), maxSerializedRecordBytes)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	finding, _ := decoded["finding_info"].(map[string]any)
	if decoded["class_uid"] != float64(2004) || finding["uid"] != "a1" {
		t.Fatalf("class_uid = %v finding_info = %v, want the finding kept", decoded["class_uid"], finding)
	}
	if unmapped, _ := decoded["unmapped"].(map[string]any); unmapped["telemetry_truncated"] != true {
		t.Fatalf("unmapped = %v, want a truncation marker", decoded["unmapped"])
	}
}

func TestSyslogUDPFallbackKeepsOCSFClassification(t *testing.T) {
	t.Parallel()

	fields := map[string]any{"event": "detection_alert", "detection_rule_id": "custom.big", "severity": "error"}
	for index := range 60 {
		fields[fmt.Sprintf("detail_%02d", index)] = strings.Repeat("d", 100)
	}
	payload, err := marshalUDPRecord(record{Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: "detection-alert", Hostname: "h", Fields: fields},
		700, marshalOCSFRecord)
	if err != nil {
		t.Fatalf("marshalUDPRecord returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["class_uid"] != float64(2004) {
		t.Fatalf("class_uid = %v, want a detection finding: %s", decoded["class_uid"], payload)
	}
}

func TestSpoolReplaysOnlyTheConfiguredSchema(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	plain, err := newSpoolStore(dir, SchemaTraceGuard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if err := plain.Write([]json.RawMessage{json.RawMessage(`{"event":"dns"}`)}); err != nil {
		t.Fatal(err)
	}
	ocsf, err := newSpoolStore(dir, SchemaOCSF)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ocsf.Close() }()
	if err := ocsf.Write([]json.RawMessage{json.RawMessage(`{"class_uid":4003}`)}); err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		store *spoolStore
		want  string
	}{"traceguard": {plain, `"event"`}, "ocsf": {ocsf, `"class_uid"`}} {
		var sent []string
		if err := test.store.Replay(func(payload []byte) error {
			sent = append(sent, string(payload))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(sent) != 1 || !strings.Contains(sent[0], test.want) {
			t.Errorf("%s replayed %v, want only its own batch", name, sent)
		}
	}
}

func TestSpoolCountsBatchesOfAnotherSchema(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	ocsf, err := newSpoolStore(dir, SchemaOCSF)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ocsf.Close() }()
	if err := ocsf.Write([]json.RawMessage{json.RawMessage(`{"class_uid":4003}`)}); err != nil {
		t.Fatal(err)
	}
	plain, err := newSpoolStore(dir, SchemaTraceGuard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plain.Close() }()
	if count, err := plain.stranded(); err != nil || count != 1 {
		t.Fatalf("stranded = %d, %v; want the OCSF batch counted", count, err)
	}
	if count, err := ocsf.stranded(); err != nil || count != 0 {
		t.Fatalf("stranded for its own schema = %d, %v; want 0", count, err)
	}
}

func TestOversizedOCSFRecordKeepsItsEventName(t *testing.T) {
	t.Parallel()

	fields := map[string]any{"event": "egress_blocked", "peer_address": "203.0.113.9"}
	for index := range 40 {
		fields[fmt.Sprintf("detail_%02d", index)] = strings.Repeat("d", 1000)
	}
	payload, err := marshalOCSFRecord(record{Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: "blocked-egress", Fields: fields})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	unmapped, _ := decoded["unmapped"].(map[string]any)
	if unmapped["event"] != "egress_blocked" || unmapped["telemetry_truncated"] != true {
		t.Fatalf("unmapped = %v, want the event name kept with the truncation marker", unmapped)
	}
}

func TestSpoolReplaySkipsUnreadableEntries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := newSpoolStore(dir, SchemaTraceGuard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	// Sorts before every batch Write names by its timestamp.
	if err := os.WriteFile(filepath.Join(dir, "0-oversized.json"), make([]byte, maxSpoolPayloadBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Write([]json.RawMessage{json.RawMessage(`{"event":"dns"}`)}); err != nil {
		t.Fatal(err)
	}
	var sent []string
	err = store.Replay(func(payload []byte) error {
		sent = append(sent, string(payload))
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "0-oversized.json") {
		t.Errorf("Replay error = %v, want the unreadable entry reported", err)
	}
	if len(sent) != 1 || !strings.Contains(sent[0], `"event"`) {
		t.Fatalf("Replay sent %v, want the batch after the unreadable entry", sent)
	}
	files, err := store.files()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "0-oversized.json" {
		t.Fatalf("spool files = %v, want only the unreadable entry left in place", files)
	}
}

// stalledCollector answers after headers only once release is closed; until
// then it holds the request or, with headersFirst, the reply body.
func stalledCollector(t *testing.T, headersFirst bool) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if headersFirst {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{"))
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server
}

func TestExportSendStopsDrainingAStalledReply(t *testing.T) {
	t.Parallel()

	server := stalledCollector(t, true)
	sink := &exportSink{client: server.Client(), target: server.URL, drainTimeout: 50 * time.Millisecond}
	started := time.Now()
	if err := sink.sendPayload(t.Context(), []byte("[]")); err != nil {
		t.Fatalf("sendPayload returned error: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("sendPayload waited %s on a stalled reply body, want about the drain timeout", elapsed)
	}
}

func TestExportReplayBudgetBoundsAStalledRequest(t *testing.T) {
	t.Parallel()

	store, err := newSpoolStore(t.TempDir(), SchemaTraceGuard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Write([]json.RawMessage{json.RawMessage(`{"event":"dns"}`)}); err != nil {
		t.Fatal(err)
	}
	server := stalledCollector(t, false)
	metrics := telemetry.NewRegistry()
	sink := &exportSink{
		client: server.Client(), target: server.URL, metrics: metrics, spool: store,
		drainTimeout: time.Second, replayBudget: 100 * time.Millisecond,
	}
	started := time.Now()
	sink.replay(context.Background())
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("replay ran %s against a stalled collector, want about its budget", elapsed)
	}
	if files, err := store.files(); err != nil || len(files) != 1 {
		t.Fatalf("spool files = %v, %v; want the unsent batch kept", files, err)
	}
	if rendered := metrics.Render(); !strings.Contains(rendered, `traceguard_event_export_total{status="replay_error"} 1`) {
		t.Fatalf("metrics lack the replay error:\n%s", rendered)
	}
}

func TestExportReplayCountsUnreadableEntries(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store, err := newSpoolStore(dir, SchemaTraceGuard)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	if err := os.WriteFile(filepath.Join(dir, "0-oversized.json"), make([]byte, maxSpoolPayloadBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	metrics := telemetry.NewRegistry()
	sink := &exportSink{metrics: metrics, spool: store, replayBudget: time.Second}
	sink.replay(t.Context())
	if rendered := metrics.Render(); !strings.Contains(rendered, `traceguard_event_export_total{status="spool_error"} 1`) {
		t.Fatalf("metrics lack the unreadable spool entry:\n%s", rendered)
	}
}
