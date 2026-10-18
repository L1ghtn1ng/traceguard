package eventsink

import (
	"encoding/json"
	"strings"
	"testing"
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
