package eventsink

import (
	"encoding/json"
	"fmt"

	"github.com/L1ghtn1ng/traceguard/internal/ocsf"
)

// Event schemas for the HTTPS export and syslog sinks.
const (
	SchemaTraceGuard = "traceguard"
	SchemaOCSF       = "ocsf"
)

// recordEncoder serializes one record for a remote sink.
type recordEncoder func(record) (json.RawMessage, error)

func newRecordEncoder(schema string) (recordEncoder, error) {
	switch schema {
	case "", SchemaTraceGuard:
		return marshalSingleRecord, nil
	case SchemaOCSF:
		return marshalOCSFRecord, nil
	default:
		return nil, fmt.Errorf("unsupported event schema %q", schema)
	}
}

// marshalOCSFRecord encodes a record as an OCSF event. An event over the
// record size limit is marked truncated rather than lost: its unmapped fields
// are dropped first, then its mapped strings and lists are shortened, which
// keeps the classification and every attribute present.
func marshalOCSFRecord(entry record) (json.RawMessage, error) {
	event := ocsf.Convert(ocsf.Record{
		Timestamp: entry.Timestamp, Level: entry.Level, Message: entry.Message,
		Hostname: entry.Hostname, Fields: entry.Fields,
	})
	encoded, err := json.Marshal(event)
	if err != nil || len(encoded) <= maxSerializedRecordBytes {
		return encoded, err
	}
	// Several TraceGuard events share an OCSF class and activity, so keep
	// the names that tell them apart.
	kept := map[string]any{"telemetry_truncated": true}
	if unmapped, ok := event["unmapped"].(map[string]any); ok {
		for _, name := range []string{"event", "source_event"} {
			if text, ok := unmapped[name].(string); ok {
				kept[name], _ = truncateUTF8(text, 128)
			}
		}
	}
	event["unmapped"] = kept
	for _, bounds := range []struct{ text, items int }{{0, 0}, {512, 16}, {128, 4}} {
		candidate := event
		if bounds.text > 0 {
			candidate = shrinkOCSFMap(event, bounds.text, bounds.items)
		}
		encoded, err = json.Marshal(candidate)
		if err != nil {
			return nil, err
		}
		if len(encoded) <= maxSerializedRecordBytes {
			return encoded, nil
		}
	}
	return nil, fmt.Errorf("serialized OCSF event exceeds %d bytes", maxSerializedRecordBytes)
}

// shrinkOCSFMap copies an OCSF object with every string cut to text bytes
// and every list to items entries.
func shrinkOCSFMap(object map[string]any, text, items int) map[string]any {
	shrunk := make(map[string]any, len(object))
	for key, value := range object {
		shrunk[key] = shrinkOCSFValue(value, text, items)
	}
	return shrunk
}

func shrinkOCSFValue(value any, text, items int) any {
	switch typed := value.(type) {
	case string:
		short, _ := truncateUTF8(typed, text)
		return short
	case map[string]any:
		return shrinkOCSFMap(typed, text, items)
	case []map[string]any:
		shrunk := make([]map[string]any, 0, min(len(typed), items))
		for _, item := range typed[:min(len(typed), items)] {
			shrunk = append(shrunk, shrinkOCSFMap(item, text, items))
		}
		return shrunk
	case []string:
		shrunk := make([]string, 0, min(len(typed), items))
		for _, item := range typed[:min(len(typed), items)] {
			short, _ := truncateUTF8(item, text)
			shrunk = append(shrunk, short)
		}
		return shrunk
	case []any:
		shrunk := make([]any, 0, min(len(typed), items))
		for _, item := range typed[:min(len(typed), items)] {
			shrunk = append(shrunk, shrinkOCSFValue(item, text, items))
		}
		return shrunk
	default:
		return value
	}
}
