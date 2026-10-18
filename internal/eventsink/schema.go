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

// marshalOCSFRecord encodes a record as an OCSF event. If the event exceeds
// the record size limit, its unmapped fields are dropped and the event is
// marked truncated rather than lost.
func marshalOCSFRecord(entry record) (json.RawMessage, error) {
	event := ocsf.Convert(ocsf.Record{
		Timestamp: entry.Timestamp, Level: entry.Level, Message: entry.Message,
		Hostname: entry.Hostname, Fields: entry.Fields,
	})
	encoded, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	if len(encoded) <= maxSerializedRecordBytes {
		return encoded, nil
	}
	event["unmapped"] = map[string]any{"telemetry_truncated": true}
	encoded, err = json.Marshal(event)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxSerializedRecordBytes {
		return nil, fmt.Errorf("serialized OCSF event exceeds %d bytes", maxSerializedRecordBytes)
	}
	return encoded, nil
}
