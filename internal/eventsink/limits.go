package eventsink

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxRecordMessageBytes    = 4096
	maxRecordStringBytes     = 4096
	maxRecordFields          = 128
	maxRecordSliceItems      = 128
	maxRecordObjectFields    = 16
	maxRecordFieldBytes      = 24 << 10
	maxSerializedRecordBytes = 32 << 10
	maxRecordEnvelopeBytes   = 1 << 10
	maxSyslogUDPPayloadBytes = 8 << 10
)

func boundTelemetry(msg string, fields map[string]any, fieldBudget int) (string, map[string]any) {
	boundedMessage, messageTruncated := truncateUTF8(msg, maxRecordMessageBytes)
	if fieldBudget <= 0 || fieldBudget > maxRecordFieldBytes {
		fieldBudget = maxRecordFieldBytes
	}
	encodedMessage, err := json.Marshal(boundedMessage)
	if err != nil {
		encodedMessage = nil
		messageTruncated = true
	}
	serializedFieldBudget := maxSerializedRecordBytes - len(encodedMessage) - maxRecordEnvelopeBytes
	fieldBudget = min(fieldBudget, max(0, serializedFieldBudget))

	// Admit the cheapest fields first so small kernel and core fields always
	// survive. Process-controlled strings such as command lines and paths can
	// expand up to six times under JSON escaping; ordering by name would let
	// one of them exhaust the budget and drop identity fields sorted after it.
	type candidate struct {
		key       string
		value     any
		keyCost   int
		cost      int
		truncated bool
	}
	candidates := make([]candidate, 0, len(fields))
	truncatedFields := 0
	for key, raw := range fields {
		encodedKey, err := json.Marshal(key)
		if err != nil || len(encodedKey) > maxRecordStringBytes {
			truncatedFields++
			continue
		}
		value, valueTruncated := boundValue(raw)
		encoded, err := json.Marshal(value)
		if err != nil {
			value = "[unserializable]"
			encoded = []byte(`"[unserializable]"`)
			valueTruncated = true
		}
		keyCost := len(encodedKey) + 2 // colon and comma
		candidates = append(candidates, candidate{
			key: key, value: value, keyCost: keyCost, cost: keyCost + len(encoded), truncated: valueTruncated,
		})
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		if order := cmp.Compare(a.cost, b.cost); order != 0 {
			return order
		}
		return strings.Compare(a.key, b.key)
	})

	bounded := make(map[string]any, min(len(candidates)+2, maxRecordFields+2))
	used := 0
	for index, field := range candidates {
		if index >= maxRecordFields {
			truncatedFields += len(candidates) - index
			break
		}
		remaining := fieldBudget - used
		if field.cost > remaining {
			text, ok := field.value.(string)
			if !ok {
				truncatedFields++
				continue
			}
			shortened, encodedLen, ok := truncateJSONString(text, remaining-field.keyCost)
			if !ok {
				truncatedFields++
				continue
			}
			field.value = shortened
			field.cost = field.keyCost + encodedLen
			field.truncated = true
		}
		bounded[field.key] = field.value
		used += field.cost
		if field.truncated {
			truncatedFields++
		}
	}
	if messageTruncated || truncatedFields > 0 {
		bounded["telemetry_truncated"] = true
		bounded["telemetry_truncated_fields"] = truncatedFields
	}
	return boundedMessage, bounded
}

func boundValue(value any) (any, bool) {
	switch typed := value.(type) {
	case string:
		return truncateUTF8(typed, maxRecordStringBytes)
	case []string:
		limit := min(len(typed), maxRecordSliceItems)
		bounded := make([]string, 0, limit)
		truncated := len(typed) > limit
		for _, item := range typed[:limit] {
			item, itemTruncated := truncateUTF8(item, maxRecordStringBytes)
			bounded = append(bounded, item)
			truncated = truncated || itemTruncated
		}
		return bounded, truncated
	case []any:
		limit := min(len(typed), maxRecordSliceItems)
		bounded := make([]any, 0, limit)
		truncated := len(typed) > limit
		for _, item := range typed[:limit] {
			item, itemTruncated := boundValue(item)
			bounded = append(bounded, item)
			truncated = truncated || itemTruncated
		}
		return bounded, truncated
	case map[string]any:
		// Unknown containers are not walked. The one exception is a small
		// flat object, such as an entry of a heartbeat's active responses,
		// which passes unchanged or not at all.
		if smallFlatObject(typed) {
			return typed, false
		}
		return "[value truncated]", true
	case nil, bool,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64,
		float32, float64, json.Number:
		return value, false
	default:
		return "[value truncated]", true
	}
}

func truncateUTF8(value string, limit int) (string, bool) {
	if len(value) <= limit {
		return value, false
	}
	value = value[:limit]
	for !utf8.ValidString(value) {
		_, size := utf8.DecodeLastRuneInString(value)
		if size <= 0 || size > len(value) {
			value = strings.ToValidUTF8(value, "")
			break
		}
		value = value[:len(value)-size]
	}
	return value, true
}

// truncateJSONString returns the longest UTF-8 prefix of value whose JSON
// encoding fits in limit bytes, along with that encoded length.
func truncateJSONString(value string, limit int) (string, int, bool) {
	if limit < len(`""`)+1 {
		return "", 0, false
	}
	low, high := 0, len(value)
	for low < high {
		mid := (low + high + 1) / 2
		prefix, _ := truncateUTF8(value, mid)
		encoded, err := json.Marshal(prefix)
		if err == nil && len(encoded) <= limit {
			low = mid
		} else {
			high = mid - 1
		}
	}
	prefix, _ := truncateUTF8(value, low)
	if prefix == "" {
		return "", 0, false
	}
	encoded, err := json.Marshal(prefix)
	if err != nil || len(encoded) > limit {
		return "", 0, false
	}
	return prefix, len(encoded), true
}

const (
	maxSmallObjectKeyBytes    = 64
	maxSmallObjectStringBytes = 256
)

// smallFlatObject reports whether an object has at most
// maxRecordObjectFields fields, each with a short key and a scalar value.
func smallFlatObject(object map[string]any) bool {
	if len(object) > maxRecordObjectFields {
		return false
	}
	for key, value := range object {
		if len(key) > maxSmallObjectKeyBytes {
			return false
		}
		switch typed := value.(type) {
		case string:
			if len(typed) > maxSmallObjectStringBytes || !utf8.ValidString(typed) {
				return false
			}
		case nil, bool,
			int, int8, int16, int32, int64,
			uint, uint8, uint16, uint32, uint64,
			float32, float64, json.Number:
		default:
			return false
		}
	}
	return true
}
