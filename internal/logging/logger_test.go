package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestLoggerJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := NewLogger(&buf, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	logger.Info("dns", map[string]any{
		"program": "curl",
		"pid":     uint32(42),
	})

	line := strings.TrimSpace(buf.String())
	var decoded map[string]any
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}

	if decoded["message"] != "dns" {
		t.Fatalf("message = %v, want dns", decoded["message"])
	}
	if decoded["program"] != "curl" {
		t.Fatalf("program = %v, want curl", decoded["program"])
	}
	if decoded["level"] != "info" {
		t.Fatalf("level = %v, want info", decoded["level"])
	}
}
