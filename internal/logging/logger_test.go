package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

func TestNewLoggerUsesOperatingSystemHostname(t *testing.T) {
	t.Parallel()

	want, err := os.Hostname()
	if err != nil {
		t.Fatalf("os.Hostname returned error: %v", err)
	}
	logger, err := NewLogger(io.Discard, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	if logger.Hostname() != strings.TrimSpace(want) {
		t.Fatalf("hostname = %q, want %q", logger.Hostname(), strings.TrimSpace(want))
	}
}

func TestLoggerJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := newLogger(&buf, "json", "worker-1")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	if err := logger.Info("dns", map[string]any{
		"program": "curl",
		"pid":     uint32(42),
	}); err != nil {
		t.Fatalf("Info returned error: %v", err)
	}

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
	if decoded["hostname"] != "worker-1" {
		t.Fatalf("hostname = %v, want worker-1", decoded["hostname"])
	}
}

func TestLoggerJSONProtectsReservedFields(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := newLogger(&buf, "json", "worker-1")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	if err := logger.Info("dns", map[string]any{"timestamp": "forged", "level": "forged", "message": "forged", "hostname": "forged"}); err != nil {
		t.Fatalf("Info returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatalf("json.Unmarshal returned error: %v", err)
	}
	if decoded["level"] != "info" || decoded["message"] != "dns" || decoded["timestamp"] == "forged" || decoded["hostname"] != "worker-1" {
		t.Fatalf("reserved fields were overwritten: %#v", decoded)
	}
}

func TestLoggerTextIncludesProtectedHostname(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger, err := newLogger(&buf, "text", "worker-1")
	if err != nil {
		t.Fatalf("newLogger returned error: %v", err)
	}
	if err := logger.Info("dns", map[string]any{"hostname": "forged", "program": "curl"}); err != nil {
		t.Fatalf("Info returned error: %v", err)
	}

	line := strings.TrimSpace(buf.String())
	if !strings.Contains(line, `dns level="info" hostname="worker-1" program="curl"`) {
		t.Fatalf("text log = %q, want protected hostname", line)
	}
	if strings.Contains(line, "forged") {
		t.Fatalf("text log contains caller-supplied hostname: %q", line)
	}
}

func TestNewLoggerRejectsEmptyHostname(t *testing.T) {
	t.Parallel()

	if _, err := newLogger(io.Discard, "json", " \t "); err == nil {
		t.Fatal("newLogger accepted an empty hostname")
	}
}
