package eventsink

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func testSyslogConfig(tag string) Config {
	return Config{
		SyslogURL:      "syslog+udp://127.0.0.1:514",
		SyslogFacility: "local0",
		SyslogTag:      tag,
		SyslogTimeout:  time.Second,
	}
}

func assertSyslogPrintUSASCII(t *testing.T, field, value string) {
	t.Helper()
	for i := 0; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 {
			t.Fatalf("%s %q contains byte 0x%02x outside PRINTUSASCII", field, value, value[i])
		}
	}
}

func TestSanitizeSyslogTokenProducesRFC5424Token(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		max   int
		want  string
	}{
		{name: "plain", value: "worker-1.example", max: maxSyslogHostnameBytes, want: "worker-1.example"},
		{name: "empty", value: "", max: maxSyslogHostnameBytes, want: "-"},
		{name: "whitespace only", value: " \t\n", max: maxSyslogHostnameBytes, want: "-"},
		{name: "trimmed", value: "  host  ", max: maxSyslogHostnameBytes, want: "host"},
		{name: "inner whitespace", value: "bad host", max: maxSyslogHostnameBytes, want: "bad_host"},
		{name: "control bytes", value: "a\x00b\x1bc\x7fd", max: maxSyslogHostnameBytes, want: "a_b_c_d"},
		{name: "newline injection", value: "host\n<13>1 forged", max: maxSyslogHostnameBytes, want: "host_<13>1_forged"},
		{name: "non-ascii", value: "hést", max: maxSyslogHostnameBytes, want: "h__st"},
		{name: "truncated", value: strings.Repeat("h", 300), max: maxSyslogHostnameBytes, want: strings.Repeat("h", maxSyslogHostnameBytes)},
		{name: "truncated tag length", value: strings.Repeat("t", 60), max: maxSyslogTagBytes, want: strings.Repeat("t", maxSyslogTagBytes)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeSyslogToken(tt.value, tt.max)
			if got != tt.want {
				t.Fatalf("sanitizeSyslogToken(%q, %d) = %q, want %q", tt.value, tt.max, got, tt.want)
			}
			if len(got) > tt.max {
				t.Fatalf("sanitizeSyslogToken(%q, %d) length = %d, want <= %d", tt.value, tt.max, len(got), tt.max)
			}
			assertSyslogPrintUSASCII(t, "token", got)
		})
	}
}

func TestNewSyslogSinkRejectsNonRFC5424Tag(t *testing.T) {
	t.Parallel()

	for _, tag := range []string{
		"",
		"   ",
		"trace guard",
		"trace\tguard",
		"trace\x00guard",
		"trace\x1bguard",
		"trace\x7fguard",
		"traceéguard",
		strings.Repeat("t", maxSyslogTagBytes+1),
	} {
		sink, err := newSyslogSink(context.Background(), testSyslogConfig(tag), telemetry.NewRegistry(), "worker-1")
		if err == nil {
			_ = sink.Close()
			t.Fatalf("newSyslogSink accepted tag %q", tag)
		}
		if !strings.Contains(err.Error(), "event syslog tag must be 1-48 bytes of printable US-ASCII") {
			t.Fatalf("newSyslogSink(%q) error = %q, want tag validation error", tag, err)
		}
	}
}

func TestNewSyslogSinkAcceptsMaxLengthPrintableTag(t *testing.T) {
	t.Parallel()

	tag := "!" + strings.Repeat("~", maxSyslogTagBytes-1)
	sink, err := newSyslogSink(context.Background(), testSyslogConfig(tag), telemetry.NewRegistry(), "worker-1")
	if err != nil {
		t.Fatalf("newSyslogSink returned error: %v", err)
	}
	closeTestResource(t, sink)
	if sink.tag != tag {
		t.Fatalf("sink tag = %q, want %q", sink.tag, tag)
	}
}

func TestSyslogMessageHeaderTokensArePrintUSASCII(t *testing.T) {
	t.Parallel()

	hostname := "hést\x00name\n<13>1 " + strings.Repeat("x", 400)
	sink, err := newSyslogSink(context.Background(), testSyslogConfig("traceguard"), telemetry.NewRegistry(), hostname)
	if err != nil {
		t.Fatalf("newSyslogSink returned error: %v", err)
	}
	closeTestResource(t, sink)

	message, err := sink.message(record{Timestamp: "2026-07-10T12:00:00Z", Level: "info", Message: "dns"})
	if err != nil {
		t.Fatalf("message returned error: %v", err)
	}
	// <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
	fields := strings.SplitN(string(message), " ", 8)
	if len(fields) != 8 {
		t.Fatalf("syslog message = %q, want RFC 5424 header", message)
	}
	if fields[0] != "<134>1" || fields[1] != "2026-07-10T12:00:00Z" {
		t.Fatalf("syslog header prefix = %q %q, want <134>1 and timestamp", fields[0], fields[1])
	}
	gotHostname, appName, procID, msgID := fields[2], fields[3], fields[4], fields[5]
	if len(gotHostname) != maxSyslogHostnameBytes {
		t.Fatalf("HOSTNAME length = %d, want %d", len(gotHostname), maxSyslogHostnameBytes)
	}
	if !strings.HasPrefix(gotHostname, "h__st_name_<13>1_x") {
		t.Fatalf("HOSTNAME = %q, want sanitized hostname", gotHostname)
	}
	if appName != "traceguard" || procID != "-" || msgID != "-" || fields[6] != "-" {
		t.Fatalf("syslog header = %q, want traceguard - - -", fields[3:7])
	}
	for name, value := range map[string]string{"HOSTNAME": gotHostname, "APP-NAME": appName, "PROCID": procID, "MSGID": msgID} {
		assertSyslogPrintUSASCII(t, name, value)
	}
	if strings.Count(string(message), "\n") != 0 {
		t.Fatalf("syslog message contains newline: %q", message)
	}
}
