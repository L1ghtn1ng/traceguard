package eventsink

import (
	"bufio"
	"context"
	"io"
	"net"
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

// acceptFrames accepts TCP connections and sends each connection's reader.
func acceptFrames(t *testing.T) (string, <-chan *bufio.Reader) {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	closeTestResource(t, listener)
	accepted := make(chan *bufio.Reader, 4)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = conn.Close() })
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			accepted <- bufio.NewReader(conn)
		}
	}()
	return listener.Addr().String(), accepted
}

func readFrame(t *testing.T, reader *bufio.Reader, want string) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != want {
		t.Fatalf("frame = %q, %v; want %q", got, err, want)
	}
}

func nextConnection(t *testing.T, accepted <-chan *bufio.Reader) *bufio.Reader {
	t.Helper()
	select {
	case reader := <-accepted:
		return reader
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a syslog connection")
		return nil
	}
}

func TestSyslogSendReusesTCPConnection(t *testing.T) {
	t.Parallel()

	address, accepted := acceptFrames(t)
	sink := &syslogSink{network: "tcp", address: address, timeout: time.Second, idleProbe: time.Hour}
	var conn *syslogConn
	var err error
	for _, message := range []string{"first", "second"} {
		if conn, err = sink.send(t.Context(), conn, []byte(message)); err != nil {
			t.Fatalf("send %q returned error: %v", message, err)
		}
	}
	defer func() { _ = conn.Close() }()

	reader := nextConnection(t, accepted)
	readFrame(t, reader, "5 first")
	readFrame(t, reader, "6 second")
	select {
	case <-accepted:
		t.Fatal("send opened a second connection instead of reusing the first")
	default:
	}
}

func TestSyslogSendRedialsAfterFailedWrite(t *testing.T) {
	t.Parallel()

	address, accepted := acceptFrames(t)
	// Skip the idle check, so the failed write itself triggers the redial.
	sink := &syslogSink{network: "tcp", address: address, timeout: time.Second, idleProbe: time.Hour}
	stale, peer := net.Pipe()
	_ = peer.Close()
	_ = stale.Close()
	conn, err := sink.send(t.Context(), &syslogConn{Conn: stale, dialed: time.Now(), used: time.Now()}, []byte("retry"))
	if err != nil {
		t.Fatalf("send over a broken connection returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	readFrame(t, nextConnection(t, accepted), "5 retry")
}

func TestSyslogSendRedialsAfterCollectorClosesIdleConnection(t *testing.T) {
	t.Parallel()

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	closeTestResource(t, listener)
	closed := make(chan struct{})
	second := make(chan string, 1)
	go func() {
		first, err := listener.Accept()
		if err != nil {
			return
		}
		buffer := make([]byte, len("5 first"))
		_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.ReadFull(first, buffer)
		// The collector drops the idle connection, as a load balancer does.
		_ = first.Close()
		close(closed)
		next, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = next.Close() }()
		_ = next.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer = make([]byte, len("6 second"))
		_, _ = io.ReadFull(next, buffer)
		second <- string(buffer)
	}()

	sink := &syslogSink{network: "tcp", address: listener.Addr().String(), timeout: time.Second}
	conn, err := sink.send(t.Context(), nil, []byte("first"))
	if err != nil {
		t.Fatalf("send first returned error: %v", err)
	}
	<-closed
	// Let the collector's FIN reach the client.
	time.Sleep(50 * time.Millisecond)
	conn, err = sink.send(t.Context(), conn, []byte("second"))
	if err != nil {
		t.Fatalf("send second returned error: %v", err)
	}
	defer func() { _ = conn.Close() }()
	select {
	case message := <-second:
		if message != "6 second" {
			t.Fatalf("second frame = %q, want it delivered on a new connection", message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the message after the collector closed the connection was lost")
	}
}

func TestSyslogSendRedialsOldConnections(t *testing.T) {
	t.Parallel()

	t.Run("tcp", func(t *testing.T) {
		t.Parallel()
		address, accepted := acceptFrames(t)
		sink := &syslogSink{network: "tcp", address: address, timeout: time.Second, maxConnAge: time.Nanosecond, idleProbe: time.Hour}
		var conn *syslogConn
		var err error
		for _, message := range []string{"first", "second"} {
			if conn, err = sink.send(t.Context(), conn, []byte(message)); err != nil {
				t.Fatalf("send %q returned error: %v", message, err)
			}
		}
		defer func() { _ = conn.Close() }()
		readFrame(t, nextConnection(t, accepted), "5 first")
		readFrame(t, nextConnection(t, accepted), "6 second")
	})

	t.Run("udp", func(t *testing.T) {
		t.Parallel()
		server, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket returned error: %v", err)
		}
		closeTestResource(t, server)
		sink := &syslogSink{network: "udp", address: server.LocalAddr().String(), timeout: time.Second, maxConnAge: time.Nanosecond}
		var conn *syslogConn
		for _, message := range []string{"first", "second"} {
			if conn, err = sink.send(t.Context(), conn, []byte(message)); err != nil {
				t.Fatalf("send %q returned error: %v", message, err)
			}
		}
		defer func() { _ = conn.Close() }()
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		sources := make([]string, 0, 2)
		buffer := make([]byte, 64)
		for range 2 {
			_, from, err := server.ReadFrom(buffer)
			if err != nil {
				t.Fatalf("ReadFrom returned error: %v", err)
			}
			sources = append(sources, from.String())
		}
		if sources[0] == sources[1] {
			t.Fatalf("both datagrams came from %s, want the old socket redialed", sources[0])
		}
	})
}
