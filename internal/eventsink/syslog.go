package eventsink

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type syslogSink struct {
	mu         sync.Mutex
	closed     bool
	network    string
	address    string
	serverName string
	facility   int
	tag        string
	timeout    time.Duration
	tlsConfig  *tls.Config
	queue      chan []byte
	metrics    *telemetry.Registry
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	hostname   string
	encode     recordEncoder
}

// RFC 5424 section 6 header field limits. HOSTNAME, APP-NAME, PROCID and
// MSGID must consist of PRINTUSASCII (%d33-126) only.
const (
	maxSyslogHostnameBytes = 255
	maxSyslogTagBytes      = 48
)

func newSyslogSink(ctx context.Context, cfg Config, metrics *telemetry.Registry, hostname string) (*syslogSink, error) {
	encode, err := newRecordEncoder(cfg.Schema)
	if err != nil {
		return nil, err
	}
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.SyslogURL))
	if err != nil {
		return nil, errors.New("event syslog url is not valid")
	}
	network, tlsEnabled, err := syslogNetwork(parsed.Scheme)
	if err != nil {
		return nil, err
	}
	host := parsed.Hostname()
	port := parsed.Port()
	if host == "" || port == "" {
		return nil, errors.New("event syslog url must include host and port")
	}
	if parsed.User != nil {
		return nil, errors.New("event syslog url must not contain user credentials")
	}
	facility, ok := syslogFacilityCode(cfg.SyslogFacility)
	if !ok {
		return nil, fmt.Errorf("unsupported event syslog facility %q", cfg.SyslogFacility)
	}
	tag := strings.TrimSpace(cfg.SyslogTag)
	if tag == "" || len(tag) > maxSyslogTagBytes || !isSyslogPrintUSASCII(tag) {
		return nil, fmt.Errorf("event syslog tag must be 1-%d bytes of printable US-ASCII (no whitespace or control characters)", maxSyslogTagBytes)
	}
	if cfg.SyslogTimeout <= 0 {
		return nil, errors.New("event syslog timeout must be positive")
	}

	var tlsConfig *tls.Config
	if tlsEnabled {
		rootCAs, err := x509.SystemCertPool()
		if err != nil || rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		if strings.TrimSpace(cfg.SyslogCAPath) != "" {
			pem, err := os.ReadFile(cfg.SyslogCAPath)
			if err != nil {
				return nil, fmt.Errorf("read event syslog ca: %w", err)
			}
			if !rootCAs.AppendCertsFromPEM(pem) {
				return nil, errors.New("append event syslog ca: no certificates found")
			}
		}
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
			ServerName: host,
		}
	}

	sinkCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	sink := &syslogSink{
		network:    network,
		address:    net.JoinHostPort(host, port),
		serverName: host,
		facility:   facility,
		tag:        tag,
		timeout:    cfg.SyslogTimeout,
		tlsConfig:  tlsConfig,
		queue:      make(chan []byte, syslogQueueSize),
		metrics:    metrics,
		cancel:     cancel,
		hostname:   sanitizeSyslogToken(hostname, maxSyslogHostnameBytes),
		encode:     encode,
	}
	sink.wg.Go(func() {
		sink.run(sinkCtx)
	})
	return sink, nil
}

func (s *syslogSink) Enqueue(entry record) {
	payload, err := s.message(entry)
	if err != nil {
		s.metrics.IncEventSyslog("error")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.metrics.IncEventSyslog("dropped")
		return
	}
	select {
	case s.queue <- payload:
		s.metrics.IncEventSyslog("queued")
	default:
		s.metrics.IncEventSyslog("dropped")
	}
}

func (s *syslogSink) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case payload, ok := <-s.queue:
			if !ok {
				return
			}
			if err := s.send(ctx, payload); err != nil {
				s.metrics.IncEventSyslog("error")
				continue
			}
			s.metrics.IncEventSyslog("success")
		}
	}
}

func (s *syslogSink) send(ctx context.Context, payload []byte) (sendErr error) {
	dialer := &net.Dialer{Timeout: s.timeout}
	var conn net.Conn
	var err error
	if s.tlsConfig != nil {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: s.tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, s.network, s.address)
	} else {
		conn, err = dialer.DialContext(ctx, s.network, s.address)
	}
	if err != nil {
		return err
	}
	defer func() {
		sendErr = errors.Join(sendErr, conn.Close())
	}()
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return err
	}
	if s.network == "tcp" {
		payload = fmt.Appendf(nil, "%d %s", len(payload), payload)
	}
	_, err = conn.Write(payload)
	return err
}

func (s *syslogSink) message(entry record) ([]byte, error) {
	priority := s.facility*8 + syslogSeverity(entry.Level)
	timestamp := strings.TrimSpace(entry.Timestamp)
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	header := fmt.Sprintf("<%d>1 %s %s %s - - - ", priority, timestamp, s.hostname, s.tag)
	var payload []byte
	var err error
	if s.network == "udp" {
		available := maxSyslogUDPPayloadBytes - len(header)
		if available <= 0 {
			return nil, errors.New("syslog header exceeds UDP payload limit")
		}
		payload, err = marshalUDPRecord(entry, available, s.encode)
	} else {
		payload, err = s.encode(entry)
	}
	if err != nil {
		return nil, err
	}
	return append([]byte(header), payload...), nil
}

func marshalUDPRecord(entry record, limit int, encode recordEncoder) ([]byte, error) {
	// Records were already bounded by the recorder; only shorten them further
	// when the complete record does not fit in one datagram.
	if payload, err := encode(entry); err == nil && len(payload) <= limit {
		return payload, nil
	}
	originalMessage := entry.Message
	originalFields := entry.Fields
	for _, bounds := range []struct {
		message int
		fields  int
	}{
		{message: 2048, fields: 4096},
		{message: 1024, fields: 2048},
		{message: 512, fields: 1024},
		{message: 256, fields: 512},
	} {
		message, messageTruncated := truncateUTF8(originalMessage, bounds.message)
		entry.Message, entry.Fields = boundTelemetry(message, originalFields, bounds.fields)
		entry.Fields["syslog_udp_bounded"] = true
		if messageTruncated {
			entry.Fields["telemetry_truncated"] = true
		}
		payload, err := encode(entry)
		if err == nil && len(payload) <= limit {
			return payload, nil
		}
	}
	entry.Message, _ = truncateUTF8(originalMessage, 128)
	entry.Fields = map[string]any{
		"syslog_udp_bounded":         true,
		"telemetry_truncated":        true,
		"telemetry_truncated_fields": len(originalFields),
	}
	// Keep what classifies the record, so an OCSF event keeps its class.
	for _, name := range udpClassificationFields {
		if text, ok := originalFields[name].(string); ok {
			entry.Fields[name], _ = truncateUTF8(text, 128)
		}
	}
	payload, err := encode(entry)
	if err != nil {
		return nil, err
	}
	if len(payload) > limit {
		return nil, fmt.Errorf("bounded syslog record exceeds %d-byte payload budget", limit)
	}
	return payload, nil
}

// udpClassificationFields survive the last UDP fallback: the event name and
// the fields that pick its OCSF class, activity, disposition, and finding.
var udpClassificationFields = []string{
	"event", "operation", "change", "mode", "source_event", "alert_id", "detection_rule_id", "severity",
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(syslogShutdownFlush):
		s.cancel()
		<-done
	}
	s.cancel()
	return nil
}

func syslogNetwork(scheme string) (network string, tlsEnabled bool, err error) {
	switch scheme {
	case "syslog+udp":
		return "udp", false, nil
	case "syslog+tcp":
		return "tcp", false, nil
	case "syslog+tls":
		return "tcp", true, nil
	default:
		return "", false, errors.New("event syslog url must use syslog+udp://, syslog+tcp://, or syslog+tls://")
	}
}

func syslogFacilityCode(facility string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(facility)) {
	case "kern":
		return 0, true
	case "user":
		return 1, true
	case "mail":
		return 2, true
	case "daemon":
		return 3, true
	case "auth":
		return 4, true
	case "syslog":
		return 5, true
	case "lpr":
		return 6, true
	case "news":
		return 7, true
	case "uucp":
		return 8, true
	case "cron":
		return 9, true
	case "authpriv":
		return 10, true
	case "ftp":
		return 11, true
	case "local0":
		return 16, true
	case "local1":
		return 17, true
	case "local2":
		return 18, true
	case "local3":
		return 19, true
	case "local4":
		return 20, true
	case "local5":
		return 21, true
	case "local6":
		return 22, true
	case "local7":
		return 23, true
	default:
		return 0, false
	}
}

func syslogSeverity(level string) int {
	if strings.EqualFold(strings.TrimSpace(level), "error") {
		return 3
	}
	return 6
}

// sanitizeSyslogToken makes value safe for an RFC 5424 header field: every
// byte outside PRINTUSASCII (%d33-126) is replaced with '_', the result is
// truncated to maxBytes, and an empty value becomes the NILVALUE "-".
func sanitizeSyslogToken(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" || maxBytes <= 0 {
		return "-"
	}
	if len(value) > maxBytes {
		value = value[:maxBytes]
	}
	if isSyslogPrintUSASCII(value) {
		return value
	}
	sanitized := []byte(value)
	for i, b := range sanitized {
		if !isSyslogPrintUSASCIIByte(b) {
			sanitized[i] = '_'
		}
	}
	return string(sanitized)
}

func isSyslogPrintUSASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if !isSyslogPrintUSASCIIByte(value[i]) {
			return false
		}
	}
	return true
}

func isSyslogPrintUSASCIIByte(b byte) bool {
	return b >= 33 && b <= 126
}
