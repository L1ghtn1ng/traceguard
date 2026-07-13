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
}

func newSyslogSink(ctx context.Context, cfg Config, metrics *telemetry.Registry) (*syslogSink, error) {
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.SyslogURL))
	if err != nil {
		return nil, fmt.Errorf("parse event syslog url: %w", err)
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
	facility, ok := syslogFacilityCode(cfg.SyslogFacility)
	if !ok {
		return nil, fmt.Errorf("unsupported event syslog facility %q", cfg.SyslogFacility)
	}
	tag := strings.TrimSpace(cfg.SyslogTag)
	if tag == "" || strings.ContainsAny(tag, " \t\r\n") {
		return nil, errors.New("event syslog tag must be non-empty and must not contain whitespace")
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

	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		hostname = "-"
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
		hostname:   sanitizeSyslogToken(hostname),
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
			if err := s.send(payload); err != nil {
				s.metrics.IncEventSyslog("error")
				continue
			}
			s.metrics.IncEventSyslog("success")
		}
	}
}

func (s *syslogSink) send(payload []byte) error {
	dialer := &net.Dialer{Timeout: s.timeout}
	var conn net.Conn
	var err error
	if s.tlsConfig != nil {
		conn, err = tls.DialWithDialer(dialer, s.network, s.address, s.tlsConfig)
	} else {
		conn, err = dialer.Dial(s.network, s.address)
	}
	if err != nil {
		return err
	}
	defer conn.Close()
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
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		return nil, err
	}
	priority := s.facility*8 + syslogSeverity(entry.Level)
	timestamp := strings.TrimSpace(entry.Timestamp)
	if timestamp == "" {
		timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	message := fmt.Sprintf("<%d>1 %s %s %s - - - %s", priority, timestamp, s.hostname, s.tag, payload)
	return []byte(message), nil
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

func sanitizeSyslogToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "-"
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return "-"
	}
	return value
}
