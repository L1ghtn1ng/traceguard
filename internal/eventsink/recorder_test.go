package eventsink

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestRecorderWritesArchive(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "traceguard.log")
	logWriter, err := logging.NewRotatingFile(logPath, logging.Options{
		MaxSizeBytes: 1 << 20,
		MaxBackups:   2,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		t.Fatalf("NewRotatingFile returned error: %v", err)
	}
	defer logWriter.Close()

	logger, err := logging.NewLogger(logWriter, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	archivePath := filepath.Join(t.TempDir(), "events.jsonl")
	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{
		ArchivePath: archivePath,
	})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	defer recorder.Close()

	recorder.Info("dns", map[string]any{
		"domain":  "example.com",
		"program": "curl",
	})

	content, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	text := string(content)
	for _, want := range []string{`"message":"dns"`, `"domain":"example.com"`, `"program":"curl"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("archive missing %q in %q", want, text)
		}
	}
}

func TestRecorderErrorDedupSuppressesRepeatedErrors(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)

	now = now.Add(2 * time.Minute)
	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)

	now = now.Add(3 * time.Minute)
	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if _, ok := lines[0]["suppressed_count"]; ok {
		t.Fatalf("first log line unexpectedly had suppressed_count: %#v", lines[0])
	}
	if got := lines[1]["suppressed_count"]; got != float64(1) {
		t.Fatalf("suppressed_count = %#v, want 1", got)
	}
}

func TestRecorderErrorDedupEmitsDifferentErrors(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)
	now := time.Date(2026, time.April, 3, 12, 0, 0, 0, time.UTC)
	recorder.now = func() time.Time { return now }

	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("dial tcp: i/o timeout"), nil, 5*time.Minute)
	now = now.Add(time.Minute)
	recorder.ErrorDedup("refresh kubernetes metadata", errors.New("401 Unauthorized"), nil, 5*time.Minute)

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[1]["error"]; got != "401 Unauthorized" {
		t.Fatalf("second error = %#v, want 401 Unauthorized", got)
	}
}

func TestRecorderInfoIfChangedSuppressesUnchangedPayload(t *testing.T) {
	t.Parallel()

	recorder, buffer := newTestRecorder(t)

	if !recorder.InfoIfChanged("policy loaded", map[string]any{
		"block_domains": 1,
		"source":        "https://example.test/blocklist.txt",
	}) {
		t.Fatal("InfoIfChanged did not emit initial policy snapshot")
	}
	if recorder.InfoIfChanged("policy loaded", map[string]any{
		"source":        "https://example.test/blocklist.txt",
		"block_domains": 1,
	}) {
		t.Fatal("InfoIfChanged emitted unchanged policy snapshot")
	}
	if !recorder.InfoIfChanged("policy loaded", map[string]any{
		"block_domains": 2,
		"source":        "https://example.test/blocklist.txt",
	}) {
		t.Fatal("InfoIfChanged suppressed changed policy snapshot")
	}

	lines := decodeLogLines(t, buffer)
	if len(lines) != 2 {
		t.Fatalf("log line count = %d, want 2", len(lines))
	}
	if got := lines[0]["block_domains"]; got != float64(1) {
		t.Fatalf("first block_domains = %#v, want 1", got)
	}
	if got := lines[1]["block_domains"]; got != float64(2) {
		t.Fatalf("second block_domains = %#v, want 2", got)
	}
}

func TestExportSinkBatchesAndSetsAuthHeader(t *testing.T) {
	t.Parallel()

	requests := make(chan struct {
		auth string
		body []byte
	}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Fatalf("gzip.NewReader: %v", err)
			}
			body, _ = io.ReadAll(reader)
			_ = reader.Close()
		} else {
			body, _ = io.ReadAll(r.Body)
		}
		requests <- struct {
			auth string
			body []byte
		}{
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	sink, err := newExportSink(context.Background(), Config{
		ExportURL:        server.URL,
		ExportAuthHeader: "Authorization",
		ExportAuthToken:  "Bearer token",
		ExportBatchSize:  2,
		ExportFlush:      time.Minute,
		ExportGzip:       true,
	}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	defer sink.Close()
	if transport, ok := sink.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	sink.Enqueue(record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "one"})
	sink.Enqueue(record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "two"})

	select {
	case req := <-requests:
		if req.auth != "Bearer token" {
			t.Fatalf("auth header = %q, want Bearer token", req.auth)
		}
		var payload []map[string]any
		if err := json.Unmarshal(req.body, &payload); err != nil {
			t.Fatalf("json.Unmarshal returned error: %v", err)
		}
		if len(payload) != 2 {
			t.Fatalf("batch len = %d, want 2", len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for export request")
	}
}

func TestNewExportSinkLoadsClientCertificate(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath, keyPath := writeClientCertificate(t, tempDir)
	caPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caPath, encodeServerCertPEM(t, httptest.NewTLSServer(http.NotFoundHandler())), 0o644); err != nil {
		t.Fatalf("WriteFile ca: %v", err)
	}

	sink, err := newExportSink(context.Background(), Config{
		ExportURL:        "https://127.0.0.1:6443",
		ExportBatchSize:  1,
		ExportFlush:      time.Second,
		ExportCAPath:     caPath,
		ExportClientCert: certPath,
		ExportClientKey:  keyPath,
	}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	defer sink.Close()

	transport, ok := sink.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("client transport type = %T, want *http.Transport", sink.client.Transport)
	}
	if transport.TLSClientConfig == nil || len(transport.TLSClientConfig.Certificates) != 1 {
		t.Fatalf("TLSClientConfig certificates = %d, want 1", len(transport.TLSClientConfig.Certificates))
	}
}

func TestExportSinkSpoolsAndReplays(t *testing.T) {
	t.Parallel()

	var failMode atomic.Bool
	failMode.Store(true)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failMode.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	spoolDir := filepath.Join(t.TempDir(), "spool")
	sink, err := newExportSink(context.Background(), Config{
		ExportURL:        server.URL,
		ExportAuthHeader: "Authorization",
		ExportBatchSize:  1,
		ExportFlush:      10 * time.Millisecond,
		ExportSpoolPath:  spoolDir,
	}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	defer sink.Close()
	if transport, ok := sink.client.Transport.(*http.Transport); ok {
		transport.TLSClientConfig = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: true,
		}
	}

	sink.Enqueue(record{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), Level: "info", Message: "spool"})

	deadline := time.Now().Add(5 * time.Second)
	for {
		files, err := os.ReadDir(spoolDir)
		if err == nil && len(files) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for spool file")
		}
		time.Sleep(20 * time.Millisecond)
	}

	failMode.Store(false)
	if err := sink.spool.Replay(func(payload []byte) error {
		return sink.sendPayload(context.Background(), payload)
	}); err != nil {
		t.Fatalf("Replay returned error: %v", err)
	}

	files, err := os.ReadDir(spoolDir)
	if err != nil {
		t.Fatalf("ReadDir returned error: %v", err)
	}
	if len(files) != 0 {
		t.Fatalf("expected empty spool after replay, got %d files", len(files))
	}
}

func newTestRecorder(t *testing.T) (*Recorder, *bytes.Buffer) {
	t.Helper()

	var buffer bytes.Buffer
	logger, err := logging.NewLogger(&buffer, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	recorder, err := NewRecorder(context.Background(), logger, telemetry.NewRegistry(), Config{})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	t.Cleanup(func() {
		_ = recorder.Close()
	})
	return recorder, &buffer
}

func decodeLogLines(t *testing.T, buffer *bytes.Buffer) []map[string]any {
	t.Helper()

	lines := strings.Split(strings.TrimSpace(buffer.String()), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}

	decoded := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("json.Unmarshal returned error: %v", err)
		}
		decoded = append(decoded, entry)
	}
	return decoded
}

func writeClientCertificate(t *testing.T, dir string) (string, string) {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey returned error: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "traceguard-client",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate returned error: %v", err)
	}

	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatalf("WriteFile cert: %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey returned error: %v", err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), 0o600); err != nil {
		t.Fatalf("WriteFile key: %v", err)
	}
	return certPath, keyPath
}

func encodeServerCertPEM(t *testing.T, server *httptest.Server) []byte {
	t.Helper()
	defer server.Close()

	if server.Certificate() == nil {
		t.Fatal("server certificate is nil")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
}
