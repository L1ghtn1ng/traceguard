package eventsink

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
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

	"traceguard/internal/logging"
	"traceguard/internal/telemetry"
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
