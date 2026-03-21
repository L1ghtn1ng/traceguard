package eventsink

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"traceguard/internal/logging"
	"traceguard/internal/telemetry"
)

const (
	exportQueueSize      = 1024
	exportReplayInterval = 15 * time.Second
	maxSpoolFiles        = 10000
)

type Config struct {
	ArchivePath      string
	ExportURL        string
	ExportAuthHeader string
	ExportAuthToken  string
	ExportBatchSize  int
	ExportFlush      time.Duration
	ExportSpoolPath  string
	ExportCAPath     string
	ExportClientCert string
	ExportClientKey  string
	ExportGzip       bool
}

type Recorder struct {
	logger   *logging.Logger
	archive  *archiveSink
	exporter *exportSink
}

type record struct {
	Timestamp string         `json:"timestamp"`
	Level     string         `json:"level"`
	Message   string         `json:"message"`
	Fields    map[string]any `json:"-"`
}

func NewRecorder(ctx context.Context, logger *logging.Logger, metrics *telemetry.Registry, cfg Config) (*Recorder, error) {
	recorder := &Recorder{logger: logger}
	if strings.TrimSpace(cfg.ArchivePath) != "" {
		archive, err := newArchiveSink(cfg.ArchivePath, metrics)
		if err != nil {
			return nil, err
		}
		recorder.archive = archive
	}
	if strings.TrimSpace(cfg.ExportURL) != "" {
		exporter, err := newExportSink(ctx, cfg, metrics)
		if err != nil {
			if recorder.archive != nil {
				_ = recorder.archive.Close()
			}
			return nil, err
		}
		recorder.exporter = exporter
	}
	return recorder, nil
}

func (r *Recorder) Close() error {
	var errs []error
	if r.archive != nil {
		errs = append(errs, r.archive.Close())
	}
	if r.exporter != nil {
		errs = append(errs, r.exporter.Close())
	}
	return errors.Join(errs...)
}

func (r *Recorder) Info(msg string, fields map[string]any) {
	r.emit("info", msg, fields)
}

func (r *Recorder) Error(msg string, err error, fields map[string]any) {
	merged := cloneFields(fields)
	if err != nil {
		merged["error"] = err.Error()
	}
	r.emit("error", msg, merged)
}

func (r *Recorder) emit(level, msg string, fields map[string]any) {
	if fields == nil {
		fields = map[string]any{}
	}
	r.logger.Log(level, msg, fields)

	entry := record{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   msg,
		Fields:    cloneFields(fields),
	}
	if r.archive != nil {
		r.archive.Write(entry)
	}
	if r.exporter != nil {
		r.exporter.Enqueue(entry)
	}
}

type archiveSink struct {
	writer  *logging.RotatingFile
	mu      sync.Mutex
	metrics *telemetry.Registry
}

func newArchiveSink(path string, metrics *telemetry.Registry) (*archiveSink, error) {
	writer, err := logging.NewRotatingFile(path, logging.Options{
		MaxSizeBytes: 1 << 30,
		MaxBackups:   5,
		FileMode:     0o640,
		DirMode:      0o750,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize event archive: %w", err)
	}
	return &archiveSink{writer: writer, metrics: metrics}, nil
}

func (a *archiveSink) Write(entry record) {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		a.metrics.IncEventArchive("error")
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.writer.Write(append(payload, '\n')); err != nil {
		a.metrics.IncEventArchive("error")
		return
	}
	a.metrics.IncEventArchive("success")
}

func (a *archiveSink) Close() error {
	return a.writer.Close()
}

type exportSink struct {
	client     *http.Client
	target     string
	authHeader string
	authToken  string
	batchSize  int
	flushEvery time.Duration
	gzip       bool
	queue      chan json.RawMessage
	metrics    *telemetry.Registry
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	spool      *spoolStore
}

func newExportSink(ctx context.Context, cfg Config, metrics *telemetry.Registry) (*exportSink, error) {
	parsed, err := neturl.Parse(cfg.ExportURL)
	if err != nil {
		return nil, fmt.Errorf("parse export url: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("export url must use https://")
	}

	sinkCtx, cancel := context.WithCancel(ctx)
	transport, err := newExportTransport(cfg)
	if err != nil {
		cancel()
		return nil, err
	}

	var spool *spoolStore
	if strings.TrimSpace(cfg.ExportSpoolPath) != "" {
		spool, err = newSpoolStore(cfg.ExportSpoolPath)
		if err != nil {
			cancel()
			return nil, err
		}
	}

	sink := &exportSink{
		client: &http.Client{
			Timeout:   20 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL == nil || req.URL.Scheme != "https" {
					return errors.New("redirect target must use https")
				}
				return nil
			},
		},
		target:     parsed.String(),
		authHeader: strings.TrimSpace(cfg.ExportAuthHeader),
		authToken:  cfg.ExportAuthToken,
		batchSize:  cfg.ExportBatchSize,
		flushEvery: cfg.ExportFlush,
		gzip:       cfg.ExportGzip,
		queue:      make(chan json.RawMessage, exportQueueSize),
		metrics:    metrics,
		cancel:     cancel,
		spool:      spool,
	}
	sink.wg.Add(1)
	go func() {
		defer sink.wg.Done()
		sink.run(sinkCtx)
	}()
	return sink, nil
}

func (e *exportSink) Enqueue(entry record) {
	payload, err := marshalSingleRecord(entry)
	if err != nil {
		e.metrics.IncEventExport("error")
		return
	}
	select {
	case e.queue <- payload:
		e.metrics.IncEventExport("queued")
	default:
		e.metrics.IncEventExport("dropped")
	}
}

func (e *exportSink) run(ctx context.Context) {
	flushTicker := time.NewTicker(e.flushEvery)
	defer flushTicker.Stop()
	replayTicker := time.NewTicker(exportReplayInterval)
	defer replayTicker.Stop()

	batch := make([]json.RawMessage, 0, e.batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.sendBatch(ctx, batch); err != nil {
			e.metrics.IncEventExport("error")
			if e.spool != nil {
				if spoolErr := e.spool.Write(batch); spoolErr == nil {
					e.metrics.IncEventExport("spooled")
				} else {
					e.metrics.IncEventExport("spool_error")
				}
			}
		} else {
			e.metrics.IncEventExport("success")
		}
		batch = batch[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case payload := <-e.queue:
			batch = append(batch, payload)
			if len(batch) >= e.batchSize {
				flush()
			}
		case <-flushTicker.C:
			flush()
		case <-replayTicker.C:
			if e.spool == nil {
				continue
			}
			_ = e.spool.Replay(func(payload []byte) error {
				if err := e.sendPayload(ctx, payload); err != nil {
					e.metrics.IncEventExport("replay_error")
					return err
				}
				e.metrics.IncEventExport("replayed")
				return nil
			})
		}
	}
}

func (e *exportSink) sendBatch(ctx context.Context, batch []json.RawMessage) error {
	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	return e.sendPayload(ctx, payload)
}

func (e *exportSink) sendPayload(ctx context.Context, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if e.gzip {
		compressed, err := gzipPayload(payload)
		if err != nil {
			return err
		}
		req.Body = io.NopCloser(bytes.NewReader(compressed))
		req.ContentLength = int64(len(compressed))
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(compressed)), nil
		}
		req.Header.Set("Content-Encoding", "gzip")
	}
	if e.authHeader != "" && e.authToken != "" {
		req.Header.Set(e.authHeader, e.authToken)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %s", resp.Status)
	}
	return nil
}

func newExportTransport(cfg Config) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if strings.TrimSpace(cfg.ExportCAPath) != "" {
		pem, err := os.ReadFile(cfg.ExportCAPath)
		if err != nil {
			return nil, fmt.Errorf("read event export ca: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("append event export ca: no certificates found")
		}
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    rootCAs,
	}
	if strings.TrimSpace(cfg.ExportClientCert) != "" || strings.TrimSpace(cfg.ExportClientKey) != "" {
		certificate, err := tls.LoadX509KeyPair(cfg.ExportClientCert, cfg.ExportClientKey)
		if err != nil {
			return nil, fmt.Errorf("load event export client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       tlsConfig,
	}, nil
}

func gzipPayload(payload []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func (e *exportSink) Close() error {
	e.cancel()
	e.wg.Wait()
	return nil
}

type spoolStore struct {
	dir string
	mu  sync.Mutex
}

func newSpoolStore(path string) (*spoolStore, error) {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return nil, fmt.Errorf("create export spool directory: %w", err)
	}
	return &spoolStore{dir: path}, nil
}

func (s *spoolStore) Write(batch []json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	existing, err := s.files()
	if err != nil {
		return err
	}
	if len(existing) >= maxSpoolFiles {
		return fmt.Errorf("export spool capacity exceeded")
	}

	payload, err := json.Marshal(batch)
	if err != nil {
		return err
	}

	name, err := spoolFilename()
	if err != nil {
		return err
	}
	tempPath := filepath.Join(s.dir, name+".tmp")
	finalPath := filepath.Join(s.dir, name+".json")
	if err := os.WriteFile(tempPath, payload, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tempPath, finalPath); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	return nil
}

func (s *spoolStore) Replay(send func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := s.files()
	if err != nil {
		return err
	}
	for _, file := range files {
		payload, err := os.ReadFile(filepath.Join(s.dir, file))
		if err != nil {
			return err
		}
		if err := send(payload); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(s.dir, file)); err != nil {
			return err
		}
	}
	return nil
}

func (s *spoolStore) files() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	return out, nil
}

func marshalSingleRecord(entry record) (json.RawMessage, error) {
	payload := make(map[string]any, len(entry.Fields)+3)
	payload["timestamp"] = entry.Timestamp
	payload["level"] = entry.Level
	payload["message"] = entry.Message
	for key, value := range entry.Fields {
		payload[key] = value
	}
	return json.Marshal(payload)
}

func cloneFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(fields))
	for key, value := range fields {
		cloned[key] = value
	}
	return cloned
}

func spoolFilename() (string, error) {
	var randBytes [6]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(randBytes[:])), nil
}
