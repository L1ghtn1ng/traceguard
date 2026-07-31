package eventsink

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"golang.org/x/sys/unix"
)

type exportSink struct {
	client        *http.Client
	target        string
	authorization string
	queue         chan json.RawMessage
	metrics       *telemetry.Registry
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	spool         *spoolStore
}

func newExportSink(ctx context.Context, cfg Config, metrics *telemetry.Registry) (*exportSink, error) {
	parsed, err := neturl.Parse(cfg.ExportURL)
	if err != nil {
		return nil, fmt.Errorf("parse export url: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("export url must use https://")
	}

	// The recorder owns the export worker lifetime. Keep it alive through run
	// context cancellation so events emitted during shutdown are drained by Close.
	sinkCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	transport, err := newExportTransport(cfg)
	if err != nil {
		cancel()
		return nil, err
	}

	var spool *spoolStore
	if cfg.ExportSpool {
		spool, err = newSpoolStore(exportSpoolPath)
		if err != nil {
			cancel()
			return nil, err
		}
	}

	sink := &exportSink{
		client: &http.Client{
			Timeout:       20 * time.Second,
			Transport:     transport,
			CheckRedirect: checkHTTPSRedirect,
		},
		target:        parsed.String(),
		authorization: strings.TrimSpace(cfg.ExportAuthorization),
		queue:         make(chan json.RawMessage, exportQueueSize),
		metrics:       metrics,
		cancel:        cancel,
		spool:         spool,
	}
	sink.updateQueueDepth()
	sink.updateSpoolFiles()
	sink.wg.Go(func() {
		sink.run(sinkCtx)
	})
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
		e.updateQueueDepth()
	default:
		e.metrics.IncEventExport("dropped")
		e.metrics.SetEventExportLastError()
		e.updateQueueDepth()
	}
}

func (e *exportSink) run(ctx context.Context) {
	flushTicker := time.NewTicker(exportFlushEvery)
	defer flushTicker.Stop()
	replayTicker := time.NewTicker(exportReplayInterval)
	defer replayTicker.Stop()

	batch := make([]json.RawMessage, 0, exportBatchSize)
	flush := func(flushCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		if err := e.sendBatch(flushCtx, batch); err != nil {
			e.metrics.IncEventExport("error")
			e.metrics.SetEventExportLastError()
			if e.spool != nil {
				if spoolErr := e.spool.Write(batch); spoolErr == nil {
					e.metrics.IncEventExport("spooled")
					e.updateSpoolFiles()
				} else {
					e.metrics.IncEventExport("spool_error")
					e.metrics.SetEventExportLastError()
				}
			}
		} else {
			e.metrics.IncEventExport("success")
			e.metrics.SetEventExportLastSuccess()
		}
		batch = batch[:0]
	}
	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), exportShutdownFlush)
		defer cancel()
		for {
			select {
			case payload := <-e.queue:
				batch = append(batch, payload)
				e.updateQueueDepth()
				if len(batch) >= exportBatchSize {
					flush(shutdownCtx)
				}
			default:
				// The worker context is already canceled during Close; use a short
				// independent context so the final batch can be delivered or spooled.
				flush(shutdownCtx)
				return
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			shutdown()
			return
		case payload := <-e.queue:
			batch = append(batch, payload)
			e.updateQueueDepth()
			if len(batch) >= exportBatchSize {
				flush(ctx)
			}
		case <-flushTicker.C:
			flush(ctx)
		case <-replayTicker.C:
			if e.spool == nil {
				continue
			}
			_ = e.spool.Replay(func(payload []byte) error {
				if err := e.sendPayload(ctx, payload); err != nil {
					e.metrics.IncEventExport("replay_error")
					e.metrics.SetEventExportLastError()
					return err
				}
				e.metrics.IncEventExport("replayed")
				e.metrics.SetEventExportLastSuccess()
				return nil
			})
			e.updateSpoolFiles()
		}
	}
}

func (e *exportSink) updateQueueDepth() {
	e.metrics.SetEventExportQueueDepth(len(e.queue))
}

func (e *exportSink) updateSpoolFiles() {
	if e.spool == nil {
		e.metrics.SetEventExportSpoolFiles(0)
		return
	}
	files, err := e.spool.files()
	if err != nil {
		e.metrics.SetEventExportLastError()
		return
	}
	e.metrics.SetEventExportSpoolFiles(len(files))
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
	if e.authorization != "" {
		req.Header.Set("Authorization", e.authorization)
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

func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL == nil || req.URL.Scheme != "https" {
		return errors.New("redirect target must use https")
	}
	if len(via) == 0 || via[0].URL == nil || !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return errors.New("redirect target must use the original origin")
	}
	return nil
}

func (e *exportSink) Close() error {
	e.cancel()
	e.wg.Wait()
	if e.spool != nil {
		return e.spool.Close()
	}
	return nil
}

type spoolStore struct {
	dir *os.File
	mu  sync.Mutex
}

func newSpoolStore(path string) (*spoolStore, error) {
	cleaned := filepath.Clean(path)
	if err := os.MkdirAll(cleaned, 0o750); err != nil {
		return nil, fmt.Errorf("create export spool directory: %w", err)
	}
	dir, err := safefile.OpenAbsolute(cleaned, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("export spool directory %q must not traverse symlinks: %w", cleaned, err)
	}
	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, fmt.Errorf("stat export spool directory: %w", err)
	}
	if !info.IsDir() {
		_ = dir.Close()
		return nil, fmt.Errorf("export spool directory %q is not a directory", cleaned)
	}
	return &spoolStore{dir: dir}, nil
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
	if len(payload) > maxSpoolPayloadBytes {
		return fmt.Errorf("export spool payload exceeds %d bytes", maxSpoolPayloadBytes)
	}
	usage, err := s.usage(existing)
	if err != nil {
		return err
	}
	if usage+int64(len(payload)) > maxSpoolBytes {
		return fmt.Errorf("export spool byte capacity exceeded")
	}

	name, err := spoolFilename()
	if err != nil {
		return err
	}
	tempName := name + ".tmp"
	finalName := name + ".json"
	temp, err := safefile.OpenBeneath(int(s.dir.Fd()), tempName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := temp.Write(payload); err != nil {
		_ = temp.Close()
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	if err := temp.Close(); err != nil {
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	if err := unix.Renameat(int(s.dir.Fd()), tempName, int(s.dir.Fd()), finalName); err != nil {
		_ = unix.Unlinkat(int(s.dir.Fd()), tempName, 0)
		return err
	}
	return unix.Fsync(int(s.dir.Fd()))
}

func (s *spoolStore) usage(files []string) (int64, error) {
	var total int64
	for _, file := range files {
		entry, err := safefile.OpenBeneath(int(s.dir.Fd()), file, unix.O_RDONLY, 0)
		if err != nil {
			return 0, err
		}
		info, err := entry.Stat()
		_ = entry.Close()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf("spool entry %q is not a regular file", file)
		}
		total += info.Size()
		if total > maxSpoolBytes {
			return total, nil
		}
	}
	return total, nil
}

func (s *spoolStore) Replay(send func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	files, err := s.files()
	if err != nil {
		return err
	}
	for _, file := range files {
		payload, err := safefile.ReadFileBeneath(int(s.dir.Fd()), file, maxSpoolPayloadBytes)
		if err != nil {
			return err
		}
		if err := send(payload); err != nil {
			return err
		}
		if err := unix.Unlinkat(int(s.dir.Fd()), file, 0); err != nil {
			return err
		}
	}
	return nil
}

func (s *spoolStore) files() ([]string, error) {
	dir, err := safefile.OpenBeneath(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !filepath.IsLocal(entry.Name()) {
			continue
		}
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	return out, nil
}

func (s *spoolStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return nil
	}
	err := s.dir.Close()
	s.dir = nil
	return err
}

func marshalSingleRecord(entry record) (json.RawMessage, error) {
	payload := make(map[string]any, len(entry.Fields)+3)
	payload["timestamp"] = entry.Timestamp
	payload["level"] = entry.Level
	payload["message"] = entry.Message
	for key, value := range entry.Fields {
		if key == "timestamp" || key == "level" || key == "message" {
			continue
		}
		payload[key] = value
	}
	return json.Marshal(payload)
}

func cloneFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(fields))
	maps.Copy(cloned, fields)
	return cloned
}

func spoolFilename() (string, error) {
	var randBytes [6]byte
	if _, err := rand.Read(randBytes[:]); err != nil {
		return "", err
	}
	return fmt.Sprintf("%d-%s", time.Now().UTC().UnixNano(), hex.EncodeToString(randBytes[:])), nil
}
