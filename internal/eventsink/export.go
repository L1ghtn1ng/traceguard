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
	"io"
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

	"github.com/L1ghtn1ng/traceguard/internal/runid"
	"github.com/L1ghtn1ng/traceguard/internal/safefile"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"golang.org/x/sys/unix"
)

type exportSink struct {
	client        *http.Client
	target        string
	authorization string
	// events is ExportEventsAll or ExportEventsAlerts.
	events string
	// priority carries records someone may need to act on. The worker
	// drains it first, and when it is full its records spill to the spool
	// rather than being dropped behind routine telemetry.
	priority chan json.RawMessage
	queue    chan json.RawMessage
	spill    chan json.RawMessage
	// spillOnce closes spill exactly once.
	spillOnce sync.Once
	// holdUntil, read and written only by the worker, defers sends after a
	// collector asked for a pause with Retry-After.
	holdUntil time.Time
	// tooLarge, worker-only, counts 413s with Retry-After for the spool file
	// tooLargeFile, which is set aside after maxTooLargeRetries so a batch
	// that really is too large cannot block the ones behind it.
	tooLarge     int
	tooLargeFile string
	metrics      *telemetry.Registry
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	spool        *spoolStore
	encode       recordEncoder
	// drainTimeout bounds reading a reply body after its headers arrive,
	// and replayBudget bounds one replay tick, requests included.
	drainTimeout time.Duration
	replayBudget time.Duration
}

// ExportClient builds an HTTPS client and Authorization header value from
// the export settings, for other agent features that talk to the same
// collector. The client has no overall or response-header timeout; callers
// bound each request with its context.
func ExportClient(cfg Config) (*http.Client, string, error) {
	authorization, err := exportAuthorization(cfg)
	if err != nil {
		return nil, "", err
	}
	transport, err := newExportTransport(cfg)
	if err != nil {
		return nil, "", err
	}
	// A long-poll holds the response until it has something to send, so
	// the export transport's header timeout would cut every idle poll short.
	transport.ResponseHeaderTimeout = 0
	return &http.Client{Transport: transport, CheckRedirect: checkHTTPSRedirect}, authorization, nil
}

func exportAuthorization(cfg Config) (string, error) {
	authorization := strings.TrimSpace(cfg.ExportAuthorization)
	if strings.TrimSpace(cfg.ExportAuthorizationFile) != "" {
		if authorization != "" {
			return "", errors.New("export authorization and authorization file must not both be set")
		}
		if !filepath.IsAbs(cfg.ExportAuthorizationFile) {
			return "", errors.New("export authorization file must be an absolute path")
		}
		secret, err := safefile.ReadSecret(cfg.ExportAuthorizationFile)
		if err != nil {
			return "", fmt.Errorf("read export authorization file: %w", err)
		}
		authorization = strings.TrimSpace(secret)
	}
	return authorization, nil
}

func newExportSink(ctx context.Context, cfg Config, metrics *telemetry.Registry) (*exportSink, error) {
	encode, err := newRecordEncoder(cfg.Schema)
	if err != nil {
		return nil, err
	}
	events := strings.ToLower(strings.TrimSpace(cfg.ExportEvents))
	switch events {
	case "":
		events = ExportEventsAll
	case ExportEventsAll, ExportEventsAlerts:
	default:
		return nil, fmt.Errorf("unsupported export events %q: use all or alerts", cfg.ExportEvents)
	}
	// Never include the raw URL or the *url.Error in returned errors: the
	// query string may carry secrets such as access tokens.
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.ExportURL))
	if err != nil {
		return nil, errors.New("export url is not valid")
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("export url must use https://")
	}
	if parsed.User != nil {
		return nil, errors.New("export url must not contain user credentials; use the authorization header or mTLS")
	}
	authorization, err := exportAuthorization(cfg)
	if err != nil {
		return nil, err
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
		spool, err = newSpoolStore(exportSpoolPath, cfg.Schema)
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
		authorization: authorization,
		events:        events,
		priority:      make(chan json.RawMessage, exportQueueSize),
		queue:         make(chan json.RawMessage, exportQueueSize),
		metrics:       metrics,
		cancel:        cancel,
		spool:         spool,
		encode:        encode,
		drainTimeout:  exportDrainTimeout,
		replayBudget:  exportReplayBudget,
	}
	sink.updateQueueDepth()
	sink.updateSpoolFiles()
	if spool != nil {
		sink.spill = make(chan json.RawMessage, exportSpillSize)
		sink.wg.Go(sink.runSpill)
	}
	sink.wg.Go(func() {
		sink.run(sinkCtx)
	})
	return sink, nil
}

func (e *exportSink) Enqueue(entry record) {
	priority := isPriorityRecord(entry)
	if !priority && e.events == ExportEventsAlerts {
		return
	}
	payload, err := e.encode(entry)
	if err != nil {
		e.metrics.IncEventExport("error")
		return
	}
	defer e.updateQueueDepth()
	if !priority {
		select {
		case e.queue <- payload:
			e.metrics.IncEventExport("queued")
		default:
			e.metrics.IncEventExport("dropped")
			e.metrics.SetEventExportLastError()
		}
		return
	}
	select {
	case e.priority <- payload:
		e.metrics.IncEventExport("queued")
		return
	default:
	}
	// The worker is stalled on a slow collector. Never block the caller:
	// hand the record to the spill writer, which spools it, and drop it
	// only when that is full too.
	if e.spill != nil {
		select {
		case e.spill <- payload:
			e.metrics.IncEventExport("spilled")
			return
		default:
		}
	}
	e.metrics.IncEventExport("dropped_priority")
	e.metrics.SetEventExportLastError()
}

// runSpill writes priority records the worker could not take straight to
// the spool, in batches, until the spill channel closes.
func (e *exportSink) runSpill() {
	batch := make([]json.RawMessage, 0, exportBatchSize)
	batchBytes := 2
	write := func() {
		if len(batch) == 0 {
			return
		}
		if err := e.spool.Write(batch); err != nil {
			e.metrics.IncEventExport("spool_error")
			e.metrics.AddEventExport("lost_priority", len(batch))
			e.metrics.SetEventExportLastError()
		} else {
			e.metrics.IncEventExport("spooled")
			e.updateSpoolFiles()
		}
		batch = batch[:0]
		batchBytes = 2
	}
	for payload := range e.spill {
		if len(batch) > 0 && batchBytes+1+len(payload) > maxSpoolPayloadBytes {
			write()
		}
		batch = append(batch, payload)
		batchBytes += len(payload) + 1
		// Write as soon as the channel is momentarily empty, so a record
		// reaches disk promptly rather than waiting for a full batch.
		if len(batch) >= exportBatchSize || len(e.spill) == 0 {
			write()
		}
	}
	write()
}

func (e *exportSink) run(ctx context.Context) {
	flushTicker := time.NewTicker(exportFlushEvery)
	defer flushTicker.Stop()
	replayTicker := time.NewTicker(exportReplayInterval)
	defer replayTicker.Stop()

	batch := make([]json.RawMessage, 0, exportBatchSize)
	batchBytes := 2 // JSON array brackets.
	// batchPriority counts the priority records in batch, so a batch that
	// can be neither sent nor spooled is reported as lost alerts too.
	batchPriority := 0
	lost := func() {
		e.metrics.AddEventExport("lost", len(batch)-batchPriority)
		e.metrics.AddEventExport("lost_priority", batchPriority)
	}
	flush := func(flushCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		var err error
		if e.spool != nil && time.Now().Before(e.holdUntil) {
			// The collector asked for a pause; keep the batch for replay.
			err = errExportHeld
		} else {
			err = e.sendBatch(flushCtx, batch)
			e.noteRetryAfter(err)
		}
		if errors.Is(err, errPermanentRejection) {
			e.rejectBatch(batch)
		} else if err != nil {
			if !errors.Is(err, errExportHeld) {
				e.metrics.IncEventExport("error")
				e.metrics.SetEventExportLastError()
			}
			if e.spool == nil {
				lost()
			} else if spoolErr := e.spool.Write(batch); spoolErr == nil {
				e.metrics.IncEventExport("spooled")
				e.updateSpoolFiles()
			} else {
				e.metrics.IncEventExport("spool_error")
				e.metrics.SetEventExportLastError()
				lost()
			}
		} else {
			e.metrics.IncEventExport("success")
			e.metrics.SetEventExportLastSuccess()
		}
		batch = batch[:0]
		batchBytes = 2
		batchPriority = 0
	}
	appendPayload := func(flushCtx context.Context, payload json.RawMessage, priority bool) {
		separator := 0
		if len(batch) > 0 {
			separator = 1
		}
		if len(batch) > 0 && (len(batch) >= exportBatchSize || batchBytes+separator+len(payload) > maxSpoolPayloadBytes) {
			flush(flushCtx)
			separator = 0
		}
		batch = append(batch, payload)
		batchBytes += separator + len(payload)
		if priority {
			batchPriority++
		}
	}
	shutdown := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), exportShutdownFlush)
		defer cancel()
		// A final attempt ignores any Retry-After pause: whatever cannot be
		// sent is spooled anyway.
		e.holdUntil = time.Time{}
		for {
			select {
			case payload := <-e.priority:
				appendPayload(shutdownCtx, payload, true)
				e.updateQueueDepth()
				if len(batch) >= exportBatchSize {
					flush(shutdownCtx)
				}
				continue
			default:
			}
			select {
			case payload := <-e.queue:
				appendPayload(shutdownCtx, payload, false)
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
		case payload := <-e.priority:
			appendPayload(ctx, payload, true)
			e.updateQueueDepth()
			if len(batch) >= exportBatchSize {
				flush(ctx)
			}
		case payload := <-e.queue:
			// Take any waiting priority records first, so routine telemetry
			// never delays them by a whole batch.
			for drained := false; !drained && len(batch) < exportBatchSize; {
				select {
				case urgent := <-e.priority:
					appendPayload(ctx, urgent, true)
				default:
					drained = true
				}
			}
			// appendPayload flushes a full batch first, so the routine
			// record never makes a batch larger than exportBatchSize.
			appendPayload(ctx, payload, false)
			e.updateQueueDepth()
			if len(batch) >= exportBatchSize {
				flush(ctx)
			}
		case <-flushTicker.C:
			flush(ctx)
		case <-replayTicker.C:
			e.replay(ctx)
		}
	}
}

// replay sends spooled batches for at most replayBudget, so live events keep
// draining from the queue while a large spool is sent. The budget bounds the
// requests too, so a stalled collector cannot hold the worker past it.
func (e *exportSink) replay(ctx context.Context) {
	if e.spool == nil || time.Now().Before(e.holdUntil) {
		return
	}
	deadline := time.Now().Add(e.replayBudget)
	replayCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	sendFailed := false
	err := e.spool.replayUntil(deadline, func(file string, payload []byte) error {
		if time.Now().Before(e.holdUntil) {
			// A reply in this pass asked for a pause; keep the rest for later.
			sendFailed = true
			return errExportHeld
		}
		err := e.sendPayload(replayCtx, payload, deliveryReplay)
		e.noteRetryAfter(err)
		if status, ok := errors.AsType[*statusError](err); ok && status.code == http.StatusRequestEntityTooLarge && status.retryHint {
			if file != e.tooLargeFile {
				e.tooLargeFile, e.tooLarge = file, 0
			}
			e.tooLarge++
			if e.tooLarge >= maxTooLargeRetries {
				e.tooLarge = 0
				return fmt.Errorf("%w after %d tries: %w", errPermanentRejection, maxTooLargeRetries, err)
			}
		}
		if errors.Is(err, errPermanentRejection) {
			// replayUntil sets the file aside, reports it, and carries on.
			return err
		}
		if errors.Is(err, errExportHeld) {
			sendFailed = true
			return err
		}
		if err != nil {
			sendFailed = true
			e.metrics.IncEventExport("replay_error")
			e.metrics.SetEventExportLastError()
			return err
		}
		e.metrics.IncEventExport("replayed")
		e.metrics.SetEventExportLastSuccess()
		return nil
	}, func(discarded bool) {
		// Counted once the file is out of the replay queue, so a batch
		// that cannot be moved is not counted again on every tick.
		e.metrics.IncEventExport("rejected")
		e.metrics.SetEventExportLastError()
		if discarded {
			e.metrics.IncEventExport("rejected_discarded")
		}
	})
	// A failed send was counted above; unreadable entries and listing
	// failures are spool errors.
	var readErr *spoolReadError
	if err != nil && (!sendFailed || errors.As(err, &readErr)) {
		e.metrics.IncEventExport("spool_error")
		e.metrics.SetEventExportLastError()
	}
	e.updateSpoolFiles()
}

func (e *exportSink) updateQueueDepth() {
	e.metrics.SetEventExportQueueDepth(len(e.queue) + len(e.priority))
}

// noteRetryAfter starts a pause when a collector replied with Retry-After.
func (e *exportSink) noteRetryAfter(err error) {
	var status *statusError
	if errors.As(err, &status) && status.retryAfter > 0 {
		e.holdUntil = time.Now().Add(status.retryAfter)
	}
}

// rejectBatch keeps a batch the collector refused out of the replay queue,
// setting it aside for inspection when the spool is on.
func (e *exportSink) rejectBatch(batch []json.RawMessage) {
	e.metrics.IncEventExport("rejected")
	e.metrics.SetEventExportLastError()
	if e.spool == nil {
		return
	}
	payload, err := json.Marshal(batch)
	if err != nil {
		return
	}
	discarded, err := e.spool.writeRejected(payload)
	switch {
	case err != nil:
		e.metrics.IncEventExport("spool_error")
	case discarded:
		e.metrics.IncEventExport("rejected_discarded")
	}
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
	if len(payload) > maxSpoolPayloadBytes {
		return fmt.Errorf("export batch exceeds %d bytes", maxSpoolPayloadBytes)
	}
	return e.sendPayload(ctx, payload, deliveryLive)
}

// DeliveryHeader tells a collector how a batch was sent: "live" batches hold
// only records of the process sending them, which is running now; "replay"
// batches come from the spool, and may be from any earlier run.
const DeliveryHeader = "TraceGuard-Delivery"

// RunHeader names the sending process's run, so a collector can tell a
// replay of the running process's own records from one inherited from an
// earlier run.
const RunHeader = "TraceGuard-Run"

const (
	deliveryLive   = "live"
	deliveryReplay = "replay"
)

func (e *exportSink) sendPayload(ctx context.Context, payload []byte, delivery string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.target, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(DeliveryHeader, delivery)
	req.Header.Set(RunHeader, runid.ID)
	if e.authorization != "" {
		req.Header.Set("Authorization", e.authorization)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	// Drain a short reply so the connection returns to the keep-alive pool,
	// but cancel the request rather than wait on a body that stalls.
	stop := time.AfterFunc(e.drainTimeout, cancel)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainedResponseBytes))
	stop.Stop()
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		failure := &statusError{code: resp.StatusCode, status: resp.Status}
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusRequestEntityTooLarge {
			failure.retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
			failure.retryHint = validRetryAfter(resp.Header.Get("Retry-After"))
		}
		return failure
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
	e.closeSpill()
	e.wg.Wait()
	if e.spool != nil {
		return e.spool.Close()
	}
	return nil
}

// spoolStore keeps undelivered batches as files. Each event schema has its
// own file suffix, because batches are stored encoded: a batch is replayed
// only while the schema it was written in is configured, so a collector never
// receives a mix of formats.
type spoolStore struct {
	dir    *os.File
	suffix string
	mu     sync.Mutex
}

// spoolSuffix names the spool files of an event schema. TraceGuard batches
// keep the original .json suffix.
func spoolSuffix(schema string) string {
	if schema == SchemaOCSF {
		return ".ocsf.json"
	}
	return ".json"
}

// isSpoolFile reports whether name is a spool file of the schema with suffix.
func isSpoolFile(name, suffix string) bool {
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	return suffix != ".json" || !strings.HasSuffix(name, spoolSuffix(SchemaOCSF))
}

func newSpoolStore(path, schema string) (*spoolStore, error) {
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
	return &spoolStore{dir: dir, suffix: spoolSuffix(schema)}, nil
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
	finalName := name + s.suffix
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

// spoolReadError reports a spool entry that could not be read for replay.
type spoolReadError struct {
	file string
	err  error
}

func (e *spoolReadError) Error() string { return fmt.Sprintf("read spool entry %q: %v", e.file, e.err) }

func (e *spoolReadError) Unwrap() error { return e.err }

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
	return s.ReplayUntil(time.Time{}, send)
}

// ReplayUntil sends spooled batches oldest first until one fails to send or,
// with a non-zero deadline, the deadline passes; the rest wait for the next
// call. A file that cannot be read is left in place and skipped, so it does
// not hold back the files after it.
func (s *spoolStore) ReplayUntil(deadline time.Time, send func([]byte) error) error {
	return s.replayUntil(deadline, func(_ string, payload []byte) error { return send(payload) }, nil)
}

// replayUntil is ReplayUntil, except that a batch send reports as
// permanently rejected is moved to the rejected directory, or deleted when
// that fails or is full, and replay carries on; onReject, when set, hears of
// each one. The spool lock is held to list, read and remove files but never
// while a batch is being sent, so the spill writer keeps spooling alerts
// through a slow replay.
func (s *spoolStore) replayUntil(deadline time.Time, send func(file string, payload []byte) error, onReject func(discarded bool)) error {
	s.mu.Lock()
	files, err := s.files()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	var unreadable error
	for _, file := range files {
		if !deadline.IsZero() && !time.Now().Before(deadline) {
			break
		}
		s.mu.Lock()
		if s.dir == nil {
			s.mu.Unlock()
			return errors.Join(unreadable, errors.New("export spool is closed"))
		}
		payload, err := safefile.ReadFileBeneath(int(s.dir.Fd()), file, maxSpoolPayloadBytes)
		s.mu.Unlock()
		if err != nil {
			unreadable = errors.Join(unreadable, &spoolReadError{file: file, err: err})
			continue
		}
		if err := send(file, payload); err != nil {
			if !errors.Is(err, errPermanentRejection) {
				return errors.Join(unreadable, err)
			}
			discarded, rejectErr := s.setAside(file, int64(len(payload)))
			if rejectErr != nil {
				return errors.Join(unreadable, rejectErr)
			}
			if onReject != nil {
				onReject(discarded)
			}
			continue
		}
		s.mu.Lock()
		err = s.remove(file)
		s.mu.Unlock()
		if err != nil {
			return errors.Join(unreadable, err)
		}
	}
	return unreadable
}

// setAside moves a rejected spool file to the rejected directory. When that
// is full or cannot be used, the file is deleted instead, so it never blocks
// the batches behind it; discarded reports that.
func (s *spoolStore) setAside(file string, size int64) (discarded bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return false, errors.New("export spool is closed")
	}
	discarded, err = s.reject(file, size)
	if err == nil {
		return discarded, nil
	}
	if removeErr := s.remove(file); removeErr != nil {
		return false, errors.Join(err, removeErr)
	}
	return true, nil
}

func (s *spoolStore) remove(file string) error {
	if s.dir == nil {
		return errors.New("export spool is closed")
	}
	return unix.Unlinkat(int(s.dir.Fd()), file, 0)
}

func (s *spoolStore) files() (files []string, listErr error) {
	dir, err := safefile.OpenBeneath(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		listErr = errors.Join(listErr, dir.Close())
	}()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isSpoolFile(entry.Name(), s.suffix) || !filepath.IsLocal(entry.Name()) {
			continue
		}
		out = append(out, entry.Name())
	}
	sort.Strings(out)
	return out, nil
}

// stranded counts spool files written under another event schema. They
// are kept, and sent once that schema is configured again.
func (s *spoolStore) stranded() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, err := safefile.OpenBeneath(int(s.dir.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = dir.Close() }()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasSuffix(name, ".json") && !isSpoolFile(name, s.suffix) {
			count++
		}
	}
	return count, nil
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
	payload := make(map[string]any, len(entry.Fields)+4)
	payload["timestamp"] = entry.Timestamp
	payload["level"] = entry.Level
	payload["message"] = entry.Message
	payload["hostname"] = entry.Hostname
	for key, value := range entry.Fields {
		if key == "timestamp" || key == "level" || key == "message" || key == "hostname" {
			continue
		}
		payload[key] = value
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if len(encoded) > maxSerializedRecordBytes {
		return nil, fmt.Errorf("serialized event record exceeds %d bytes", maxSerializedRecordBytes)
	}
	return encoded, nil
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
