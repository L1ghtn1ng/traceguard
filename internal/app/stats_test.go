package app

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/logging"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type fakeRingBufferStats struct {
	stats ebpfmonitor.RingBufferStats
	err   error
}

func (f *fakeRingBufferStats) RingBufferStats() (ebpfmonitor.RingBufferStats, error) {
	return f.stats, f.err
}

// syncBuffer lets tests read log output while background workers write it.
type syncBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func (b *syncBuffer) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buffer.Reset()
}

func newTestRecorder(t *testing.T) (*eventsink.Recorder, *syncBuffer) {
	t.Helper()
	output := &syncBuffer{}
	logger, err := logging.NewLogger(output, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	recorder, err := eventsink.NewRecorder(t.Context(), logger, telemetry.NewRegistry(), eventsink.Config{})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	return recorder, output
}

func TestRingBufferWatcherReportsOnlyNewDrops(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	metrics := telemetry.NewRegistry()
	source := &fakeRingBufferStats{stats: ebpfmonitor.RingBufferStats{
		SizeBytes: 1 << 24, UnreadBytes: 632,
		Drops: map[uint32]uint64{ebpfmonitor.EventDNS: 5, ebpfmonitor.EventExec: 0},
	}}
	watcher := newRingBufferWatcher(source, metrics, recorder)

	watcher.collect()
	if strings.Contains(output.String(), "events dropped") {
		t.Fatalf("baseline collection reported pre-existing drops as new: %s", output.String())
	}
	if dropped, unread := watcher.status(); dropped != 0 || unread != 632 {
		t.Fatalf("status after baseline = (%d, %d), want (0, 632)", dropped, unread)
	}
	rendered := metrics.Render()
	for _, want := range []string{
		`traceguard_ringbuf_dropped_total{kind="dns"} 5`,
		`traceguard_ringbuf_dropped_total{kind="exec"} 0`,
		`traceguard_ringbuf_size_bytes 16777216`,
		`traceguard_ringbuf_unread_bytes 632`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("metrics missing %q:\n%s", want, rendered)
		}
	}

	source.stats.Drops = map[uint32]uint64{ebpfmonitor.EventDNS: 8, ebpfmonitor.EventExec: 2}
	watcher.collect()
	logged := output.String()
	for _, want := range []string{`"message":"eBPF ring buffer full; events dropped"`, `"dropped_events":5`, `"dropped_dns":3`, `"dropped_exec":2`} {
		if !strings.Contains(logged, want) {
			t.Errorf("drop record missing %q: %s", want, logged)
		}
	}
	if dropped, _ := watcher.status(); dropped != 5 {
		t.Fatalf("dropped since baseline = %d, want 5", dropped)
	}

	output.Reset()
	watcher.collect()
	if strings.Contains(output.String(), "events dropped") {
		t.Fatalf("unchanged counters reported drops: %s", output.String())
	}
}

func TestRingBufferWatcherKeepsBaselineForUnreadableKinds(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	source := &fakeRingBufferStats{stats: ebpfmonitor.RingBufferStats{
		Drops: map[uint32]uint64{ebpfmonitor.EventDNS: 1, ebpfmonitor.EventExec: 9},
	}}
	watcher := newRingBufferWatcher(source, telemetry.NewRegistry(), recorder)
	watcher.collect()

	// A failed lookup omits the kind; its baseline must survive so a later
	// successful read does not report the whole cumulative count as new.
	source.stats.Drops = map[uint32]uint64{ebpfmonitor.EventDNS: 1}
	source.err = errors.New("lookup failed")
	watcher.collect()
	if !strings.Contains(output.String(), "collect eBPF ring buffer statistics") {
		t.Fatalf("collection error not recorded: %s", output.String())
	}

	source.stats.Drops = map[uint32]uint64{ebpfmonitor.EventDNS: 1, ebpfmonitor.EventExec: 9}
	source.err = nil
	output.Reset()
	watcher.collect()
	if strings.Contains(output.String(), "events dropped") {
		t.Fatalf("recovered kind reported old drops as new: %s", output.String())
	}
}

// NewMonitor needs kernel privileges, so guard the startup order
// structurally: the ring buffer reader must start before any policy source is
// loaded or applied, or attached programs can fill the buffer meanwhile.
func TestRunStartsEventReaderBeforePolicyLoad(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "app.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]token.Pos{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			receiver, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			name := receiver.Name + "." + selector.Sel.Name
			if _, seen := calls[name]; !seen {
				calls[name] = call.Pos()
			}
			return true
		})
	}
	reader, ok := calls["monitor.Run"]
	if !ok {
		t.Fatal("Run no longer calls monitor.Run")
	}
	for _, policyCall := range []string{"yamlManager.Load", "policyController.ApplyBundle", "monitor.ApplyPolicy"} {
		pos, ok := calls[policyCall]
		if !ok {
			t.Fatalf("Run no longer calls %s; update this ordering test", policyCall)
		}
		if pos < reader {
			t.Errorf("%s at %s runs before the ring buffer reader starts at %s", policyCall, fset.Position(pos), fset.Position(reader))
		}
	}
}

func TestExceptionWatcherPublishesMetricsAndRecordsExpiryOnce(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	metrics := telemetry.NewRegistry()
	detector, err := detection.New(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := detection.Compile(nil, nil, []policyconfig.DetectionException{{
		ID: "agent-imds", Rules: []string{"baseline.cloud-metadata-access"}, Reason: "agent",
		Expires: policyconfig.Timestamp{Time: time.Unix(100, 0)},
		Match:   policyconfig.DetectionMatch{UIDs: []uint32{0}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	detector.Install(compiled)
	watcher := newExceptionWatcher(detector, metrics, recorder)

	watcher.collect(time.Unix(50, 0))
	rendered := metrics.Render()
	for _, want := range []string{
		`traceguard_detection_exceptions{state="active"} 1`,
		`traceguard_detection_exceptions{state="expired"} 0`,
		`traceguard_detection_suppressed_total{exception="agent-imds"} 0`,
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("metrics missing %q:\n%s", want, rendered)
		}
	}

	watcher.collect(time.Unix(100, 0))
	watcher.collect(time.Unix(105, 0))
	if got := strings.Count(output.String(), `"message":"detection exception expired"`); got != 1 {
		t.Fatalf("expiry records = %d, want 1: %s", got, output.String())
	}
	if !strings.Contains(metrics.Render(), `traceguard_detection_exceptions{state="expired"} 1`) {
		t.Fatalf("expired gauge not updated:\n%s", metrics.Render())
	}
}
