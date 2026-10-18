package app

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/logging"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type fakeRingBufferStats struct {
	stats ebpfmonitor.RingBufferStats
	err   error
}

func (f *fakeRingBufferStats) RingBufferStats() (ebpfmonitor.RingBufferStats, error) {
	return f.stats, f.err
}

func newTestRecorder(t *testing.T) (*eventsink.Recorder, *bytes.Buffer) {
	t.Helper()
	var output bytes.Buffer
	logger, err := logging.NewLogger(&output, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}
	recorder, err := eventsink.NewRecorder(t.Context(), logger, telemetry.NewRegistry(), eventsink.Config{})
	if err != nil {
		t.Fatalf("NewRecorder returned error: %v", err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	return recorder, &output
}

func TestCollectRingBufferStatsReportsOnlyNewDrops(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	metrics := telemetry.NewRegistry()
	source := &fakeRingBufferStats{stats: ebpfmonitor.RingBufferStats{
		SizeBytes: 1 << 24, UnreadBytes: 632,
		Drops: map[uint32]uint64{ebpfmonitor.EventDNS: 5, ebpfmonitor.EventExec: 0},
	}}

	baseline := collectRingBufferStats(source, metrics, recorder, nil)
	if strings.Contains(output.String(), "events dropped") {
		t.Fatalf("baseline collection reported pre-existing drops as new: %s", output.String())
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
	baseline = collectRingBufferStats(source, metrics, recorder, baseline)
	logged := output.String()
	for _, want := range []string{`"message":"eBPF ring buffer full; events dropped"`, `"dropped_events":5`, `"dropped_dns":3`, `"dropped_exec":2`} {
		if !strings.Contains(logged, want) {
			t.Errorf("drop record missing %q: %s", want, logged)
		}
	}
	if got := baseline[ebpfmonitor.EventDNS]; got != 8 {
		t.Fatalf("baseline dns = %d, want 8", got)
	}

	output.Reset()
	collectRingBufferStats(source, metrics, recorder, baseline)
	if strings.Contains(output.String(), "events dropped") {
		t.Fatalf("unchanged counters reported drops: %s", output.String())
	}
}

func TestCollectRingBufferStatsKeepsBaselineForUnreadableKinds(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	source := &fakeRingBufferStats{
		stats: ebpfmonitor.RingBufferStats{Drops: map[uint32]uint64{ebpfmonitor.EventDNS: 1}},
		err:   errors.New("lookup failed"),
	}
	previous := map[uint32]uint64{ebpfmonitor.EventDNS: 1, ebpfmonitor.EventExec: 9}
	next := collectRingBufferStats(source, telemetry.NewRegistry(), recorder, previous)
	if got := next[ebpfmonitor.EventExec]; got != 9 {
		t.Fatalf("baseline exec = %d, want previous value 9 kept", got)
	}
	if !strings.Contains(output.String(), "collect eBPF ring buffer statistics") {
		t.Fatalf("collection error not recorded: %s", output.String())
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
