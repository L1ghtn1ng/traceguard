// Package replay evaluates detection rules over an archived event stream, so
// rule and exception changes can be measured before rollout.
package replay

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/safefile"
)

// maxLineBytes bounds one archive record; the recorder bounds records well
// below this.
const maxLineBytes = 1 << 20

type Config struct {
	// ArchivePath is a JSONL event archive, optionally gzip-compressed
	// when it ends in .gz.
	ArchivePath string
	// PolicyPath optionally supplies detection rules, disabled rule IDs, and
	// exceptions; without it only the built-in baseline runs.
	PolicyPath string
}

// Summary counts what a replay read and what each rule raised.
type Summary struct {
	Records    int
	Evaluated  int
	Skipped    int
	Malformed  int
	Alerts     map[string]int
	Severity   map[string]string
	Exceptions []detection.ExceptionStatus
}

// Run writes each alert to alerts as one JSON line and returns the summary.
func Run(cfg Config, alerts io.Writer) (Summary, error) {
	engine, err := newEngine(cfg.PolicyPath)
	if err != nil {
		return Summary{}, err
	}
	file, err := safefile.OpenAbsolute(cfg.ArchivePath, os.O_RDONLY, 0)
	if err != nil {
		return Summary{}, fmt.Errorf("open event archive: %w", err)
	}
	defer func() { _ = file.Close() }()
	var input io.Reader = file
	if strings.HasSuffix(cfg.ArchivePath, ".gz") {
		decompressed, err := gzip.NewReader(file)
		if err != nil {
			return Summary{}, fmt.Errorf("open gzip event archive: %w", err)
		}
		defer func() { _ = decompressed.Close() }()
		input = decompressed
	}

	summary := Summary{Alerts: make(map[string]int), Severity: make(map[string]string)}
	encoder := json.NewEncoder(alerts)
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	var last time.Time
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		summary.Records++
		event, ok, err := decodeEvent(line)
		if err != nil {
			summary.Malformed++
			continue
		}
		if !ok {
			summary.Skipped++
			continue
		}
		summary.Evaluated++
		last = event.Timestamp
		for _, alert := range engine.Evaluate(event) {
			summary.Alerts[alert.RuleID]++
			summary.Severity[alert.RuleID] = alert.Severity
			record := alert.RecordFields(event.Name)
			record["timestamp"] = alert.Timestamp.Format(time.RFC3339Nano)
			if err := encoder.Encode(record); err != nil {
				return summary, fmt.Errorf("write alert: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return summary, fmt.Errorf("read event archive: %w", err)
	}
	summary.Exceptions = engine.ExceptionStatus(last)
	return summary, nil
}

func newEngine(policyPath string) (*detection.Engine, error) {
	engine, err := detection.New(nil, nil)
	if err != nil {
		return nil, err
	}
	if policyPath == "" {
		return engine, nil
	}
	payload, err := safefile.ReadFile(policyPath, policy.MaxDocumentBytes)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", policyPath, err)
	}
	document, err := policy.Parse(payload)
	if err != nil {
		return nil, fmt.Errorf("parse policy %q: %w", policyPath, err)
	}
	bundle, err := policy.Merge(policy.Document{Version: policy.Version}, document)
	if err != nil {
		return nil, err
	}
	compiled, err := detection.Compile(bundle.DetectionRules, bundle.DisabledRuleIDs, bundle.DetectionExceptions)
	if err != nil {
		return nil, fmt.Errorf("compile detection policy: %w", err)
	}
	engine.Install(compiled)
	return engine, nil
}

// decodeEvent turns one archive record into a detection event. Records that
// are not kernel events, such as alerts, heartbeats, and daemon status, are
// reported as not ok.
func decodeEvent(line []byte) (detection.Event, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	var fields map[string]any
	if err := decoder.Decode(&fields); err != nil {
		return detection.Event{}, false, err
	}
	name, _ := fields["event"].(string)
	switch name {
	case "", "detection_alert", "heartbeat":
		return detection.Event{}, false, nil
	}
	timestamp, _ := fields["timestamp"].(string)
	at, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		return detection.Event{}, false, fmt.Errorf("record timestamp: %w", err)
	}
	for key, value := range fields {
		if number, ok := value.(json.Number); ok {
			fields[key] = convertNumber(number)
		}
	}
	return detection.Event{Timestamp: at, Name: name, Fields: fields}, true, nil
}

// convertNumber keeps integers exact, so 64-bit cgroup IDs group the same way
// they do live, and falls back to float64 otherwise.
func convertNumber(number json.Number) any {
	text := number.String()
	if !strings.ContainsAny(text, ".eE") {
		if unsigned, err := strconv.ParseUint(text, 10, 64); err == nil {
			return unsigned
		}
		if signed, err := strconv.ParseInt(text, 10, 64); err == nil {
			return signed
		}
	}
	if value, err := number.Float64(); err == nil && !math.IsInf(value, 0) {
		return value
	}
	return text
}

// WriteSummary prints per-rule alert counts, noisiest first, and exception
// activity.
func WriteSummary(summary Summary, out io.Writer) error {
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(writer, "records\t%d\nevaluated\t%d\nskipped\t%d\nmalformed\t%d\n\n", summary.Records, summary.Evaluated, summary.Skipped, summary.Malformed)
	rules := make([]string, 0, len(summary.Alerts))
	for rule := range summary.Alerts {
		rules = append(rules, rule)
	}
	slices.SortFunc(rules, func(left, right string) int {
		if summary.Alerts[left] != summary.Alerts[right] {
			return summary.Alerts[right] - summary.Alerts[left]
		}
		return strings.Compare(left, right)
	})
	_, _ = fmt.Fprintln(writer, "RULE\tALERTS\tSEVERITY")
	for _, rule := range rules {
		_, _ = fmt.Fprintf(writer, "%s\t%d\t%s\n", rule, summary.Alerts[rule], summary.Severity[rule])
	}
	if len(summary.Exceptions) > 0 {
		_, _ = fmt.Fprintln(writer, "\nEXCEPTION\tSUPPRESSED\tEXPIRED")
		for _, exception := range summary.Exceptions {
			_, _ = fmt.Fprintf(writer, "%s\t%d\t%t\n", exception.ID, exception.Suppressed, exception.Expired)
		}
	}
	return writer.Flush()
}
