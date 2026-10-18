package telemetry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	detectionAlertsMetric     = "traceguard_detection_alerts_total"
	detectionSuppressedMetric = "traceguard_detection_suppressed_total"
	uptimeMetric              = "traceguard_uptime_seconds"
	maxMetricsResponseBytes   = 32 << 20
	// uptimeSlack absorbs whole-second uptime truncation and the gap between
	// a scrape returning and the daemon rendering it.
	uptimeSlack = 2 * time.Second
)

// AlertSnapshot holds the detection counters from one metrics scrape.
type AlertSnapshot struct {
	// Alerts counts alerts by rule ID, summed across severities.
	Alerts map[string]uint64
	// Severities lists each rule's severity labels.
	Severities map[string][]string
	// Suppressed counts events each exception suppressed.
	Suppressed map[string]uint64
	// Uptime is the daemon's reported uptime.
	Uptime time.Duration
}

// RankedCount is one rule's or exception's count in a noisy-rule report.
type RankedCount struct {
	ID       string
	Count    uint64
	Severity string
}

// NoisyRulesReport ranks rules by alerts and exceptions by suppressed events.
type NoisyRulesReport struct {
	Rules      []RankedCount
	Exceptions []RankedCount
	// Window is how long the counts cover: the sampling window, or the
	// daemon's uptime for a single scrape.
	Window time.Duration
	// Cumulative is true when the counts run from daemon start.
	Cumulative bool
}

// NoisyRulesConfig selects the daemon to scrape and the window to compare.
type NoisyRulesConfig struct {
	// MetricsAddr is the daemon's -metrics-addr.
	MetricsAddr string
	// Window, when positive, ranks by the increase between two scrapes this
	// far apart instead of by counts since the daemon started.
	Window time.Duration
	Client *http.Client
}

// ReportNoisyRules scrapes a running daemon's metrics and writes its rules
// ranked by alert volume.
func ReportNoisyRules(ctx context.Context, cfg NoisyRulesConfig, out io.Writer) error {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	url := metricsURL(cfg.MetricsAddr)
	first, err := ScrapeAlerts(ctx, client, url)
	if err != nil {
		return err
	}
	firstAt := time.Now()
	if cfg.Window <= 0 {
		return WriteNoisyRules(out, RankNoisyRules(AlertSnapshot{}, first, first.Uptime, true))
	}
	timer := time.NewTimer(cfg.Window)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	secondStart := time.Now()
	second, err := ScrapeAlerts(ctx, client, url)
	if err != nil {
		return err
	}
	secondAt := time.Now()
	if restartedBetween(first, second, secondStart.Sub(firstAt), secondAt.Sub(secondStart)) {
		// The daemon restarted between scrapes, so its counters did too.
		return WriteNoisyRules(out, RankNoisyRules(AlertSnapshot{}, second, second.Uptime, true))
	}
	return WriteNoisyRules(out, RankNoisyRules(first, second, cfg.Window, false))
}

// restartedBetween reports whether the daemon restarted between two scrapes
// elapsed apart: its uptime then grew by less than the wall time that passed,
// allowing for truncation and the second scrape's own latency.
func restartedBetween(first, second AlertSnapshot, elapsed, latency time.Duration) bool {
	return second.Uptime+uptimeSlack+latency < first.Uptime+elapsed
}

func metricsURL(addr string) string {
	host := strings.TrimSpace(addr)
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	return "http://" + host + "/metrics"
}

// ScrapeAlerts fetches and parses the detection counters at url.
func ScrapeAlerts(ctx context.Context, client *http.Client, url string) (AlertSnapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return AlertSnapshot{}, fmt.Errorf("build metrics request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return AlertSnapshot{}, fmt.Errorf("scrape %s: %w", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return AlertSnapshot{}, fmt.Errorf("scrape %s: HTTP %d", url, response.StatusCode)
	}
	return ParseAlertSnapshot(io.LimitReader(response.Body, maxMetricsResponseBytes))
}

// ParseAlertSnapshot reads detection counters from Prometheus text output.
func ParseAlertSnapshot(reader io.Reader) (AlertSnapshot, error) {
	snapshot := AlertSnapshot{
		Alerts: make(map[string]uint64), Severities: make(map[string][]string), Suppressed: make(map[string]uint64),
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	sawUptime := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, labels, value, err := parseSample(line)
		if err != nil {
			continue
		}
		switch name {
		case uptimeMetric:
			const maxSeconds = uint64(math.MaxInt64 / int64(time.Second))
			snapshot.Uptime = time.Duration(min(value, maxSeconds)) * time.Second
			sawUptime = true
		case detectionAlertsMetric:
			rule := labels["rule_id"]
			if rule == "" {
				continue
			}
			snapshot.Alerts[rule] = saturatingAdd(snapshot.Alerts[rule], value)
			if severity := labels["severity"]; severity != "" && !slices.Contains(snapshot.Severities[rule], severity) {
				snapshot.Severities[rule] = append(snapshot.Severities[rule], severity)
			}
		case detectionSuppressedMetric:
			if exception := labels["exception"]; exception != "" {
				snapshot.Suppressed[exception] = saturatingAdd(snapshot.Suppressed[exception], value)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return AlertSnapshot{}, fmt.Errorf("read metrics: %w", err)
	}
	if !sawUptime {
		return AlertSnapshot{}, errors.New("metrics output lacks traceguard_uptime_seconds; is this a TraceGuard metrics endpoint?")
	}
	return snapshot, nil
}

// RankNoisyRules ranks the increase from before to after, busiest first, over
// a window that is cumulative when it runs from daemon start. A counter lower
// in after than in before was reset, so its after value counts.
func RankNoisyRules(before, after AlertSnapshot, window time.Duration, cumulative bool) NoisyRulesReport {
	report := NoisyRulesReport{Window: window, Cumulative: cumulative}
	for rule, count := range after.Alerts {
		if delta := counterDelta(before.Alerts[rule], count); delta > 0 {
			severities := slices.Clone(after.Severities[rule])
			slices.Sort(severities)
			report.Rules = append(report.Rules, RankedCount{ID: rule, Count: delta, Severity: strings.Join(severities, ",")})
		}
	}
	for exception, count := range after.Suppressed {
		if delta := counterDelta(before.Suppressed[exception], count); delta > 0 {
			report.Exceptions = append(report.Exceptions, RankedCount{ID: exception, Count: delta})
		}
	}
	byCount := func(left, right RankedCount) int {
		if left.Count != right.Count {
			if left.Count > right.Count {
				return -1
			}
			return 1
		}
		return strings.Compare(left.ID, right.ID)
	}
	slices.SortFunc(report.Rules, byCount)
	slices.SortFunc(report.Exceptions, byCount)
	return report
}

// WriteNoisyRules writes a report as aligned tables.
func WriteNoisyRules(out io.Writer, report NoisyRulesReport) error {
	writer := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	scope := "since the daemon started " + report.Window.String() + " ago"
	if !report.Cumulative {
		scope = "during the last " + report.Window.String()
	}
	var total uint64
	for _, rule := range report.Rules {
		total = saturatingAdd(total, rule.Count)
	}
	_, _ = fmt.Fprintf(writer, "alerts %s: %d\n\n", scope, total)
	_, _ = fmt.Fprintln(writer, "RULE\tALERTS\tSHARE\tPER_HOUR\tSEVERITY")
	for _, rule := range report.Rules {
		_, _ = fmt.Fprintf(writer, "%s\t%d\t%.1f%%\t%s\t%s\n", rule.ID, rule.Count,
			100*float64(rule.Count)/float64(total), perHour(rule.Count, report.Window), rule.Severity)
	}
	if len(report.Exceptions) > 0 {
		_, _ = fmt.Fprintln(writer, "\nEXCEPTION\tSUPPRESSED\tPER_HOUR")
		for _, exception := range report.Exceptions {
			_, _ = fmt.Fprintf(writer, "%s\t%d\t%s\n", exception.ID, exception.Count, perHour(exception.Count, report.Window))
		}
	}
	return writer.Flush()
}

func perHour(count uint64, window time.Duration) string {
	if window <= 0 {
		return "-"
	}
	return strconv.FormatFloat(float64(count)/window.Hours(), 'f', 1, 64)
}

func counterDelta(before, after uint64) uint64 {
	if after < before {
		return after
	}
	return after - before
}

func saturatingAdd(left, right uint64) uint64 {
	if right > math.MaxUint64-left {
		return math.MaxUint64
	}
	return left + right
}

// parseSample splits one Prometheus text sample into its name, labels, and a
// non-negative integer value.
func parseSample(line string) (string, map[string]string, uint64, error) {
	var name, rest string
	labels := map[string]string{}
	if open := strings.IndexByte(line, '{'); open >= 0 {
		name = line[:open]
		parsed, remainder, err := parseLabels(line[open+1:])
		if err != nil {
			return "", nil, 0, err
		}
		labels, rest = parsed, remainder
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", nil, 0, errors.New("sample lacks a value")
		}
		name, rest = fields[0], strings.Join(fields[1:], " ")
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return "", nil, 0, errors.New("sample lacks a value")
	}
	value, err := strconv.ParseFloat(fields[0], 64)
	if err != nil || math.IsNaN(value) || value < 0 {
		return "", nil, 0, fmt.Errorf("invalid sample value %q", fields[0])
	}
	if value >= math.MaxUint64 {
		return name, labels, math.MaxUint64, nil
	}
	return name, labels, uint64(value), nil
}

// parseLabels reads label pairs up to the closing brace and returns them with
// the text after it.
func parseLabels(text string) (map[string]string, string, error) {
	labels := map[string]string{}
	for {
		text = strings.TrimLeft(text, " ,")
		if strings.HasPrefix(text, "}") {
			return labels, text[1:], nil
		}
		equals := strings.IndexByte(text, '=')
		if equals <= 0 || equals+1 >= len(text) || text[equals+1] != '"' {
			return nil, "", errors.New("malformed label")
		}
		key := strings.TrimSpace(text[:equals])
		var value strings.Builder
		index := equals + 2
		closed := false
		for index < len(text) {
			char := text[index]
			if char == '\\' && index+1 < len(text) {
				switch text[index+1] {
				case 'n':
					value.WriteByte('\n')
				default:
					value.WriteByte(text[index+1])
				}
				index += 2
				continue
			}
			if char == '"' {
				closed = true
				index++
				break
			}
			value.WriteByte(char)
			index++
		}
		if !closed {
			return nil, "", errors.New("unterminated label value")
		}
		labels[key] = value.String()
		text = text[index:]
	}
}
