package telemetry

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
)

type Registry struct {
	mu       sync.RWMutex
	started  time.Time
	counters map[string]int64
	gauges   map[string]int64
}

func NewRegistry() *Registry {
	return &Registry{
		started:  time.Now().UTC(),
		counters: make(map[string]int64),
		gauges:   make(map[string]int64),
	}
}

func (r *Registry) IncEvent(kind, transport string) {
	r.incCounter(metricKey2("traceguard_events_total", "kind", kind, "transport", transport))
}

func (r *Registry) IncConnection(direction, family, protocol, attribution string) {
	r.incCounter(metricKey4("traceguard_connections_total",
		"attribution", attribution,
		"direction", direction,
		"family", family,
		"protocol", protocol,
	))
}

func (r *Registry) IncBlocklistRefresh(success bool) {
	name := "traceguard_blocklist_refresh_errors_total"
	status := "error"
	if success {
		name = "traceguard_blocklist_refresh_success_total"
		status = "success"
	}
	r.incCounter(name)
	r.setGauge(metricKey1("traceguard_blocklist_last_refresh_timestamp_seconds", "status", status), time.Now().UTC().Unix())
}

func (r *Registry) IncBlocklistLoad(source string, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey2("traceguard_blocklist_load_total", "source", source, "status", status))
}

func (r *Registry) SetPolicyCounts(domains, endpoints int) {
	r.setGauge("traceguard_policy_domains", int64(domains))
	r.setGauge("traceguard_policy_endpoints", int64(endpoints))
}

func (r *Registry) SetPolicyLastLoaded() {
	r.setGauge("traceguard_policy_last_loaded_timestamp_seconds", time.Now().UTC().Unix())
}

func (r *Registry) SetPolicyMode(mode string) {
	gauges := make(map[string]int64, 3)
	for _, candidate := range []string{"observe", "dry_run", "block"} {
		value := int64(0)
		if candidate == mode {
			value = 1
		}
		gauges[metricKey1("traceguard_policy_mode", "mode", candidate)] = value
	}
	r.replaceGauges("traceguard_policy_mode", gauges)
}

func (r *Registry) SetPolicyRuleCounts(counts map[string]int) {
	gauges := make(map[string]int64, len(counts))
	for key, value := range counts {
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		gauges[metricKey2("traceguard_policy_rules", "action", parts[0], "type", parts[1])] = int64(value)
	}
	r.replaceGauges("traceguard_policy_rules", gauges)
}

func (r *Registry) IncProcessCache(hit bool) {
	name := "traceguard_process_cache_miss_total"
	if hit {
		name = "traceguard_process_cache_hit_total"
	}
	r.incCounter(name)
}

func (r *Registry) IncProcessMetadata(source string) {
	switch source {
	case "proc", "fallback":
	default:
		source = "fallback"
	}
	r.incCounter(metricKey1("traceguard_process_metadata_total", "source", source))
}

func (r *Registry) IncProcessLSMMetadata(source string) {
	switch source {
	case "selinux", "apparmor":
	default:
		source = "none"
	}
	r.incCounter(metricKey1("traceguard_process_lsm_metadata_total", "source", source))
}

func (r *Registry) IncPolicyDecision(decision string) {
	r.incCounter(metricKey1("traceguard_policy_decisions_total", "decision", decision))
}

func (r *Registry) IncPolicyReload(trigger string, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey2("traceguard_policy_reload_total", "status", status, "trigger", trigger))
}

func (r *Registry) IncEventArchive(status string) {
	r.incCounter(metricKey1("traceguard_event_archive_total", "status", status))
}

func (r *Registry) IncEventExport(status string) {
	r.incCounter(metricKey1("traceguard_event_export_total", "status", status))
}

func (r *Registry) IncEventSyslog(status string) {
	r.incCounter(metricKey1("traceguard_event_syslog_total", "status", status))
}

func (r *Registry) SetEventExportQueueDepth(depth int) {
	r.setGauge("traceguard_event_export_queue_depth", int64(depth))
}

func (r *Registry) SetEventExportSpoolFiles(count int) {
	r.setGauge("traceguard_event_export_spool_files", int64(count))
}

func (r *Registry) SetEventExportLastSuccess() {
	r.setGauge("traceguard_event_export_last_success_timestamp_seconds", time.Now().UTC().Unix())
}

func (r *Registry) SetEventExportLastError() {
	r.setGauge("traceguard_event_export_last_error_timestamp_seconds", time.Now().UTC().Unix())
}

func (r *Registry) IncKubernetesRefresh(success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey1("traceguard_kubernetes_refresh_total", "status", status))
}

func (r *Registry) SetKubernetesPodCount(count int) {
	r.setGauge("traceguard_kubernetes_pods", int64(count))
}

func (r *Registry) IncKubernetesEnrichment(hit bool) {
	status := "miss"
	if hit {
		status = "hit"
	}
	r.incCounter(metricKey1("traceguard_kubernetes_enrichment_total", "status", status))
}

func (r *Registry) SetEBPFAttachedPrograms(count int) {
	r.setGauge("traceguard_ebpf_attached_programs", int64(count))
}

func (r *Registry) IncEBPFReadError() {
	r.incCounter("traceguard_ebpf_read_errors_total")
}

func (r *Registry) StartServer(ctx context.Context, addr string, logger *logging.Logger) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Render()))
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen metrics server: %w", err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		logger.Info("metrics server listening", map[string]any{
			"address": listener.Addr().String(),
		})
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server stopped", err, map[string]any{
				"address": addr,
			})
		}
	}()

	return nil
}

func (r *Registry) Render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lines := make([]string, 0, len(r.counters)+len(r.gauges)+1)
	lines = append(lines, fmt.Sprintf("traceguard_uptime_seconds %d", int64(time.Since(r.started).Seconds())))

	counterKeys := make([]string, 0, len(r.counters))
	for key := range r.counters {
		counterKeys = append(counterKeys, key)
	}
	sort.Strings(counterKeys)
	for _, key := range counterKeys {
		lines = append(lines, fmt.Sprintf("%s %d", key, r.counters[key]))
	}

	gaugeKeys := make([]string, 0, len(r.gauges))
	for key := range r.gauges {
		gaugeKeys = append(gaugeKeys, key)
	}
	sort.Strings(gaugeKeys)
	for _, key := range gaugeKeys {
		lines = append(lines, fmt.Sprintf("%s %d", key, r.gauges[key]))
	}

	return strings.Join(lines, "\n") + "\n"
}

func (r *Registry) incCounter(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters[name]++
}

func (r *Registry) setGauge(name string, value int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gauges[name] = value
}

func (r *Registry) replaceGauges(prefix string, values map[string]int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key := range r.gauges {
		if key == prefix || strings.HasPrefix(key, prefix+"{") {
			delete(r.gauges, key)
		}
	}
	for key, value := range values {
		r.gauges[key] = value
	}
}

func metricKey1(name, key, value string) string {
	var builder strings.Builder
	builder.Grow(len(name) + len(key) + len(value) + 5)
	builder.WriteString(name)
	builder.WriteByte('{')
	writeMetricLabel(&builder, key, value)
	builder.WriteByte('}')
	return builder.String()
}

func metricKey2(name, key1, value1, key2, value2 string) string {
	var builder strings.Builder
	builder.Grow(len(name) + len(key1) + len(value1) + len(key2) + len(value2) + 10)
	builder.WriteString(name)
	builder.WriteByte('{')
	writeMetricLabel(&builder, key1, value1)
	builder.WriteByte(',')
	writeMetricLabel(&builder, key2, value2)
	builder.WriteByte('}')
	return builder.String()
}

func metricKey4(name, key1, value1, key2, value2, key3, value3, key4, value4 string) string {
	var builder strings.Builder
	builder.Grow(len(name) + len(key1) + len(value1) + len(key2) + len(value2) + len(key3) + len(value3) + len(key4) + len(value4) + 20)
	builder.WriteString(name)
	builder.WriteByte('{')
	writeMetricLabel(&builder, key1, value1)
	builder.WriteByte(',')
	writeMetricLabel(&builder, key2, value2)
	builder.WriteByte(',')
	writeMetricLabel(&builder, key3, value3)
	builder.WriteByte(',')
	writeMetricLabel(&builder, key4, value4)
	builder.WriteByte('}')
	return builder.String()
}

func writeMetricLabel(builder *strings.Builder, key, value string) {
	builder.WriteString(key)
	builder.WriteString("=\"")
	builder.WriteString(escapeLabelValue(value))
	builder.WriteByte('"')
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return value
}
