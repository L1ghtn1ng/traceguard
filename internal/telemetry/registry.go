package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"traceguard/internal/logging"
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
	r.incCounter(metricKey("traceguard_events_total", map[string]string{
		"kind":      kind,
		"transport": transport,
	}))
}

func (r *Registry) IncBlocklistRefresh(success bool) {
	name := "traceguard_blocklist_refresh_errors_total"
	if success {
		name = "traceguard_blocklist_refresh_success_total"
	}
	r.incCounter(name)
}

func (r *Registry) SetPolicyCounts(domains, endpoints int) {
	r.setGauge("traceguard_policy_domains", int64(domains))
	r.setGauge("traceguard_policy_endpoints", int64(endpoints))
}

func (r *Registry) IncProcessCache(hit bool) {
	name := "traceguard_process_cache_miss_total"
	if hit {
		name = "traceguard_process_cache_hit_total"
	}
	r.incCounter(name)
}

func (r *Registry) IncPolicyDecision(decision string) {
	r.incCounter(metricKey("traceguard_policy_decisions_total", map[string]string{
		"decision": decision,
	}))
}

func (r *Registry) IncPolicyReload(trigger string, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey("traceguard_policy_reload_total", map[string]string{
		"trigger": trigger,
		"status":  status,
	}))
}

func (r *Registry) IncEventArchive(status string) {
	r.incCounter(metricKey("traceguard_event_archive_total", map[string]string{
		"status": status,
	}))
}

func (r *Registry) IncEventExport(status string) {
	r.incCounter(metricKey("traceguard_event_export_total", map[string]string{
		"status": status,
	}))
}

func (r *Registry) IncKubernetesRefresh(success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey("traceguard_kubernetes_refresh_total", map[string]string{
		"status": status,
	}))
}

func (r *Registry) SetKubernetesPodCount(count int) {
	r.setGauge("traceguard_kubernetes_pods", int64(count))
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

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	go func() {
		logger.Info("metrics server listening", map[string]any{
			"address": addr,
		})
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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

func metricKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var builder strings.Builder
	builder.WriteString(name)
	builder.WriteByte('{')
	for idx, key := range keys {
		if idx > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(key)
		builder.WriteString("=\"")
		builder.WriteString(escapeLabelValue(labels[key]))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func escapeLabelValue(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	value = strings.ReplaceAll(value, "\n", `\n`)
	return value
}
