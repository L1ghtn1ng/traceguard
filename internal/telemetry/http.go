package telemetry

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
)

func (r *Registry) StartServer(ctx context.Context, addr string, logger *logging.Logger) error {
	if strings.TrimSpace(addr) == "" {
		return nil
	}

	mux := r.httpHandler()

	server := newHTTPServer(addr, mux)
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

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

func (r *Registry) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !r.Healthy() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("unhealthy\n"))
			return
		}
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(r.Render()))
	})
	return mux
}

func (r *Registry) Render() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	lines := make([]string, 0, 3*(len(r.counters)+len(r.gauges)+1))
	emittedMetadata := make(map[string]struct{}, len(r.counters)+len(r.gauges)+1)
	lines = appendMetric(lines, emittedMetadata, "traceguard_uptime_seconds", int64(time.Since(r.started).Seconds()))

	counterKeys := make([]string, 0, len(r.counters))
	for key := range r.counters {
		counterKeys = append(counterKeys, key)
	}
	sort.Strings(counterKeys)
	for _, key := range counterKeys {
		lines = appendMetric(lines, emittedMetadata, key, r.counters[key])
	}

	gaugeKeys := make([]string, 0, len(r.gauges))
	for key := range r.gauges {
		gaugeKeys = append(gaugeKeys, key)
	}
	sort.Strings(gaugeKeys)
	for _, key := range gaugeKeys {
		lines = appendMetric(lines, emittedMetadata, key, r.gauges[key])
	}

	return strings.Join(lines, "\n") + "\n"
}

func appendMetric(lines []string, emitted map[string]struct{}, key string, value int64) []string {
	name := key
	if labelStart := strings.IndexByte(name, '{'); labelStart >= 0 {
		name = name[:labelStart]
	}
	if _, ok := emitted[name]; !ok {
		emitted[name] = struct{}{}
		metricType := "gauge"
		if strings.HasSuffix(name, "_total") {
			metricType = "counter"
		}
		help := strings.ReplaceAll(strings.TrimPrefix(name, "traceguard_"), "_", " ")
		lines = append(lines,
			fmt.Sprintf("# HELP %s TraceGuard %s.", name, help),
			fmt.Sprintf("# TYPE %s %s", name, metricType),
		)
	}
	return append(lines, fmt.Sprintf("%s %d", key, value))
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
	maps.Copy(r.gauges, values)
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
