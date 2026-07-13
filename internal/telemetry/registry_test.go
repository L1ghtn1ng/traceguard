package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
)

func TestRenderIncludesCountersAndGauges(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.IncEvent("dns", "udp")
	registry.IncProcessCache(true)
	registry.IncPolicyDecision("block")
	registry.IncPolicyReload("sighup", true)
	registry.IncEventArchive("success")
	registry.IncEventExport("queued")
	registry.IncEventSyslog("success")
	registry.SetEventExportQueueDepth(7)
	registry.SetEventExportSpoolFiles(2)
	registry.SetEventExportLastSuccess()
	registry.SetEventExportLastError()
	registry.IncKubernetesRefresh(true)
	registry.IncKubernetesEnrichment(true)
	registry.IncConnection("inbound", "ipv4", "tcp", "kernel-ingress")
	registry.SetPolicyCounts(4, 2)
	registry.SetPolicyLastLoaded()
	registry.SetPolicyMode("block")
	registry.SetPolicyRuleCounts(map[string]int{
		"block|domain":   2,
		"allow|endpoint": 1,
	})
	registry.SetKubernetesPodCount(3)
	registry.IncBlocklistLoad("remote", true)
	registry.IncProcessMetadata("proc")
	registry.IncProcessLSMMetadata("apparmor")
	registry.SetEBPFAttachedPrograms(14)
	registry.SetKernelFeatures(map[string]bool{"enhanced_telemetry": true, "btf": false, "bpf_lsm": true})
	registry.IncEBPFReadError()

	rendered := registry.Render()
	checks := []string{
		`# HELP traceguard_events_total TraceGuard events total.`,
		`# TYPE traceguard_events_total counter`,
		`# HELP traceguard_policy_domains TraceGuard policy domains.`,
		`# TYPE traceguard_policy_domains gauge`,
		`traceguard_blocklist_load_total{source="remote",status="success"} 1`,
		`traceguard_ebpf_attached_programs 14`,
		`traceguard_ebpf_read_errors_total 1`,
		`traceguard_kernel_feature_enabled{feature="bpf_lsm"} 1`,
		`traceguard_kernel_feature_enabled{feature="btf"} 0`,
		`traceguard_kernel_feature_enabled{feature="enhanced_telemetry"} 1`,
		`traceguard_events_total{kind="dns",transport="udp"} 1`,
		`traceguard_event_export_queue_depth 7`,
		`traceguard_event_export_spool_files 2`,
		`traceguard_policy_decisions_total{decision="block"} 1`,
		`traceguard_policy_mode{mode="block"} 1`,
		`traceguard_policy_mode{mode="dry_run"} 0`,
		`traceguard_policy_rules{action="allow",type="endpoint"} 1`,
		`traceguard_policy_rules{action="block",type="domain"} 2`,
		`traceguard_policy_reload_total{status="success",trigger="sighup"} 1`,
		`traceguard_event_archive_total{status="success"} 1`,
		`traceguard_event_export_total{status="queued"} 1`,
		`traceguard_event_syslog_total{status="success"} 1`,
		`traceguard_kubernetes_refresh_total{status="success"} 1`,
		`traceguard_kubernetes_enrichment_total{status="hit"} 1`,
		`traceguard_connections_total{attribution="kernel-ingress",direction="inbound",family="ipv4",protocol="tcp"} 1`,
		`traceguard_process_cache_hit_total 1`,
		`traceguard_process_metadata_total{source="proc"} 1`,
		`traceguard_process_lsm_metadata_total{source="apparmor"} 1`,
		`traceguard_policy_domains 4`,
		`traceguard_policy_endpoints 2`,
		`traceguard_kubernetes_pods 3`,
	}
	for _, check := range checks {
		if !strings.Contains(rendered, check) {
			t.Fatalf("Render() missing %q in %q", check, rendered)
		}
	}
}

func TestMetricsServerUsesBoundedTimeouts(t *testing.T) {
	t.Parallel()

	server := newHTTPServer("127.0.0.1:0", http.NotFoundHandler())
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("ReadHeaderTimeout is not bounded")
	}
	if server.WriteTimeout <= 0 {
		t.Fatal("WriteTimeout is not bounded")
	}
	if server.IdleTimeout <= 0 {
		t.Fatal("IdleTimeout is not bounded")
	}
}

func TestEventSinkHealthRecovers(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	if !registry.Healthy() {
		t.Fatal("new registry is unhealthy")
	}
	registry.SetEventSinkHealthy("archive", false)
	if registry.Healthy() {
		t.Fatal("registry stayed healthy after sink failure")
	}
	registry.SetEventSinkHealthy("archive", true)
	if !registry.Healthy() {
		t.Fatal("registry did not recover after sink success")
	}
}

func TestHealthEndpointReportsSinkFailure(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.SetEventSinkHealthy("archive", false)
	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	response := httptest.NewRecorder()
	registry.httpHandler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || response.Body.String() != "unhealthy\n" {
		t.Fatalf("health response = %d %q, want 503 unhealthy", response.Code, response.Body.String())
	}
}

func TestSetPolicyRuleCountsReplacesStaleGauges(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.SetPolicyRuleCounts(map[string]int{
		"block|domain": 4,
		"allow|domain": 1,
	})
	registry.SetPolicyRuleCounts(map[string]int{
		"block|domain": 2,
	})

	rendered := registry.Render()
	if !strings.Contains(rendered, `traceguard_policy_rules{action="block",type="domain"} 2`) {
		t.Fatalf("Render() missing replacement policy rule count in %q", rendered)
	}
	if strings.Contains(rendered, `traceguard_policy_rules{action="allow",type="domain"}`) {
		t.Fatalf("Render() kept stale policy rule count in %q", rendered)
	}
}

func TestRenderEscapesDirectMetricLabels(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.IncEvent("dns\"query", "udp\\test\nline")

	rendered := registry.Render()
	check := `traceguard_events_total{kind="dns\"query",transport="udp\\test\nline"} 1`
	if !strings.Contains(rendered, check) {
		t.Fatalf("Render() missing escaped label %q in %q", check, rendered)
	}
}

func TestStartServerReturnsListenError(t *testing.T) {
	t.Parallel()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	defer listener.Close()

	logger, err := logging.NewLogger(io.Discard, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	err = NewRegistry().StartServer(context.Background(), listener.Addr().String(), logger)
	if err == nil || !strings.Contains(err.Error(), "listen metrics server") {
		t.Fatalf("StartServer error = %v, want listen failure", err)
	}
}
