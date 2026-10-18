package telemetry

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/logging"
)

func TestRenderIncludesCountersAndGauges(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.IncEvent("dns", "udp")
	registry.IncProcessCache(true)
	registry.IncPolicyDecision("block")
	registry.IncPolicyReload("sighup", true)
	registry.IncPolicySourceLoad("remote", true)
	registry.SetPolicySourceHealthy("remote", true)
	registry.SetEgressRuleCounts(2, 3)
	registry.IncEgressDecision("block", "dry-run")
	registry.IncLSMDecision("exec", "block", "dry-run")
	registry.IncBindDecision("block", "block")
	registry.IncUnixDecision("block", "dry-run", "connect")
	registry.IncSockoptDecision("block", "block")
	registry.SetDetectionRules(4)
	registry.SetDetectionStateGroups(7)
	registry.IncDetectionAlert("metadata-burst", "warning")
	registry.IncCgroupReconcile(true)
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
	registry.IncProcessMetadata("proc")
	registry.IncProcessLSMMetadata("apparmor")
	registry.SetEBPFAttachedPrograms(14)
	registry.SetEBPFProgramStats("lsm_exec", 123*time.Nanosecond, 7, 2)
	registry.SetHookHealthy("lsm-exec", true)
	registry.SetKernelFeatures(map[string]bool{"enhanced_telemetry": true, "btf": false, "bpf_lsm": true})
	registry.IncEBPFReadError()
	registry.SetRingBufferStats(16777216, 4096, map[string]uint64{"dns": 3, "exec": 0})
	registry.SetPolicyDigest("old")
	registry.SetPolicyDigest("abc123")
	registry.SetDetectionExceptions(1, 0, map[string]uint64{"removed": 4})
	registry.SetDetectionExceptions(2, 1, map[string]uint64{"agent-imds": 3})

	rendered := registry.Render()
	checks := []string{
		`# HELP traceguard_events_total TraceGuard events total.`,
		`# TYPE traceguard_events_total counter`,
		`# HELP traceguard_policy_domains TraceGuard policy domains.`,
		`# TYPE traceguard_policy_domains gauge`,
		`traceguard_ebpf_attached_programs 14`,
		`traceguard_ebpf_read_errors_total 1`,
		`# TYPE traceguard_ringbuf_dropped_total counter`,
		`traceguard_ringbuf_dropped_total{kind="dns"} 3`,
		`traceguard_ringbuf_dropped_total{kind="exec"} 0`,
		`traceguard_ringbuf_size_bytes 16777216`,
		`traceguard_ringbuf_unread_bytes 4096`,
		`traceguard_policy_info{sha256="abc123"} 1`,
		`traceguard_detection_exceptions{state="active"} 2`,
		`traceguard_detection_exceptions{state="expired"} 1`,
		`traceguard_detection_suppressed_total{exception="agent-imds"} 3`,
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
		`traceguard_policy_source_load_total{source="remote",status="success"} 1`,
		`traceguard_policy_source_healthy{source="remote"} 1`,
		`traceguard_egress_rules{action="allow"} 2`,
		`traceguard_egress_rules{action="block"} 3`,
		`traceguard_egress_decisions_total{decision="block",mode="dry-run"} 1`,
		`traceguard_lsm_decisions_total{decision="block",domain="exec",mode="dry-run"} 1`,
		`traceguard_bind_decisions_total{decision="block",mode="block"} 1`,
		`traceguard_unix_decisions_total{decision="block",mode="dry-run",op="connect"} 1`,
		`traceguard_sockopt_decisions_total{decision="block",mode="block"} 1`,
		`traceguard_hook_healthy{hook="lsm-exec"} 1`,
		`traceguard_ebpf_program_runtime_nanoseconds{program="lsm_exec"} 123`,
		`traceguard_ebpf_program_run_count{program="lsm_exec"} 7`,
		`traceguard_ebpf_program_recursion_misses{program="lsm_exec"} 2`,
		`traceguard_detection_rules 4`,
		`traceguard_detection_state_groups 7`,
		`traceguard_detection_alerts_total{rule_id="metadata-burst",severity="warning"} 1`,
		`traceguard_cgroup_reconcile_total{status="success"} 1`,
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
	if strings.Contains(rendered, `exception="removed"`) {
		t.Fatal("Render() kept a removed exception's suppression counter")
	}
	if strings.Contains(rendered, `sha256="old"`) {
		t.Fatal("Render() kept a replaced policy digest")
	}
}

func TestHookHealthAffectsReadinessAndRecovers(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	registry.SetHookHealthy("unix", false)
	if registry.Healthy() {
		t.Fatal("registry stayed healthy after required hook failure")
	}
	registry.SetHookHealthy("unix", true)
	if !registry.Healthy() {
		t.Fatal("registry did not recover after hook became ready")
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

func TestPolicySourceHealthAffectsReadinessAndRecovers(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	registry.SetPolicySourceHealthy("remote", false)
	if registry.Healthy() {
		t.Fatal("registry stayed healthy after policy source failure")
	}
	registry.SetPolicySourceHealthy("remote", true)
	if !registry.Healthy() {
		t.Fatal("registry did not recover after policy source success")
	}
}

func TestHealthEndpointReportsSinkFailure(t *testing.T) {
	t.Parallel()

	registry := NewRegistry()
	registry.SetEventSinkHealthy("archive", false)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/health", nil)
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

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen returned error: %v", err)
	}
	t.Cleanup(func() {
		if err := listener.Close(); err != nil {
			t.Errorf("close test listener: %v", err)
		}
	})

	logger, err := logging.NewLogger(io.Discard, "json")
	if err != nil {
		t.Fatalf("NewLogger returned error: %v", err)
	}

	err = NewRegistry().StartServer(context.Background(), listener.Addr().String(), logger)
	if err == nil || !strings.Contains(err.Error(), "listen metrics server") {
		t.Fatalf("StartServer error = %v, want listen failure", err)
	}
}
