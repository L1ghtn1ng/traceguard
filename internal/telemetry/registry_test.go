package telemetry

import (
	"context"
	"io"
	"net"
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
	registry.IncKubernetesRefresh(true)
	registry.IncConnection("inbound", "ipv4", "tcp", "kernel-ingress")
	registry.SetPolicyCounts(4, 2)
	registry.SetKubernetesPodCount(3)

	rendered := registry.Render()
	checks := []string{
		`traceguard_events_total{kind="dns",transport="udp"} 1`,
		`traceguard_policy_decisions_total{decision="block"} 1`,
		`traceguard_policy_reload_total{status="success",trigger="sighup"} 1`,
		`traceguard_event_archive_total{status="success"} 1`,
		`traceguard_event_export_total{status="queued"} 1`,
		`traceguard_kubernetes_refresh_total{status="success"} 1`,
		`traceguard_connections_total{attribution="kernel-ingress",direction="inbound",family="ipv4",protocol="tcp"} 1`,
		`traceguard_process_cache_hit_total 1`,
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
