package telemetry

import (
	"strings"
	"testing"
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
