package telemetry

import (
	"strings"
	"sync"
	"time"
)

type Registry struct {
	mu        sync.RWMutex
	started   time.Time
	counters  map[string]int64
	gauges    map[string]int64
	unhealthy map[string]struct{}
}

func NewRegistry() *Registry {
	return &Registry{
		started:   time.Now().UTC(),
		counters:  make(map[string]int64),
		gauges:    make(map[string]int64),
		unhealthy: make(map[string]struct{}),
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

func (r *Registry) IncPolicySourceLoad(source string, success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey2("traceguard_policy_source_load_total", "source", source, "status", status))
}

func (r *Registry) SetPolicySourceHealthy(source string, healthy bool) {
	r.setComponentHealthy("policy:"+source, "traceguard_policy_source_healthy", "source", source, healthy)
}

func (r *Registry) SetEgressRuleCounts(allow, block int) {
	r.replaceGauges("traceguard_egress_rules", map[string]int64{
		metricKey1("traceguard_egress_rules", "action", "allow"): int64(allow),
		metricKey1("traceguard_egress_rules", "action", "block"): int64(block),
	})
}

func (r *Registry) IncEgressDecision(decision, mode string) {
	r.incCounter(metricKey2("traceguard_egress_decisions_total", "decision", decision, "mode", mode))
}

func (r *Registry) SetDetectionRules(count int) {
	r.setGauge("traceguard_detection_rules", int64(count))
}

func (r *Registry) SetDetectionStateGroups(count int) {
	r.setGauge("traceguard_detection_state_groups", int64(count))
}

func (r *Registry) IncDetectionAlert(ruleID, severity string) {
	r.incCounter(metricKey2("traceguard_detection_alerts_total", "rule_id", ruleID, "severity", severity))
}

func (r *Registry) IncCgroupReconcile(success bool) {
	status := "error"
	if success {
		status = "success"
	}
	r.incCounter(metricKey1("traceguard_cgroup_reconcile_total", "status", status))
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

func (r *Registry) SetKernelFeatures(features map[string]bool) {
	gauges := make(map[string]int64, len(features))
	for feature, enabled := range features {
		value := int64(0)
		if enabled {
			value = 1
		}
		gauges[metricKey1("traceguard_kernel_feature_enabled", "feature", feature)] = value
	}
	r.replaceGauges("traceguard_kernel_feature_enabled", gauges)
}

func (r *Registry) IncEBPFReadError() {
	r.incCounter("traceguard_ebpf_read_errors_total")
}

func (r *Registry) SetEventSinkHealthy(sink string, healthy bool) {
	r.setComponentHealthy("sink:"+sink, "traceguard_event_sink_healthy", "sink", sink, healthy)
}

func (r *Registry) setComponentHealthy(component, metric, label, value string, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if healthy {
		delete(r.unhealthy, component)
		r.gauges[metricKey1(metric, label, value)] = 1
		return
	}
	r.unhealthy[component] = struct{}{}
	r.gauges[metricKey1(metric, label, value)] = 0
}

func (r *Registry) Healthy() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.unhealthy) == 0
}
