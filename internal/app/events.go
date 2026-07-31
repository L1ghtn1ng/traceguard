package app

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

type processMetadataCache interface {
	Lookup(uint32, string) (processinfo.Metadata, bool)
	Invalidate(uint32)
}

func lookupProcessForEvent(cache processMetadataCache, event ebpf.Event) (processinfo.Metadata, bool) {
	process, hit := cache.Lookup(event.PID, event.Comm)
	if event.Kind == ebpf.EventExec {
		// exec events are emitted at syscall entry, before the process image
		// changes. Invalidate after enrichment so subsequent events cannot retain
		// pre-exec metadata for the full cache TTL.
		cache.Invalidate(event.PID)
	}
	return process, hit
}

func policyMode(cfg config.Config) string {
	switch {
	case cfg.Block && !cfg.DryRun:
		return "block"
	case cfg.DryRun:
		return "dry_run"
	default:
		return "observe"
	}
}

func policyRuleCounts(rules blocklist.Rules, resolvedBlockEndpoints, resolvedAllowEndpoints int) map[string]int {
	return map[string]int{
		"block|domain":        len(rules.BlockDomains),
		"allow|domain":        len(rules.AllowDomains),
		"block|suffix":        len(rules.BlockSuffixes),
		"allow|suffix":        len(rules.AllowSuffixes),
		"block|endpoint":      resolvedBlockEndpoints,
		"allow|endpoint":      resolvedAllowEndpoints,
		"block|endpoint_cidr": len(rules.BlockEndpointCIDRs),
		"allow|endpoint_cidr": len(rules.AllowEndpointCIDRs),
	}
}

func IsPermissionError(err error) bool {
	return errors.Is(err, ebpf.ErrInsufficientPrivileges)
}

func validateRulesForMode(cfg config.Config, rules blocklist.Rules) error {
	return nil
}

func resolverHost(index *atomic.Pointer[map[string]string], event ebpf.Event) string {
	current := index.Load()
	if current == nil {
		return ""
	}
	if host, ok := (*current)[resolverIndexKey(event.Transport, event.Address, event.Port)]; ok {
		return host
	}
	return ""
}

func resolverIndexKey(transport, address string, port uint16) string {
	return fmt.Sprintf("%s|%s|%d", transport, address, port)
}

func appendSocketFields(fields map[string]any, event ebpf.Event, process processinfo.Metadata) {
	if !isSocketAwareEvent(event.Kind) {
		return
	}
	if attribution := eventAttribution(event, process); attribution != "" {
		fields["attribution"] = attribution
	}
	if event.SocketHook != "" {
		fields["socket_hook"] = event.SocketHook
	}
	if event.SocketFamily != "" {
		fields["socket_family"] = event.SocketFamily
	}
	if event.SocketProtocol != "" {
		fields["socket_protocol"] = event.SocketProtocol
	}
}

func appendKernelFeatureFields(fields map[string]any, event ebpf.Event) {
	if event.KernelFeatureSet != "" {
		fields["kernel_feature_set"] = event.KernelFeatureSet
	}
	if event.EventSource != "" {
		fields["event_source"] = event.EventSource
	}
	if event.UIDSource != "" {
		fields["uid_source"] = event.UIDSource
		fields["kernel_uid"] = event.KernelUID
	}
	if event.CgroupID != 0 {
		fields["cgroup_id"] = event.CgroupID
	}
	if event.SocketCookie != 0 {
		fields["socket_cookie"] = event.SocketCookie
	}
}

func resolveExecutablePath(event ebpf.Event, process processinfo.Metadata) string {
	if event.PID == 0 {
		return ""
	}
	if event.Kind == ebpf.EventExec && event.Filename != "" {
		return event.Filename
	}
	if process.Exe != "" {
		return process.Exe
	}
	if len(process.Cmdline) > 0 && filepath.IsAbs(process.Cmdline[0]) {
		return process.Cmdline[0]
	}
	return ""
}

func eventAttribution(event ebpf.Event, process processinfo.Metadata) string {
	if isSocketAwareEvent(event.Kind) && process.Source == processinfo.SourceProc {
		return processinfo.SourceProc
	}
	return event.Attribution
}

func isSocketAwareEvent(kind uint32) bool {
	switch kind {
	case ebpf.EventDNS, ebpf.EventBlocked, ebpf.EventResolver, ebpf.EventResolverBlocked,
		ebpf.EventConnection, ebpf.EventEgressBlocked, ebpf.EventEgressWouldBlock:
		return true
	default:
		return false
	}
}

func domainDecision(policy *atomic.Pointer[blocklist.Policy], domain string) blocklist.Decision {
	current := policy.Load()
	if current == nil {
		return blocklist.DecisionNone
	}
	return current.DomainDecision(domain)
}

func endpointDecision(policy *atomic.Pointer[blocklist.Policy], transport, address string, port uint16) blocklist.Decision {
	current := policy.Load()
	if current == nil {
		return blocklist.DecisionNone
	}
	return current.EndpointDecision(transport, address, port)
}

func eventKindName(kind uint32) string {
	switch kind {
	case ebpf.EventDNS:
		return "dns"
	case ebpf.EventBlocked:
		return "blocked"
	case ebpf.EventExec:
		return "exec"
	case ebpf.EventResolver:
		return "resolver"
	case ebpf.EventResolverBlocked:
		return "resolver_blocked"
	case ebpf.EventConnection:
		return "connection"
	case ebpf.EventFileAccess:
		return "file_access"
	case ebpf.EventEgressBlocked:
		return "egress_blocked"
	case ebpf.EventEgressWouldBlock:
		return "egress_would_block"
	default:
		return "unknown"
	}
}

func fileAccessName(flags uint32) string {
	const (
		unknownFlags = 1 << 31
		oAccMode     = 0x3
		oWritable    = 0x1
		oReadWrite   = 0x2
		oCreat       = 0x40
		oTrunc       = 0x200
	)
	if flags&unknownFlags != 0 {
		return "unknown"
	}
	if flags&(oCreat|oTrunc) != 0 {
		return "write"
	}
	switch flags & oAccMode {
	case oWritable, oReadWrite:
		return "write"
	default:
		return "read"
	}
}

func fileAuditEventName(flags uint32) string {
	if fileCreated(flags) {
		return "file_created"
	}
	return "file_access"
}

func fileCreated(flags uint32) bool {
	const (
		unknownFlags = 1 << 31
		oCreat       = 0x40
	)
	return flags&unknownFlags == 0 && flags&oCreat != 0
}

func emitDetectionAlerts(detector *detection.Engine, recorder *eventsink.Recorder, metrics *telemetry.Registry, timestamp time.Time, eventName string, fields map[string]any) {
	alerts := detector.Evaluate(detection.Event{
		Timestamp: timestamp,
		Name:      eventName,
		Fields:    fields,
	})
	metrics.SetDetectionStateGroups(detector.StateCount())
	for _, alert := range alerts {
		alertFields := alert.Fields
		alertFields["source_event"] = eventName
		alertFields["event"] = "detection_alert"
		alertFields["detection_rule_id"] = alert.RuleID
		alertFields["severity"] = alert.Severity
		alertFields["detection_message"] = alert.Message
		alertFields["tags"] = alert.Tags
		alertFields["threshold_count"] = alert.Count
		if alert.Window > 0 {
			alertFields["threshold_window"] = alert.Window.String()
		}
		metrics.IncDetectionAlert(alert.RuleID, alert.Severity)
		recorder.InfoAt(alert.Timestamp, "detection-alert", alertFields)
	}
}
