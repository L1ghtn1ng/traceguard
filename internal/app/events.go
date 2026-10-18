package app

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
	"github.com/L1ghtn1ng/traceguard/internal/response"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/threatintel"
)

type processMetadataCache interface {
	LookupAt(uint32, string, uint64) (processinfo.Metadata, bool)
	Invalidate(uint32)
}

func lookupProcessForEvent(cache processMetadataCache, event ebpf.Event) (processinfo.Metadata, bool) {
	process, hit := cache.LookupAt(event.PID, event.Comm, event.ProcessStartTime)
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
	case cfg.EmergencyAllow:
		return "observe"
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
	if cfg.EmergencyAllow || (!cfg.Block && !cfg.DryRun) {
		return nil
	}
	for _, endpoint := range append(slices.Clone(rules.BlockEndpoints), rules.AllowEndpoints...) {
		if net.ParseIP(endpoint.Host) == nil {
			return fmt.Errorf("resolver endpoint %q uses a hostname; block and dry-run modes require authenticated literal IP or CIDR endpoints", endpoint.Host)
		}
	}
	return nil
}

func appendSocketFields(fields map[string]any, event ebpf.Event) {
	if !isSocketAwareEvent(event.Kind) {
		return
	}
	if attribution := eventAttribution(event); attribution != "" {
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

func appendEventIdentityFields(fields map[string]any, event ebpf.Event) {
	switch event.UIDSource {
	case "kernel":
		fields["uid_source"] = event.UIDSource
		fields["uid"] = event.KernelUID
		fields["kernel_uid"] = event.KernelUID
		if event.Comm != "" {
			fields["program"] = event.Comm
		}
		if event.ProcessStartTime != 0 {
			fields["process_start_ticks"] = event.ProcessStartTime
		}
		if event.CgroupID != 0 {
			fields["cgroup_id"] = event.CgroupID
		}
	case "socket-cache":
		fields["identity_source"] = event.UIDSource
		fields["cached_uid"] = event.KernelUID
		if event.Comm != "" {
			fields["cached_program"] = event.Comm
		}
		if event.ProcessStartTime != 0 {
			fields["cached_process_start_ticks"] = event.ProcessStartTime
		}
		if event.CgroupID != 0 {
			fields["cached_cgroup_id"] = event.CgroupID
		}
	default:
		if event.Comm != "" {
			fields["observed_program"] = event.Comm
		}
		if event.ProcessStartTime != 0 {
			fields["observed_process_start_ticks"] = event.ProcessStartTime
		}
	}
}

func appendKernelFeatureFields(fields map[string]any, event ebpf.Event) {
	if event.KernelFeatureSet != "" {
		fields["kernel_feature_set"] = event.KernelFeatureSet
	}
	if event.EventSource != "" {
		fields["event_source"] = event.EventSource
	}
	if event.SocketCookie != 0 {
		fields["socket_cookie"] = event.SocketCookie
	}
}

func resolveExecutablePath(event ebpf.Event) string {
	if event.PID == 0 {
		return ""
	}
	if (event.Kind == ebpf.EventExecBlocked || event.Kind == ebpf.EventExecWouldBlock) && event.Filename != "" {
		return event.Filename
	}
	return ""
}

func eventAttribution(event ebpf.Event) string {
	return event.Attribution
}

func isSocketAwareEvent(kind uint32) bool {
	switch kind {
	case ebpf.EventDNS, ebpf.EventBlocked, ebpf.EventResolver, ebpf.EventResolverBlocked,
		ebpf.EventConnection, ebpf.EventEgressBlocked, ebpf.EventEgressWouldBlock,
		ebpf.EventBindBlocked, ebpf.EventBindWouldBlock, ebpf.EventUnixBlocked,
		ebpf.EventUnixWouldBlock, ebpf.EventSockoptBlocked, ebpf.EventSockoptWouldBlock,
		ebpf.EventSockOps:
		return true
	default:
		return false
	}
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
	case ebpf.EventExecBlocked:
		return "exec_blocked"
	case ebpf.EventExecWouldBlock:
		return "exec_would_block"
	case ebpf.EventFileBlocked:
		return "file_blocked"
	case ebpf.EventFileWouldBlock:
		return "file_would_block"
	case ebpf.EventBindBlocked:
		return "bind_blocked"
	case ebpf.EventBindWouldBlock:
		return "bind_would_block"
	case ebpf.EventUnixBlocked:
		return "unix_blocked"
	case ebpf.EventUnixWouldBlock:
		return "unix_would_block"
	case ebpf.EventSockoptBlocked:
		return "sockopt_blocked"
	case ebpf.EventSockoptWouldBlock:
		return "sockopt_would_block"
	case ebpf.EventSockOps:
		return "tcp_sockops"
	case ebpf.EventMemfdCreate:
		return "memfd_create"
	case ebpf.EventPtrace:
		return "ptrace"
	case ebpf.EventProcessVM:
		return "process_vm"
	case ebpf.EventModuleLoad:
		return "module_load"
	case ebpf.EventBPFProgLoad:
		return "bpf_prog_load"
	case ebpf.EventIOURingSetup:
		return "io_uring_setup"
	case ebpf.EventMount:
		return "mount"
	case ebpf.EventNamespaceChange:
		return "namespace_change"
	case ebpf.EventPrivilegeChange:
		return "privilege_change"
	case ebpf.EventFileChange:
		return "file_change"
	default:
		return "unknown"
	}
}

func unixOperationName(operation uint32) string {
	switch operation {
	case 1:
		return "connect"
	case 2:
		return "sendmsg"
	case 4:
		return "recvmsg"
	default:
		return "unknown"
	}
}

func enforcementEventMode(wouldBlock bool) string {
	if wouldBlock {
		return "dry-run"
	}
	return "block"
}

func appendEnforcementDecisionFields(fields map[string]any, event ebpf.Event, mode string) {
	fields["policy"] = string(blocklist.DecisionBlock)
	fields["mode"] = mode
	if event.RuleID == "" {
		fields["policy_rule_id"] = "default"
		return
	}
	fields["policy_rule_id"] = event.RuleID
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

// alertSink records alerts and hands each to the responder, if any.
type alertSink struct {
	recorder  *eventsink.Recorder
	metrics   *telemetry.Registry
	responder *response.Responder
}

func (s alertSink) record(eventName string, alerts []detection.Alert) {
	for _, alert := range alerts {
		s.metrics.IncDetectionAlert(alert.RuleID, alert.Severity)
		s.recorder.InfoAt(alert.Timestamp, "detection-alert", alert.RecordFields(eventName))
		if s.responder != nil {
			s.responder.Submit(alert)
		}
	}
}

func emitDetectionAlerts(detector *detection.Engine, sink alertSink, timestamp time.Time, eventName string, fields map[string]any) {
	alerts := detector.Evaluate(detection.Event{
		Timestamp: timestamp,
		Name:      eventName,
		Fields:    fields,
	})
	sink.metrics.SetDetectionStateGroups(detector.StateCount())
	sink.record(eventName, alerts)
}

// emitThreatIntelAlerts records alerts for events whose domain or peer
// address is in a loaded feed.
func emitThreatIntelAlerts(matcher *threatintel.Matcher, sink alertSink, timestamp time.Time, eventName string, fields map[string]any) {
	sink.record(eventName, matcher.Evaluate(detection.Event{Timestamp: timestamp, Name: eventName, Fields: fields}))
}
