// Package ocsf converts TraceGuard records to Open Cybersecurity Schema
// Framework (OCSF) 1.3.0 events.
//
// Fields that map to an OCSF attribute are moved there; every other field is
// kept under unmapped, so a converted record loses nothing and repeats
// nothing.
package ocsf

import (
	"fmt"
	"maps"
	"strings"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/version"
)

// Version is the OCSF schema version events are written in.
const Version = "1.3.0"

// Category and class UIDs used by the mapping.
const (
	categorySystem   = 1
	categoryFindings = 2
	categoryNetwork  = 4

	ClassBase                    = 0
	ClassFileSystemActivity      = 1001
	ClassKernelExtensionActivity = 1002
	ClassProcessActivity         = 1007
	ClassDetectionFinding        = 2004
	ClassNetworkActivity         = 4001
	ClassDNSActivity             = 4003
)

const activityOther = 99

// Record is one TraceGuard record: the envelope and its flat fields.
type Record struct {
	Timestamp string
	Level     string
	Message   string
	Hostname  string
	Fields    map[string]any
}

// converter consumes record fields as they are mapped.
type converter struct {
	fields map[string]any
}

func (c *converter) take(name string) (any, bool) {
	value, ok := c.fields[name]
	if ok {
		delete(c.fields, name)
	}
	return value, ok
}

func (c *converter) text(name string) string {
	value, _ := c.take(name)
	text, _ := value.(string)
	return text
}

func (c *converter) peek(name string) string {
	text, _ := c.fields[name].(string)
	return text
}

// Convert maps a record to an OCSF event.
func Convert(record Record) map[string]any {
	c := &converter{fields: maps.Clone(record.Fields)}
	if c.fields == nil {
		c.fields = map[string]any{}
	}
	event := map[string]any{
		"message":     record.Message,
		"severity_id": severityID(record.Level),
		"metadata": map[string]any{
			"version": Version,
			"product": map[string]any{"name": "TraceGuard", "vendor_name": "TraceGuard", "version": version.Program},
		},
		"device": map[string]any{"hostname": record.Hostname, "type_id": 0},
	}
	if at, err := time.Parse(time.RFC3339Nano, record.Timestamp); err == nil {
		event["time"] = at.UnixMilli()
	}

	name := c.text("event")
	class, activity := classify(name, c)
	if class == ClassDetectionFinding {
		mapFinding(event, c)
	} else {
		mapActor(event, c)
		switch class {
		case ClassDNSActivity:
			mapDNS(event, c)
		case ClassNetworkActivity:
			mapNetwork(event, c)
		case ClassProcessActivity, ClassKernelExtensionActivity:
			mapProcessTarget(event, name, c)
		case ClassFileSystemActivity:
			mapFile(event, name, c)
		}
		mapDisposition(event, name, c)
	}
	category := map[int]int{
		ClassFileSystemActivity: categorySystem, ClassKernelExtensionActivity: categorySystem,
		ClassProcessActivity: categorySystem, ClassDetectionFinding: categoryFindings,
		ClassNetworkActivity: categoryNetwork, ClassDNSActivity: categoryNetwork,
	}[class]
	event["category_uid"] = category
	event["class_uid"] = class
	event["activity_id"] = activity
	event["type_uid"] = class*100 + activity
	if name != "" {
		c.fields["event"] = name
	}
	if len(c.fields) > 0 {
		event["unmapped"] = c.fields
	}
	return event
}

// classify picks the OCSF class and activity for a TraceGuard event name.
func classify(name string, c *converter) (int, int) {
	switch name {
	case "dns", "blocked":
		return ClassDNSActivity, 1 // Query
	case "connection", "resolver", "egress_would_block", "bind_would_block":
		return ClassNetworkActivity, 1 // Open
	case "resolver_blocked", "egress_blocked", "bind_blocked":
		return ClassNetworkActivity, 5 // Refuse
	case "unix_blocked", "unix_would_block", "sockopt_blocked", "sockopt_would_block", "tcp_sockops":
		return ClassNetworkActivity, activityOther
	case "exec", "exec_blocked", "exec_would_block":
		return ClassProcessActivity, 1 // Launch
	case "ptrace", "process_vm":
		if op := c.peek("operation"); op == "traceme" || op == "read" {
			return ClassProcessActivity, 3 // Open
		}
		return ClassProcessActivity, 4 // Inject
	case "privilege_change":
		if strings.HasSuffix(c.peek("operation"), "uid") {
			return ClassProcessActivity, 5 // Set User ID
		}
		return ClassProcessActivity, activityOther
	case "memfd_create", "io_uring_setup", "namespace_change":
		return ClassProcessActivity, activityOther
	case "module_load", "bpf_prog_load":
		return ClassKernelExtensionActivity, 1 // Load
	case "file_access", "file_blocked", "file_would_block":
		return ClassFileSystemActivity, 14 // Open
	case "file_created":
		return ClassFileSystemActivity, 1 // Create
	case "mount":
		return ClassFileSystemActivity, 12 // Mount
	case "file_change":
		switch c.peek("operation") {
		case "unlink", "rmdir":
			return ClassFileSystemActivity, 4 // Delete
		case "rename":
			return ClassFileSystemActivity, 5 // Rename
		case "truncate":
			return ClassFileSystemActivity, 3 // Update
		default:
			return ClassFileSystemActivity, 6 // Set Attributes
		}
	case "file_integrity":
		return ClassFileSystemActivity, map[string]int{"created": 1, "modified": 3, "deleted": 4, "attributes": 6}[c.peek("change")]
	case "detection_alert":
		return ClassDetectionFinding, 1 // Create
	default:
		return ClassBase, 0
	}
}

// severityID maps syslog-style severities and log levels to OCSF.
func severityID(level string) int {
	switch strings.ToLower(level) {
	case "debug", "info", "informational":
		return 1
	case "notice":
		return 2
	case "warn", "warning":
		return 3
	case "error":
		return 4
	case "critical":
		return 5
	case "alert", "emergency":
		return 6
	default:
		return 0
	}
}

// mapActor fills actor.process and actor.user from event-time identity.
func mapActor(event map[string]any, c *converter) {
	process := map[string]any{}
	if pid, ok := c.take("pid"); ok {
		process["pid"] = pid
	}
	if name := c.text("program"); name != "" {
		process["name"] = name
	}
	if exe := c.text("current_exe"); exe != "" {
		process["file"] = map[string]any{"path": exe, "type_id": 1}
	}
	actor := map[string]any{}
	if uid, ok := c.take("kernel_uid"); ok {
		c.take("uid")
		actor["user"] = map[string]any{"uid": fmt.Sprint(uid)}
	}
	if len(process) > 0 {
		actor["process"] = process
	}
	if len(actor) > 0 {
		event["actor"] = actor
	}
}

func endpoint(address, port any) map[string]any {
	out := map[string]any{}
	if text, ok := address.(string); ok && text != "" {
		out["ip"] = text
	}
	if port != nil {
		out["port"] = port
	}
	return out
}

func mapDNS(event map[string]any, c *converter) {
	if domain := c.text("domain"); domain != "" {
		event["query"] = map[string]any{"hostname": domain}
	}
}

func mapNetwork(event map[string]any, c *converter) {
	peerAddress, _ := c.take("peer_address")
	if peerAddress == nil {
		peerAddress, _ = c.take("address")
	}
	peerPort, _ := c.take("peer_port")
	if peerPort == nil {
		peerPort, _ = c.take("port")
	}
	localAddress, _ := c.take("local_address")
	localPort, _ := c.take("local_port")
	peer, local := endpoint(peerAddress, peerPort), endpoint(localAddress, localPort)
	info := map[string]any{}
	if protocol := c.text("socket_protocol"); protocol != "" {
		info["protocol_name"] = protocol
	}
	switch c.text("direction") {
	case "inbound":
		info["direction_id"] = 1
		event["src_endpoint"], event["dst_endpoint"] = peer, local
	case "outbound":
		info["direction_id"] = 2
		event["src_endpoint"], event["dst_endpoint"] = local, peer
	default:
		event["src_endpoint"], event["dst_endpoint"] = local, peer
	}
	if len(info) > 0 {
		event["connection_info"] = info
	}
}

// mapProcessTarget fills the process an event acts on.
func mapProcessTarget(event map[string]any, name string, c *converter) {
	process := map[string]any{}
	switch name {
	case "exec", "exec_blocked", "exec_would_block":
		path := c.text("requested_path")
		if exe := c.text("exe"); exe != "" {
			path = exe
		}
		if path == "" {
			path = c.text("path")
		}
		if path != "" {
			process["file"] = map[string]any{"path": path, "type_id": 1}
		}
		if args, ok := c.take("command_line"); ok {
			process["cmd_line"] = joinArgs(args)
		}
	case "ptrace", "process_vm":
		if pid, ok := c.take("target_pid"); ok {
			process["pid"] = pid
		}
	case "module_load":
		if path := c.text("module_path"); path != "" {
			event["driver"] = map[string]any{"file": map[string]any{"path": path, "type_id": 1}}
		}
	}
	if len(process) > 0 {
		event["process"] = process
	}
}

func mapFile(event map[string]any, name string, c *converter) {
	file := map[string]any{"type_id": 1}
	switch name {
	case "file_integrity":
		file["path"] = c.text("path")
		if digest := c.text("sha256"); digest != "" {
			file["hashes"] = []map[string]any{{"algorithm_id": 3, "algorithm": "SHA-256", "value": digest}}
		}
		if size, ok := c.take("size"); ok {
			file["size"] = size
		}
		if c.peek("file_type") == "directory" {
			file["type_id"] = 2
		}
	case "mount":
		file["path"] = c.text("mount_target")
		file["type_id"] = 2
	case "file_blocked", "file_would_block":
		file["path"] = c.text("path")
	default:
		file["path"] = c.text("requested_path")
	}
	event["file"] = file
	if newPath := c.text("new_path"); newPath != "" {
		event["file_result"] = map[string]any{"path": newPath, "type_id": 1}
	}
}

// mapDisposition records whether policy allowed the operation.
func mapDisposition(event map[string]any, name string, c *converter) {
	switch {
	case strings.HasSuffix(name, "_blocked") || name == "blocked":
		event["action_id"], event["disposition_id"] = 2, 2 // Denied, Blocked
	case strings.HasSuffix(name, "_would_block") || c.peek("mode") == "dry-run":
		event["action_id"], event["disposition_id"] = 1, 15 // Allowed, Detected
	}
}

// mapFinding maps a detection alert to a Detection Finding.
func mapFinding(event map[string]any, c *converter) {
	ruleID := c.text("detection_rule_id")
	finding := map[string]any{
		"uid":      fmt.Sprintf("%s:%v", ruleID, event["time"]),
		"title":    c.text("detection_message"),
		"analytic": map[string]any{"uid": ruleID, "name": ruleID, "type_id": 1},
	}
	if source := c.text("source_event"); source != "" {
		finding["desc"] = "TraceGuard " + source + " event matched " + ruleID
	}
	if tags, ok := c.take("tags"); ok {
		finding["types"] = tags
	}
	event["finding_info"] = finding
	event["severity_id"] = severityID(c.text("severity"))
	var attacks []map[string]any
	for _, technique := range stringList(c, "mitre_techniques") {
		attack := map[string]any{"technique": map[string]any{"uid": technique}}
		if parent, _, ok := strings.Cut(technique, "."); ok {
			attack["technique"] = map[string]any{"uid": parent}
			attack["sub_technique"] = map[string]any{"uid": technique}
		}
		attacks = append(attacks, attack)
	}
	for _, tactic := range stringList(c, "mitre_tactics") {
		attacks = append(attacks, map[string]any{"tactic": map[string]any{"uid": tactic}})
	}
	if len(attacks) > 0 {
		event["attacks"] = attacks
	}
	mapActor(event, c)
}

func stringList(c *converter, name string) []string {
	value, _ := c.take(name)
	switch items := value.(type) {
	case []string:
		return items
	case []any:
		out := make([]string, 0, len(items))
		for _, item := range items {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func joinArgs(value any) string {
	switch args := value.(type) {
	case []string:
		return strings.Join(args, " ")
	case []any:
		parts := make([]string, 0, len(args))
		for _, arg := range args {
			parts = append(parts, fmt.Sprint(arg))
		}
		return strings.Join(parts, " ")
	default:
		return fmt.Sprint(value)
	}
}
