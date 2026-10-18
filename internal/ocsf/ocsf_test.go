package ocsf

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func convert(t *testing.T, level string, fields map[string]any) map[string]any {
	t.Helper()
	event := Convert(Record{Timestamp: "2026-10-18T10:00:00.5Z", Level: level, Message: "msg", Hostname: "host-1", Fields: fields})
	if _, err := json.Marshal(event); err != nil {
		t.Fatalf("converted event does not marshal: %v", err)
	}
	return event
}

func TestConvertSetsRequiredBaseAttributes(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{"event": "exec", "pid": uint32(7)})
	for key, want := range map[string]any{
		"class_uid": ClassProcessActivity, "category_uid": categorySystem, "activity_id": 1, "type_uid": 100701,
		"severity_id": 1, "time": time.Date(2026, 10, 18, 10, 0, 0, 500e6, time.UTC).UnixMilli(), "message": "msg",
	} {
		if !reflect.DeepEqual(event[key], want) {
			t.Errorf("%s = %#v, want %#v", key, event[key], want)
		}
	}
	metadata := object(t, event["metadata"])
	if metadata["version"] != Version {
		t.Fatalf("metadata = %v", metadata)
	}
	if object(t, event["device"])["hostname"] != "host-1" {
		t.Fatalf("device = %v", event["device"])
	}
}

func TestConvertClassifiesEvents(t *testing.T) {
	t.Parallel()

	tests := []struct {
		fields          map[string]any
		class, activity int
	}{
		{map[string]any{"event": "dns", "domain": "example.com"}, ClassDNSActivity, 1},
		{map[string]any{"event": "connection", "direction": "outbound"}, ClassNetworkActivity, 1},
		{map[string]any{"event": "egress_blocked"}, ClassNetworkActivity, 5},
		{map[string]any{"event": "ptrace", "operation": "attach"}, ClassProcessActivity, 4},
		{map[string]any{"event": "ptrace", "operation": "traceme"}, ClassProcessActivity, 3},
		{map[string]any{"event": "privilege_change", "operation": "setresuid"}, ClassProcessActivity, 5},
		{map[string]any{"event": "privilege_change", "operation": "capset"}, ClassProcessActivity, 99},
		{map[string]any{"event": "module_load"}, ClassKernelExtensionActivity, 1},
		{map[string]any{"event": "file_created", "requested_path": "/tmp/x"}, ClassFileSystemActivity, 1},
		{map[string]any{"event": "file_change", "operation": "rename"}, ClassFileSystemActivity, 5},
		{map[string]any{"event": "file_change", "operation": "rmdir"}, ClassFileSystemActivity, 4},
		{map[string]any{"event": "file_integrity", "change": "attributes"}, ClassFileSystemActivity, 6},
		{map[string]any{"event": "mount"}, ClassFileSystemActivity, 12},
		{map[string]any{"event": "detection_alert"}, ClassDetectionFinding, 1},
		{map[string]any{"policy_sha256": "abc"}, ClassBase, 0},
	}
	for _, test := range tests {
		event := convert(t, "info", test.fields)
		if event["class_uid"] != test.class || event["activity_id"] != test.activity {
			t.Errorf("%v: class %v activity %v, want %d %d", test.fields, event["class_uid"], event["activity_id"], test.class, test.activity)
		}
	}
}

func TestConvertMapsNetworkEndpointsByDirection(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{
		"event": "connection", "direction": "inbound", "socket_protocol": "tcp",
		"peer_address": "203.0.113.9", "peer_port": uint16(51000), "local_address": "10.0.0.5", "local_port": uint16(22),
	})
	if src := object(t, event["src_endpoint"]); src["ip"] != "203.0.113.9" || src["port"] != uint16(51000) {
		t.Fatalf("inbound src_endpoint = %v", src)
	}
	if dst := object(t, event["dst_endpoint"]); dst["port"] != uint16(22) {
		t.Fatalf("inbound dst_endpoint = %v", dst)
	}
	if info := object(t, event["connection_info"]); info["direction_id"] != 1 || info["protocol_name"] != "tcp" {
		t.Fatalf("connection_info = %v", info)
	}
	// The native event name is kept so SIEM queries can still filter on it.
	if !reflect.DeepEqual(event["unmapped"], map[string]any{"event": "connection"}) {
		t.Fatalf("unmapped = %v, want only the native event name", event["unmapped"])
	}
}

func TestConvertKeepsUnmappedFieldsOnce(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{
		"event": "exec", "pid": uint32(9), "program": "bash", "kernel_uid": uint32(1000), "uid": uint32(1000),
		"requested_path": "/usr/bin/curl", "command_line": []string{"curl", "-s"}, "exec_source": "path",
	})
	actor := object(t, event["actor"])
	if object(t, actor["user"])["uid"] != "1000" || object(t, actor["process"])["name"] != "bash" {
		t.Fatalf("actor = %v", actor)
	}
	process := object(t, event["process"])
	if process["cmd_line"] != "curl -s" || object(t, process["file"])["path"] != "/usr/bin/curl" {
		t.Fatalf("process = %v", process)
	}
	unmapped := object(t, event["unmapped"])
	if !reflect.DeepEqual(unmapped, map[string]any{"event": "exec", "exec_source": "path"}) {
		t.Fatalf("unmapped = %v", unmapped)
	}
}

func TestConvertDetectionFindingCarriesAttacks(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{
		"event": "detection_alert", "detection_rule_id": "runtime.ptrace-attach", "severity": "warning",
		"detection_message": "ptrace attach", "source_event": "ptrace", "tags": []string{"runtime"},
		"mitre_tactics": []string{"TA0004"}, "mitre_techniques": []string{"T1055.008"}, "program": "gdb",
	})
	if event["severity_id"] != 3 {
		t.Fatalf("severity_id = %v, want the alert's warning", event["severity_id"])
	}
	finding := object(t, event["finding_info"])
	if finding["title"] != "ptrace attach" || object(t, finding["analytic"])["uid"] != "runtime.ptrace-attach" {
		t.Fatalf("finding_info = %v", finding)
	}
	want := []map[string]any{
		{"technique": map[string]any{"uid": "T1055"}, "sub_technique": map[string]any{"uid": "T1055.008"}},
		{"tactic": map[string]any{"uid": "TA0004"}},
	}
	if !reflect.DeepEqual(event["attacks"], want) {
		t.Fatalf("attacks = %#v", event["attacks"])
	}
}

func TestConvertFileIntegrityHashesAndDisposition(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{
		"event": "file_integrity", "change": "modified", "path": "/etc/shadow", "sha256": "ab", "size": int64(10), "file_type": "file",
	})
	file := object(t, event["file"])
	if file["path"] != "/etc/shadow" || file["size"] != int64(10) {
		t.Fatalf("file = %v", file)
	}
	if hashes := objects(t, file["hashes"]); hashes[0]["algorithm_id"] != 3 || hashes[0]["value"] != "ab" {
		t.Fatalf("hashes = %v", hashes)
	}

	blocked := convert(t, "info", map[string]any{"event": "exec_blocked", "path": "/tmp/x"})
	if blocked["action_id"] != 2 || blocked["disposition_id"] != 2 {
		t.Fatalf("blocked disposition = %v %v", blocked["action_id"], blocked["disposition_id"])
	}
	dryRun := convert(t, "info", map[string]any{"event": "exec_would_block", "path": "/tmp/x"})
	if dryRun["action_id"] != 1 || dryRun["disposition_id"] != 15 {
		t.Fatalf("dry-run disposition = %v %v", dryRun["action_id"], dryRun["disposition_id"])
	}
}

func TestConvertSetsRequiredClassAttributes(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		fields       map[string]any
		activityName string
		required     string
	}{
		{map[string]any{"event": "dns", "pid": uint32(3), "domain": "example.com"}, "Query", "query"},
		{map[string]any{"event": "tcp_sockops", "pid": uint32(3)}, "tcp_sockops", "dst_endpoint"},
		{map[string]any{"event": "privilege_change", "operation": "capset", "pid": uint32(3), "program": "sh"}, "capset", "process"},
		{map[string]any{"event": "memfd_create", "pid": uint32(3), "program": "sh"}, "memfd_create", "process"},
		{map[string]any{"event": "bpf_prog_load", "pid": uint32(3), "bpf_prog_type": "kprobe"}, "Load", "driver"},
		{map[string]any{"event": "module_load", "pid": uint32(3), "operation": "init_module"}, "Load", "driver"},
		{map[string]any{"event": "file_access", "pid": uint32(3), "requested_path": "/etc/hosts"}, "Open", "file"},
		{map[string]any{"event": "detection_alert", "source_event": "exec", "pid": uint32(3)}, "Create", "finding_info"},
	} {
		event := convert(t, "info", test.fields)
		if event["activity_name"] != test.activityName {
			t.Errorf("%v: activity_name = %v, want %q", test.fields, event["activity_name"], test.activityName)
		}
		if event["action_id"] != 1 {
			t.Errorf("%v: action_id = %v, want 1 (Allowed)", test.fields, event["action_id"])
		}
		if _, ok := event[test.required]; !ok {
			t.Errorf("%v: missing required %s in %v", test.fields, test.required, event)
		}
		if profiles := object(t, event["metadata"])["profiles"]; !reflect.DeepEqual(profiles, []string{"security_control"}) {
			t.Errorf("%v: metadata.profiles = %v", test.fields, profiles)
		}
	}
	if file := object(t, object(t, convert(t, "info", map[string]any{"event": "module_load"})["driver"])["file"]); file["name"] != "unknown" {
		t.Fatalf("pathless module driver file = %v, want a named placeholder", file)
	}
	if process := object(t, convert(t, "info", map[string]any{"event": "memfd_create", "pid": uint32(3)})["process"]); process["pid"] != uint32(3) {
		t.Fatalf("memfd_create process = %v, want the calling process", process)
	}
	if base := convert(t, "info", map[string]any{"policy_sha256": "abc"}); base["action_id"] != nil || base["activity_name"] != "Unknown" {
		t.Fatalf("base event action_id = %v activity_name = %v", base["action_id"], base["activity_name"])
	}
}

func TestConvertKeepsRequestedExecPath(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{"event": "exec", "requested_path": "./run", "exe": "/opt/app/run"})
	if file := object(t, object(t, event["process"])["file"]); file["path"] != "/opt/app/run" || file["name"] != "run" {
		t.Fatalf("process.file = %v, want the resolved executable", file)
	}
	if object(t, event["unmapped"])["requested_path"] != "./run" {
		t.Fatalf("unmapped = %v, want the requested path kept", event["unmapped"])
	}
}

func TestConvertFileIntegrityActorAndDeletedType(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{
		"event": "file_integrity", "change": "deleted", "path": "/etc/cron.d", "previous_file_type": "directory",
		"actor_pid": uint32(44), "actor_program": "rm", "actor_kernel_uid": uint32(0), "actor_current_exe": "/usr/bin/rm",
	})
	if file := object(t, event["file"]); file["type_id"] != 2 || file["name"] != "cron.d" {
		t.Fatalf("deleted directory file = %v", file)
	}
	actor := object(t, event["actor"])
	process := object(t, actor["process"])
	if process["pid"] != uint32(44) || process["name"] != "rm" || object(t, actor["user"])["uid"] != "0" {
		t.Fatalf("actor = %v, want the triggering process", actor)
	}
	if unmapped := object(t, event["unmapped"]); unmapped["actor_pid"] != nil || unmapped["actor_program"] != nil {
		t.Fatalf("unmapped = %v, actor fields were not moved", unmapped)
	}
}

func TestConvertFindingUIDIsTheAlertID(t *testing.T) {
	t.Parallel()

	first := convert(t, "info", map[string]any{"event": "detection_alert", "alert_id": "A1", "detection_rule_id": "r"})
	second := convert(t, "info", map[string]any{"event": "detection_alert", "alert_id": "B2", "detection_rule_id": "r"})
	if object(t, first["finding_info"])["uid"] != "A1" || object(t, second["finding_info"])["uid"] != "B2" {
		t.Fatalf("finding uids = %v, %v", first["finding_info"], second["finding_info"])
	}
	blocked := convert(t, "info", map[string]any{"event": "detection_alert", "source_event": "exec_blocked", "detection_rule_id": "r"})
	if blocked["action_id"] != 2 || blocked["disposition_id"] != 2 {
		t.Fatalf("finding on a blocked event: action %v disposition %v", blocked["action_id"], blocked["disposition_id"])
	}
}

func TestSeverityIDs(t *testing.T) {
	t.Parallel()

	for level, want := range map[string]int{"debug": 1, "info": 1, "notice": 2, "warning": 3, "error": 4, "critical": 5, "emergency": 6, "odd": 0} {
		if got := severityID(level); got != want {
			t.Errorf("severityID(%q) = %d, want %d", level, got, want)
		}
	}
}

func object(t *testing.T, value any) map[string]any {
	t.Helper()
	out, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("value %#v is not an object", value)
	}
	return out
}

func objects(t *testing.T, value any) []map[string]any {
	t.Helper()
	out, ok := value.([]map[string]any)
	if !ok {
		t.Fatalf("value %#v is not a list of objects", value)
	}
	return out
}

// TestConvertClassifiesProducerDNSAndResolverRecords uses the records the
// daemon writes, whose message is a transport or would-block name while the
// event field keeps the kernel event name.
func TestConvertClassifiesProducerDNSAndResolverRecords(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		message     string
		fields      map[string]any
		class       int
		action      int
		disposition any
	}{
		{"dns", map[string]any{"event": "dns", "domain": "example.com"}, ClassDNSActivity, 1, nil},
		{"would-block", map[string]any{"event": "dns", "domain": "example.com", "policy": "block", "mode": "dry-run"}, ClassDNSActivity, 1, 15},
		{"blocked", map[string]any{"event": "blocked", "domain": "example.com", "policy": "block"}, ClassDNSActivity, 2, 2},
		{"udp", map[string]any{"event": "resolver", "address": "9.9.9.9", "port": uint16(53)}, ClassNetworkActivity, 1, nil},
		{"would-block-tcp", map[string]any{"event": "resolver", "address": "9.9.9.9", "port": uint16(53), "mode": "dry-run"}, ClassNetworkActivity, 1, 15},
		{"blocked-udp", map[string]any{"event": "resolver_blocked", "address": "9.9.9.9", "port": uint16(53)}, ClassNetworkActivity, 2, 2},
	} {
		event := Convert(Record{Timestamp: "2026-10-18T10:00:00Z", Level: "info", Message: test.message, Hostname: "h", Fields: test.fields})
		if event["class_uid"] != test.class || event["action_id"] != test.action || event["disposition_id"] != test.disposition {
			t.Errorf("%s: class %v action %v disposition %v, want %d %d %v",
				test.message, event["class_uid"], event["action_id"], event["disposition_id"], test.class, test.action, test.disposition)
		}
	}
}

func TestConvertSummaryFindings(t *testing.T) {
	t.Parallel()

	bind := convert(t, "info", map[string]any{"event": "bind_blocked", "pid": uint32(1), "socket_protocol": "tcp", "local_address": "0.0.0.0", "local_port": uint16(22)})
	if info := object(t, bind["connection_info"]); info["direction_id"] != 0 {
		t.Errorf("bind connection_info = %v, want direction_id 0 (Unknown)", info)
	}
	if _, ok := bind["src_endpoint"]; !ok {
		t.Errorf("bind lost its local endpoint: %v", bind)
	}
	if dst := object(t, bind["dst_endpoint"]); len(dst) != 0 {
		t.Errorf("bind dst_endpoint = %v, want the required but unknown peer", dst)
	}
	if unix := convert(t, "info", map[string]any{"event": "unix_blocked", "pid": uint32(1), "path": "/run/docker.sock"}); object(t, unix["dst_endpoint"])["name"] != "/run/docker.sock" {
		t.Errorf("unix dst_endpoint = %v, want the socket path", unix["dst_endpoint"])
	}
	if _, ok := convert(t, "info", map[string]any{"event": "sockopt_blocked", "pid": uint32(1)})["src_endpoint"]; ok {
		t.Error("socket option event carries an empty src_endpoint")
	}

	cached := convert(t, "info", map[string]any{"event": "connection", "direction": "inbound", "cached_uid": uint32(33), "cached_program": "nginx"})
	actor := object(t, cached["actor"])
	if object(t, actor["user"])["uid"] != "33" || object(t, actor["process"])["name"] != "nginx" {
		t.Errorf("socket-cache actor = %v", actor)
	}

	exec := convert(t, "info", map[string]any{"event": "exec", "pid": uint32(5), "program": "bash", "current_exe": "/usr/bin/curl"})
	if _, ok := object(t, object(t, exec["actor"])["process"])["file"]; ok || object(t, exec["unmapped"])["current_exe"] != "/usr/bin/curl" {
		t.Errorf("exec actor = %v unmapped = %v, want current_exe left unmapped", exec["actor"], exec["unmapped"])
	}

	deleted := convert(t, "info", map[string]any{"event": "file_integrity", "change": "deleted", "path": "/etc/passwd",
		"previous_file_type": "file", "previous_sha256": "ab", "previous_size": int64(9)})
	file := object(t, deleted["file"])
	if file["size"] != int64(9) || objects(t, file["hashes"])[0]["value"] != "ab" {
		t.Errorf("deleted file = %v, want its previous digest and size", file)
	}
	if actor, ok := deleted["actor"].(map[string]any); !ok || len(actor) != 0 {
		t.Errorf("rescan actor = %v, want the required but unknown actor", deleted["actor"])
	}

	for _, operation := range []string{"link", "symlink"} {
		if event := convert(t, "info", map[string]any{"event": "file_change", "operation": operation, "requested_path": "/tmp/x", "new_path": "/etc/cron.d/x"}); event["activity_id"] != 1 {
			t.Errorf("%s activity = %v, want 1 (Create)", operation, event["activity_id"])
		}
	}
}

func TestConvertLinkCreationNamesTheCreatedFile(t *testing.T) {
	t.Parallel()

	symlink := convert(t, "info", map[string]any{"event": "file_change", "operation": "symlink", "requested_path": "/etc/passwd", "new_path": "/tmp/link"})
	if file := object(t, symlink["file"]); file["path"] != "/tmp/link" || file["type_id"] != 7 {
		t.Fatalf("symlink file = %v, want the created symlink", file)
	}
	if _, ok := symlink["file_result"]; ok || object(t, symlink["unmapped"])["requested_path"] != "/etc/passwd" {
		t.Fatalf("symlink = %v, want the target text kept unmapped", symlink)
	}
	link := convert(t, "info", map[string]any{"event": "file_change", "operation": "link", "requested_path": "/etc/shadow", "new_path": "/tmp/copy"})
	if file := object(t, link["file"]); file["path"] != "/tmp/copy" || file["type_id"] != 1 {
		t.Fatalf("link file = %v, want the created link", file)
	}
}

func TestConvertDirectoryRemovalIsAFolder(t *testing.T) {
	t.Parallel()

	event := convert(t, "info", map[string]any{"event": "file_change", "operation": "rmdir", "requested_path": "/etc/cron.d"})
	if file := object(t, event["file"]); file["type_id"] != 2 || event["activity_id"] != 4 {
		t.Fatalf("rmdir file = %v activity = %v, want a deleted folder", file, event["activity_id"])
	}
}
