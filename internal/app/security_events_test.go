package app

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestSecurityOperationNamesMatchPolicyValidation(t *testing.T) {
	t.Parallel()

	for event, codes := range map[string]map[uint32]string{
		"ptrace": ptraceRequests, "process_vm": processVMOperations, "module_load": moduleOperations,
		"namespace_change": namespaceOperations, "privilege_change": privilegeOperations,
	} {
		names := make([]string, 0, len(codes))
		for _, name := range codes {
			names = append(names, name)
		}
		want := slices.Clone(policyconfig.SecurityEventOperations[event])
		slices.Sort(names)
		slices.Sort(want)
		if !slices.Equal(names, want) {
			t.Errorf("%s operations = %v, policy accepts %v", event, names, want)
		}
	}
}

func TestSecurityEventNamesAreDetectionEvents(t *testing.T) {
	t.Parallel()

	for kind := ebpf.EventMemfdCreate; kind <= ebpf.EventPrivilegeChange; kind++ {
		name := eventKindName(kind)
		if name == "unknown" {
			t.Fatalf("security event kind %d has no name", kind)
		}
		rule := policyconfig.DetectionRule{ID: "probe", Severity: "notice", Events: []string{name}, Message: "probe"}
		if _, err := policyconfig.Merge(policyconfig.Document{Version: 1, DetectionRules: []policyconfig.DetectionRule{rule}}, policyconfig.Document{}); err != nil {
			t.Fatalf("detection rule on %q rejected: %v", name, err)
		}
	}
}

func TestAppendSecurityEventFields(t *testing.T) {
	t.Parallel()

	procRoot := t.TempDir()
	fdDir := filepath.Join(procRoot, "42", "fd")
	if err := os.MkdirAll(fdDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/lib/modules/rootkit.ko", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name  string
		event ebpf.Event
		want  map[string]any
	}{
		{"memfd", ebpf.Event{Kind: ebpf.EventMemfdCreate, Filename: "payload", FileFlags: 0x3}, map[string]any{
			"memfd_name": "payload", "memfd_flags": []string{"cloexec", "allow_sealing"},
		}},
		{"ptrace attach", ebpf.Event{Kind: ebpf.EventPtrace, Operation: 16, FileMode: 900}, map[string]any{
			"operation": "attach", "target_pid": uint32(900),
		}},
		{"process_vm write", ebpf.Event{Kind: ebpf.EventProcessVM, Operation: 1, FileMode: 77}, map[string]any{
			"operation": "write", "target_pid": uint32(77),
		}},
		{"finit_module", ebpf.Event{Kind: ebpf.EventModuleLoad, PID: 42, Operation: 1, FileMode: 3}, map[string]any{
			"operation": "finit_module", "module_fd": uint32(3), "module_flags": uint32(0), "module_path": "/lib/modules/rootkit.ko",
		}},
		{"bpf", ebpf.Event{Kind: ebpf.EventBPFProgLoad, FileMode: 29}, map[string]any{"bpf_prog_type": "lsm"}},
		{"bpf unknown", ebpf.Event{Kind: ebpf.EventBPFProgLoad, FileMode: 999}, map[string]any{"bpf_prog_type": "unknown_999"}},
		{"mount", ebpf.Event{Kind: ebpf.EventMount, MountSource: "/dev/sda1", Filename: "/mnt", MountFSType: "ext4", FileFlags: 1}, map[string]any{
			"mount_source": "/dev/sda1", "mount_target": "/mnt", "mount_fstype": "ext4", "mount_flags": uint32(1),
		}},
		{"unshare", ebpf.Event{Kind: ebpf.EventNamespaceChange, Operation: 1, FileFlags: 0x10020000}, map[string]any{
			"operation": "unshare", "namespace_types": []string{"mount", "user"},
		}},
		{"setns any", ebpf.Event{Kind: ebpf.EventNamespaceChange, Operation: 0, FileMode: 5}, map[string]any{
			"operation": "setns", "setns_fd": uint32(5), "namespace_types": []string{"any"},
		}},
		{"setuid root", ebpf.Event{Kind: ebpf.EventPrivilegeChange, Operation: 0, FileMode: 0}, map[string]any{
			"operation": "setuid", "requested_uid": uint32(0),
		}},
		{"setresgid unchanged", ebpf.Event{Kind: ebpf.EventPrivilegeChange, Operation: 5, FileMode: ^uint32(0)}, map[string]any{
			"operation": "setresgid",
		}},
		{"capset", ebpf.Event{Kind: ebpf.EventPrivilegeChange, Operation: 6, FileFlags: 1<<21 | 1<<12}, map[string]any{
			"operation": "capset", "requested_capabilities": []string{"net_admin", "sys_admin"},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fields := map[string]any{}
			appendSecurityEventFields(fields, test.event, procRoot)
			test.want["value_source"] = "syscall-requested"
			if !reflect.DeepEqual(fields, test.want) {
				t.Fatalf("fields = %#v, want %#v", fields, test.want)
			}
		})
	}
}

func TestOperationNameReportsUnknownCodes(t *testing.T) {
	t.Parallel()
	if got := operationName(ptraceRequests, 99); got != "unknown_"+strconv.Itoa(99) {
		t.Fatalf("operationName = %q", got)
	}
}

func TestAppendExecFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		event ebpf.Event
		want  map[string]any
	}{
		{"path", ebpf.Event{Filename: "/usr/bin/curl", Args: []string{"curl", "--password", "hunter2"}}, map[string]any{
			"exec_syscall": "execve", "exec_source": "path", "command_line": []string{"curl", "--password", "[REDACTED]"},
		}},
		{"memfd execveat", ebpf.Event{Operation: 1, FileFlags: 0x1000, FileMode: 5, Args: []string{"x"}, ArgsTruncated: true}, map[string]any{
			"exec_syscall": "execveat", "exec_source": "fd", "exec_fd": int32(5), "command_line": []string{"x"}, "command_line_truncated": true,
		}},
		{"proc self fd", ebpf.Event{Filename: "/proc/self/fd/9"}, map[string]any{
			"exec_syscall": "execve", "exec_source": "fd", "exec_fd": int32(9), "command_line": []string{},
		}},
		{"dev fd", ebpf.Event{Filename: "/dev/fd/3"}, map[string]any{
			"exec_syscall": "execve", "exec_source": "fd", "exec_fd": int32(3), "command_line": []string{},
		}},
		{"proc path that is not a descriptor", ebpf.Event{Filename: "/proc/self/exe"}, map[string]any{
			"exec_syscall": "execve", "exec_source": "path", "command_line": []string{},
		}},
		{"execveat with path", ebpf.Event{Operation: 1, FileFlags: 0x1000, Filename: "./tool"}, map[string]any{
			"exec_syscall": "execveat", "exec_source": "path", "command_line": []string{},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fields := map[string]any{}
			appendExecFields(fields, test.event)
			test.want["requested_path"] = test.event.Filename
			test.want["path_source"] = "syscall-requested"
			if !reflect.DeepEqual(fields, test.want) {
				t.Fatalf("fields = %#v, want %#v", fields, test.want)
			}
		})
	}
}
