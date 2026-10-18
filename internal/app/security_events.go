package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
)

// Operation codes mirror the PROCESS_VM_*, MODULE_LOAD_*, NAMESPACE_*, and
// PRIVILEGE_* definitions in traceguard.c.
var (
	ptraceRequests = map[uint32]string{
		0: "traceme", 4: "poketext", 5: "pokedata", 6: "pokeuser", 16: "attach", 0x4206: "seize",
	}
	processVMOperations = map[uint32]string{0: "read", 1: "write"}
	moduleOperations    = map[uint32]string{0: "init_module", 1: "finit_module"}
	namespaceOperations = map[uint32]string{0: "setns", 1: "unshare"}
	privilegeOperations = map[uint32]string{
		0: "setuid", 1: "setgid", 2: "setreuid", 3: "setregid", 4: "setresuid", 5: "setresgid", 6: "capset",
	}
)

// namedBits lists the names of the set bits in value, in bit order.
func namedBits(value uint32, names []string) []string {
	out := make([]string, 0, 4)
	for bit, name := range names {
		if name != "" && value&(1<<bit) != 0 {
			out = append(out, name)
		}
	}
	return out
}

var memfdFlagNames = []string{"cloexec", "allow_sealing", "hugetlb", "noexec_seal", "exec"}

// namespaceFlags maps CLONE_NEW* bits to namespace names.
var namespaceFlags = []struct {
	bit  uint32
	name string
}{
	{0x00000080, "time"}, {0x00020000, "mount"}, {0x02000000, "cgroup"}, {0x04000000, "uts"},
	{0x08000000, "ipc"}, {0x10000000, "user"}, {0x20000000, "pid"}, {0x40000000, "net"},
}

// bpfProgramTypes names enum bpf_prog_type values.
var bpfProgramTypes = []string{
	"unspec", "socket_filter", "kprobe", "sched_cls", "sched_act", "tracepoint", "xdp", "perf_event",
	"cgroup_skb", "cgroup_sock", "lwt_in", "lwt_out", "lwt_xmit", "sock_ops", "sk_skb", "cgroup_device",
	"sk_msg", "raw_tracepoint", "cgroup_sock_addr", "lwt_seg6local", "lirc_mode2", "sk_reuseport", "flow_dissector", "cgroup_sysctl",
	"raw_tracepoint_writable", "cgroup_sockopt", "tracing", "struct_ops", "ext", "lsm", "sk_lookup", "syscall",
	"netfilter",
}

const unchangedID = ^uint32(0)

func operationName(names map[uint32]string, operation uint32) string {
	if name, ok := names[operation]; ok {
		return name
	}
	return "unknown_" + strconv.FormatUint(uint64(operation), 10)
}

// appendSecurityEventFields adds the requested syscall arguments of a
// security event. procRoot locates /proc for best-effort descriptor
// resolution.
func appendSecurityEventFields(fields map[string]any, event ebpf.Event, procRoot string) {
	fields["value_source"] = "syscall-requested"
	switch event.Kind {
	case ebpf.EventMemfdCreate:
		fields["memfd_name"] = event.Filename
		fields["memfd_flags"] = namedBits(event.FileFlags, memfdFlagNames)
	case ebpf.EventPtrace:
		fields["operation"] = operationName(ptraceRequests, event.Operation)
		fields["target_pid"] = event.FileMode
	case ebpf.EventProcessVM:
		fields["operation"] = operationName(processVMOperations, event.Operation)
		fields["target_pid"] = event.FileMode
	case ebpf.EventModuleLoad:
		fields["operation"] = operationName(moduleOperations, event.Operation)
		if names := moduleParameterNames(event.Filename); len(names) > 0 {
			fields["module_param_names"] = names
		}
		if event.Operation == 1 {
			fields["module_fd"] = event.FileMode
			fields["module_flags"] = event.FileFlags
			if path, ok := resolveDescriptor(procRoot, event.PID, event.FileMode); ok {
				fields["module_path"] = path
			}
		}
	case ebpf.EventBPFProgLoad:
		if int(event.FileMode) < len(bpfProgramTypes) {
			fields["bpf_prog_type"] = bpfProgramTypes[event.FileMode]
		} else {
			fields["bpf_prog_type"] = "unknown_" + strconv.FormatUint(uint64(event.FileMode), 10)
		}
	case ebpf.EventIOURingSetup:
		fields["io_uring_entries"] = event.FileMode
		fields["io_uring_flags"] = event.FileFlags
	case ebpf.EventMount:
		fields["mount_source"] = event.MountSource
		fields["mount_target"] = event.Filename
		fields["mount_fstype"] = event.MountFSType
		fields["mount_flags"] = event.FileFlags
	case ebpf.EventNamespaceChange:
		fields["operation"] = operationName(namespaceOperations, event.Operation)
		types := make([]string, 0, len(namespaceFlags))
		for _, flag := range namespaceFlags {
			if event.FileFlags&flag.bit != 0 {
				types = append(types, flag.name)
			}
		}
		if event.Operation == 0 {
			fields["setns_fd"] = event.FileMode
			if event.FileFlags == 0 {
				types = append(types, "any")
			}
		}
		fields["namespace_types"] = types
	case ebpf.EventPrivilegeChange:
		operation := operationName(privilegeOperations, event.Operation)
		fields["operation"] = operation
		switch operation {
		case "setuid", "setreuid", "setresuid":
			if event.FileMode != unchangedID {
				fields["requested_uid"] = event.FileMode
			}
		case "setgid", "setregid", "setresgid":
			if event.FileMode != unchangedID {
				fields["requested_gid"] = event.FileMode
			}
		case "capset":
			fields["requested_capabilities"] = namedBits(event.FileFlags, policyconfig.CapabilityNames)
		}
	}
}

// resolveDescriptor reads the target of a process's file descriptor. It is
// best effort: the descriptor may already be closed, and reading another
// process's descriptors needs ptrace access.
func resolveDescriptor(procRoot string, pid, fd uint32) (string, bool) {
	if pid == 0 {
		return "", false
	}
	target, err := os.Readlink(fmt.Sprintf("%s/%d/fd/%d", procRoot, pid, fd))
	if err != nil || target == "" {
		return "", false
	}
	return target, true
}

const (
	execSyscallExecveat = 1
	atEmptyPath         = 0x1000
)

// appendExecFields adds the exec syscall, the redacted command line, and how
// the executable was named.
func appendExecFields(fields map[string]any, event ebpf.Event) {
	fields["requested_path"] = event.Filename
	fields["path_source"] = "syscall-requested"
	fields["exec_syscall"] = "execve"
	if event.Operation == execSyscallExecveat {
		fields["exec_syscall"] = "execveat"
	}
	fields["command_line"] = config.RedactCommandLine(event.Args)
	if event.ArgsTruncated {
		fields["command_line_truncated"] = true
	}
	if fd, ok := execDescriptor("/proc", event); ok {
		fields["exec_source"] = "fd"
		fields["exec_fd"] = fd
	} else {
		fields["exec_source"] = "path"
	}
}

// execDescriptor reports the file descriptor an exec ran when it named the
// executable by descriptor rather than by path: execveat with AT_EMPTY_PATH,
// or a path into /dev/fd or a /proc fd directory, as fexecve uses. Such
// executables, a memfd for example, may have no file on disk to inspect. The
// path is cleaned first, and a relative one is resolved through procRoot, so
// spellings like //proc/self/fd/3 or "3" run from /proc/self/fd are found.
func execDescriptor(procRoot string, event ebpf.Event) (int32, bool) {
	if event.Operation == execSyscallExecveat && event.FileFlags&atEmptyPath != 0 && event.Filename == "" {
		return int32(event.FileMode), true //nolint:gosec // dirfd is a signed descriptor carried in the unsigned field
	}
	path := event.Filename
	if path == "" {
		return 0, false
	}
	if !filepath.IsAbs(path) {
		resolved, ok := resolveRequestedPath(procRoot, event.PID, event.FileMode, path)
		if !ok {
			return 0, false
		}
		path = resolved
	}
	path = filepath.Clean(path)
	if rest, ok := strings.CutPrefix(path, "/dev/fd/"); ok {
		return parseDescriptor(rest)
	}
	rest, ok := strings.CutPrefix(path, "/proc/")
	if !ok {
		return 0, false
	}
	// <process>/fd/<n> or <process>/task/<tid>/fd/<n>
	parts := strings.Split(rest, "/")
	process := func(name string) bool {
		return name == "self" || name == "thread-self" || isDecimal(name)
	}
	switch {
	case len(parts) == 3 && parts[1] == "fd" && process(parts[0]):
		return parseDescriptor(parts[2])
	case len(parts) == 5 && parts[1] == "task" && isDecimal(parts[2]) && parts[3] == "fd" && process(parts[0]):
		return parseDescriptor(parts[4])
	}
	return 0, false
}

func isDecimal(text string) bool {
	return text != "" && strings.Trim(text, "0123456789") == ""
}

func parseDescriptor(text string) (int32, bool) {
	fd, err := strconv.ParseInt(text, 10, 32)
	if err != nil || fd < 0 {
		return 0, false
	}
	return int32(fd), true
}

// moduleParameterNames returns the names in a module parameter string such
// as "debug=1 key=secret flag". Values are dropped because parameters can
// carry credentials.
func moduleParameterNames(params string) []string {
	var names []string
	for field := range strings.FieldsSeq(params) {
		name, _, _ := strings.Cut(field, "=")
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}
