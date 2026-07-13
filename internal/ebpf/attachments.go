package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type attachmentFunctions struct {
	attachCgroup     func(link.CgroupOptions) (io.Closer, error)
	attachTracepoint func(string, string, *ebpf.Program) (io.Closer, error)
}

func defaultAttachmentFunctions() attachmentFunctions {
	return attachmentFunctions{
		attachCgroup: func(opts link.CgroupOptions) (io.Closer, error) {
			return link.AttachCgroup(opts)
		},
		attachTracepoint: func(category, name string, program *ebpf.Program) (io.Closer, error) {
			return link.Tracepoint(category, name, program, nil)
		},
	}
}

func attachMonitorPrograms(cgroupPath string, opts Options, objects monitorObjects, functions attachmentFunctions) ([]io.Closer, error) {
	links := make([]io.Closer, 0, 16)
	rollback := func(cause error) error {
		errs := []error{cause}
		for index := len(links) - 1; index >= 0; index-- {
			if links[index] != nil {
				errs = append(errs, links[index].Close())
			}
		}
		return errors.Join(errs...)
	}
	attachCgroup := func(program *ebpf.Program, attach ebpf.AttachType, name string) error {
		lnk, err := functions.attachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: attach, Program: program})
		if err != nil {
			if isPermissionDenied(err) {
				return fmt.Errorf("%w: attach %s program: %v", ErrInsufficientPrivileges, name, err)
			}
			return fmt.Errorf("attach %s program: %w", name, err)
		}
		links = append(links, lnk)
		return nil
	}

	for _, spec := range []struct {
		program *ebpf.Program
		attach  ebpf.AttachType
		name    string
	}{
		{objects.TraceDns, ebpf.AttachCGroupInetEgress, "DNS cgroup egress"},
		{objects.TraceConnectionIngress, ebpf.AttachCGroupInetIngress, "connection ingress"},
		{objects.TraceSendmsg4, ebpf.AttachCGroupUDP4Sendmsg, "sendmsg4"},
		{objects.TraceSendmsg6, ebpf.AttachCGroupUDP6Sendmsg, "sendmsg6"},
		{objects.TraceRecvmsg4, ebpf.AttachCGroupUDP4Recvmsg, "recvmsg4"},
		{objects.TraceRecvmsg6, ebpf.AttachCGroupUDP6Recvmsg, "recvmsg6"},
		{objects.TraceConnect4, ebpf.AttachCGroupInet4Connect, "connect4"},
		{objects.TraceConnect6, ebpf.AttachCGroupInet6Connect, "connect6"},
		{objects.TracePostBind4, ebpf.AttachCGroupInet4PostBind, "post_bind4"},
		{objects.TracePostBind6, ebpf.AttachCGroupInet6PostBind, "post_bind6"},
	} {
		if err := attachCgroup(spec.program, spec.attach, spec.name); err != nil {
			return nil, rollback(err)
		}
	}

	attachTracepoint := func(name string, program *ebpf.Program, optional bool) (bool, error) {
		lnk, err := functions.attachTracepoint("syscalls", name, program)
		if err != nil {
			if isPermissionDenied(err) {
				return false, fmt.Errorf("%w: attach %s tracepoint requires tracepoint perf-event access; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid: %v", ErrInsufficientPrivileges, name, err)
			}
			if optional && (errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENOENT)) {
				return false, nil
			}
			if optional {
				return false, fmt.Errorf("attach optional %s tracepoint: %w", name, err)
			}
			return false, fmt.Errorf("attach %s tracepoint: %w", name, err)
		}
		links = append(links, lnk)
		return true, nil
	}
	for _, spec := range []struct {
		name    string
		program *ebpf.Program
	}{
		{"sys_enter_execve", objects.TraceExecve},
		{"sys_enter_execveat", objects.TraceExecveat},
	} {
		if _, err := attachTracepoint(spec.name, spec.program, false); err != nil {
			return nil, rollback(err)
		}
	}

	if opts.FileAudit {
		attached := 0
		for _, spec := range []struct {
			name    string
			program *ebpf.Program
		}{
			{"sys_enter_open", objects.TraceOpen},
			{"sys_enter_openat", objects.TraceOpenat},
			{"sys_enter_openat2", objects.TraceOpenat2},
			{"sys_enter_creat", objects.TraceCreat},
		} {
			ok, err := attachTracepoint(spec.name, spec.program, true)
			if err != nil {
				return nil, rollback(err)
			}
			if ok {
				attached++
			}
		}
		if attached == 0 {
			return nil, rollback(errors.New("file audit enabled but no open-style syscall tracepoints could be attached"))
		}
	}

	return links, nil
}
