package ebpf

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type attachmentFunctions struct {
	attachCgroup     func(link.CgroupOptions) (io.Closer, error)
	attachTracepoint func(string, string, *ebpf.Program) (io.Closer, error)
	attachLSM        func(link.LSMOptions) (io.Closer, error)
}

func defaultAttachmentFunctions() attachmentFunctions {
	return attachmentFunctions{
		attachCgroup: func(opts link.CgroupOptions) (io.Closer, error) {
			return link.AttachCgroup(opts)
		},
		attachTracepoint: func(category, name string, program *ebpf.Program) (io.Closer, error) {
			return link.Tracepoint(category, name, program, nil)
		},
		attachLSM: func(opts link.LSMOptions) (io.Closer, error) {
			return link.AttachLSM(opts)
		},
	}
}

func attachOptionalPrograms(cgroupPath string, opts Options, programs optionalPrograms, functions attachmentFunctions) ([]io.Closer, AttachState) {
	links := make([]io.Closer, 0, 9)
	state := AttachState{}
	recordFailure := func(name string, err error) {
		if programs.Failures == nil {
			return
		}
		programs.Failures[name] = err
	}
	attachCgroup := func(name string, program *ebpf.Program, attach ebpf.AttachType, attached *bool) {
		if program == nil {
			if err := removePinnedLink(opts, name); err != nil {
				recordFailure(name, err)
			}
			return
		}
		lnk, err := attachOrUpdatePinnedLink(opts, name, program, validatePinnedCgroupLink(cgroupPath, attach), func() (ioCloser, error) {
			return functions.attachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: attach, Program: program})
		})
		if err != nil {
			if lnk != nil {
				_ = lnk.Close()
			}
			recordFailure(name, fmt.Errorf("attach optional %s program: %w", name, err))
			return
		}
		links = append(links, lnk)
		*attached = true
	}
	attachLSM := func(name string, program *ebpf.Program, attached *bool) {
		if program == nil || functions.attachLSM == nil {
			if err := removePinnedLink(opts, name); err != nil {
				recordFailure(name, err)
			}
			return
		}
		// Host-wide LSM deny links must remain bound to this daemon's lifecycle.
		// Persisting them could block the next daemon before it can publish its
		// non-reusable identity or activate emergency-allow mode.
		if err := removePinnedLink(opts, name); err != nil {
			recordFailure(name, fmt.Errorf("remove stale pinned %s link: %w", name, err))
			return
		}
		lnk, err := functions.attachLSM(link.LSMOptions{Program: program})
		if err != nil {
			if lnk != nil {
				_ = lnk.Close()
			}
			recordFailure(name, fmt.Errorf("attach optional %s program: %w", name, err))
			return
		}
		links = append(links, lnk)
		*attached = true
	}

	attachLSM("lsm-exec", programs.LSMExec, &state.LSMExecAttached)
	attachLSM("lsm-file", programs.LSMFile, &state.LSMFileAttached)
	attachCgroup("bind4", programs.Bind4, ebpf.AttachCGroupInet4Bind, &state.Bind4Attached)
	attachCgroup("bind6", programs.Bind6, ebpf.AttachCGroupInet6Bind, &state.Bind6Attached)
	attachCgroup("unix-connect", programs.UnixConnect, ebpf.AttachCgroupUnixConnect, &state.UnixConnectAttached)
	attachCgroup("unix-sendmsg", programs.UnixSendmsg, ebpf.AttachCgroupUnixSendmsg, &state.UnixSendmsgAttached)
	attachCgroup("unix-recvmsg", programs.UnixRecvmsg, ebpf.AttachCgroupUnixRecvmsg, &state.UnixRecvmsgAttached)
	attachCgroup("sockopt", programs.Sockopt, ebpf.AttachCGroupSetsockopt, &state.SockoptAttached)
	attachCgroup("sockops", programs.SockOps, ebpf.AttachCGroupSockOps, &state.SockOpsAttached)
	return links, state
}

func attachMonitorPrograms(cgroupPath string, opts Options, objects monitorObjects, functions attachmentFunctions) ([]io.Closer, error) {
	links := make([]io.Closer, 0, 16)
	rollback := func(cause error) error {
		errs := []error{cause}
		for _, link := range slices.Backward(links) {
			if link != nil {
				errs = append(errs, link.Close())
			}
		}
		return errors.Join(errs...)
	}
	attachCgroup := func(program *ebpf.Program, attach ebpf.AttachType, name string) error {
		lnk, err := attachOrUpdatePinnedLink(opts, name, program, validatePinnedCgroupLink(cgroupPath, attach), func() (ioCloser, error) {
			return functions.attachCgroup(link.CgroupOptions{Path: cgroupPath, Attach: attach, Program: program})
		})
		if err != nil {
			if isPermissionDenied(err) {
				return fmt.Errorf("%w: attach %s program: %w", ErrInsufficientPrivileges, name, err)
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
		lnk, err := attachOrUpdatePinnedLink(opts, name, program, nil, func() (ioCloser, error) {
			return functions.attachTracepoint("syscalls", name, program)
		})
		if err != nil {
			if isPermissionDenied(err) {
				return false, fmt.Errorf("%w: attach %s tracepoint requires tracepoint perf-event access; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid: %w", ErrInsufficientPrivileges, name, err)
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

	for _, tracepoint := range objects.tracepoints() {
		if !opts.SecurityEvents {
			if err := removePinnedLink(opts, tracepoint.tracepoint); err != nil {
				return nil, rollback(err)
			}
			continue
		}
		// Each syscall is optional: some architectures lack one, and the
		// others still attach.
		if _, err := attachTracepoint(tracepoint.tracepoint, tracepoint.handle, true); err != nil {
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
	} else {
		for _, name := range []string{"sys_enter_open", "sys_enter_openat", "sys_enter_openat2", "sys_enter_creat"} {
			if err := removePinnedLink(opts, name); err != nil {
				return nil, rollback(err)
			}
		}
	}
	// File change tracepoints feed file integrity checks, so they attach even
	// with open auditing off.
	for _, tracepoint := range objects.fileChangeTracepoints() {
		if _, err := attachTracepoint(tracepoint.tracepoint, tracepoint.handle, true); err != nil {
			return nil, rollback(err)
		}
	}

	return links, nil
}
