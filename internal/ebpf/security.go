package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"
)

// securityPrograms observe syscalls commonly used for kernel tampering,
// fileless execution, process injection, container escape, and privilege
// changes. They never deny anything.
type securityPrograms struct {
	TraceMemfdCreate     *ebpf.Program `ebpf:"trace_memfd_create"`
	TracePtrace          *ebpf.Program `ebpf:"trace_ptrace"`
	TraceProcessVMReadv  *ebpf.Program `ebpf:"trace_process_vm_readv"`
	TraceProcessVMWritev *ebpf.Program `ebpf:"trace_process_vm_writev"`
	TraceInitModule      *ebpf.Program `ebpf:"trace_init_module"`
	TraceFinitModule     *ebpf.Program `ebpf:"trace_finit_module"`
	TraceBPF             *ebpf.Program `ebpf:"trace_bpf"`
	TraceIOURingSetup    *ebpf.Program `ebpf:"trace_io_uring_setup"`
	TraceMount           *ebpf.Program `ebpf:"trace_mount"`
	TraceSetns           *ebpf.Program `ebpf:"trace_setns"`
	TraceUnshare         *ebpf.Program `ebpf:"trace_unshare"`
	TraceSetuid          *ebpf.Program `ebpf:"trace_setuid"`
	TraceSetgid          *ebpf.Program `ebpf:"trace_setgid"`
	TraceSetreuid        *ebpf.Program `ebpf:"trace_setreuid"`
	TraceSetregid        *ebpf.Program `ebpf:"trace_setregid"`
	TraceSetresuid       *ebpf.Program `ebpf:"trace_setresuid"`
	TraceSetresgid       *ebpf.Program `ebpf:"trace_setresgid"`
	TraceCapset          *ebpf.Program `ebpf:"trace_capset"`
}

type securityTracepoint struct {
	// program is the collection program name, also used for pins and stats.
	program string
	// tracepoint is the syscalls tracepoint the program attaches to.
	tracepoint string
	handle     *ebpf.Program
}

func (p *securityPrograms) tracepoints() []securityTracepoint {
	return []securityTracepoint{
		{"trace_memfd_create", "sys_enter_memfd_create", p.TraceMemfdCreate},
		{"trace_ptrace", "sys_enter_ptrace", p.TracePtrace},
		{"trace_process_vm_readv", "sys_enter_process_vm_readv", p.TraceProcessVMReadv},
		{"trace_process_vm_writev", "sys_enter_process_vm_writev", p.TraceProcessVMWritev},
		{"trace_init_module", "sys_enter_init_module", p.TraceInitModule},
		{"trace_finit_module", "sys_enter_finit_module", p.TraceFinitModule},
		{"trace_bpf", "sys_enter_bpf", p.TraceBPF},
		{"trace_io_uring_setup", "sys_enter_io_uring_setup", p.TraceIOURingSetup},
		{"trace_mount", "sys_enter_mount", p.TraceMount},
		{"trace_setns", "sys_enter_setns", p.TraceSetns},
		{"trace_unshare", "sys_enter_unshare", p.TraceUnshare},
		{"trace_setuid", "sys_enter_setuid", p.TraceSetuid},
		{"trace_setgid", "sys_enter_setgid", p.TraceSetgid},
		{"trace_setreuid", "sys_enter_setreuid", p.TraceSetreuid},
		{"trace_setregid", "sys_enter_setregid", p.TraceSetregid},
		{"trace_setresuid", "sys_enter_setresuid", p.TraceSetresuid},
		{"trace_setresgid", "sys_enter_setresgid", p.TraceSetresgid},
		{"trace_capset", "sys_enter_capset", p.TraceCapset},
	}
}

func (p *securityPrograms) Close() error {
	var errs []error
	for _, tracepoint := range p.tracepoints() {
		if tracepoint.handle != nil {
			errs = append(errs, tracepoint.handle.Close())
		}
	}
	return errors.Join(errs...)
}
