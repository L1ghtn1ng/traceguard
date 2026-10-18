package ebpf

import (
	"errors"

	"github.com/cilium/ebpf"
)

// fileChangePrograms observe path-based unlink, rename, chmod, chown, and
// truncate requests. They attach with file auditing and never deny anything.
type fileChangePrograms struct {
	TraceUnlink    *ebpf.Program `ebpf:"trace_unlink"`
	TraceUnlinkat  *ebpf.Program `ebpf:"trace_unlinkat"`
	TraceRmdir     *ebpf.Program `ebpf:"trace_rmdir"`
	TraceRename    *ebpf.Program `ebpf:"trace_rename"`
	TraceRenameat  *ebpf.Program `ebpf:"trace_renameat"`
	TraceRenameat2 *ebpf.Program `ebpf:"trace_renameat2"`
	TraceChmod     *ebpf.Program `ebpf:"trace_chmod"`
	TraceFchmodat  *ebpf.Program `ebpf:"trace_fchmodat"`
	TraceFchmodat2 *ebpf.Program `ebpf:"trace_fchmodat2"`
	TraceChown     *ebpf.Program `ebpf:"trace_chown"`
	TraceLchown    *ebpf.Program `ebpf:"trace_lchown"`
	TraceFchownat  *ebpf.Program `ebpf:"trace_fchownat"`
	TraceTruncate  *ebpf.Program `ebpf:"trace_truncate"`
}

func (p *fileChangePrograms) fileChangeTracepoints() []securityTracepoint {
	return []securityTracepoint{
		{"trace_unlink", "sys_enter_unlink", p.TraceUnlink},
		{"trace_unlinkat", "sys_enter_unlinkat", p.TraceUnlinkat},
		{"trace_rmdir", "sys_enter_rmdir", p.TraceRmdir},
		{"trace_rename", "sys_enter_rename", p.TraceRename},
		{"trace_renameat", "sys_enter_renameat", p.TraceRenameat},
		{"trace_renameat2", "sys_enter_renameat2", p.TraceRenameat2},
		{"trace_chmod", "sys_enter_chmod", p.TraceChmod},
		{"trace_fchmodat", "sys_enter_fchmodat", p.TraceFchmodat},
		{"trace_fchmodat2", "sys_enter_fchmodat2", p.TraceFchmodat2},
		{"trace_chown", "sys_enter_chown", p.TraceChown},
		{"trace_lchown", "sys_enter_lchown", p.TraceLchown},
		{"trace_fchownat", "sys_enter_fchownat", p.TraceFchownat},
		{"trace_truncate", "sys_enter_truncate", p.TraceTruncate},
	}
}

func (p *fileChangePrograms) Close() error {
	var errs []error
	for _, tracepoint := range p.fileChangeTracepoints() {
		if tracepoint.handle != nil {
			errs = append(errs, tracepoint.handle.Close())
		}
	}
	return errors.Join(errs...)
}

// observeTracepoints returns every optional observe-only tracepoint program.
func (o *monitorObjects) observeTracepoints() []securityTracepoint {
	return append(o.tracepoints(), o.fileChangeTracepoints()...)
}
