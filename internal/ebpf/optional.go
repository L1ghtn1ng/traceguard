package ebpf

import (
	"errors"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

type optionalPrograms struct {
	LSMExec     *ebpf.Program
	LSMFile     *ebpf.Program
	Bind4       *ebpf.Program
	Bind6       *ebpf.Program
	UnixConnect *ebpf.Program
	UnixSendmsg *ebpf.Program
	UnixRecvmsg *ebpf.Program
	Sockopt     *ebpf.Program
	SockOps     *ebpf.Program
	LsmPathBuf  *ebpf.Map
	Failures    map[string]error
}

func (o *optionalPrograms) Close() error {
	var errs []error
	for _, closer := range []interface{ Close() error }{
		o.LSMExec, o.LSMFile, o.Bind4, o.Bind6, o.UnixConnect, o.UnixSendmsg,
		o.UnixRecvmsg, o.Sockopt, o.SockOps, o.LsmPathBuf,
	} {
		if closer != nil {
			errs = append(errs, closer.Close())
		}
	}
	return errors.Join(errs...)
}

func loadOptionalPrograms(selectedObject string, loadOptions *ebpf.CollectionOptions, objects monitorObjects, pinnedLsmPath *ebpf.Map) optionalPrograms {
	loaded := optionalPrograms{Failures: make(map[string]error)}
	spec, err := loadSelectedMonitorSpec(selectedObject)
	if err != nil {
		loaded.Failures["collection"] = err
		return loaded
	}

	load := func(name, program string, target any, lsmPath *ebpf.Map) error {
		selected, selectErr := selectOptionalProgram(spec, program)
		if selectErr != nil {
			loaded.Failures[name] = selectErr
			return selectErr
		}
		opts := *loadOptions
		opts.MapReplacements = optionalMapReplacements(objects, lsmPath)
		if err := selected.LoadAndAssign(target, &opts); err != nil {
			loaded.Failures[name] = err
			return err
		}
		return nil
	}

	taskStorageErr := features.HaveMapType(ebpf.TaskStorage)
	lsmProgramErr := features.HaveProgramType(ebpf.LSM)
	if taskStorageErr == nil && lsmProgramErr == nil {
		var exec struct {
			Program *ebpf.Program `ebpf:"lsm_bprm_check_security"`
			PathBuf *ebpf.Map     `ebpf:"lsm_path_buf"`
		}
		if load("lsm-exec", "lsm_bprm_check_security", &exec, pinnedLsmPath) == nil {
			loaded.LSMExec = exec.Program
			loaded.LsmPathBuf = exec.PathBuf
		}

		if loaded.LsmPathBuf != nil {
			var file struct {
				Program *ebpf.Program `ebpf:"lsm_file_open"`
			}
			if load("lsm-file", "lsm_file_open", &file, loaded.LsmPathBuf) == nil {
				loaded.LSMFile = file.Program
			}
		} else {
			var file struct {
				Program *ebpf.Program `ebpf:"lsm_file_open"`
				PathBuf *ebpf.Map     `ebpf:"lsm_path_buf"`
			}
			if load("lsm-file", "lsm_file_open", &file, pinnedLsmPath) == nil {
				loaded.LSMFile = file.Program
				loaded.LsmPathBuf = file.PathBuf
			}
		}
	} else {
		probeErr := errors.Join(taskStorageErr, lsmProgramErr)
		loaded.Failures["lsm-exec"] = fmt.Errorf("skip LSM exec program after feature probe: %w", probeErr)
		loaded.Failures["lsm-file"] = fmt.Errorf("skip LSM file program after feature probe: %w", probeErr)
	}

	loadProgram := func(name, tag string, destination **ebpf.Program) {
		target := &singleOptionalProgram{}
		if err := loadTaggedOptionalProgram(spec, loadOptions, objects, loaded.LsmPathBuf, tag, target); err != nil {
			loaded.Failures[name] = err
			return
		}
		*destination = target.Program
	}
	loadProgram("bind4", "trace_bind4", &loaded.Bind4)
	loadProgram("bind6", "trace_bind6", &loaded.Bind6)
	loadProgram("unix-connect", "trace_connect_unix", &loaded.UnixConnect)
	loadProgram("unix-sendmsg", "trace_sendmsg_unix", &loaded.UnixSendmsg)
	loadProgram("unix-recvmsg", "trace_recvmsg_unix", &loaded.UnixRecvmsg)
	loadProgram("sockopt", "trace_setsockopt", &loaded.Sockopt)
	loadProgram("sockops", "trace_sockops", &loaded.SockOps)
	return loaded
}

// singleOptionalProgram is populated by loadTaggedOptionalProgram after it
// narrows a copied collection spec to one program. This keeps verifier failure
// in one optional hook from suppressing unrelated hooks.
type singleOptionalProgram struct {
	Program *ebpf.Program
}

func loadTaggedOptionalProgram(spec *ebpf.CollectionSpec, base *ebpf.CollectionOptions, objects monitorObjects, lsmPath *ebpf.Map, tag string, target *singleOptionalProgram) error {
	only, err := selectOptionalProgram(spec, tag)
	if err != nil {
		return err
	}
	var tagged struct {
		Program *ebpf.Program `ebpf:"optional_program"`
	}
	// LoadAndAssign matches struct tags to collection names. Rename only in the
	// private copy so the generated object remains the source of truth.
	only.Programs["optional_program"] = only.Programs[tag]
	delete(only.Programs, tag)
	opts := *base
	opts.MapReplacements = optionalMapReplacements(objects, lsmPath)
	if err := only.LoadAndAssign(&tagged, &opts); err != nil {
		return err
	}
	target.Program = tagged.Program
	return nil
}

func selectOptionalProgram(spec *ebpf.CollectionSpec, name string) (*ebpf.CollectionSpec, error) {
	program, ok := spec.Programs[name]
	if !ok {
		return nil, fmt.Errorf("optional program %q is absent from the selected object", name)
	}
	selected := spec.Copy()
	selected.Programs = map[string]*ebpf.ProgramSpec{name: program.Copy()}
	return selected, nil
}

func loadSelectedMonitorSpec(selectedObject string) (*ebpf.CollectionSpec, error) {
	loaders := map[string]func() (*ebpf.CollectionSpec, error){
		"traceguard":                        loadTraceguard,
		"traceguardDNSCompat":               loadTraceguardDNSCompat,
		"traceguardRecvmsgCompat":           loadTraceguardRecvmsgCompat,
		"traceguardDNSRecvmsgCompat":        loadTraceguardDNSRecvmsgCompat,
		"traceguardLinux71":                 loadTraceguardLinux71,
		"traceguardLinux71DNSCompat":        loadTraceguardLinux71DNSCompat,
		"traceguardLinux71RecvmsgCompat":    loadTraceguardLinux71RecvmsgCompat,
		"traceguardLinux71DNSRecvmsgCompat": loadTraceguardLinux71DNSRecvmsgCompat,
	}
	loader, ok := loaders[selectedObject]
	if !ok {
		return nil, fmt.Errorf("unknown selected eBPF object %q", selectedObject)
	}
	return loader()
}

func optionalMapReplacements(o monitorObjects, lsmPath *ebpf.Map) map[string]*ebpf.Map {
	replacements := map[string]*ebpf.Map{
		"settings": o.Settings, "policy_selector": o.PolicySelector,
		"policy_readers": o.PolicyReaders, "daemon_identity": o.DaemonIdentity,
		"rule_names": o.RuleNames, "events": o.Events, "ringbuf_drops": o.RingbufDrops,
		"socket_info": o.SocketInfo, "listener_info": o.ListenerInfo, "connection_dedupe": o.ConnectionDedupe,
		"exec_allow_paths": o.ExecAllowPaths, "exec_block_paths": o.ExecBlockPaths,
		"file_allow_paths": o.FileAllowPaths, "file_block_paths": o.FileBlockPaths,
		"unix_allow_paths": o.UnixAllowPaths, "unix_block_paths": o.UnixBlockPaths,
		"bind4_allow_rules": o.Bind4AllowRules, "bind4_block_rules": o.Bind4BlockRules,
		"bind6_allow_rules": o.Bind6AllowRules, "bind6_block_rules": o.Bind6BlockRules,
		"sockopt_allow": o.SockoptAllow, "sockopt_block": o.SockoptBlock,
	}
	if lsmPath != nil {
		replacements["lsm_path_buf"] = lsmPath
	}
	for name, replacement := range replacements {
		if replacement == nil {
			delete(replacements, name)
		}
	}
	return replacements
}

func closeClosers(closers []io.Closer) error {
	var errs []error
	for _, closer := range closers {
		if closer != nil {
			errs = append(errs, closer.Close())
		}
	}
	return errors.Join(errs...)
}
