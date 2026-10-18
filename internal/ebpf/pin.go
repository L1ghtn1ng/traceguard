package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	DefaultPinPath   = "/sys/fs/bpf/traceguard"
	pinLayoutVersion = 7
	pinSettingsSize  = 32
	pinEventSize     = 632
	pinMetadataSize  = 96
)

var pinMetadataMagic = [16]byte{'T', 'R', 'A', 'C', 'E', 'G', 'U', 'A', 'R', 'D', '-', 'E', 'B', 'P', 'F', 0}

type pinMetadata struct {
	Magic        [16]byte
	Layout       uint32
	SettingsSize uint32
	EventSize    uint32
	_            uint32
	Object       [64]byte
}

func (o Options) pinPath() string {
	if strings.TrimSpace(o.PinPath) != "" {
		return filepath.Clean(o.PinPath)
	}
	return DefaultPinPath
}

func Unpin(path string) error {
	cleaned := filepath.Clean(path)
	if cleaned != DefaultPinPath {
		return fmt.Errorf("refuse unsafe eBPF pin path %q", path)
	}
	return unpinPinPath(cleaned)
}

func rejectPinnedStateInUnpinnedMode(opts Options) error {
	if opts.PinEBPF {
		return nil
	}
	root := opts.pinPath()
	if _, err := os.Lstat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("check for existing eBPF pins at %s: %w", root, err)
	}
	return fmt.Errorf("existing TraceGuard eBPF pins at %s may still be active; stop the previous daemon and run traceguard -unpin before starting without -pin-ebpf", root)
}

func unpinPinPath(path string) error {
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) || cleaned == string(filepath.Separator) || cleaned == "/sys/fs/bpf" || filepath.Base(cleaned) != "traceguard" {
		return fmt.Errorf("refuse unsafe eBPF pin path %q", path)
	}
	if err := os.RemoveAll(cleaned); err != nil {
		return fmt.Errorf("remove eBPF pins %s: %w", cleaned, err)
	}
	return nil
}

func preparePinnedMaps(opts Options) (map[string]*ebpf.Map, *pinMetadata, error) {
	if !opts.PinEBPF {
		return nil, nil, nil
	}
	root := opts.pinPath()
	metadataMap, err := ebpf.LoadPinnedMap(filepath.Join(root, "layout"), nil)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist) {
			if removeErr := unpinPinPath(root); removeErr != nil {
				return nil, nil, removeErr
			}
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("load eBPF pin metadata: %w", err)
	}
	defer func() { _ = metadataMap.Close() }()
	var metadata pinMetadata
	if err := metadataMap.Lookup(uint32(0), &metadata); err != nil {
		return nil, nil, discardInvalidPins(root, fmt.Errorf("read eBPF pin metadata: %w", err))
	}
	if metadata.Magic != pinMetadataMagic || metadata.Layout != pinLayoutVersion ||
		metadata.SettingsSize != pinSettingsSize || metadata.EventSize != pinEventSize {
		return nil, nil, discardInvalidPins(root, errors.New("eBPF pin layout does not match this binary"))
	}
	entries, err := os.ReadDir(filepath.Join(root, "maps"))
	if err != nil {
		return nil, nil, discardInvalidPins(root, fmt.Errorf("read pinned maps: %w", err))
	}
	maps := make(map[string]*ebpf.Map, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		pinned, loadErr := ebpf.LoadPinnedMap(filepath.Join(root, "maps", entry.Name()), nil)
		if loadErr != nil {
			_ = closePinnedMapHandles(maps)
			return nil, nil, discardInvalidPins(root, fmt.Errorf("load pinned map %s: %w", entry.Name(), loadErr))
		}
		maps[entry.Name()] = pinned
	}
	return maps, &metadata, nil
}

func discardInvalidPins(root string, cause error) error {
	if err := unpinPinPath(root); err != nil {
		return errors.Join(cause, err)
	}
	return nil
}

func closePinnedMapHandles(maps map[string]*ebpf.Map) error {
	var errs []error
	for _, pinned := range maps {
		if pinned != nil {
			errs = append(errs, pinned.Close())
		}
	}
	return errors.Join(errs...)
}

func pinLoadedObjects(opts Options, objects monitorObjects, optional optionalPrograms) error {
	if !opts.PinEBPF {
		return nil
	}
	root := opts.pinPath()
	for _, directory := range []string{root, filepath.Join(root, "maps"), filepath.Join(root, "progs"), filepath.Join(root, "links")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fmt.Errorf("create eBPF pin directory %s: %w", directory, err)
		}
		if err := os.Chmod(directory, 0o700); err != nil { //nolint:gosec // bpffs directories require execute permission.
			return fmt.Errorf("secure eBPF pin directory %s: %w", directory, err)
		}
	}
	for name, target := range monitorMapHandles(objects, optional) {
		path := filepath.Join(root, "maps", name)
		if target == nil {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale pinned map %s: %w", name, err)
			}
			continue
		}
		if pinExists(path) {
			continue
		}
		if err := target.Pin(path); err != nil {
			return fmt.Errorf("pin map %s: %w", name, err)
		}
	}
	for name, target := range monitorProgramHandles(objects, optional) {
		path := filepath.Join(root, "progs", name)
		if target == nil {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale pinned program %s: %w", name, err)
			}
			continue
		}
		if pinExists(path) {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("replace pinned program %s: %w", name, err)
			}
		}
		if err := target.Pin(path); err != nil {
			return fmt.Errorf("pin program %s: %w", name, err)
		}
	}
	return nil
}

func finalizePinMetadata(opts Options, selectedObject string) error {
	if !opts.PinEBPF {
		return nil
	}
	return writePinMetadata(opts.pinPath(), selectedObject)
}

func writePinMetadata(root, selectedObject string) error {
	metadata := pinMetadata{
		Magic: pinMetadataMagic, Layout: pinLayoutVersion,
		SettingsSize: pinSettingsSize, EventSize: pinEventSize,
	}
	copy(metadata.Object[:], selectedObject)
	spec := &ebpf.MapSpec{Name: "traceguard_layout", Type: ebpf.Array, KeySize: 4, ValueSize: pinMetadataSize, MaxEntries: 1}
	metadataMap, err := ebpf.NewMap(spec)
	if err != nil {
		return fmt.Errorf("create eBPF pin metadata map: %w", err)
	}
	defer func() { _ = metadataMap.Close() }()
	if err := metadataMap.Put(uint32(0), metadata); err != nil {
		return fmt.Errorf("write eBPF pin metadata map: %w", err)
	}
	path := filepath.Join(root, "layout")
	if pinExists(path) {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("replace eBPF pin metadata: %w", err)
		}
	}
	if err := metadataMap.Pin(path); err != nil {
		return fmt.Errorf("pin eBPF metadata: %w", err)
	}
	return nil
}

func pinExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

type pinnedLinkValidator func(link.Link) error

func attachOrUpdatePinnedLink(opts Options, name string, program *ebpf.Program, validate pinnedLinkValidator, attach func() (ioCloser, error)) (ioCloser, error) {
	if !opts.PinEBPF {
		return attach()
	}
	path := filepath.Join(opts.pinPath(), "links", sanitizePinName(name))
	if pinExists(path) {
		pinned, err := link.LoadPinnedLink(path, nil)
		if err == nil {
			if validate == nil || validate(pinned) == nil {
				if err := pinned.Update(program); err == nil {
					return pinned, nil
				}
			}
			_ = pinned.Close()
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("replace pinned link %s: %w", name, err)
		}
	}
	attached, err := attach()
	if err != nil {
		return attached, err
	}
	pinnable, ok := attached.(link.Link)
	if !ok {
		_ = attached.Close()
		return nil, fmt.Errorf("pin link %s: attachment is not a bpf_link", name)
	}
	if err := pinnable.Pin(path); err != nil {
		_ = attached.Close()
		return nil, fmt.Errorf("pin link %s: %w", name, err)
	}
	return attached, nil
}

func validatePinnedCgroupLink(cgroupPath string, attach ebpf.AttachType) pinnedLinkValidator {
	return func(pinned link.Link) error {
		expectedID, err := cgroupinfo.ID(cgroupPath)
		if err != nil {
			return fmt.Errorf("read expected cgroup identity: %w", err)
		}
		infoLink, ok := pinned.(interface{ Info() (*link.Info, error) })
		if !ok {
			return errors.New("pinned link does not expose target information")
		}
		info, err := infoLink.Info()
		if err != nil {
			return fmt.Errorf("read pinned link target: %w", err)
		}
		cgroup := info.Cgroup()
		if cgroup == nil {
			return errors.New("pinned link is not a cgroup link")
		}
		return validateCgroupLinkTarget(cgroup.CgroupId, uint32(cgroup.AttachType), expectedID, uint32(attach))
	}
}

func validateCgroupLinkTarget(actualID uint64, actualAttach uint32, expectedID uint64, expectedAttach uint32) error {
	if actualID != expectedID || actualAttach != expectedAttach {
		return fmt.Errorf("pinned cgroup target mismatch: id=%d attach=%d, want id=%d attach=%d",
			actualID, actualAttach, expectedID, expectedAttach)
	}
	return nil
}

func removePinnedLink(opts Options, name string) error {
	if !opts.PinEBPF {
		return nil
	}
	path := filepath.Join(opts.pinPath(), "links", sanitizePinName(name))
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale pinned link %s: %w", name, err)
	}
	return nil
}

type ioCloser interface {
	Close() error
}

func sanitizePinName(name string) string {
	replacer := strings.NewReplacer(" ", "_", "/", "_", "-", "_")
	return replacer.Replace(strings.ToLower(name))
}

func monitorMapHandles(o monitorObjects, optional optionalPrograms) map[string]*ebpf.Map {
	return map[string]*ebpf.Map{
		"allowlist": o.Allowlist, "allow_suffixes": o.AllowSuffixes, "block_suffixes": o.BlockSuffixes,
		"blocklist": o.Blocklist, "dns_scratch": o.DnsScratch, "exec_argv_scratch": o.ExecArgvScratch, "socket_info": o.SocketInfo,
		"listener_info": o.ListenerInfo, "connection_dedupe": o.ConnectionDedupe,
		"endpoint4_allow_rules": o.Endpoint4AllowRules, "endpoint4_cidr_allow_rules": o.Endpoint4CidrAllowRules,
		"endpoint4_cidr_rules": o.Endpoint4CidrRules, "endpoint4_rules": o.Endpoint4Rules,
		"endpoint6_allow_rules": o.Endpoint6AllowRules, "endpoint6_cidr_allow_rules": o.Endpoint6CidrAllowRules,
		"endpoint6_cidr_rules": o.Endpoint6CidrRules, "endpoint6_rules": o.Endpoint6Rules,
		"events": o.Events, "egress4_allow_rules": o.Egress4AllowRules, "egress4_block_rules": o.Egress4BlockRules,
		"egress6_allow_rules": o.Egress6AllowRules, "egress6_block_rules": o.Egress6BlockRules,
		"exec_allow_paths": o.ExecAllowPaths, "exec_block_paths": o.ExecBlockPaths,
		"file_allow_paths": o.FileAllowPaths, "file_block_paths": o.FileBlockPaths,
		"unix_allow_paths": o.UnixAllowPaths, "unix_block_paths": o.UnixBlockPaths,
		"bind4_allow_rules": o.Bind4AllowRules, "bind4_block_rules": o.Bind4BlockRules,
		"bind6_allow_rules": o.Bind6AllowRules, "bind6_block_rules": o.Bind6BlockRules,
		"sockopt_allow": o.SockoptAllow, "sockopt_block": o.SockoptBlock,
		"policy_selector": o.PolicySelector, "policy_readers": o.PolicyReaders,
		"daemon_identity": o.DaemonIdentity, "rule_names": o.RuleNames,
		"ringbuf_drops": o.RingbufDrops, "settings": o.Settings, "lsm_path_buf": optional.LsmPathBuf,
	}
}

func monitorProgramHandles(o monitorObjects, optional optionalPrograms) map[string]*ebpf.Program {
	handles := map[string]*ebpf.Program{
		"trace_dns": o.TraceDns, "trace_connection_ingress": o.TraceConnectionIngress,
		"trace_sendmsg4": o.TraceSendmsg4, "trace_sendmsg6": o.TraceSendmsg6,
		"trace_recvmsg4": o.TraceRecvmsg4, "trace_recvmsg6": o.TraceRecvmsg6,
		"trace_connect4": o.TraceConnect4, "trace_connect6": o.TraceConnect6,
		"trace_post_bind4": o.TracePostBind4, "trace_post_bind6": o.TracePostBind6,
		"trace_execve": o.TraceExecve, "trace_execveat": o.TraceExecveat,
		"trace_open": o.TraceOpen, "trace_openat": o.TraceOpenat, "trace_openat2": o.TraceOpenat2,
		"trace_creat": o.TraceCreat, "lsm_bprm_check_security": optional.LSMExec,
		"lsm_file_open": optional.LSMFile, "trace_bind4": optional.Bind4, "trace_bind6": optional.Bind6,
		"trace_connect_unix": optional.UnixConnect, "trace_sendmsg_unix": optional.UnixSendmsg,
		"trace_recvmsg_unix": optional.UnixRecvmsg, "trace_setsockopt": optional.Sockopt,
		"trace_sockops": optional.SockOps,
	}
	for _, tracepoint := range o.observeTracepoints() {
		handles[tracepoint.program] = tracepoint.handle
	}
	return handles
}

func pinnedObjectName(metadata *pinMetadata) string {
	if metadata == nil {
		return ""
	}
	if index := bytes.IndexByte(metadata.Object[:], 0); index >= 0 {
		return string(metadata.Object[:index])
	}
	return string(metadata.Object[:])
}
