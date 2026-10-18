package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var (
	ErrInsufficientPrivileges = errors.New("insufficient privileges to attach eBPF programs; run as root or grant CAP_BPF,CAP_NET_ADMIN,CAP_PERFMON,CAP_SYS_ADMIN,CAP_SYS_RESOURCE")
	ErrUnsupportedKernel      = errors.New("unsupported kernel: TraceGuard requires Linux 6.12 or newer")
)

const (
	blocklistMaxEntries = 16384
	endpointMaxEntries  = 16384
	egressMaxEntries    = 16384
	policyMaxEntries    = 16384
)

type domainKey struct {
	Domain [domainSize]byte
}

type domainSuffixKey struct {
	Hash   uint64
	Length uint16
	Slot   uint8
	_      [5]byte
}

type runtimeSettings struct {
	BlockEnabled         uint8
	BlockAllDomains      uint8
	BlockAllResolvers    uint8
	AllowSuffixesEnabled uint8
	ActivePolicySlot     uint8
	BlockSuffixesEnabled uint8
	EgressEnabled        uint8
	EgressEnforce        uint8
	EgressDefaultBlock   uint8
	ExecEnabled          uint8
	ExecEnforce          uint8
	ExecDefaultBlock     uint8
	FileEnabled          uint8
	FileEnforce          uint8
	FileDefaultBlock     uint8
	BindEnabled          uint8
	BindEnforce          uint8
	BindDefaultBlock     uint8
	UnixEnabled          uint8
	UnixEnforce          uint8
	UnixDefaultBlock     uint8
	SockoptEnabled       uint8
	SockoptEnforce       uint8
	SockoptDefaultBlock  uint8
	PolicyGeneration     uint32
	_                    uint32
}

type daemonProcessIdentity struct {
	TGID       uint32
	_          uint32
	StartTicks uint64
}

type ruleNameKey struct {
	PolicySlot uint8
	_          [3]byte
	RuleID     uint32
}

type ruleNameValue struct {
	Name [65]byte
}

type endpoint4Key struct {
	Addr      uint32
	Port      uint16
	Transport uint8
	_         uint8
}

type endpoint6Key struct {
	Addr      [16]byte
	Port      uint16
	Transport uint8
	_         uint8
}

type endpoint4CIDRKey struct {
	PrefixLen uint32
	Data      [7]uint8
	_         [1]byte
}

type endpoint6CIDRKey struct {
	PrefixLen uint32
	Data      [19]uint8
	_         [1]byte
}

type egress4Key struct {
	PrefixLen uint32
	Data      [21]uint8
	_         [3]byte
}

type egress6Key struct {
	PrefixLen uint32
	Data      [33]uint8
	_         [3]byte
}

type ResolverEndpoint struct {
	Transport string
	IP        net.IP
	Port      uint16
}

type ResolverCIDR struct {
	Transport string
	Prefix    netip.Prefix
	Port      uint16
}

type EgressRuleConfig struct {
	ID                string
	Action            string
	UIDs              []uint32
	CgroupIDs         []uint64
	CgroupAncestorIDs []uint64
	HasUIDSelector    bool
	HasCgroupSelector bool
	CIDRs             []netip.Prefix
	Ports             []uint16
	Protocols         []string
}

type EgressPolicyConfig struct {
	Enabled      bool
	Enforce      bool
	DefaultBlock bool
	Rules        []EgressRuleConfig
}

type PathRuleConfig struct {
	ID                string
	Action            string
	UIDs              []uint32
	CgroupIDs         []uint64
	CgroupAncestorIDs []uint64
	HasUIDSelector    bool
	HasCgroupSelector bool
	PathGlobs         []string
	AccessOrOps       []uint8
}

type PathPolicyConfig struct {
	Enabled      bool
	Enforce      bool
	DefaultBlock bool
	Rules        []PathRuleConfig
}

type SockoptRuleConfig struct {
	ID                string
	Action            string
	UIDs              []uint32
	CgroupIDs         []uint64
	CgroupAncestorIDs []uint64
	HasUIDSelector    bool
	HasCgroupSelector bool
	Options           []SockoptOption
}

// SockoptOption is one kernel (level, optname) pair. Rules carry explicit
// pairs because option numbers overlap between levels.
type SockoptOption struct {
	Level   uint32
	OptName uint32
}

type SockoptPolicyConfig struct {
	Enabled      bool
	Enforce      bool
	DefaultBlock bool
	Rules        []SockoptRuleConfig
}

type PolicyConfig struct {
	BlockEnabled      bool
	BlockAllDomains   bool
	BlockAllResolvers bool
	BlockedDomains    []string
	AllowedDomains    []string
	BlockedSuffixes   []string
	AllowedSuffixes   []string
	BlockedEndpoints  []ResolverEndpoint
	AllowedEndpoints  []ResolverEndpoint
	BlockedCIDRs      []ResolverCIDR
	AllowedCIDRs      []ResolverCIDR
	Egress            EgressPolicyConfig
	Exec              PathPolicyConfig
	File              PathPolicyConfig
	Bind              EgressPolicyConfig
	Unix              PathPolicyConfig
	Sockopt           SockoptPolicyConfig
}

type Monitor struct {
	objects monitorObjects
	links   []io.Closer
	reader  *ringbuf.Reader
	// readerMu orders occupancy reads against closing the reader, whose
	// shared ring mapping is released on close.
	readerMu         sync.Mutex
	readerClosed     bool
	features         KernelFeatures
	optional         optionalPrograms
	optionalLinks    []io.Closer
	cgroupPath       string
	policyMu         sync.Mutex
	activePolicySlot uint8
	policyGeneration uint32
	attachState      AttachState
	statsCloser      io.Closer
	// daemonNamespaceErr is non-nil when LSM self-exemption cannot identify
	// the daemon, so exec and file enforcement must be refused.
	daemonNamespaceErr error
	// freshPinPath is the pin root this process created, until KeepPins.
	freshPinPath string
}

type RuntimeMetrics interface {
	IncEBPFReadError()
}

type Options struct {
	FileAudit   bool
	PinEBPF     bool
	PinPath     string
	EnableStats bool
	// ConnectionDedupeWindow suppresses repeated connection and TCP
	// retransmit events for the same flow; zero disables suppression.
	ConnectionDedupeWindow time.Duration
}

type AttachState struct {
	LSMExecAttached     bool
	LSMFileAttached     bool
	Bind4Attached       bool
	Bind6Attached       bool
	UnixConnectAttached bool
	UnixSendmsgAttached bool
	UnixRecvmsgAttached bool
	SockoptAttached     bool
	SockOpsAttached     bool
}

type monitorObjects struct {
	TraceDns               *ebpf.Program `ebpf:"trace_dns"`
	TraceConnectionIngress *ebpf.Program `ebpf:"trace_connection_ingress"`
	TraceSendmsg4          *ebpf.Program `ebpf:"trace_sendmsg4"`
	TraceSendmsg6          *ebpf.Program `ebpf:"trace_sendmsg6"`
	TraceRecvmsg4          *ebpf.Program `ebpf:"trace_recvmsg4"`
	TraceRecvmsg6          *ebpf.Program `ebpf:"trace_recvmsg6"`
	TraceConnect4          *ebpf.Program `ebpf:"trace_connect4"`
	TraceConnect6          *ebpf.Program `ebpf:"trace_connect6"`
	TracePostBind4         *ebpf.Program `ebpf:"trace_post_bind4"`
	TracePostBind6         *ebpf.Program `ebpf:"trace_post_bind6"`
	TraceExecve            *ebpf.Program `ebpf:"trace_execve"`
	TraceExecveat          *ebpf.Program `ebpf:"trace_execveat"`
	TraceOpen              *ebpf.Program `ebpf:"trace_open"`
	TraceOpenat            *ebpf.Program `ebpf:"trace_openat"`
	TraceOpenat2           *ebpf.Program `ebpf:"trace_openat2"`
	TraceCreat             *ebpf.Program `ebpf:"trace_creat"`

	Allowlist               *ebpf.Map `ebpf:"allowlist"`
	AllowSuffixes           *ebpf.Map `ebpf:"allow_suffixes"`
	BlockSuffixes           *ebpf.Map `ebpf:"block_suffixes"`
	Blocklist               *ebpf.Map `ebpf:"blocklist"`
	DnsScratch              *ebpf.Map `ebpf:"dns_scratch"`
	SocketInfo              *ebpf.Map `ebpf:"socket_info"`
	ListenerInfo            *ebpf.Map `ebpf:"listener_info"`
	ConnectionDedupe        *ebpf.Map `ebpf:"connection_dedupe"`
	Endpoint4AllowRules     *ebpf.Map `ebpf:"endpoint4_allow_rules"`
	Endpoint4CidrAllowRules *ebpf.Map `ebpf:"endpoint4_cidr_allow_rules"`
	Endpoint4CidrRules      *ebpf.Map `ebpf:"endpoint4_cidr_rules"`
	Endpoint4Rules          *ebpf.Map `ebpf:"endpoint4_rules"`
	Endpoint6AllowRules     *ebpf.Map `ebpf:"endpoint6_allow_rules"`
	Endpoint6CidrAllowRules *ebpf.Map `ebpf:"endpoint6_cidr_allow_rules"`
	Endpoint6CidrRules      *ebpf.Map `ebpf:"endpoint6_cidr_rules"`
	Endpoint6Rules          *ebpf.Map `ebpf:"endpoint6_rules"`
	Events                  *ebpf.Map `ebpf:"events"`
	Egress4AllowRules       *ebpf.Map `ebpf:"egress4_allow_rules"`
	Egress4BlockRules       *ebpf.Map `ebpf:"egress4_block_rules"`
	Egress6AllowRules       *ebpf.Map `ebpf:"egress6_allow_rules"`
	Egress6BlockRules       *ebpf.Map `ebpf:"egress6_block_rules"`
	ExecAllowPaths          *ebpf.Map `ebpf:"exec_allow_paths"`
	ExecBlockPaths          *ebpf.Map `ebpf:"exec_block_paths"`
	FileAllowPaths          *ebpf.Map `ebpf:"file_allow_paths"`
	FileBlockPaths          *ebpf.Map `ebpf:"file_block_paths"`
	UnixAllowPaths          *ebpf.Map `ebpf:"unix_allow_paths"`
	UnixBlockPaths          *ebpf.Map `ebpf:"unix_block_paths"`
	Bind4AllowRules         *ebpf.Map `ebpf:"bind4_allow_rules"`
	Bind4BlockRules         *ebpf.Map `ebpf:"bind4_block_rules"`
	Bind6AllowRules         *ebpf.Map `ebpf:"bind6_allow_rules"`
	Bind6BlockRules         *ebpf.Map `ebpf:"bind6_block_rules"`
	SockoptAllow            *ebpf.Map `ebpf:"sockopt_allow"`
	SockoptBlock            *ebpf.Map `ebpf:"sockopt_block"`
	PolicySelector          *ebpf.Map `ebpf:"policy_selector"`
	PolicyReaders           *ebpf.Map `ebpf:"policy_readers"`
	DaemonIdentity          *ebpf.Map `ebpf:"daemon_identity"`
	RuleNames               *ebpf.Map `ebpf:"rule_names"`
	RingbufDrops            *ebpf.Map `ebpf:"ringbuf_drops"`
	Settings                *ebpf.Map `ebpf:"settings"`
}

func (o *monitorObjects) Close() error {
	var errs []error
	for _, closer := range []interface{ Close() error }{
		o.TraceDns,
		o.TraceConnectionIngress,
		o.TraceSendmsg4,
		o.TraceSendmsg6,
		o.TraceRecvmsg4,
		o.TraceRecvmsg6,
		o.TraceConnect4,
		o.TraceConnect6,
		o.TracePostBind4,
		o.TracePostBind6,
		o.TraceExecve,
		o.TraceExecveat,
		o.TraceOpen,
		o.TraceOpenat,
		o.TraceOpenat2,
		o.TraceCreat,
		o.Allowlist,
		o.AllowSuffixes,
		o.BlockSuffixes,
		o.Blocklist,
		o.DnsScratch,
		o.SocketInfo,
		o.ListenerInfo,
		o.ConnectionDedupe,
		o.Endpoint4AllowRules,
		o.Endpoint4CidrAllowRules,
		o.Endpoint4CidrRules,
		o.Endpoint4Rules,
		o.Endpoint6AllowRules,
		o.Endpoint6CidrAllowRules,
		o.Endpoint6CidrRules,
		o.Endpoint6Rules,
		o.Egress4AllowRules,
		o.Egress4BlockRules,
		o.Egress6AllowRules,
		o.Egress6BlockRules,
		o.ExecAllowPaths,
		o.ExecBlockPaths,
		o.FileAllowPaths,
		o.FileBlockPaths,
		o.UnixAllowPaths,
		o.UnixBlockPaths,
		o.Bind4AllowRules,
		o.Bind4BlockRules,
		o.Bind6AllowRules,
		o.Bind6BlockRules,
		o.SockoptAllow,
		o.SockoptBlock,
		o.PolicySelector,
		o.PolicyReaders,
		o.DaemonIdentity,
		o.RuleNames,
		o.RingbufDrops,
		o.Events,
		o.Settings,
	} {
		if closer != nil {
			errs = append(errs, closer.Close())
		}
	}
	return errors.Join(errs...)
}

func NewMonitor(cgroupPath string, opts Options) (*Monitor, error) {
	if err := rejectPinnedStateInUnpinnedMode(opts); err != nil {
		return nil, err
	}
	release, err := kernelRelease()
	if err != nil {
		return nil, fmt.Errorf("detect kernel release: %w", err)
	}
	if err := validateKernelRelease(release); err != nil {
		return nil, err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock rlimit: %w", err)
	}

	var statsCloser io.Closer
	if opts.EnableStats {
		statsCloser, err = ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
		if err != nil {
			return nil, fmt.Errorf("enable eBPF runtime statistics: %w", err)
		}
	}
	closeStatsOnError := func(cause error) error {
		if statsCloser == nil {
			return cause
		}
		return errors.Join(cause, statsCloser.Close())
	}

	constants := loadConstants{connectionDedupeWindow: opts.ConnectionDedupeWindow}
	loadOptions := newCollectionOptions()
	pinnedMaps, pinLayout, err := preparePinnedMaps(opts)
	if err != nil {
		return nil, closeStatsOnError(err)
	}
	loadOptions.MapReplacements = pinnedMaps
	objects, features, err := loadMonitorObjects(loadOptions, constants)
	if err != nil {
		return nil, closeStatsOnError(errors.Join(err, closePinnedMapHandles(pinnedMaps)))
	}
	if pinLayout != nil && pinnedObjectName(pinLayout) != features.SelectedObject {
		cleanupErr := errors.Join(objects.Close(), closePinnedMapHandles(pinnedMaps), unpinPinPath(opts.pinPath()))
		if cleanupErr != nil {
			return nil, closeStatsOnError(fmt.Errorf("replace incompatible eBPF pins: %w", cleanupErr))
		}
		loadOptions = newCollectionOptions()
		pinnedMaps = nil
		pinLayout = nil
		objects, features, err = loadMonitorObjects(loadOptions, constants)
		if err != nil {
			return nil, closeStatsOnError(err)
		}
	}
	pid := os.Getpid()
	if pid < 0 {
		return nil, closeStatsOnError(errors.Join(fmt.Errorf("invalid daemon PID %d", pid), closePinnedMapHandles(pinnedMaps), objects.Close()))
	}
	daemonTGID := uint32(pid) //nolint:gosec // Linux PIDs are non-negative and bounded by pid_max
	startTime, err := readProcessStartTime("/proc/self/stat")
	if err != nil {
		return nil, closeStatsOnError(errors.Join(fmt.Errorf("read daemon process identity: %w", err), closePinnedMapHandles(pinnedMaps), objects.Close()))
	}
	daemonIdentity := daemonProcessIdentity{TGID: daemonTGID, StartTicks: startTime}
	initialSettings, err := initializePolicyState(objects, pinLayout != nil, daemonIdentity)
	if err != nil {
		return nil, closeStatsOnError(errors.Join(err, closePinnedMapHandles(pinnedMaps), objects.Close()))
	}
	optional := loadOptionalPrograms(features.SelectedObject, loadOptions, constants, objects, pinnedMaps["lsm_path_buf"])
	if err := closePinnedMapHandles(pinnedMaps); err != nil {
		return nil, closeStatsOnError(errors.Join(fmt.Errorf("close adopted eBPF map handles: %w", err), optional.Close(), objects.Close()))
	}
	// Only a pin set created by this run is removed on failure; adopted pins
	// keep the previous run's state.
	freshPinSet := opts.PinEBPF && pinLayout == nil
	failAfterPin := func(cause error) error {
		if freshPinSet {
			cause = errors.Join(cause, unpinPinPath(opts.pinPath()))
		}
		return closeStatsOnError(cause)
	}
	loadOptions.MapReplacements = nil
	if err := pinLoadedObjects(opts, objects, optional); err != nil {
		return nil, failAfterPin(errors.Join(err, optional.Close(), objects.Close()))
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		if closeErr := objects.Close(); closeErr != nil {
			return nil, failAfterPin(errors.Join(fmt.Errorf("create ring buffer reader: %w", err), closeErr, optional.Close()))
		}
		return nil, failAfterPin(errors.Join(fmt.Errorf("create ring buffer reader: %w", err), optional.Close()))
	}

	links, err := attachMonitorPrograms(cgroupPath, opts, objects, defaultAttachmentFunctions())
	if err != nil {
		return nil, failAfterPin(errors.Join(err, reader.Close(), optional.Close(), objects.Close()))
	}
	optionalLinks, attachState := attachOptionalPrograms(cgroupPath, opts, optional, defaultAttachmentFunctions())
	if err := finalizePinMetadata(opts, features.SelectedObject); err != nil {
		return nil, failAfterPin(errors.Join(err, reader.Close(), closeClosers(links), closeClosers(optionalLinks), optional.Close(), objects.Close()))
	}

	return &Monitor{
		objects: objects, optional: optional, links: links, optionalLinks: optionalLinks,
		reader: reader, features: features, cgroupPath: filepath.Clean(cgroupPath),
		activePolicySlot: initialSettings.ActivePolicySlot, policyGeneration: initialSettings.PolicyGeneration,
		attachState: attachState, statsCloser: statsCloser,
		daemonNamespaceErr: hostNamespaceError("/proc/self/ns"),
		freshPinPath:       freshPinPath(freshPinSet, opts),
	}, nil
}

func freshPinPath(fresh bool, opts Options) string {
	if !fresh {
		return ""
	}
	return opts.pinPath()
}

// KeepPins commits a pin set created by this process once startup has
// succeeded, so later shutdowns leave it in place for the next restart.
func (m *Monitor) KeepPins() {
	m.freshPinPath = ""
}

// RemoveFreshPins removes a pin set this process created but never committed
// with KeepPins. Call it after Close when startup fails, so pinned links do not
// keep policy attached without a daemon or block later unpinned starts.
func (m *Monitor) RemoveFreshPins() error {
	if m.freshPinPath == "" {
		return nil
	}
	path := m.freshPinPath
	m.freshPinPath = ""
	return unpinPinPath(path)
}

const (
	// PROC_PID_INIT_INO and PROC_TIME_INIT_INO from include/linux/proc_ns.h.
	initPIDNamespaceInode  = 0xEFFFFFFC
	initTimeNamespaceInode = 0xEFFFFFFA
)

// hostNamespaceError reports why the daemon identity published to BPF cannot
// match kernel state. BPF compares the init-namespace TGID and the unadjusted
// boot-time start, while os.Getpid and /proc/self/stat return values relative
// to the daemon's PID and time namespaces.
func hostNamespaceError(namespaceDir string) error {
	for _, namespace := range []struct {
		name     string
		inode    uint64
		optional bool
	}{
		{name: "pid", inode: initPIDNamespaceInode},
		{name: "time", inode: initTimeNamespaceInode, optional: true},
	} {
		var stat unix.Stat_t
		if err := unix.Stat(filepath.Join(namespaceDir, namespace.name), &stat); err != nil {
			if namespace.optional && errors.Is(err, unix.ENOENT) {
				continue
			}
			return fmt.Errorf("inspect %s namespace: %w", namespace.name, err)
		}
		if stat.Ino != namespace.inode {
			return fmt.Errorf("daemon runs outside the host %s namespace", namespace.name)
		}
	}
	return nil
}

func initializePolicyState(objects monitorObjects, adoptPinned bool, daemonIdentity daemonProcessIdentity) (runtimeSettings, error) {
	zero := uint32(0)
	// The daemon identity is an RCU-replaced hash value, so a restart never has
	// to rewrite the active immutable settings slot.
	if err := objects.DaemonIdentity.Put(zero, daemonIdentity); err != nil {
		return runtimeSettings{}, fmt.Errorf("initialize daemon identity: %w", err)
	}
	if adoptPinned {
		var selector uint64
		if err := objects.PolicySelector.Lookup(zero, &selector); err != nil {
			return runtimeSettings{}, fmt.Errorf("read adopted policy selector: %w", err)
		}
		slot, generation, ok := decodePolicySelector(selector)
		if ok {
			var settings runtimeSettings
			if err := objects.Settings.Lookup(uint32(slot), &settings); err != nil {
				return runtimeSettings{}, fmt.Errorf("read adopted policy settings: %w", err)
			}
			if settings.ActivePolicySlot == slot && settings.PolicyGeneration == generation {
				return settings, nil
			}
		}
		return resetPinnedPolicyState(objects, selector)
	}

	for slot := range uint8(2) {
		settings := runtimeSettings{ActivePolicySlot: slot}
		if err := objects.Settings.Put(uint32(slot), settings); err != nil {
			return runtimeSettings{}, fmt.Errorf("initialize policy settings slot %d: %w", slot, err)
		}
	}
	if err := objects.PolicySelector.Put(zero, encodePolicySelector(0, 0)); err != nil {
		return runtimeSettings{}, fmt.Errorf("initialize policy selector: %w", err)
	}
	return runtimeSettings{}, nil
}

func resetPinnedPolicyState(objects monitorObjects, currentSelector uint64) (runtimeSettings, error) {
	currentSlot, generation, ok := decodePolicySelector(currentSelector)
	if !ok {
		currentSlot = 0
		generation = 0
	}
	targetSlot := currentSlot ^ 1
	nextGeneration := generation + 1
	if nextGeneration == 0 {
		nextGeneration = 1
	}
	if err := waitForPolicyReaders(objects.PolicyReaders, targetSlot); err != nil {
		return runtimeSettings{}, fmt.Errorf("wait to reset policy slot %d: %w", targetSlot, err)
	}
	settings := runtimeSettings{ActivePolicySlot: targetSlot, PolicyGeneration: nextGeneration}
	if err := objects.Settings.Put(uint32(targetSlot), settings); err != nil {
		return runtimeSettings{}, fmt.Errorf("reset policy settings slot %d: %w", targetSlot, err)
	}
	if err := objects.PolicySelector.Put(uint32(0), encodePolicySelector(targetSlot, nextGeneration)); err != nil {
		return runtimeSettings{}, fmt.Errorf("publish reset policy selector: %w", err)
	}
	if err := waitForPolicyReaders(objects.PolicyReaders, currentSlot); err != nil {
		return runtimeSettings{}, fmt.Errorf("wait to clear old policy slot %d: %w", currentSlot, err)
	}
	if err := objects.Settings.Put(uint32(currentSlot), runtimeSettings{ActivePolicySlot: currentSlot}); err != nil {
		return runtimeSettings{}, fmt.Errorf("clear old policy settings slot %d: %w", currentSlot, err)
	}
	return settings, nil
}

func encodePolicySelector(slot uint8, generation uint32) uint64 {
	return uint64(generation)<<32 | uint64(slot)
}

func decodePolicySelector(selector uint64) (slot uint8, generation uint32, ok bool) {
	const slotMask = uint64(1<<32 - 1)
	encodedSlot := selector & slotMask
	if encodedSlot > 1 {
		return 0, 0, false
	}
	return uint8(encodedSlot), uint32(selector >> 32), true
}

func readProcessStartTime(path string) (uint64, error) {
	payload, err := os.ReadFile(path) //nolint:gosec // fixed procfs path in production; injectable in tests.
	if err != nil {
		return 0, err
	}
	value := strings.TrimSpace(string(payload))
	closeComm := strings.LastIndex(value, ")")
	if closeComm == -1 || closeComm+2 >= len(value) {
		return 0, errors.New("malformed proc stat")
	}
	fields := strings.Fields(value[closeComm+2:])
	if len(fields) < 20 {
		return 0, errors.New("proc stat is missing starttime")
	}
	startTime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse proc starttime: %w", err)
	}
	if startTime == 0 {
		return 0, errors.New("proc starttime is zero")
	}
	return startTime, nil
}

func (m *Monitor) Close() error {
	var errs []error
	if m.reader != nil {
		errs = append(errs, m.closeReader())
	}
	for _, lnk := range m.links {
		if lnk != nil {
			errs = append(errs, lnk.Close())
		}
	}
	for _, lnk := range m.optionalLinks {
		if lnk != nil {
			errs = append(errs, lnk.Close())
		}
	}
	errs = append(errs, m.optional.Close(), m.objects.Close())
	if m.statsCloser != nil {
		errs = append(errs, m.statsCloser.Close())
	}
	return errors.Join(errs...)
}

func (m *Monitor) AttachedPrograms() int {
	return len(m.links) + len(m.optionalLinks)
}

func (m *Monitor) KernelFeatures() KernelFeatures {
	return m.features
}

func (m *Monitor) AttachState() AttachState {
	return m.attachState
}

func (m *Monitor) OptionalFailures() map[string]error {
	failures := make(map[string]error, len(m.optional.Failures))
	for hook, err := range m.optional.Failures {
		if err != nil {
			failures[hook] = err
		}
	}
	return failures
}

func (m *Monitor) FeatureGates() map[string]bool {
	gates := m.features.FeatureGates()
	gates["lsm_exec_attached"] = m.attachState.LSMExecAttached
	gates["lsm_file_attached"] = m.attachState.LSMFileAttached
	gates["cgroup_bind4"] = m.attachState.Bind4Attached
	gates["cgroup_bind6"] = m.attachState.Bind6Attached
	gates["cgroup_unix_connect"] = m.attachState.UnixConnectAttached
	gates["cgroup_unix_sendmsg"] = m.attachState.UnixSendmsgAttached
	gates["cgroup_unix_recvmsg"] = m.attachState.UnixRecvmsgAttached
	gates["cgroup_sockopt"] = m.attachState.SockoptAttached
	gates["cgroup_sockops"] = m.attachState.SockOpsAttached
	return gates
}

func (m *Monitor) ProgramStats() (map[string]ebpf.ProgramStats, error) {
	if m.statsCloser == nil {
		return nil, errors.New("eBPF runtime statistics are disabled")
	}
	programs := map[string]*ebpf.Program{
		"dns": m.objects.TraceDns, "connection_ingress": m.objects.TraceConnectionIngress,
		"sendmsg4": m.objects.TraceSendmsg4, "sendmsg6": m.objects.TraceSendmsg6,
		"recvmsg4": m.objects.TraceRecvmsg4, "recvmsg6": m.objects.TraceRecvmsg6,
		"connect4": m.objects.TraceConnect4, "connect6": m.objects.TraceConnect6,
		"post_bind4": m.objects.TracePostBind4, "post_bind6": m.objects.TracePostBind6,
		"execve": m.objects.TraceExecve, "execveat": m.objects.TraceExecveat,
		"open": m.objects.TraceOpen, "openat": m.objects.TraceOpenat,
		"openat2": m.objects.TraceOpenat2, "creat": m.objects.TraceCreat,
		"lsm_exec": m.optional.LSMExec, "lsm_file": m.optional.LSMFile,
		"bind4": m.optional.Bind4, "bind6": m.optional.Bind6,
		"unix_connect": m.optional.UnixConnect, "unix_sendmsg": m.optional.UnixSendmsg,
		"unix_recvmsg": m.optional.UnixRecvmsg, "setsockopt": m.optional.Sockopt,
		"sockops": m.optional.SockOps,
	}
	result := make(map[string]ebpf.ProgramStats, len(programs))
	var errs []error
	for name, program := range programs {
		if program == nil {
			continue
		}
		stats, err := program.Stats()
		if err != nil {
			errs = append(errs, fmt.Errorf("read %s stats: %w", name, err))
			continue
		}
		result[name] = *stats
	}
	return result, errors.Join(errs...)
}

func (m *Monitor) Run(ctx context.Context, handler func(Event), metrics RuntimeMetrics) error {
	finished := make(chan struct{})
	defer close(finished)
	go closeReaderOnCancel(ctx, readerCloser(m.closeReader), finished)

	for {
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			if metrics != nil {
				metrics.IncEBPFReadError()
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}
		event, err := decodeEvent(record.RawSample)
		if err != nil {
			if metrics != nil {
				metrics.IncEBPFReadError()
			}
			return err
		}
		handler(event)
	}
}

type readerCloser func() error

func (c readerCloser) Close() error { return c() }

func (m *Monitor) closeReader() error {
	m.readerMu.Lock()
	defer m.readerMu.Unlock()
	if m.readerClosed {
		return nil
	}
	m.readerClosed = true
	return m.reader.Close()
}

func closeReaderOnCancel(ctx context.Context, reader io.Closer, finished <-chan struct{}) {
	select {
	case <-ctx.Done():
		_ = reader.Close()
	case <-finished:
	}
}
