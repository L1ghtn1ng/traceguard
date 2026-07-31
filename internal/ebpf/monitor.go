package ebpf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

var (
	ErrInsufficientPrivileges = errors.New("insufficient privileges to attach eBPF programs; run as root or grant CAP_BPF,CAP_NET_ADMIN,CAP_PERFMON,CAP_SYS_RESOURCE")
	ErrUnsupportedKernel      = errors.New("unsupported kernel: TraceGuard requires Linux 6.12 or newer")
)

const (
	blocklistMaxEntries = 16384
	endpointMaxEntries  = 16384
	egressMaxEntries    = 16384
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
	_                    [7]byte
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
}

type Monitor struct {
	objects          monitorObjects
	links            []io.Closer
	reader           *ringbuf.Reader
	features         KernelFeatures
	policyMu         sync.Mutex
	activePolicySlot uint8
	egressRuleIDs    atomic.Pointer[map[uint32]string]
	currentRuleIDs   map[uint32]string
}

type RuntimeMetrics interface {
	IncEBPFReadError()
}

type Options struct {
	FileAudit bool
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

	loadOptions := newCollectionOptions()
	objects, features, err := loadMonitorObjects(loadOptions)
	if err != nil {
		return nil, err
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		if closeErr := objects.Close(); closeErr != nil {
			return nil, errors.Join(fmt.Errorf("create ring buffer reader: %w", err), closeErr)
		}
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}

	links, err := attachMonitorPrograms(cgroupPath, opts, objects, defaultAttachmentFunctions())
	if err != nil {
		return nil, errors.Join(err, reader.Close(), objects.Close())
	}

	return &Monitor{objects: objects, links: links, reader: reader, features: features}, nil
}

func (m *Monitor) Close() error {
	var errs []error
	if m.reader != nil {
		errs = append(errs, m.reader.Close())
	}
	for _, lnk := range m.links {
		if lnk != nil {
			errs = append(errs, lnk.Close())
		}
	}
	errs = append(errs, m.objects.Close())
	return errors.Join(errs...)
}

func (m *Monitor) AttachedPrograms() int {
	return len(m.links)
}

func (m *Monitor) KernelFeatures() KernelFeatures {
	return m.features
}

func (m *Monitor) Run(ctx context.Context, handler func(Event), metrics RuntimeMetrics) error {
	finished := make(chan struct{})
	defer close(finished)
	go closeReaderOnCancel(ctx, m.reader, finished)

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
		if event.RuleNumber != 0 {
			if ruleIDs := m.egressRuleIDs.Load(); ruleIDs != nil {
				event.RuleID = (*ruleIDs)[event.RuleNumber]
			}
		}
		handler(event)
	}
}

func closeReaderOnCancel(ctx context.Context, reader io.Closer, finished <-chan struct{}) {
	select {
	case <-ctx.Done():
		_ = reader.Close()
	case <-finished:
	}
}
