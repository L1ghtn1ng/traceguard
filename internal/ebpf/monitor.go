package ebpf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var ErrInsufficientPrivileges = errors.New("insufficient privileges to attach eBPF programs; run as root or grant CAP_BPF,CAP_NET_ADMIN,CAP_PERFMON,CAP_SYS_RESOURCE")

const (
	blocklistMaxEntries = 8192
	endpointMaxEntries  = 8192
)

type domainKey struct {
	Domain [domainSize]byte
}

type runtimeSettings struct {
	BlockEnabled      uint8
	BlockAllDomains   uint8
	BlockAllResolvers uint8
	_                 [5]byte
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
}

type endpoint6CIDRKey struct {
	PrefixLen uint32
	Data      [19]uint8
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

type Monitor struct {
	objects traceguardObjects
	links   []link.Link
	reader  *ringbuf.Reader
}

func NewMonitor(cgroupPath string) (*Monitor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock rlimit: %w", err)
	}

	var objects traceguardObjects
	loadOptions := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 1 << 20,
		},
	}
	if err := loadTraceguardObjects(&objects, loadOptions); err != nil {
		return nil, fmt.Errorf("load eBPF objects: %w", err)
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		objects.Close()
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}

	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objects.TraceDns,
	})
	if err != nil {
		reader.Close()
		objects.Close()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach DNS cgroup egress program: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach DNS cgroup egress program: %w", err)
	}

	connect4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objects.TraceConnect4,
	})
	if err != nil {
		cgroupLink.Close()
		reader.Close()
		objects.Close()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach connect4 program: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach connect4 program: %w", err)
	}

	connect6Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInet6Connect,
		Program: objects.TraceConnect6,
	})
	if err != nil {
		connect4Link.Close()
		cgroupLink.Close()
		reader.Close()
		objects.Close()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach connect6 program: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach connect6 program: %w", err)
	}

	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objects.TraceExecve, nil)
	if err != nil {
		connect6Link.Close()
		connect4Link.Close()
		cgroupLink.Close()
		reader.Close()
		objects.Close()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach execve tracepoint requires tracepoint perf-event access; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach execve tracepoint: %w", err)
	}

	execveatLink, err := link.Tracepoint("syscalls", "sys_enter_execveat", objects.TraceExecveat, nil)
	if err != nil {
		execveLink.Close()
		connect6Link.Close()
		connect4Link.Close()
		cgroupLink.Close()
		reader.Close()
		objects.Close()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach execveat tracepoint requires tracepoint perf-event access; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach execveat tracepoint: %w", err)
	}

	return &Monitor{
		objects: objects,
		links:   []link.Link{cgroupLink, connect4Link, connect6Link, execveLink, execveatLink},
		reader:  reader,
	}, nil
}

func isPermissionDenied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
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

func (m *Monitor) SetPolicyMode(enabled, blockAllDomains, blockAllResolvers bool) error {
	value := runtimeSettings{}
	if enabled {
		value.BlockEnabled = 1
	}
	if blockAllDomains {
		value.BlockAllDomains = 1
	}
	if blockAllResolvers {
		value.BlockAllResolvers = 1
	}
	key := uint32(0)
	return m.objects.Settings.Put(key, value)
}

func (m *Monitor) ReplaceDomainPolicy(blocked, allowed []string) error {
	nextBlock := make(map[domainKey]struct{}, len(blocked))
	for _, domain := range blocked {
		key, err := encodeDomainKey(domain)
		if err != nil {
			return fmt.Errorf("encode blocklist entry %q: %w", domain, err)
		}
		nextBlock[key] = struct{}{}
	}
	nextAllow := make(map[domainKey]struct{}, len(allowed))
	for _, domain := range allowed {
		key, err := encodeDomainKey(domain)
		if err != nil {
			return fmt.Errorf("encode allowlist entry %q: %w", domain, err)
		}
		nextAllow[key] = struct{}{}
	}
	if len(nextBlock) > blocklistMaxEntries {
		return fmt.Errorf("blocklist contains %d entries, exceeds map capacity %d", len(nextBlock), blocklistMaxEntries)
	}
	if len(nextAllow) > blocklistMaxEntries {
		return fmt.Errorf("allowlist contains %d entries, exceeds map capacity %d", len(nextAllow), blocklistMaxEntries)
	}
	if err := syncMap(m.objects.Blocklist, nextBlock); err != nil {
		return fmt.Errorf("sync blocklist: %w", err)
	}
	if err := syncMap(m.objects.Allowlist, nextAllow); err != nil {
		return fmt.Errorf("sync allowlist: %w", err)
	}
	return nil
}

func (m *Monitor) ReplaceResolverPolicy(blocked, allowed []ResolverEndpoint, blockedCIDRs, allowedCIDRs []ResolverCIDR) error {
	nextBlock4 := make(map[endpoint4Key]struct{})
	nextBlock6 := make(map[endpoint6Key]struct{})
	nextAllow4 := make(map[endpoint4Key]struct{})
	nextAllow6 := make(map[endpoint6Key]struct{})
	nextBlockCIDR4 := make(map[endpoint4CIDRKey]struct{})
	nextBlockCIDR6 := make(map[endpoint6CIDRKey]struct{})
	nextAllowCIDR4 := make(map[endpoint4CIDRKey]struct{})
	nextAllowCIDR6 := make(map[endpoint6CIDRKey]struct{})

	load := func(endpoints []ResolverEndpoint, ipv4 map[endpoint4Key]struct{}, ipv6 map[endpoint6Key]struct{}) error {
		for _, endpoint := range endpoints {
			transport, ok := encodeResolverTransport(endpoint.Transport)
			if !ok {
				return fmt.Errorf("unsupported resolver transport %q", endpoint.Transport)
			}

			if ip4 := endpoint.IP.To4(); ip4 != nil {
				key := endpoint4Key{
					Addr:      uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24,
					Port:      endpoint.Port,
					Transport: transport,
				}
				ipv4[key] = struct{}{}
				continue
			}

			ip16 := endpoint.IP.To16()
			if ip16 == nil {
				return fmt.Errorf("invalid endpoint IP %q", endpoint.IP)
			}
			key := endpoint6Key{
				Port:      endpoint.Port,
				Transport: transport,
			}
			copy(key.Addr[:], ip16)
			ipv6[key] = struct{}{}
		}
		return nil
	}
	loadCIDRs := func(cidrs []ResolverCIDR, ipv4 map[endpoint4CIDRKey]struct{}, ipv6 map[endpoint6CIDRKey]struct{}) error {
		for _, endpoint := range cidrs {
			transport, ok := encodeResolverTransport(endpoint.Transport)
			if !ok {
				return fmt.Errorf("unsupported resolver transport %q", endpoint.Transport)
			}
			addr := endpoint.Prefix.Addr()
			if !addr.IsValid() {
				return fmt.Errorf("invalid endpoint prefix %q", endpoint.Prefix)
			}
			if addr.Is4() {
				ip := addr.As4()
				key := endpoint4CIDRKey{
					PrefixLen: uint32(24 + endpoint.Prefix.Bits()),
					Data:      [7]uint8{transport, uint8(endpoint.Port >> 8), uint8(endpoint.Port)},
				}
				copy(key.Data[3:], ip[:])
				ipv4[key] = struct{}{}
				continue
			}
			if !addr.Is6() {
				return fmt.Errorf("invalid endpoint prefix %q", endpoint.Prefix)
			}
			ip := addr.As16()
			key := endpoint6CIDRKey{
				PrefixLen: uint32(24 + endpoint.Prefix.Bits()),
				Data:      [19]uint8{transport, uint8(endpoint.Port >> 8), uint8(endpoint.Port)},
			}
			copy(key.Data[3:], ip[:])
			ipv6[key] = struct{}{}
		}
		return nil
	}
	if err := load(blocked, nextBlock4, nextBlock6); err != nil {
		return err
	}
	if err := load(allowed, nextAllow4, nextAllow6); err != nil {
		return err
	}
	if err := loadCIDRs(blockedCIDRs, nextBlockCIDR4, nextBlockCIDR6); err != nil {
		return err
	}
	if err := loadCIDRs(allowedCIDRs, nextAllowCIDR4, nextAllowCIDR6); err != nil {
		return err
	}

	if len(nextBlock4) > endpointMaxEntries || len(nextAllow4) > endpointMaxEntries {
		return fmt.Errorf("ipv4 resolver endpoints exceed map capacity %d", endpointMaxEntries)
	}
	if len(nextBlock6) > endpointMaxEntries || len(nextAllow6) > endpointMaxEntries {
		return fmt.Errorf("ipv6 resolver endpoints exceed map capacity %d", endpointMaxEntries)
	}
	if len(nextBlockCIDR4) > endpointMaxEntries || len(nextAllowCIDR4) > endpointMaxEntries {
		return fmt.Errorf("ipv4 resolver cidrs exceed map capacity %d", endpointMaxEntries)
	}
	if len(nextBlockCIDR6) > endpointMaxEntries || len(nextAllowCIDR6) > endpointMaxEntries {
		return fmt.Errorf("ipv6 resolver cidrs exceed map capacity %d", endpointMaxEntries)
	}

	if err := syncMap(m.objects.Endpoint4Rules, nextBlock4); err != nil {
		return fmt.Errorf("sync endpoint4 block rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint6Rules, nextBlock6); err != nil {
		return fmt.Errorf("sync endpoint6 block rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint4AllowRules, nextAllow4); err != nil {
		return fmt.Errorf("sync endpoint4 allow rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint6AllowRules, nextAllow6); err != nil {
		return fmt.Errorf("sync endpoint6 allow rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint4CidrRules, nextBlockCIDR4); err != nil {
		return fmt.Errorf("sync endpoint4 block cidr rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint6CidrRules, nextBlockCIDR6); err != nil {
		return fmt.Errorf("sync endpoint6 block cidr rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint4CidrAllowRules, nextAllowCIDR4); err != nil {
		return fmt.Errorf("sync endpoint4 allow cidr rules: %w", err)
	}
	if err := syncMap(m.objects.Endpoint6CidrAllowRules, nextAllowCIDR6); err != nil {
		return fmt.Errorf("sync endpoint6 allow cidr rules: %w", err)
	}
	return nil
}

func (m *Monitor) Run(ctx context.Context, handler func(Event)) error {
	go func() {
		<-ctx.Done()
		_ = m.reader.Close()
	}()

	for {
		record, err := m.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return fmt.Errorf("read ring buffer: %w", err)
		}

		event, err := decodeEvent(record.RawSample)
		if err != nil {
			return err
		}
		handler(event)
	}
}

func encodeDomainKey(domain string) (domainKey, error) {
	var key domainKey
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return key, errors.New("empty domain")
	}

	offset := 0
	for _, label := range strings.Split(domain, ".") {
		if label == "" {
			return key, errors.New("empty label")
		}
		if len(label) > 63 {
			return key, fmt.Errorf("label %q exceeds 63 bytes", label)
		}
		if offset+1+len(label)+1 > len(key.Domain) {
			return key, errors.New("domain exceeds DNS wire-format limit")
		}

		key.Domain[offset] = byte(len(label))
		offset++
		copy(key.Domain[offset:], label)
		offset += len(label)
	}

	key.Domain[offset] = 0
	return key, nil
}

func encodeResolverTransport(transport string) (uint8, bool) {
	switch strings.TrimSpace(strings.ToLower(transport)) {
	case "doh":
		return 4, true
	case "dot":
		return 3, true
	default:
		return 0, false
	}
}

func syncMap[K comparable](m *ebpf.Map, next map[K]struct{}) error {
	current := make(map[K]struct{})
	iter := m.Iterate()
	var key K
	var value uint8
	for iter.Next(&key, &value) {
		current[key] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for key := range next {
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}
	}

	for key := range current {
		if _, keep := next[key]; keep {
			continue
		}
		if err := m.Delete(key); err != nil {
			return err
		}
	}
	return nil
}
