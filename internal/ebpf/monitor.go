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
	"github.com/cilium/ebpf/btf"
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
	objects monitorObjects
	links   []link.Link
	reader  *ringbuf.Reader
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

	Allowlist               *ebpf.Map `ebpf:"allowlist"`
	Blocklist               *ebpf.Map `ebpf:"blocklist"`
	Endpoint4AllowRules     *ebpf.Map `ebpf:"endpoint4_allow_rules"`
	Endpoint4CidrAllowRules *ebpf.Map `ebpf:"endpoint4_cidr_allow_rules"`
	Endpoint4CidrRules      *ebpf.Map `ebpf:"endpoint4_cidr_rules"`
	Endpoint4Rules          *ebpf.Map `ebpf:"endpoint4_rules"`
	Endpoint6AllowRules     *ebpf.Map `ebpf:"endpoint6_allow_rules"`
	Endpoint6CidrAllowRules *ebpf.Map `ebpf:"endpoint6_cidr_allow_rules"`
	Endpoint6CidrRules      *ebpf.Map `ebpf:"endpoint6_cidr_rules"`
	Endpoint6Rules          *ebpf.Map `ebpf:"endpoint6_rules"`
	Events                  *ebpf.Map `ebpf:"events"`
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
		o.Allowlist,
		o.Blocklist,
		o.Endpoint4AllowRules,
		o.Endpoint4CidrAllowRules,
		o.Endpoint4CidrRules,
		o.Endpoint4Rules,
		o.Endpoint6AllowRules,
		o.Endpoint6CidrAllowRules,
		o.Endpoint6CidrRules,
		o.Endpoint6Rules,
		o.Events,
		o.Settings,
	} {
		if closer != nil {
			errs = append(errs, closer.Close())
		}
	}
	return errors.Join(errs...)
}

func NewMonitor(cgroupPath string) (*Monitor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raise memlock rlimit: %w", err)
	}

	loadOptions := newCollectionOptions()
	objects, err := loadMonitorObjects(loadOptions)
	if err != nil {
		return nil, err
	}

	reader, err := ringbuf.NewReader(objects.Events)
	if err != nil {
		objects.Close()
		return nil, fmt.Errorf("create ring buffer reader: %w", err)
	}

	var links []link.Link
	cleanup := func() {
		for _, lnk := range links {
			if lnk != nil {
				_ = lnk.Close()
			}
		}
		_ = reader.Close()
		_ = objects.Close()
	}

	attachCgroup := func(program *ebpf.Program, attach ebpf.AttachType, name string) error {
		lnk, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  attach,
			Program: program,
		})
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
		{program: objects.TraceDns, attach: ebpf.AttachCGroupInetEgress, name: "DNS cgroup egress"},
		{program: objects.TraceConnectionIngress, attach: ebpf.AttachCGroupInetIngress, name: "connection ingress"},
		{program: objects.TraceSendmsg4, attach: ebpf.AttachCGroupUDP4Sendmsg, name: "sendmsg4"},
		{program: objects.TraceSendmsg6, attach: ebpf.AttachCGroupUDP6Sendmsg, name: "sendmsg6"},
		{program: objects.TraceRecvmsg4, attach: ebpf.AttachCGroupUDP4Recvmsg, name: "recvmsg4"},
		{program: objects.TraceRecvmsg6, attach: ebpf.AttachCGroupUDP6Recvmsg, name: "recvmsg6"},
		{program: objects.TraceConnect4, attach: ebpf.AttachCGroupInet4Connect, name: "connect4"},
		{program: objects.TraceConnect6, attach: ebpf.AttachCGroupInet6Connect, name: "connect6"},
		{program: objects.TracePostBind4, attach: ebpf.AttachCGroupInet4PostBind, name: "post_bind4"},
		{program: objects.TracePostBind6, attach: ebpf.AttachCGroupInet6PostBind, name: "post_bind6"},
	} {
		if err := attachCgroup(spec.program, spec.attach, spec.name); err != nil {
			cleanup()
			return nil, err
		}
	}

	execveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objects.TraceExecve, nil)
	if err != nil {
		cleanup()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach execve tracepoint requires tracepoint perf-event access; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach execve tracepoint: %w", err)
	}
	links = append(links, execveLink)

	execveatLink, err := link.Tracepoint("syscalls", "sys_enter_execveat", objects.TraceExecveat, nil)
	if err != nil {
		cleanup()
		if isPermissionDenied(err) {
			return nil, fmt.Errorf("%w: attach execveat tracepoint requires tracepoint perf-event access; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid: %v", ErrInsufficientPrivileges, err)
		}
		return nil, fmt.Errorf("attach execveat tracepoint: %w", err)
	}
	links = append(links, execveatLink)

	return &Monitor{objects: objects, links: links, reader: reader}, nil
}

func newCollectionOptions() *ebpf.CollectionOptions {
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 1 << 20,
		},
	}

	kernelTypes, err := btf.LoadKernelSpec()
	if err == nil {
		opts.Programs.KernelTypes = kernelTypes
	}

	return opts
}

func loadMonitorObjects(loadOptions *ebpf.CollectionOptions) (monitorObjects, error) {
	release, _ := kernelRelease()
	if isLinux612x(release) {
		objects, err := loadMonitorVariant(loadTraceguardDNSCompat, loadOptions)
		if err == nil {
			return objects, nil
		}
		if isRecvmsgContextVerifierError(err) {
			compatObjects, compatErr := loadMonitorVariant(loadTraceguardDNSRecvmsgCompat, loadOptions)
			if compatErr != nil {
				return monitorObjects{}, fmt.Errorf("load eBPF objects for kernel %s: dns compat load failed: %v; dns+recvmsg compat retry failed: %w", release, err, compatErr)
			}
			return compatObjects, nil
		}
		if isDNSHelperVerifierError(err) {
			compatObjects, compatErr := loadMonitorVariant(loadTraceguardDNSRecvmsgCompat, loadOptions)
			if compatErr == nil {
				return compatObjects, nil
			}
		}
		return monitorObjects{}, fmt.Errorf("load eBPF objects for kernel %s: %w", release, err)
	}

	objects, err := loadMonitorVariant(loadTraceguard, loadOptions)
	if err == nil {
		return objects, nil
	}
	if isRecvmsgContextVerifierError(err) {
		compatObjects, compatErr := loadMonitorVariant(loadTraceguardRecvmsgCompat, loadOptions)
		if compatErr == nil {
			return compatObjects, nil
		}
		if isDNSHelperVerifierError(err) {
			combinedObjects, combinedErr := loadMonitorVariant(loadTraceguardDNSRecvmsgCompat, loadOptions)
			if combinedErr == nil {
				return combinedObjects, nil
			}
		}
		return monitorObjects{}, fmt.Errorf("load eBPF objects: default load failed: %v; recvmsg compat retry failed: %w", err, compatErr)
	}
	if !isDNSHelperVerifierError(err) {
		return monitorObjects{}, fmt.Errorf("load eBPF objects: %w", err)
	}

	compatObjects, compatErr := loadMonitorVariant(loadTraceguardDNSCompat, loadOptions)
	if compatErr == nil {
		return compatObjects, nil
	}
	if isRecvmsgContextVerifierError(compatErr) {
		combinedObjects, combinedErr := loadMonitorVariant(loadTraceguardDNSRecvmsgCompat, loadOptions)
		if combinedErr == nil {
			return combinedObjects, nil
		}
		return monitorObjects{}, fmt.Errorf("load eBPF objects: dns compat retry failed: %v; dns+recvmsg compat retry failed: %w", compatErr, combinedErr)
	}
	return monitorObjects{}, fmt.Errorf("load eBPF objects: default load failed: %v; compat retry failed: %w", err, compatErr)
}

func isRecvmsgContextVerifierError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return (strings.Contains(msg, "trace_recvmsg4") || strings.Contains(msg, "trace_recvmsg6") || strings.Contains(msg, "TraceRecvmsg4") || strings.Contains(msg, "TraceRecvmsg6")) &&
		(strings.Contains(msg, "invalid bpf_context access off=40") || strings.Contains(msg, "dereference of modified ctx ptr"))
}

func loadMonitorVariant(loadSpec func() (*ebpf.CollectionSpec, error), loadOptions *ebpf.CollectionOptions) (monitorObjects, error) {
	var objects monitorObjects

	spec, err := loadSpec()
	if err != nil {
		return monitorObjects{}, err
	}
	if err := spec.LoadAndAssign(&objects, loadOptions); err != nil {
		_ = objects.Close()
		return monitorObjects{}, err
	}
	return objects, nil
}

func kernelRelease() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		builder.WriteByte(byte(b))
	}
	return builder.String(), nil
}

func isLinux612x(release string) bool {
	major, minor, ok := parseKernelRelease(release)
	return ok && major == 6 && minor == 12
}

func parseKernelRelease(release string) (int, int, bool) {
	release = strings.TrimSpace(release)
	if release == "" {
		return 0, 0, false
	}
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func isDNSHelperVerifierError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "program of this type cannot use helper bpf_get_current_comm#16") &&
		strings.Contains(msg, "trace_dns")
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
