package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/kubeinfo"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

const (
	kubernetesRefreshErrorDedupeTTL = 5 * time.Minute
	fileAccessDedupeTTL             = 5 * time.Minute
)

func Run(ctx context.Context, cfg config.Config, recorder *eventsink.Recorder, metrics *telemetry.Registry, reloadCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	metrics.SetPolicyMode(policyMode(cfg))
	processCache := processinfo.NewCache("/proc", cfg.ProcessCacheTTL)
	var kubeEnricher *kubeinfo.Enricher
	if cfg.KubernetesEnrich {
		enricher, err := kubeinfo.New(ctx, kubeinfo.Config{
			APIURL:    cfg.KubernetesAPIURL,
			TokenPath: cfg.KubernetesTokenPath,
			CAPath:    cfg.KubernetesCAPath,
			NodeName:  cfg.KubernetesNodeName,
			PollEvery: cfg.KubernetesPoll,
		}, metrics, func(err error) {
			recorder.ErrorDedup("refresh kubernetes metadata", err, nil, kubernetesRefreshErrorDedupeTTL)
		})
		if err != nil {
			recorder.Error("initialize kubernetes metadata", err, nil)
		} else {
			kubeEnricher = enricher
			defer kubeEnricher.Close()
		}
	}

	monitor, err := ebpf.NewMonitor(cfg.CgroupPath, ebpf.Options{
		FileAudit: cfg.FileAudit,
	})
	if err != nil {
		return err
	}
	defer monitor.Close()
	metrics.SetEBPFAttachedPrograms(monitor.AttachedPrograms())

	errCh := make(chan error, 2)
	var endpointIndex atomic.Pointer[map[string]string]
	var runtimePolicy atomic.Pointer[blocklist.Policy]
	var policyMu sync.Mutex
	applyRules := func(rules blocklist.Rules) error {
		policyMu.Lock()
		defer policyMu.Unlock()

		if err := validateRulesForMode(cfg, rules); err != nil {
			return err
		}
		blockResolved, err := blocklist.ResolveEndpoints(ctx, rules.BlockEndpoints)
		if err != nil {
			return fmt.Errorf("resolve block endpoint rules: %w", err)
		}
		allowResolved, err := blocklist.ResolveEndpoints(ctx, rules.AllowEndpoints)
		if err != nil {
			return fmt.Errorf("resolve allow endpoint rules: %w", err)
		}
		blockMonitorEndpoints := make([]ebpf.ResolverEndpoint, 0, len(blockResolved))
		allowMonitorEndpoints := make([]ebpf.ResolverEndpoint, 0, len(allowResolved))
		blockMonitorCIDRs := make([]ebpf.ResolverCIDR, 0, len(rules.BlockEndpointCIDRs))
		allowMonitorCIDRs := make([]ebpf.ResolverCIDR, 0, len(rules.AllowEndpointCIDRs))
		index := make(map[string]string, len(blockResolved)+len(allowResolved))
		for _, endpoint := range blockResolved {
			blockMonitorEndpoints = append(blockMonitorEndpoints, ebpf.ResolverEndpoint{
				Transport: string(endpoint.Kind),
				IP:        endpoint.IP,
				Port:      endpoint.Port,
			})
			index[resolverIndexKey(string(endpoint.Kind), endpoint.IP.String(), endpoint.Port)] = endpoint.Host
		}
		for _, endpoint := range allowResolved {
			allowMonitorEndpoints = append(allowMonitorEndpoints, ebpf.ResolverEndpoint{
				Transport: string(endpoint.Kind),
				IP:        endpoint.IP,
				Port:      endpoint.Port,
			})
			index[resolverIndexKey(string(endpoint.Kind), endpoint.IP.String(), endpoint.Port)] = endpoint.Host
		}
		for _, cidr := range rules.BlockEndpointCIDRs {
			blockMonitorCIDRs = append(blockMonitorCIDRs, ebpf.ResolverCIDR{
				Transport: string(cidr.Kind),
				Prefix:    cidr.Prefix,
				Port:      cidr.Port,
			})
		}
		for _, cidr := range rules.AllowEndpointCIDRs {
			allowMonitorCIDRs = append(allowMonitorCIDRs, ebpf.ResolverCIDR{
				Transport: string(cidr.Kind),
				Prefix:    cidr.Prefix,
				Port:      cidr.Port,
			})
		}
		policy := blocklist.NewPolicy(rules, blockResolved, allowResolved)

		// Build the full next policy before changing kernel maps. Enabling block mode
		// is last so a failed refresh cannot publish a partially applied policy.
		if err := monitor.ReplaceDomainPolicy(rules.BlockDomains, rules.AllowDomains, rules.AllowSuffixes); err != nil {
			return err
		}
		if err := monitor.ReplaceResolverPolicy(blockMonitorEndpoints, allowMonitorEndpoints, blockMonitorCIDRs, allowMonitorCIDRs); err != nil {
			return err
		}
		if err := monitor.SetPolicyMode(cfg.Block && !cfg.DryRun, rules.BlockAllDomains, rules.BlockAllResolvers, len(rules.AllowSuffixes) > 0); err != nil {
			return fmt.Errorf("configure block mode: %w", err)
		}
		endpointIndex.Store(&index)
		runtimePolicy.Store(policy)
		metrics.SetPolicyCounts(len(rules.BlockDomains)+len(rules.AllowDomains)+len(rules.BlockSuffixes)+len(rules.AllowSuffixes), len(blockResolved)+len(allowResolved)+len(rules.BlockEndpointCIDRs)+len(rules.AllowEndpointCIDRs))
		metrics.SetPolicyRuleCounts(policyRuleCounts(rules, len(blockResolved), len(allowResolved)))
		metrics.SetPolicyLastLoaded()
		metrics.IncBlocklistRefresh(true)
		recorder.InfoIfChanged("policy loaded", map[string]any{
			"block_all_domains":    rules.BlockAllDomains,
			"block_all_resolvers":  rules.BlockAllResolvers,
			"block_domains":        len(rules.BlockDomains),
			"allow_domains":        len(rules.AllowDomains),
			"block_suffixes":       len(rules.BlockSuffixes),
			"allow_suffixes":       len(rules.AllowSuffixes),
			"block_endpoints":      len(blockResolved),
			"allow_endpoints":      len(allowResolved),
			"block_endpoint_cidrs": len(rules.BlockEndpointCIDRs),
			"allow_endpoint_cidrs": len(rules.AllowEndpointCIDRs),
			"source":               cfg.BlocklistURL,
			"cache":                cfg.CachePath,
			"dry_run":              cfg.DryRun,
		})
		return nil
	}

	var manager *blocklist.Manager
	if cfg.Block || cfg.DryRun || cfg.BlocklistURL != "" || len(cfg.ManualDomains) > 0 || len(cfg.ManualAllow) > 0 {
		manager = blocklist.NewManager(blocklist.Config{
			URL:           cfg.BlocklistURL,
			CachePath:     cfg.CachePath,
			RefreshPeriod: cfg.RefreshInterval,
			ManualDomains: cfg.ManualDomains,
			ManualAllow:   cfg.ManualAllow,
		})

		rules, loadMetadata, err := manager.LoadWithMetadata(ctx)
		metrics.IncBlocklistLoad(string(loadMetadata.Source), err == nil)
		if err != nil {
			metrics.IncBlocklistRefresh(false)
			return fmt.Errorf("load blocklist: %w", err)
		}
		if err := applyRules(rules); err != nil {
			metrics.IncBlocklistRefresh(false)
			return fmt.Errorf("apply blocklist: %w", err)
		}

		if cfg.BlocklistURL != "" {
			go func() {
				err := manager.WatchWithMetadata(ctx, func(rules blocklist.Rules, loadMetadata blocklist.LoadMetadata, loadErr error) error {
					metrics.IncBlocklistLoad(string(loadMetadata.Source), loadErr == nil)
					if loadErr != nil {
						return loadErr
					}
					return applyRules(rules)
				})
				if err != nil {
					metrics.IncBlocklistRefresh(false)
				}
				errCh <- err
			}()
		}
	}

	if manager != nil && reloadCh != nil {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-reloadCh:
					rules, loadMetadata, err := manager.LoadWithMetadata(ctx)
					metrics.IncBlocklistLoad(string(loadMetadata.Source), err == nil)
					if err != nil {
						metrics.IncPolicyReload("sighup", false)
						errCh <- fmt.Errorf("reload policy: %w", err)
						return
					}
					if err := applyRules(rules); err != nil {
						metrics.IncPolicyReload("sighup", false)
						errCh <- fmt.Errorf("apply reloaded policy: %w", err)
						return
					}
					metrics.IncPolicyReload("sighup", true)
					recorder.Info("policy reloaded", map[string]any{
						"trigger": "sighup",
					})
				}
			}
		}()
	}

	go func() {
		errCh <- monitor.Run(ctx, func(event ebpf.Event) {
			if event.Kind == ebpf.EventExec {
				processCache.Invalidate(event.PID)
			}
			process, hit := processCache.Lookup(event.PID, event.Comm)
			metrics.IncProcessCache(hit)
			metrics.IncProcessMetadata(process.Source)
			metrics.IncProcessLSMMetadata(process.LSMSource)
			eventName := eventKindName(event.Kind)
			if event.Kind == ebpf.EventFileAccess {
				eventName = fileAuditEventName(event.FileFlags)
			}
			metrics.IncEvent(eventName, event.Transport)
			if event.Kind == ebpf.EventConnection {
				metrics.IncConnection(event.Direction, event.SocketFamily, event.SocketProtocol, eventAttribution(event, process))
			}

			fields := map[string]any{
				"event":          eventName,
				"program":        process.Comm,
				"pid":            event.PID,
				"transport":      event.Transport,
				"exe":            resolveExecutablePath(event, process),
				"uid":            process.UID,
				"ppid":           process.PPID,
				"parent_program": process.ParentComm,
				"parent_exe":     process.ParentExe,
			}
			appendSocketFields(fields, event, process)
			if process.CgroupPath != "" {
				fields["cgroup"] = process.CgroupPath
			}
			if process.Service != "" {
				fields["service"] = process.Service
			}
			if process.Container != "" {
				fields["container_id"] = process.Container
			}
			if process.PodUID != "" {
				fields["pod_uid"] = process.PodUID
			}
			if process.Runtime != "" {
				fields["runtime"] = process.Runtime
			}
			if process.LSMLabel != "" {
				fields["lsm_label"] = process.LSMLabel
			}
			if process.LSMSource != "" {
				fields["lsm_source"] = process.LSMSource
			}
			if process.SELinux != "" {
				fields["selinux_context"] = process.SELinux
			}
			if process.AppArmor != "" {
				fields["apparmor_profile"] = process.AppArmor
			}
			if process.AppArmorMode != "" {
				fields["apparmor_mode"] = process.AppArmorMode
			}
			if kubeEnricher != nil && process.PodUID != "" {
				if pod, ok := kubeEnricher.Lookup(process.PodUID); ok {
					metrics.IncKubernetesEnrichment(true)
					if pod.Namespace != "" {
						fields["k8s_namespace"] = pod.Namespace
					}
					if pod.PodName != "" {
						fields["k8s_pod"] = pod.PodName
					}
					if pod.NodeName != "" {
						fields["k8s_node"] = pod.NodeName
					}
					if pod.PodIP != "" {
						fields["k8s_pod_ip"] = pod.PodIP
					}
					if pod.ServiceAccount != "" {
						fields["k8s_service_account"] = pod.ServiceAccount
					}
					if pod.OwnerKind != "" {
						fields["k8s_owner_kind"] = pod.OwnerKind
					}
					if pod.OwnerName != "" {
						fields["k8s_owner"] = pod.OwnerName
					}
					if pod.App != "" {
						fields["k8s_app"] = pod.App
					}
					if len(pod.Containers) > 0 {
						fields["k8s_containers"] = pod.Containers
					}
					if len(pod.Images) > 0 {
						fields["k8s_images"] = pod.Images
					}
				} else {
					metrics.IncKubernetesEnrichment(false)
				}
			}
			if len(process.Cmdline) > 0 {
				fields["cmdline"] = process.Cmdline
			}
			switch event.Kind {
			case ebpf.EventDNS:
				fields["domain"] = event.Domain
				decision := domainDecision(&runtimePolicy, event.Domain)
				if decision != blocklist.DecisionNone {
					fields["policy"] = string(decision)
				}
				metrics.IncPolicyDecision(string(decision))
				if cfg.DryRun && decision == blocklist.DecisionBlock {
					fields["mode"] = "dry-run"
					recorder.Info("would-block", fields)
					return
				}
				recorder.Info("dns", fields)
			case ebpf.EventBlocked:
				fields["domain"] = event.Domain
				fields["policy"] = string(blocklist.DecisionBlock)
				recorder.Info("blocked", fields)
			case ebpf.EventResolver:
				fields["endpoint"] = resolverHost(&endpointIndex, event)
				fields["address"] = event.Address
				fields["port"] = event.Port
				decision := endpointDecision(&runtimePolicy, event.Transport, event.Address, event.Port)
				if decision != blocklist.DecisionNone {
					fields["policy"] = string(decision)
				}
				metrics.IncPolicyDecision(string(decision))
				if cfg.DryRun && decision == blocklist.DecisionBlock {
					fields["mode"] = "dry-run"
					recorder.Info("would-block-"+event.Transport, fields)
					return
				}
				recorder.Info(event.Transport, fields)
			case ebpf.EventResolverBlocked:
				fields["endpoint"] = resolverHost(&endpointIndex, event)
				fields["address"] = event.Address
				fields["port"] = event.Port
				fields["policy"] = string(blocklist.DecisionBlock)
				recorder.Info("blocked-"+event.Transport, fields)
			case ebpf.EventExec:
				fields["filename"] = event.Filename
				recorder.Info("exec", fields)
			case ebpf.EventConnection:
				fields["direction"] = event.Direction
				fields["peer_address"] = event.Address
				fields["peer_port"] = event.Port
				fields["local_address"] = event.LocalAddress
				fields["local_port"] = event.LocalPort
				recorder.Info("connection", fields)
			case ebpf.EventFileAccess:
				fields["path"] = event.Filename
				fields["file_flags"] = event.FileFlags
				fields["file_mode"] = event.FileMode
				fields["file_access"] = fileAccessName(event.FileFlags)
				recorder.InfoDedupFileAudit(eventName, fields, fileAccessDedupeTTL)
			default:
				fields["kind"] = event.Kind
				recorder.Info("event", fields)
			}
		}, metrics)
	}()

	select {
	case err := <-errCh:
		cancel()
		return err
	case <-ctx.Done():
		return nil
	}
}

func policyMode(cfg config.Config) string {
	switch {
	case cfg.Block && !cfg.DryRun:
		return "block"
	case cfg.DryRun:
		return "dry_run"
	default:
		return "observe"
	}
}

func policyRuleCounts(rules blocklist.Rules, resolvedBlockEndpoints, resolvedAllowEndpoints int) map[string]int {
	return map[string]int{
		"block|domain":        len(rules.BlockDomains),
		"allow|domain":        len(rules.AllowDomains),
		"block|suffix":        len(rules.BlockSuffixes),
		"allow|suffix":        len(rules.AllowSuffixes),
		"block|endpoint":      resolvedBlockEndpoints,
		"allow|endpoint":      resolvedAllowEndpoints,
		"block|endpoint_cidr": len(rules.BlockEndpointCIDRs),
		"allow|endpoint_cidr": len(rules.AllowEndpointCIDRs),
	}
}

func IsPermissionError(err error) bool {
	return errors.Is(err, ebpf.ErrInsufficientPrivileges)
}

func validateRulesForMode(cfg config.Config, rules blocklist.Rules) error {
	if cfg.Block && !cfg.DryRun && len(rules.BlockSuffixes) > 0 {
		return fmt.Errorf("suffix and wildcard block domain rules are not enforceable in block mode on this kernel path; use observe or dry-run mode for block suffix policies")
	}
	return nil
}

func resolverHost(index *atomic.Pointer[map[string]string], event ebpf.Event) string {
	current := index.Load()
	if current == nil {
		return ""
	}
	if host, ok := (*current)[resolverIndexKey(event.Transport, event.Address, event.Port)]; ok {
		return host
	}
	return ""
}

func resolverIndexKey(transport, address string, port uint16) string {
	return fmt.Sprintf("%s|%s|%d", transport, address, port)
}

func appendSocketFields(fields map[string]any, event ebpf.Event, process processinfo.Metadata) {
	if !isSocketAwareEvent(event.Kind) {
		return
	}
	if attribution := eventAttribution(event, process); attribution != "" {
		fields["attribution"] = attribution
	}
	if event.SocketHook != "" {
		fields["socket_hook"] = event.SocketHook
	}
	if event.SocketFamily != "" {
		fields["socket_family"] = event.SocketFamily
	}
	if event.SocketProtocol != "" {
		fields["socket_protocol"] = event.SocketProtocol
	}
}

func resolveExecutablePath(event ebpf.Event, process processinfo.Metadata) string {
	if event.PID == 0 {
		return ""
	}
	if event.Kind == ebpf.EventExec && event.Filename != "" {
		return event.Filename
	}
	if process.Exe != "" {
		return process.Exe
	}
	if len(process.Cmdline) > 0 && filepath.IsAbs(process.Cmdline[0]) {
		return process.Cmdline[0]
	}
	return ""
}

func eventAttribution(event ebpf.Event, process processinfo.Metadata) string {
	if isSocketAwareEvent(event.Kind) && process.Source == processinfo.SourceProc {
		return processinfo.SourceProc
	}
	return event.Attribution
}

func isSocketAwareEvent(kind uint32) bool {
	switch kind {
	case ebpf.EventDNS, ebpf.EventBlocked, ebpf.EventResolver, ebpf.EventResolverBlocked, ebpf.EventConnection:
		return true
	default:
		return false
	}
}

func domainDecision(policy *atomic.Pointer[blocklist.Policy], domain string) blocklist.Decision {
	current := policy.Load()
	if current == nil {
		return blocklist.DecisionNone
	}
	return current.DomainDecision(domain)
}

func endpointDecision(policy *atomic.Pointer[blocklist.Policy], transport, address string, port uint16) blocklist.Decision {
	current := policy.Load()
	if current == nil {
		return blocklist.DecisionNone
	}
	return current.EndpointDecision(transport, address, port)
}

func eventKindName(kind uint32) string {
	switch kind {
	case ebpf.EventDNS:
		return "dns"
	case ebpf.EventBlocked:
		return "blocked"
	case ebpf.EventExec:
		return "exec"
	case ebpf.EventResolver:
		return "resolver"
	case ebpf.EventResolverBlocked:
		return "resolver_blocked"
	case ebpf.EventConnection:
		return "connection"
	case ebpf.EventFileAccess:
		return "file_access"
	default:
		return "unknown"
	}
}

func fileAccessName(flags uint32) string {
	const (
		unknownFlags = 1 << 31
		oAccMode     = 0x3
		oWritable    = 0x1
		oReadWrite   = 0x2
		oCreat       = 0x40
		oTrunc       = 0x200
	)
	if flags&unknownFlags != 0 {
		return "unknown"
	}
	if flags&(oCreat|oTrunc) != 0 {
		return "write"
	}
	switch flags & oAccMode {
	case oWritable, oReadWrite:
		return "write"
	default:
		return "read"
	}
}

func fileAuditEventName(flags uint32) string {
	if fileCreated(flags) {
		return "file_created"
	}
	return "file_access"
}

func fileCreated(flags uint32) bool {
	const (
		unknownFlags = 1 << 31
		oCreat       = 0x40
	)
	return flags&unknownFlags == 0 && flags&oCreat != 0
}
