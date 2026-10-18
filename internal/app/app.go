package app

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/detection"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	"github.com/L1ghtn1ng/traceguard/internal/fim"
	"github.com/L1ghtn1ng/traceguard/internal/kubeinfo"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
	"github.com/L1ghtn1ng/traceguard/internal/threatintel"
)

const (
	kubernetesRefreshErrorDedupeTTL = 5 * time.Minute
	policyRefreshErrorDedupeTTL     = 5 * time.Minute
	fileAccessDedupeTTL             = 5 * time.Minute
)

func Run(ctx context.Context, cfg config.Config, recorder *eventsink.Recorder, metrics *telemetry.Registry, reloadCh <-chan struct{}) (runErr error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	metrics.SetPolicyMode(policyMode(cfg))
	processCache := processinfo.NewCache("/proc", cfg.ProcessCacheTTL)
	defer func() {
		runErr = errors.Join(runErr, processCache.Close())
	}()
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
			defer func() {
				runErr = errors.Join(runErr, kubeEnricher.Close())
			}()
		}
	}

	monitor, err := ebpf.NewMonitor(cfg.CgroupPath, ebpf.Options{
		FileAudit:              cfg.FileAudit,
		SecurityEvents:         cfg.SecurityEvents,
		PinEBPF:                cfg.PinEBPF,
		EnableStats:            cfg.EBPFStats,
		ConnectionDedupeWindow: cfg.ConnectionDedupeWindow,
	})
	if err != nil {
		return err
	}
	started := false
	defer func() {
		runErr = errors.Join(runErr, monitor.Close())
		if !started {
			runErr = errors.Join(runErr, monitor.RemoveFreshPins())
		}
	}()
	// Responses are undone after the workers stop, so none can apply a new
	// one, and before the monitor closes the peer block map.
	responder := newResponder(cfg, monitor, recorder, metrics)
	defer responder.RevertAll()
	// Background workers apply policy to and read stats from the monitor.
	// Deferred after monitor.Close so it runs first: cancel and join them
	// before any map or program descriptor is closed.
	var workers sync.WaitGroup
	defer func() {
		cancel()
		workers.Wait()
	}()
	metrics.SetEBPFAttachedPrograms(monitor.AttachedPrograms())
	kernelFeatures := monitor.KernelFeatures()
	metrics.SetKernelFeatures(monitor.FeatureGates())
	attachState := monitor.AttachState()
	featureFields := map[string]any{
		"kernel_release":       kernelFeatures.Release,
		"kernel_at_least_6_12": kernelFeatures.KernelAtLeast612,
		"kernel_at_least_7_1":  kernelFeatures.KernelAtLeast71,
		"kernel_btf":           kernelFeatures.BTFAvailable,
		"kernel_bpf_lsm":       kernelFeatures.BPFLSMAvailable,
		"lsm_program_type":     kernelFeatures.LSMProgramType,
		"lsm_exec_attached":    attachState.LSMExecAttached,
		"lsm_file_attached":    attachState.LSMFileAttached,
		"cgroup_bind4":         attachState.Bind4Attached,
		"cgroup_bind6":         attachState.Bind6Attached,
		"cgroup_unix_connect":  attachState.UnixConnectAttached,
		"cgroup_unix_sendmsg":  attachState.UnixSendmsgAttached,
		"cgroup_unix_recvmsg":  attachState.UnixRecvmsgAttached,
		"cgroup_sockopt":       attachState.SockoptAttached,
		"cgroup_sockops":       attachState.SockOpsAttached,
		"enhanced_telemetry":   kernelFeatures.EnhancedTelemetry,
		"kernel_feature_set":   kernelFeatures.SelectedFeatureSet,
		"selected_bpf_object":  kernelFeatures.SelectedObject,
	}
	if kernelFeatures.EnhancedLoadFailure != "" {
		featureFields["enhanced_load_failure"] = kernelFeatures.EnhancedLoadFailure
	}
	recorder.Info("kernel features selected", featureFields)
	hookFailures := monitor.OptionalFailures()
	unavailableHooks := slices.Sorted(maps.Keys(hookFailures))
	for _, hook := range unavailableHooks {
		recorder.Error("optional eBPF hook unavailable", hookFailures[hook], map[string]any{"hook": hook})
	}
	if cfg.StrictHooks && len(unavailableHooks) > 0 {
		return fmt.Errorf("strict-hooks: optional eBPF hooks unavailable: %s", strings.Join(unavailableHooks, ", "))
	}
	if cfg.EBPFStats {
		collectProgramStats(monitor, metrics, recorder)
		workers.Go(func() { runProgramStats(ctx, monitor, metrics, recorder) })
	}

	errCh := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case errCh <- err:
		case <-ctx.Done():
		}
	}
	detector, err := detection.New(nil, nil)
	if err != nil {
		return fmt.Errorf("initialize detection engine: %w", err)
	}
	metrics.SetDetectionRules(detector.RuleCount())

	// The programs are already attached and producing events. Drain the ring
	// buffer before loading policy, which can wait on a remote fetch, so a slow
	// startup does not fill the buffer and drop events.
	ringBuffer := newRingBufferWatcher(monitor, metrics, recorder)
	ringBuffer.collect()
	workers.Go(func() { runEvery(ctx, ringBufferStatsPollInterval, func(time.Time) { ringBuffer.collect() }) })
	alerts := alertSink{recorder: recorder, metrics: metrics, responder: responder}
	workers.Go(func() {
		runEvery(ctx, ringBufferStatsPollInterval, func(now time.Time) {
			responder.Expire(now)
			publishResponseStats(responder, monitor, metrics)
		})
	})
	integrity := fim.NewWatcher("/")
	workers.Go(func() { integrity.Run(ctx, newIntegrityEmitter(alerts, detector)) })
	integrityStats := &integrityStatsWatcher{watcher: integrity, metrics: metrics, recorder: recorder}
	workers.Go(func() { runEvery(ctx, ringBufferStatsPollInterval, integrityStats.collect) })
	intel := &atomic.Pointer[threatintel.Matcher]{}
	handleEvent := newEventHandler(cfg, recorder, metrics, processCache, kubeEnricher, detector, integrity, intel, alerts)
	workers.Go(func() { reportErr(monitor.Run(ctx, handleEvent, metrics)) })

	policyController := newPolicyController(ctx, cfg, monitor, recorder, metrics, detector, integrity, intel, responder)

	var yamlManager *policyconfig.Manager
	if !cfg.EmergencyAllow && (cfg.PolicyPath != "" || cfg.PolicyURL != "") {
		yamlManager, err = policyconfig.NewManager(policyconfig.Config{
			Path:              cfg.PolicyPath,
			URL:               cfg.PolicyURL,
			CachePath:         cfg.PolicyCachePath,
			RefreshPeriod:     cfg.PolicyRefreshInterval,
			Authorization:     cfg.PolicyAuthorization,
			AuthorizationFile: cfg.PolicyAuthorizationFile,
			CAPath:            cfg.PolicyCAPath,
			ClientCertPath:    cfg.PolicyClientCert,
			ClientKeyPath:     cfg.PolicyClientKey,
			SigningKeyPath:    cfg.PolicySigningKey,
			Validate: func(bundle policyconfig.Bundle) error {
				return validateBundleForMode(cfg, bundle)
			},
		})
		if err != nil {
			return fmt.Errorf("initialize YAML policy source: %w", err)
		}
		bundle, metadata, loadErr := yamlManager.Load(ctx)
		source := yamlPolicySource(metadata, cfg)
		metrics.IncPolicySourceLoad(source, loadErr == nil)
		setYAMLPolicyHealth(metrics, cfg, metadata, loadErr)
		if metadata.CachePersistError != "" {
			recorder.Error("persist fetched YAML policy cache", errors.New(metadata.CachePersistError), nil)
		}
		if metadata.StaleFallback {
			recorder.Error("remote YAML policy unavailable; using stale cache", errors.New(metadata.RemoteError), nil)
		}
		if loadErr != nil {
			return fmt.Errorf("load YAML policy: %w", loadErr)
		}
		if err := policyController.ApplyBundle(bundle); err != nil {
			return fmt.Errorf("apply YAML policy: %w", err)
		}
		if cfg.PolicyURL != "" {
			workers.Go(func() {
				yamlManager.Watch(ctx, func(bundle policyconfig.Bundle, metadata policyconfig.LoadMetadata, loadErr error) {
					source := yamlPolicySource(metadata, cfg)
					metrics.IncPolicySourceLoad(source, loadErr == nil)
					setYAMLPolicyHealth(metrics, cfg, metadata, loadErr)
					if metadata.CachePersistError != "" {
						recorder.Error("persist fetched YAML policy cache", errors.New(metadata.CachePersistError), nil)
					}
					if metadata.StaleFallback {
						recorder.ErrorDedup("remote YAML policy unavailable; using stale cache", errors.New(metadata.RemoteError), nil, policyRefreshErrorDedupeTTL)
					}
					if loadErr != nil {
						recorder.ErrorDedup("refresh YAML policy", loadErr, map[string]any{"source": source}, policyRefreshErrorDedupeTTL)
						return
					}
					if err := applyPolicyWithHealth(metrics, func() error {
						return policyController.ApplyBundle(bundle)
					}); err != nil {
						recorder.ErrorDedup("apply refreshed YAML policy", err, map[string]any{"source": source}, policyRefreshErrorDedupeTTL)
					}
				})
			})
		}
	}
	if cfg.EmergencyAllow {
		if err := monitor.ApplyPolicy(ebpf.PolicyConfig{}); err != nil {
			return fmt.Errorf("publish emergency allow policy: %w", err)
		}
		if err := policyController.RecordApplied(policyconfig.Bundle{}); err != nil {
			return err
		}
		for _, hook := range []string{"lsm-exec", "lsm-file", "bind", "unix", "sockopt"} {
			metrics.SetHookHealthy(hook, true)
		}
		recorder.Info("emergency allow mode active", map[string]any{"policy_sources_ignored": true})
	} else if yamlManager == nil {
		// A pinned monitor may contain the previous run's policy. Explicitly
		// publish an empty policy when this run has no configured policy source.
		if err := monitor.ApplyPolicy(ebpf.PolicyConfig{}); err != nil {
			return fmt.Errorf("publish empty policy: %w", err)
		}
		if err := policyController.RecordApplied(policyconfig.Bundle{}); err != nil {
			return err
		}
		for _, hook := range []string{"lsm-exec", "lsm-file", "bind", "unix", "sockopt"} {
			metrics.SetHookHealthy(hook, true)
		}
	}

	if reloadCh != nil && yamlManager != nil {
		workers.Go(func() { runPolicyReloads(ctx, reloadCh, yamlManager, policyController, cfg, recorder, metrics) })
	}
	if yamlManager != nil {
		workers.Go(func() { runCgroupReconciliation(ctx, policyController, recorder, metrics) })
		feeds := &feedWatcher{source: policyController.Source, apply: policyController.ApplyBundle, metrics: metrics, recorder: recorder}
		feeds.collect(time.Now())
		workers.Go(func() { runEvery(ctx, threatIntelPollInterval, feeds.collect) })
	}

	exceptions := newExceptionWatcher(detector, metrics, recorder)
	exceptions.collect(time.Now())
	workers.Go(func() { runEvery(ctx, ringBufferStatsPollInterval, exceptions.collect) })

	started = true
	monitor.KeepPins()
	if cfg.HeartbeatInterval > 0 {
		status := heartbeatStatus{
			started: time.Now(), mode: policyMode(cfg), policyDigest: policyController.Digest,
			unavailableHooks: unavailableHooks, ringBuffer: ringBuffer, detector: detector, healthy: metrics.Healthy,
		}
		workers.Go(func() { runHeartbeat(ctx, cfg.HeartbeatInterval, recorder, status) })
	}

	select {
	case err := <-errCh:
		runErr = err
	case <-ctx.Done():
	}
	return runErr
}

// newEventHandler enriches, records, and evaluates detections for each
// kernel event read from the ring buffer.
func newEventHandler(cfg config.Config, recorder *eventsink.Recorder, metrics *telemetry.Registry, processCache *processinfo.Cache, kubeEnricher *kubeinfo.Enricher, detector *detection.Engine, integrity *fim.Watcher, intel *atomic.Pointer[threatintel.Matcher], alerts alertSink) func(ebpf.Event) {
	selfPID := uint32(os.Getpid()) //nolint:gosec // PIDs fit in 32 bits
	return func(event ebpf.Event) {
		// File integrity hashing opens every watched file; auditing the
		// daemon's own file activity would only report that work.
		if (event.Kind == ebpf.EventFileAccess || event.Kind == ebpf.EventFileChange) && event.PID == selfPID {
			return
		}
		process, hit := lookupProcessForEvent(processCache, event)
		metrics.IncProcessCache(hit)
		metrics.IncProcessMetadata(process.Source)
		metrics.IncProcessLSMMetadata(process.LSMSource)
		eventName := eventKindName(event.Kind)
		if event.Kind == ebpf.EventFileAccess {
			eventName = fileAuditEventName(event.FileFlags)
		}
		metrics.IncEvent(eventName, event.Transport)
		if event.Kind == ebpf.EventConnection {
			metrics.IncConnection(event.Direction, event.SocketFamily, event.SocketProtocol, eventAttribution(event))
		}

		fields := map[string]any{
			"event":     eventName,
			"pid":       event.PID,
			"transport": event.Transport,
		}
		appendEventIdentityFields(fields, event)
		if executable := resolveExecutablePath(event); executable != "" {
			fields["exe"] = executable
			fields["exe_source"] = "kernel-resolved"
		}
		if process.Source == processinfo.SourceProc {
			fields["current_program"] = process.Comm
			fields["current_exe"] = process.Exe
			fields["current_uid"] = process.UID
			fields["current_ppid"] = process.PPID
			fields["current_parent_program"] = process.ParentComm
			fields["current_parent_exe"] = process.ParentExe
			fields["current_process_attribution"] = processinfo.SourceProc
		}
		appendSocketFields(fields, event)
		if process.CgroupPath != "" {
			fields["current_cgroup"] = process.CgroupPath
		}
		if process.Service != "" {
			fields["current_service"] = process.Service
		}
		if process.Container != "" {
			fields["current_container_id"] = process.Container
		}
		if process.PodUID != "" {
			fields["current_pod_uid"] = process.PodUID
		}
		if process.Runtime != "" {
			fields["current_runtime"] = process.Runtime
		}
		if process.LSMLabel != "" {
			fields["current_lsm_label"] = process.LSMLabel
		}
		if process.LSMSource != "" {
			fields["current_lsm_source"] = process.LSMSource
		}
		if process.SELinux != "" {
			fields["current_selinux_context"] = process.SELinux
		}
		if process.AppArmor != "" {
			fields["current_apparmor_profile"] = process.AppArmor
		}
		if process.AppArmorMode != "" {
			fields["current_apparmor_mode"] = process.AppArmorMode
		}
		appendKernelFeatureFields(fields, event)
		if kubeEnricher != nil && process.PodUID != "" {
			if pod, ok := kubeEnricher.Lookup(process.PodUID); ok {
				metrics.IncKubernetesEnrichment(true)
				if pod.Namespace != "" {
					fields["current_k8s_namespace"] = pod.Namespace
				}
				if pod.PodName != "" {
					fields["current_k8s_pod"] = pod.PodName
				}
				if pod.NodeName != "" {
					fields["current_k8s_node"] = pod.NodeName
				}
				if pod.PodIP != "" {
					fields["current_k8s_pod_ip"] = pod.PodIP
				}
				if pod.ServiceAccount != "" {
					fields["current_k8s_service_account"] = pod.ServiceAccount
				}
				if pod.OwnerKind != "" {
					fields["current_k8s_owner_kind"] = pod.OwnerKind
				}
				if pod.OwnerName != "" {
					fields["current_k8s_owner"] = pod.OwnerName
				}
				if pod.App != "" {
					fields["current_k8s_app"] = pod.App
				}
				if len(pod.Containers) > 0 {
					fields["current_k8s_containers"] = pod.Containers
				}
				if len(pod.Images) > 0 {
					fields["current_k8s_images"] = pod.Images
				}
			} else {
				metrics.IncKubernetesEnrichment(false)
			}
		}
		if len(process.Cmdline) > 0 {
			fields["current_cmdline"] = config.RedactCommandLine(process.Cmdline)
		}
		if process.CmdlineTruncated {
			fields["current_cmdline_truncated"] = true
		}
		if event.PathTruncated {
			fields["path_truncated"] = true
		}
		switch event.Kind {
		case ebpf.EventDNS:
			fields["domain"] = event.Domain
			decision := blocklist.Decision(event.PolicyDecision)
			if decision != blocklist.DecisionNone {
				fields["policy"] = string(decision)
			}
			metrics.IncPolicyDecision(string(decision))
			if cfg.DryRun && decision == blocklist.DecisionBlock {
				fields["mode"] = "dry-run"
				recorder.InfoAt(event.Timestamp, "would-block", fields)
			} else {
				recorder.InfoAt(event.Timestamp, "dns", fields)
			}
		case ebpf.EventBlocked:
			fields["domain"] = event.Domain
			fields["policy"] = string(blocklist.DecisionBlock)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			recorder.InfoAt(event.Timestamp, "blocked", fields)
		case ebpf.EventResolver:
			fields["endpoint"] = event.Address
			fields["address"] = event.Address
			fields["port"] = event.Port
			decision := blocklist.Decision(event.PolicyDecision)
			if decision != blocklist.DecisionNone {
				fields["policy"] = string(decision)
			}
			metrics.IncPolicyDecision(string(decision))
			if cfg.DryRun && decision == blocklist.DecisionBlock {
				fields["mode"] = "dry-run"
				recorder.InfoAt(event.Timestamp, "would-block-"+event.Transport, fields)
			} else {
				recorder.InfoAt(event.Timestamp, event.Transport, fields)
			}
		case ebpf.EventResolverBlocked:
			fields["endpoint"] = event.Address
			fields["address"] = event.Address
			fields["port"] = event.Port
			fields["policy"] = string(blocklist.DecisionBlock)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			recorder.InfoAt(event.Timestamp, "blocked-"+event.Transport, fields)
		case ebpf.EventExec:
			appendExecFields(fields, event)
			recorder.InfoAt(event.Timestamp, "exec", fields)
		case ebpf.EventConnection:
			fields["direction"] = event.Direction
			fields["peer_address"] = event.Address
			fields["peer_port"] = event.Port
			fields["local_address"] = event.LocalAddress
			fields["local_port"] = event.LocalPort
			recorder.InfoAt(event.Timestamp, "connection", fields)
		case ebpf.EventFileAccess:
			fields["requested_path"] = event.Filename
			fields["path_source"] = "syscall-requested"
			fields["file_flags"] = event.FileFlags
			fields["file_mode"] = event.FileMode
			fields["file_access"] = fileAccessName(event.FileFlags)
			recorder.InfoDedupFileAuditAt(event.Timestamp, eventName, fields, fileAccessDedupeTTL)
			notifyIntegrity(integrity, "/proc", event, fields)
		case ebpf.EventFileChange:
			appendFileChangeFields(fields, event)
			recorder.InfoAt(event.Timestamp, eventName, fields)
			notifyIntegrity(integrity, "/proc", event, fields)
		case ebpf.EventEgressBlocked, ebpf.EventEgressWouldBlock:
			fields["direction"] = event.Direction
			fields["peer_address"] = event.Address
			fields["peer_port"] = event.Port
			fields["local_address"] = event.LocalAddress
			fields["local_port"] = event.LocalPort
			fields["policy"] = string(blocklist.DecisionBlock)
			mode := "block"
			if event.Kind == ebpf.EventEgressWouldBlock {
				mode = "dry-run"
			}
			fields["mode"] = mode
			if event.RuleID != "" {
				fields["policy_rule_id"] = event.RuleID
			} else {
				fields["policy_rule_id"] = "default"
			}
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			metrics.IncEgressDecision("block", mode)
			recorder.InfoAt(event.Timestamp, eventName, fields)
		case ebpf.EventExecBlocked, ebpf.EventExecWouldBlock:
			mode := enforcementEventMode(event.Kind == ebpf.EventExecWouldBlock)
			fields["path"] = event.Filename
			appendEnforcementDecisionFields(fields, event, mode)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			metrics.IncLSMDecision("exec", "block", mode)
			recorder.InfoAt(event.Timestamp, eventName, fields)
		case ebpf.EventFileBlocked, ebpf.EventFileWouldBlock:
			mode := enforcementEventMode(event.Kind == ebpf.EventFileWouldBlock)
			fields["path"] = event.Filename
			fields["file_flags"] = event.FileFlags
			fields["file_access"] = fileAccessName(event.FileFlags)
			appendEnforcementDecisionFields(fields, event, mode)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			metrics.IncLSMDecision("file", "block", mode)
			recorder.InfoAt(event.Timestamp, eventName, fields)
		case ebpf.EventBindBlocked, ebpf.EventBindWouldBlock:
			mode := enforcementEventMode(event.Kind == ebpf.EventBindWouldBlock)
			fields["local_address"] = event.LocalAddress
			fields["local_port"] = event.LocalPort
			appendEnforcementDecisionFields(fields, event, mode)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			metrics.IncBindDecision("block", mode)
			recorder.InfoAt(event.Timestamp, eventName, fields)
		case ebpf.EventUnixBlocked, ebpf.EventUnixWouldBlock:
			mode := enforcementEventMode(event.Kind == ebpf.EventUnixWouldBlock)
			operation := unixOperationName(event.FileFlags)
			fields["path"] = event.Filename
			fields["unix_op"] = operation
			appendEnforcementDecisionFields(fields, event, mode)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			metrics.IncUnixDecision("block", mode, operation)
			recorder.InfoAt(event.Timestamp, eventName, fields)
		case ebpf.EventSockoptBlocked, ebpf.EventSockoptWouldBlock:
			mode := enforcementEventMode(event.Kind == ebpf.EventSockoptWouldBlock)
			fields["sockopt_level"] = event.FileFlags
			fields["sockopt_optname"] = event.FileMode
			appendEnforcementDecisionFields(fields, event, mode)
			metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
			metrics.IncSockoptDecision("block", mode)
			recorder.InfoAt(event.Timestamp, eventName, fields)
		case ebpf.EventSockOps:
			fields["direction"] = event.Direction
			fields["peer_address"] = event.Address
			fields["peer_port"] = event.Port
			fields["local_address"] = event.LocalAddress
			fields["local_port"] = event.LocalPort
			fields["sockops_op"] = event.FileFlags
			if event.FileMode != 0 {
				fields["tcp_state"] = event.FileMode
			}
			recorder.InfoAt(event.Timestamp, eventName, fields)
		default:
			if ebpf.IsSecurityEvent(event.Kind) {
				appendSecurityEventFields(fields, event, "/proc")
				recorder.InfoAt(event.Timestamp, eventName, fields)
				break
			}
			fields["kind"] = event.Kind
			recorder.InfoAt(event.Timestamp, "event", fields)
		}
		emitDetectionAlerts(detector, alerts, event.Timestamp, eventName, fields)
		emitThreatIntelAlerts(intel.Load(), alerts, event.Timestamp, eventName, fields)
	}
}
