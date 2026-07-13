package app

import (
	"context"
	"errors"
	"fmt"
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
	policyRefreshErrorDedupeTTL     = 5 * time.Minute
	fileAccessDedupeTTL             = 5 * time.Minute
)

func Run(ctx context.Context, cfg config.Config, recorder *eventsink.Recorder, metrics *telemetry.Registry, reloadCh <-chan struct{}) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	metrics.SetPolicyMode(policyMode(cfg))
	processCache := processinfo.NewCache("/proc", cfg.ProcessCacheTTL)
	defer processCache.Close()
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
	kernelFeatures := monitor.KernelFeatures()
	metrics.SetKernelFeatures(kernelFeatures.FeatureGates())
	featureFields := map[string]any{
		"kernel_release":       kernelFeatures.Release,
		"kernel_at_least_6_12": kernelFeatures.KernelAtLeast612,
		"kernel_at_least_7_1":  kernelFeatures.KernelAtLeast71,
		"kernel_btf":           kernelFeatures.BTFAvailable,
		"kernel_bpf_lsm":       kernelFeatures.BPFLSMAvailable,
		"enhanced_telemetry":   kernelFeatures.EnhancedTelemetry,
		"kernel_feature_set":   kernelFeatures.SelectedFeatureSet,
		"selected_bpf_object":  kernelFeatures.SelectedObject,
	}
	if kernelFeatures.EnhancedLoadFailure != "" {
		featureFields["enhanced_load_failure"] = kernelFeatures.EnhancedLoadFailure
	}
	recorder.Info("kernel features selected", featureFields)

	errCh := make(chan error, 1)
	reportErr := func(err error) {
		select {
		case errCh <- err:
		case <-ctx.Done():
		}
	}
	policy := newPolicyController(ctx, cfg, monitor, recorder, metrics)
	applyRules := policy.Apply
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
		if loadMetadata.CachePersistError != "" {
			recorder.Error("persist fetched blocklist cache", errors.New(loadMetadata.CachePersistError), nil)
		}
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
					if loadMetadata.CachePersistError != "" {
						recorder.Error("persist fetched blocklist cache", errors.New(loadMetadata.CachePersistError), nil)
					}
					if loadErr != nil {
						metrics.IncBlocklistRefresh(false)
						recorder.ErrorDedup("refresh blocklist", loadErr, nil, policyRefreshErrorDedupeTTL)
						return nil
					}
					if err := applyRules(rules); err != nil {
						metrics.IncBlocklistRefresh(false)
						recorder.ErrorDedup("apply refreshed blocklist", err, nil, policyRefreshErrorDedupeTTL)
					}
					return nil
				})
				if err != nil {
					metrics.IncBlocklistRefresh(false)
				}
				reportErr(err)
			}()
		}
	}

	if manager != nil && reloadCh != nil {
		go runPolicyReloads(ctx, reloadCh, manager.LoadWithMetadata, applyRules, func(result policyReloadResult) {
			metrics.IncBlocklistLoad(string(result.Metadata.Source), result.Phase != "load")
			if result.Metadata.CachePersistError != "" {
				recorder.Error("persist fetched blocklist cache", errors.New(result.Metadata.CachePersistError), nil)
			}
			if result.Err != nil {
				metrics.IncPolicyReload("sighup", false)
				message := "reload policy"
				if result.Phase == "apply" {
					message = "apply reloaded policy"
				}
				recorder.Error(message, result.Err, map[string]any{"trigger": "sighup"})
				return
			}
			metrics.IncPolicyReload("sighup", true)
			recorder.Info("policy reloaded", map[string]any{"trigger": "sighup"})
		})
	}

	monitorDone := make(chan struct{})
	go func() {
		defer close(monitorDone)
		reportErr(monitor.Run(ctx, func(event ebpf.Event) {
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
			appendKernelFeatureFields(fields, event)
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
				decision := domainDecision(&policy.runtimePolicy, event.Domain)
				if decision != blocklist.DecisionNone {
					fields["policy"] = string(decision)
				}
				metrics.IncPolicyDecision(string(decision))
				if cfg.DryRun && decision == blocklist.DecisionBlock {
					fields["mode"] = "dry-run"
					recorder.InfoAt(event.Timestamp, "would-block", fields)
					return
				}
				recorder.InfoAt(event.Timestamp, "dns", fields)
			case ebpf.EventBlocked:
				fields["domain"] = event.Domain
				fields["policy"] = string(blocklist.DecisionBlock)
				metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
				recorder.InfoAt(event.Timestamp, "blocked", fields)
			case ebpf.EventResolver:
				fields["endpoint"] = resolverHost(&policy.endpointIndex, event)
				fields["address"] = event.Address
				fields["port"] = event.Port
				decision := endpointDecision(&policy.runtimePolicy, event.Transport, event.Address, event.Port)
				if decision != blocklist.DecisionNone {
					fields["policy"] = string(decision)
				}
				metrics.IncPolicyDecision(string(decision))
				if cfg.DryRun && decision == blocklist.DecisionBlock {
					fields["mode"] = "dry-run"
					recorder.InfoAt(event.Timestamp, "would-block-"+event.Transport, fields)
					return
				}
				recorder.InfoAt(event.Timestamp, event.Transport, fields)
			case ebpf.EventResolverBlocked:
				fields["endpoint"] = resolverHost(&policy.endpointIndex, event)
				fields["address"] = event.Address
				fields["port"] = event.Port
				fields["policy"] = string(blocklist.DecisionBlock)
				metrics.IncPolicyDecision(string(blocklist.DecisionBlock))
				recorder.InfoAt(event.Timestamp, "blocked-"+event.Transport, fields)
			case ebpf.EventExec:
				fields["filename"] = event.Filename
				recorder.InfoAt(event.Timestamp, "exec", fields)
			case ebpf.EventConnection:
				fields["direction"] = event.Direction
				fields["peer_address"] = event.Address
				fields["peer_port"] = event.Port
				fields["local_address"] = event.LocalAddress
				fields["local_port"] = event.LocalPort
				recorder.InfoAt(event.Timestamp, "connection", fields)
			case ebpf.EventFileAccess:
				fields["path"] = event.Filename
				fields["file_flags"] = event.FileFlags
				fields["file_mode"] = event.FileMode
				fields["file_access"] = fileAccessName(event.FileFlags)
				recorder.InfoDedupFileAuditAt(event.Timestamp, eventName, fields, fileAccessDedupeTTL)
			default:
				fields["kind"] = event.Kind
				recorder.InfoAt(event.Timestamp, "event", fields)
			}
		}, metrics))
	}()

	var runErr error
	select {
	case err := <-errCh:
		runErr = err
	case <-ctx.Done():
	}
	cancel()
	<-monitorDone
	return runErr
}
