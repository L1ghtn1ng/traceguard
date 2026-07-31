package app

import (
	"context"
	"errors"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/eventsink"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

const cgroupReconcileInterval = 30 * time.Second

func yamlPolicySource(metadata policyconfig.LoadMetadata, cfg config.Config) string {
	if metadata.RemoteSource != policyconfig.LoadSourceNone {
		return string(metadata.RemoteSource)
	}
	if cfg.PolicyPath != "" {
		return "local"
	}
	return "none"
}

func setYAMLPolicyHealth(metrics *telemetry.Registry, cfg config.Config, metadata policyconfig.LoadMetadata, loadErr error) {
	if cfg.PolicyPath != "" {
		metrics.SetPolicySourceHealthy("local", loadErr == nil)
	}
	if cfg.PolicyURL != "" {
		metrics.SetPolicySourceHealthy("remote", loadErr == nil && !metadata.StaleFallback)
		if metadata.CachePersistError != "" {
			metrics.SetPolicySourceHealthy("cache", false)
		} else if metadata.RemoteSource == policyconfig.LoadSourceRemote || metadata.RemoteSource == policyconfig.LoadSourceCache {
			metrics.SetPolicySourceHealthy("cache", true)
		}
	}
}

func applyPolicyWithHealth(metrics *telemetry.Registry, apply func() error) error {
	err := apply()
	metrics.SetPolicySourceHealthy("apply", err == nil)
	return err
}

func runPolicyReloads(
	ctx context.Context,
	reloadCh <-chan struct{},
	yaml *policyconfig.Manager,
	controller *policyController,
	cfg config.Config,
	recorder *eventsink.Recorder,
	metrics *telemetry.Registry,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-reloadCh:
			if !ok {
				return
			}
			bundle, metadata, reloadErr := yaml.Load(ctx)
			source := yamlPolicySource(metadata, cfg)
			metrics.IncPolicySourceLoad(source, reloadErr == nil)
			setYAMLPolicyHealth(metrics, cfg, metadata, reloadErr)
			if metadata.CachePersistError != "" {
				recorder.Error("persist fetched YAML policy cache", errors.New(metadata.CachePersistError), nil)
			}
			if metadata.StaleFallback {
				recorder.ErrorDedup("remote YAML policy unavailable; using stale cache", errors.New(metadata.RemoteError), nil, policyRefreshErrorDedupeTTL)
			}
			if reloadErr == nil {
				reloadErr = applyPolicyWithHealth(metrics, func() error {
					return controller.ApplyBundle(bundle)
				})
			}
			if reloadErr != nil {
				metrics.IncPolicyReload("sighup", false)
				recorder.Error("reload policy", reloadErr, map[string]any{"trigger": "sighup"})
				continue
			}
			metrics.IncPolicyReload("sighup", true)
			recorder.Info("policy reloaded", map[string]any{"trigger": "sighup"})
		}
	}
}

func runCgroupReconciliation(ctx context.Context, controller *policyController, recorder *eventsink.Recorder, metrics *telemetry.Registry) {
	ticker := time.NewTicker(cgroupReconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := controller.ReconcileCgroups(); err != nil {
				metrics.IncCgroupReconcile(false)
				metrics.SetPolicySourceHealthy("cgroup", false)
				recorder.ErrorDedup("reconcile egress cgroup selectors", err, nil, policyRefreshErrorDedupeTTL)
			} else {
				metrics.SetPolicySourceHealthy("cgroup", true)
			}
		}
	}
}
