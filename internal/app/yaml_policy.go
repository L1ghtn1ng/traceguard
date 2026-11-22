package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
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
	}
}

func applyPolicyWithHealth(metrics *telemetry.Registry, apply func() error) error {
	err := apply()
	metrics.SetPolicySourceHealthy("apply", err == nil)
	return err
}

// reloadRequest asks the reload worker to load and apply policy now. done,
// when set, receives the outcome.
type reloadRequest struct {
	trigger string
	done    chan<- error
}

// policyApplier applies loaded bundles from the periodic refresh and from
// reloads. It applies each and records its remote digest as the one in
// force under one lock, and refuses a bundle loaded before the one last
// applied, so a slow refresh can never roll back a newer policy.
type policyApplier struct {
	mu      sync.Mutex
	applied uint64
	// reported is the sequence of the load whose health was last reported,
	// and cached that of the last load that touched the cache.
	reported uint64
	cached   uint64
}

// cacheHealth reports a load's effect on the cache in the order the loads
// ran: a newer successful write supersedes an older failure, but a 304,
// which does not touch the cache, supersedes nothing.
func (a *policyApplier) cacheHealth(metrics *telemetry.Registry, metadata policyconfig.LoadMetadata) {
	if !metadata.CacheTouched {
		// Rejected before the cache, or answered 304: nothing to say.
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if metadata.Sequence != 0 && metadata.Sequence < a.cached {
		return
	}
	a.cached = metadata.Sequence
	metrics.SetPolicySourceHealthy("cache", metadata.CachePersistError == "")
}

// health reports a load's source health, unless a newer load already did,
// so an older refresh cannot overwrite a newer one's status.
func (a *policyApplier) health(metadata policyconfig.LoadMetadata, report func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if metadata.Sequence != 0 && metadata.Sequence < a.reported {
		return
	}
	a.reported = metadata.Sequence
	report()
}

func (a *policyApplier) apply(metrics *telemetry.Registry, controller *policyController, yaml *policyconfig.Manager, bundle policyconfig.Bundle, metadata policyconfig.LoadMetadata) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if metadata.Sequence != 0 && metadata.Sequence < a.applied {
		// A newer load is already in force.
		return nil
	}
	if err := applyPolicyWithHealth(metrics, func() error {
		return controller.ApplyBundle(bundle)
	}); err != nil {
		return err
	}
	a.applied = metadata.Sequence
	yaml.SetAppliedDigest(metadata.RemoteDigest)
	return nil
}

func runPolicyReloads(
	ctx context.Context,
	applier *policyApplier,
	reloadCh <-chan reloadRequest,
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
		case request, ok := <-reloadCh:
			if !ok {
				return
			}
			reloadErr := reloadPolicy(ctx, applier, request.trigger, yaml, controller, cfg, recorder, metrics)
			if request.done != nil {
				request.done <- reloadErr
			}
		}
	}
}

func reloadPolicy(
	ctx context.Context,
	applier *policyApplier,
	trigger string,
	yaml *policyconfig.Manager,
	controller *policyController,
	cfg config.Config,
	recorder *eventsink.Recorder,
	metrics *telemetry.Registry,
) error {
	bundle, metadata, reloadErr := yaml.Load(ctx)
	source := yamlPolicySource(metadata, cfg)
	metrics.IncPolicySourceLoad(source, reloadErr == nil)
	if cfg.PolicyURL != "" {
		applier.cacheHealth(metrics, metadata)
	}
	applier.health(metadata, func() { setYAMLPolicyHealth(metrics, cfg, metadata, reloadErr) })
	if metadata.CachePersistError != "" {
		recorder.Error("persist fetched YAML policy cache", errors.New(metadata.CachePersistError), nil)
	}
	if metadata.StaleFallback {
		recorder.ErrorDedup("remote YAML policy unavailable; using stale cache", errors.New(metadata.RemoteError), nil, policyRefreshErrorDedupeTTL)
	}
	if reloadErr == nil {
		reloadErr = applier.apply(metrics, controller, yaml, bundle, metadata)
	}
	if reloadErr != nil {
		metrics.IncPolicyReload(trigger, false)
		recorder.Error("reload policy", reloadErr, map[string]any{"trigger": trigger})
		return reloadErr
	}
	if metadata.StaleFallback {
		// The policy in force is the last known one; say so rather than
		// report a fresh fetch.
		metrics.IncPolicyReload(trigger, true)
		return fmt.Errorf("the remote policy could not be fetched, so the last known policy stays in force: %s", metadata.RemoteError)
	}
	metrics.IncPolicyReload(trigger, true)
	recorder.Info("policy reloaded", map[string]any{"trigger": trigger})
	return nil
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
