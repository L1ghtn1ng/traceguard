package doctor

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/L1ghtn1ng/traceguard/internal/config"
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
)

var defaultChecks = environmentChecks{
	stat:                      os.Stat,
	lstat:                     os.Lstat,
	readFile:                  os.ReadFile,
	statfs:                    unix.Statfs,
	geteuid:                   os.Geteuid,
	validateProcRoot:          processinfo.ValidateRoot,
	checkTracepointPerfAccess: checkTracepointPerfEventAccess,
	detectKernelFeatures:      ebpfmonitor.ProbeKernelFeatures,
}

type environmentChecks struct {
	stat                      func(string) (fs.FileInfo, error)
	lstat                     func(string) (fs.FileInfo, error)
	readFile                  func(string) ([]byte, error)
	statfs                    func(string, *unix.Statfs_t) error
	geteuid                   func() int
	validateProcRoot          func(string) error
	checkTracepointPerfAccess func() error
	detectKernelFeatures      func() ebpfmonitor.KernelFeatures
}

func Run(cfg config.Config, w io.Writer) error {
	return runWithChecks(cfg, w, defaultChecks)
}

func runWithChecks(cfg config.Config, w io.Writer, env environmentChecks) error {
	var failures int
	var writeErr error
	var localPolicy *policyconfig.Document

	check := func(ok bool, name, detail string) {
		state := "PASS"
		if !ok {
			state = "FAIL"
			failures++
		}
		if _, err := fmt.Fprintf(w, "%s %s: %s\n", state, name, detail); err != nil {
			writeErr = errors.Join(writeErr, err)
		}
	}
	info := func(level, name, detail string) {
		if _, err := fmt.Fprintf(w, "%s %s: %s\n", level, name, detail); err != nil {
			writeErr = errors.Join(writeErr, err)
		}
	}

	check(runtime.GOOS == "linux", "os", fmt.Sprintf("runtime=%s", runtime.GOOS))

	if info, err := env.stat(cfg.CgroupPath); err != nil {
		check(false, "cgroup-path", err.Error())
	} else {
		check(info.IsDir(), "cgroup-path", cfg.CgroupPath)
	}

	var statfs unix.Statfs_t
	if err := env.statfs(cfg.CgroupPath, &statfs); err != nil {
		check(false, "cgroup-v2", err.Error())
	} else {
		check(statfs.Type == int64(unix.CGROUP2_SUPER_MAGIC), "cgroup-v2", fmt.Sprintf("fstype=%#x", statfs.Type))
	}

	logDir := filepath.Dir(cfg.LogPath)
	if !filepath.IsAbs(cfg.LogPath) {
		check(false, "log-path", "must be absolute")
	} else if info, err := env.stat(logDir); err == nil {
		check(info.IsDir(), "log-path", cfg.LogPath)
	} else if os.IsNotExist(err) {
		parent := filepath.Dir(logDir)
		parentInfo, parentErr := env.stat(parent)
		check(parentErr == nil && parentInfo.IsDir(), "log-path", fmt.Sprintf("%s (directory will be created at startup)", cfg.LogPath))
	} else {
		check(false, "log-path", err.Error())
	}
	check(strings.TrimSpace(cfg.PolicyCachePath) != "" && filepath.IsAbs(cfg.PolicyCachePath), "policy-cache-path", emptyDetail(cfg.PolicyCachePath, "must be a non-empty absolute path"))
	check(cfg.PolicyRefreshInterval > 0, "policy-refresh-interval", cfg.PolicyRefreshInterval.String())
	if cfg.PolicyPath != "" {
		if !filepath.IsAbs(cfg.PolicyPath) {
			check(false, "policy-path", "must be absolute")
		} else if info, err := env.stat(cfg.PolicyPath); err != nil {
			check(false, "policy-path", err.Error())
		} else if info.IsDir() {
			check(false, "policy-path", "must be a regular file")
		} else if info.Size() > policyconfig.MaxDocumentBytes {
			check(false, "policy-path", fmt.Sprintf("file exceeds %d bytes", policyconfig.MaxDocumentBytes))
		} else if payload, err := env.readFile(cfg.PolicyPath); err != nil {
			check(false, "policy-parse", err.Error())
		} else if document, err := policyconfig.Parse(payload); err != nil {
			check(false, "policy-parse", err.Error())
		} else {
			localPolicy = &document
			check(true, "policy-path", cfg.PolicyPath)
			check(true, "policy-parse", fmt.Sprintf("version=%d egress_rules=%d exec_rules=%d file_rules=%d bind_rules=%d unix_rules=%d sockopt_rules=%d detections=%d",
				document.Version, len(document.Egress.Rules), len(document.Exec.Rules), len(document.File.Rules),
				len(document.Bind.Rules), len(document.Unix.Rules), len(document.Sockopt.Rules), len(document.DetectionRules)))
		}
	} else {
		check(true, "policy-path", "not configured")
	}
	var remotePolicy *policyconfig.Document
	if cfg.PolicyURL != "" {
		parsed, err := url.Parse(cfg.PolicyURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil,
			"policy-url", config.SanitizeURL(cfg.PolicyURL))
		// Doctor does not fetch the remote policy, so the cached copy the daemon
		// falls back to is the best available view of the remote base policy.
		if document, err := readPolicyFile(env, cfg.PolicyCachePath); err != nil {
			info("WARN", "policy-remote-cache", fmt.Sprintf("remote policy is not fetched by doctor and the cache is unavailable (%v); exec/file enforcement checks cover only the local policy", err))
		} else {
			remotePolicy = &document
			check(true, "policy-remote-cache", fmt.Sprintf("%s exec_rules=%d file_rules=%d", cfg.PolicyCachePath, len(document.Exec.Rules), len(document.File.Rules)))
		}
	} else {
		check(true, "policy-url", "not configured")
	}
	if cfg.PinEBPF {
		bpffsRoot := filepath.Dir(ebpfmonitor.DefaultPinPath)
		bpffsInfo, statErr := env.stat(bpffsRoot)
		var bpffs unix.Statfs_t
		statfsErr := env.statfs(bpffsRoot, &bpffs)
		ready := statErr == nil && bpffsInfo.IsDir() && statfsErr == nil && bpffs.Type == int64(unix.BPF_FS_MAGIC)
		detail := fmt.Sprintf("%s (bpffs=%t)", ebpfmonitor.DefaultPinPath, statfsErr == nil && bpffs.Type == int64(unix.BPF_FS_MAGIC))
		if statErr != nil {
			detail = statErr.Error()
		} else if statfsErr != nil {
			detail = statfsErr.Error()
		}
		check(ready, "pin-dir", detail)
	} else if _, err := env.lstat(ebpfmonitor.DefaultPinPath); err == nil {
		check(false, "pin-dir", fmt.Sprintf("existing TraceGuard eBPF pins at %s may still be active; stop the previous daemon and run traceguard -unpin before starting without -pin-ebpf", ebpfmonitor.DefaultPinPath))
	} else if errors.Is(err, os.ErrNotExist) || errors.Is(err, fs.ErrNotExist) {
		check(true, "pin-dir", "disabled; no existing TraceGuard pins")
	} else {
		check(false, "pin-dir", fmt.Sprintf("check for existing eBPF pins at %s: %v", ebpfmonitor.DefaultPinPath, err))
	}
	for _, target := range []struct {
		path string
		name string
	}{
		{path: cfg.PolicyCAPath, name: "policy-ca-path"},
		{path: cfg.PolicyClientCert, name: "policy-client-cert"},
		{path: cfg.PolicyClientKey, name: "policy-client-key"},
	} {
		if target.path == "" {
			continue
		}
		if !filepath.IsAbs(target.path) {
			check(false, target.name, "must be absolute")
		} else if info, err := env.stat(target.path); err != nil {
			check(false, target.name, err.Error())
		} else {
			check(!info.IsDir(), target.name, target.path)
		}
	}
	check((cfg.PolicyClientCert == "") == (cfg.PolicyClientKey == ""), "policy-client-credentials", "certificate and key must be configured together")

	if cfg.MetricsAddr != "" {
		_, err := net.ResolveTCPAddr("tcp", cfg.MetricsAddr)
		check(err == nil, "metrics-addr", cfg.MetricsAddr)
		if err == nil && !isLoopbackListenAddress(cfg.MetricsAddr) {
			info("WARN", "metrics-exposure", "listener is not loopback-only; protect unauthenticated /metrics and /health with a trusted network boundary")
		}
	} else {
		check(true, "metrics-addr", "disabled")
	}
	if cfg.EventExportURL != "" {
		parsed, err := url.Parse(cfg.EventExportURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil,
			"event-export-url", config.SanitizeURL(cfg.EventExportURL))
		if cfg.EventExportCAPath != "" {
			if info, err := env.stat(cfg.EventExportCAPath); err != nil {
				check(false, "event-export-ca-path", err.Error())
			} else {
				check(!info.IsDir(), "event-export-ca-path", cfg.EventExportCAPath)
			}
		} else {
			check(true, "event-export-ca-path", "system trust store")
		}
		if cfg.EventExportClientCert != "" || cfg.EventExportClientKey != "" {
			if info, err := env.stat(cfg.EventExportClientCert); err != nil {
				check(false, "event-export-client-cert", err.Error())
			} else {
				check(!info.IsDir(), "event-export-client-cert", cfg.EventExportClientCert)
			}
			if info, err := env.stat(cfg.EventExportClientKey); err != nil {
				check(false, "event-export-client-key", err.Error())
			} else {
				check(!info.IsDir(), "event-export-client-key", cfg.EventExportClientKey)
			}
		} else {
			check(true, "event-export-client-cert", "disabled")
		}
	}
	if cfg.EventSyslogURL != "" {
		parsed, err := url.Parse(cfg.EventSyslogURL)
		check(err == nil && validSyslogURL(parsed) && parsed.User == nil,
			"event-syslog-url", config.SanitizeURL(cfg.EventSyslogURL))
		check(validSyslogFacility(cfg.EventSyslogFacility), "event-syslog-facility", cfg.EventSyslogFacility)
		check(validSyslogTag(cfg.EventSyslogTag), "event-syslog-tag", cfg.EventSyslogTag)
		check(cfg.EventSyslogTimeout > 0, "event-syslog-timeout", cfg.EventSyslogTimeout.String())
		if cfg.EventSyslogCAPath != "" {
			if info, err := env.stat(cfg.EventSyslogCAPath); err != nil {
				check(false, "event-syslog-ca-path", err.Error())
			} else {
				check(!info.IsDir(), "event-syslog-ca-path", cfg.EventSyslogCAPath)
			}
		} else if parsed != nil && parsed.Scheme == "syslog+tls" {
			check(true, "event-syslog-ca-path", "system trust store")
		}
	} else {
		check(true, "event-syslog", "disabled")
	}

	if err := env.validateProcRoot("/proc"); err != nil {
		check(false, "procfs", err.Error())
	} else {
		check(true, "procfs", "/proc")
	}

	euid := env.geteuid()
	check(euid == 0, "privileges", fmt.Sprintf("effective_uid=%d", euid))
	if err := env.checkTracepointPerfAccess(); err != nil {
		check(false, "tracepoint-perf-event", err.Error())
	} else {
		check(true, "tracepoint-perf-event", "syscalls/sys_enter_execve")
	}
	features := env.detectKernelFeatures()
	check(true, "kernel-release", emptyDetail(features.Release, "unknown"))
	check(features.KernelAtLeast612, "kernel-at-least-6.12", enabledDetail(features.KernelAtLeast612))
	check(true, "kernel-at-least-7.1", enabledDetail(features.KernelAtLeast71))
	check(true, "kernel-btf", enabledDetail(features.BTFAvailable))
	check(true, "kernel-bpf-lsm", enabledDetail(features.BPFLSMAvailable))
	check(true, "lsm-program-type", enabledDetail(features.LSMProgramType))
	check(true, "task-storage-map", enabledDetail(features.TaskStorage))
	info("INFO", "lsm-exec-attached", "verified by the real optional attach at daemon startup")
	info("INFO", "lsm-file-attached", "verified by the real optional attach at daemon startup")
	info("INFO", "cgroup-bind", "bind4 and bind6 are verified independently at daemon startup")
	info("INFO", "cgroup-unix", "connect, sendmsg, and recvmsg are verified independently at daemon startup")
	info("INFO", "cgroup-sockopt", "verified by the real optional attach at daemon startup")
	check(true, "kernel-bpf-object", emptyDetail(features.SelectedObject, "none"))
	check(true, "kernel-enhanced-telemetry", enhancedTelemetryDetail(features))
	if effective, ok := effectivePolicy(remotePolicy, localPolicy, check); ok {
		execBlocks := policyBlockRuleCount(effective.Exec.Rules, func(rule policyconfig.PathRule) string { return rule.Action })
		fileBlocks := policyBlockRuleCount(effective.File.Rules, func(rule policyconfig.FileRule) string { return rule.Action })
		lsmScopeOK := execBlocks+fileBlocks == 0 || filepath.Clean(cfg.CgroupPath) == "/sys/fs/cgroup"
		check(lsmScopeOK, "lsm-scope", "exec/file MAC enforcement is host-wide and requires cgroup-path /sys/fs/cgroup")
		if cfg.Block && !cfg.DryRun {
			// The daemon loads the exec and file LSM programs only with
			// task storage support as well.
			lsmReady := features.BPFLSMAvailable && features.LSMProgramType && features.TaskStorage
			check(execBlocks == 0 || lsmReady, "exec-enforce-ready", enabledDetail(lsmReady))
			check(fileBlocks == 0 || lsmReady, "file-enforce-ready", enabledDetail(lsmReady))
		}
		for _, rule := range effective.Exec.Rules {
			if rule.Action == "block" && len(rule.Selectors.UIDs) == 0 && len(rule.Selectors.CgroupPaths) == 0 && len(rule.Selectors.CgroupPrefixes) == 0 {
				info("WARN", "exec-host-wide-rule", fmt.Sprintf("rule %s has no selectors", rule.ID))
			}
		}
		for _, rule := range effective.File.Rules {
			if rule.Action == "block" && len(rule.Selectors.UIDs) == 0 && len(rule.Selectors.CgroupPaths) == 0 && len(rule.Selectors.CgroupPrefixes) == 0 {
				info("WARN", "file-host-wide-rule", fmt.Sprintf("rule %s has no selectors", rule.ID))
			}
		}
	}

	check(cfg.LogFormat == "text" || cfg.LogFormat == "json", "log-format", cfg.LogFormat)
	check(cfg.ProcessCacheTTL > 0, "process-cache-ttl", cfg.ProcessCacheTTL.String())
	check(true, "file-audit", enabledDetail(cfg.FileAudit))
	check(true, "selinux", selinuxStatus(env))
	check(true, "apparmor", apparmorStatus(env))
	for _, finding := range hostPosture(env.readFile, features) {
		info(finding.level, finding.name, finding.detail)
	}
	if cfg.KubernetesEnrich {
		parsed, err := url.Parse(cfg.KubernetesAPIURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil,
			"kubernetes-api-url", config.SanitizeURL(cfg.KubernetesAPIURL))
		if info, err := env.stat(cfg.KubernetesTokenPath); err != nil {
			check(false, "kubernetes-token-path", err.Error())
		} else {
			check(!info.IsDir(), "kubernetes-token-path", cfg.KubernetesTokenPath)
		}
		if info, err := env.stat(cfg.KubernetesCAPath); err != nil {
			check(false, "kubernetes-ca-path", err.Error())
		} else {
			check(!info.IsDir(), "kubernetes-ca-path", cfg.KubernetesCAPath)
		}
		check(cfg.KubernetesPoll > 0, "kubernetes-poll-interval", cfg.KubernetesPoll.String())
		if cfg.KubernetesNodeName != "" {
			check(true, "kubernetes-node-name", cfg.KubernetesNodeName)
		} else {
			check(true, "kubernetes-node-name", "cluster-wide pod listing")
		}
	} else {
		check(true, "kubernetes-enrich", "disabled")
	}

	if writeErr != nil {
		return fmt.Errorf("write doctor output: %w", writeErr)
	}
	if failures > 0 {
		return fmt.Errorf("doctor found %d failing checks", failures)
	}
	if _, err := io.WriteString(w, "PASS summary: environment looks ready for TraceGuard\n"); err != nil {
		return fmt.Errorf("write doctor summary: %w", err)
	}
	return nil
}

func isLoopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(address))
	if err != nil || host == "" {
		return false
	}
	host = strings.Trim(host, "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func policyBlockRuleCount[T any](rules []T, action func(T) string) int {
	count := 0
	for _, rule := range rules {
		if action(rule) == "block" {
			count++
		}
	}
	return count
}

// readPolicyFile reads and strictly parses a policy file through the injected
// environment, applying the same size limit as the daemon.
func readPolicyFile(env environmentChecks, path string) (policyconfig.Document, error) {
	if strings.TrimSpace(path) == "" || !filepath.IsAbs(path) {
		return policyconfig.Document{}, errors.New("path must be a non-empty absolute path")
	}
	info, err := env.stat(path)
	if err != nil {
		return policyconfig.Document{}, err
	}
	if !info.Mode().IsRegular() {
		return policyconfig.Document{}, fmt.Errorf("%s must be a regular file", path)
	}
	if info.Size() > policyconfig.MaxDocumentBytes {
		return policyconfig.Document{}, fmt.Errorf("%s exceeds %d bytes", path, policyconfig.MaxDocumentBytes)
	}
	payload, err := env.readFile(path)
	if err != nil {
		return policyconfig.Document{}, err
	}
	document, err := policyconfig.Parse(payload)
	if err != nil {
		return policyconfig.Document{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return document, nil
}

// effectivePolicy merges the cached remote base policy with the local overlay
// exactly as the daemon does, so enforcement readiness checks see rules from
// either source and honour disabled_rule_ids. It reports false when no policy
// source was loaded or the merge failed.
func effectivePolicy(remote, local *policyconfig.Document, check func(bool, string, string)) (policyconfig.Bundle, bool) {
	if remote == nil && local == nil {
		return policyconfig.Bundle{}, false
	}
	base := policyconfig.Document{Version: policyconfig.Version}
	if remote != nil {
		base = *remote
	}
	overlay := policyconfig.Document{Version: policyconfig.Version}
	if local != nil {
		overlay = *local
	}
	bundle, err := policyconfig.Merge(base, overlay)
	if err != nil {
		check(false, "policy-effective", err.Error())
		return policyconfig.Bundle{}, false
	}
	if remote != nil {
		check(true, "policy-effective", fmt.Sprintf("cached remote base merged with local overlay: exec_rules=%d file_rules=%d", len(bundle.Exec.Rules), len(bundle.File.Rules)))
	}
	return bundle, true
}
