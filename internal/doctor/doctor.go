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
	"github.com/L1ghtn1ng/traceguard/internal/processinfo"
)

var defaultChecks = environmentChecks{
	stat:                      os.Stat,
	readFile:                  os.ReadFile,
	statfs:                    unix.Statfs,
	geteuid:                   os.Geteuid,
	validateProcRoot:          processinfo.ValidateRoot,
	checkTracepointPerfAccess: checkTracepointPerfEventAccess,
	detectKernelFeatures:      ebpfmonitor.ProbeKernelFeatures,
}

type environmentChecks struct {
	stat                      func(string) (fs.FileInfo, error)
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
	check(strings.TrimSpace(cfg.CachePath) != "" && filepath.IsAbs(cfg.CachePath), "cache-path", emptyDetail(cfg.CachePath, "must be a non-empty absolute path"))

	if cfg.BlocklistURL != "" {
		parsed, err := url.Parse(cfg.BlocklistURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "", "blocklist-url", cfg.BlocklistURL)
	} else {
		check(true, "blocklist-url", "not configured")
	}

	if cfg.MetricsAddr != "" {
		_, err := net.ResolveTCPAddr("tcp", cfg.MetricsAddr)
		check(err == nil, "metrics-addr", cfg.MetricsAddr)
	} else {
		check(true, "metrics-addr", "disabled")
	}
	if cfg.EventExportURL != "" {
		parsed, err := url.Parse(cfg.EventExportURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "", "event-export-url", cfg.EventExportURL)
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
		check(err == nil && validSyslogURL(parsed), "event-syslog-url", cfg.EventSyslogURL)
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
	check(true, "kernel-bpf-object", emptyDetail(features.SelectedObject, "none"))
	check(true, "kernel-enhanced-telemetry", enhancedTelemetryDetail(features))

	check(cfg.LogFormat == "text" || cfg.LogFormat == "json", "log-format", cfg.LogFormat)
	check(cfg.ProcessCacheTTL > 0, "process-cache-ttl", cfg.ProcessCacheTTL.String())
	check(true, "file-audit", enabledDetail(cfg.FileAudit))
	check(true, "selinux", selinuxStatus(env))
	check(true, "apparmor", apparmorStatus(env))
	if cfg.KubernetesEnrich {
		parsed, err := url.Parse(cfg.KubernetesAPIURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "", "kubernetes-api-url", cfg.KubernetesAPIURL)
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
