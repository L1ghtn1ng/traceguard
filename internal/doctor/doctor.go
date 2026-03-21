package doctor

import (
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"

	"traceguard/internal/config"
	"traceguard/internal/processinfo"
)

func Run(cfg config.Config, w io.Writer) error {
	var failures int

	check := func(ok bool, name, detail string) {
		state := "PASS"
		if !ok {
			state = "FAIL"
			failures++
		}
		_, _ = fmt.Fprintf(w, "%s %s: %s\n", state, name, detail)
	}

	check(runtime.GOOS == "linux", "os", fmt.Sprintf("runtime=%s", runtime.GOOS))

	if info, err := os.Stat(cfg.CgroupPath); err != nil {
		check(false, "cgroup-path", err.Error())
	} else {
		check(info.IsDir(), "cgroup-path", cfg.CgroupPath)
	}

	var statfs unix.Statfs_t
	if err := unix.Statfs(cfg.CgroupPath, &statfs); err != nil {
		check(false, "cgroup-v2", err.Error())
	} else {
		check(uint64(statfs.Type) == unix.CGROUP2_SUPER_MAGIC, "cgroup-v2", fmt.Sprintf("fstype=%#x", uint64(statfs.Type)))
	}

	logDir := filepath.Dir(cfg.LogPath)
	if !filepath.IsAbs(cfg.LogPath) {
		check(false, "log-path", "must be absolute")
	} else if info, err := os.Stat(logDir); err == nil {
		check(info.IsDir(), "log-path", cfg.LogPath)
	} else if os.IsNotExist(err) {
		parent := filepath.Dir(logDir)
		parentInfo, parentErr := os.Stat(parent)
		check(parentErr == nil && parentInfo.IsDir(), "log-path", fmt.Sprintf("%s (directory will be created at startup)", cfg.LogPath))
	} else {
		check(false, "log-path", err.Error())
	}

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
			if info, err := os.Stat(cfg.EventExportCAPath); err != nil {
				check(false, "event-export-ca-path", err.Error())
			} else {
				check(!info.IsDir(), "event-export-ca-path", cfg.EventExportCAPath)
			}
		} else {
			check(true, "event-export-ca-path", "system trust store")
		}
		if cfg.EventExportClientCert != "" || cfg.EventExportClientKey != "" {
			if info, err := os.Stat(cfg.EventExportClientCert); err != nil {
				check(false, "event-export-client-cert", err.Error())
			} else {
				check(!info.IsDir(), "event-export-client-cert", cfg.EventExportClientCert)
			}
			if info, err := os.Stat(cfg.EventExportClientKey); err != nil {
				check(false, "event-export-client-key", err.Error())
			} else {
				check(!info.IsDir(), "event-export-client-key", cfg.EventExportClientKey)
			}
		} else {
			check(true, "event-export-client-cert", "disabled")
		}
	}

	if err := processinfo.ValidateRoot("/proc"); err != nil {
		check(false, "procfs", err.Error())
	} else {
		check(true, "procfs", "/proc")
	}

	euid := os.Geteuid()
	check(euid == 0, "privileges", fmt.Sprintf("effective_uid=%d", euid))

	check(cfg.LogFormat == "text" || cfg.LogFormat == "json", "log-format", cfg.LogFormat)
	check(cfg.ProcessCacheTTL > 0, "process-cache-ttl", cfg.ProcessCacheTTL.String())
	if cfg.KubernetesEnrich {
		parsed, err := url.Parse(cfg.KubernetesAPIURL)
		check(err == nil && parsed.Scheme == "https" && parsed.Host != "", "kubernetes-api-url", cfg.KubernetesAPIURL)
		if info, err := os.Stat(cfg.KubernetesTokenPath); err != nil {
			check(false, "kubernetes-token-path", err.Error())
		} else {
			check(!info.IsDir(), "kubernetes-token-path", cfg.KubernetesTokenPath)
		}
		if info, err := os.Stat(cfg.KubernetesCAPath); err != nil {
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

	if failures > 0 {
		return fmt.Errorf("doctor found %d failing checks", failures)
	}
	_, _ = io.WriteString(w, "PASS summary: environment looks ready for TraceGuard\n")
	return nil
}

func Summary(err error) string {
	if err == nil {
		return "ok"
	}
	return strings.TrimSpace(err.Error())
}
