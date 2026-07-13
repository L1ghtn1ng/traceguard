package doctor

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
	"golang.org/x/sys/unix"
)

func validSyslogURL(parsed *url.URL) bool {
	if parsed == nil {
		return false
	}
	switch parsed.Scheme {
	case "syslog+udp", "syslog+tcp", "syslog+tls":
	default:
		return false
	}
	return parsed.Hostname() != "" && parsed.Port() != ""
}

func validSyslogFacility(facility string) bool {
	switch strings.ToLower(strings.TrimSpace(facility)) {
	case "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp",
		"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7":
		return true
	default:
		return false
	}
}

func validSyslogTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	return tag != "" && !strings.ContainsAny(tag, " \t\r\n")
}

func Summary(err error) string {
	if err == nil {
		return "ok"
	}
	return strings.TrimSpace(err.Error())
}

func enabledDetail(enabled bool) string {
	if enabled {
		return "enabled"
	}
	return "disabled"
}

func emptyDetail(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func enhancedTelemetryDetail(features ebpfmonitor.KernelFeatures) string {
	if features.EnhancedTelemetry {
		return "enabled"
	}
	if features.EnhancedLoadFailure != "" {
		return "disabled: " + features.EnhancedLoadFailure
	}
	return "disabled"
}

func selinuxStatus(env environmentChecks) string {
	raw, err := env.readFile("/sys/fs/selinux/enforce")
	if err != nil {
		return "not detected"
	}
	switch strings.TrimSpace(string(raw)) {
	case "1":
		return "enforcing"
	case "0":
		return "permissive"
	default:
		return "detected"
	}
}

func apparmorStatus(env environmentChecks) string {
	raw, err := env.readFile("/sys/module/apparmor/parameters/enabled")
	if err != nil {
		return "not detected"
	}
	switch strings.ToUpper(strings.TrimSpace(string(raw))) {
	case "Y", "1":
		return "enabled"
	case "N", "0":
		return "disabled"
	default:
		return "detected"
	}
}

func checkTracepointPerfEventAccess() error {
	tracefsPath, err := locateTraceFS()
	if err != nil {
		return err
	}

	tracepointIDPath := filepath.Join(tracefsPath, "events", "syscalls", "sys_enter_execve", "id")
	// #nosec G304 -- tracepointIDPath is built from fixed tracefs candidates and a fixed kernel tracepoint path.
	rawID, err := os.ReadFile(tracepointIDPath)
	if err != nil {
		return fmt.Errorf("read tracepoint id: %w", err)
	}

	tracepointID, err := strconv.ParseUint(strings.TrimSpace(string(rawID)), 10, 64)
	if err != nil {
		return fmt.Errorf("parse tracepoint id %q: %w", strings.TrimSpace(string(rawID)), err)
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Size:        uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
		Config:      tracepointID,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}

	fd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return fmt.Errorf("%w; grant CAP_PERFMON (or CAP_SYS_ADMIN on older kernels) or lower kernel.perf_event_paranoid", err)
		}
		return fmt.Errorf("open tracepoint perf event: %w", err)
	}
	_ = unix.Close(fd)

	return nil
}

func locateTraceFS() (string, error) {
	candidates := []string{
		"/sys/kernel/tracing",
		"/sys/kernel/debug/tracing",
	}
	for _, candidate := range candidates {
		info, err := os.Stat(filepath.Join(candidate, "events"))
		if err == nil && info.IsDir() {
			return candidate, nil
		}
	}
	return "", errors.New("tracefs is not mounted at /sys/kernel/tracing or /sys/kernel/debug/tracing")
}
