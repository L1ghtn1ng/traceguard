package doctor

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/L1ghtn1ng/traceguard/internal/config"
)

func TestRunReportsReadyEnvironment(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := readyConfig(root)
	var out bytes.Buffer

	err := runWithChecks(cfg, &out, passingChecks(t, root))
	if err != nil {
		t.Fatalf("runWithChecks returned error: %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "PASS summary: environment looks ready for TraceGuard") {
		t.Fatalf("output missing success summary:\n%s", out.String())
	}
}

func TestRunReportsConfigAndEnvironmentFailures(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := readyConfig(root)
	cfg.BlocklistURL = "http://example.test/blocklist.txt"
	cfg.EventExportURL = "http://collector.test/events"
	cfg.EventExportCAPath = filepath.Join(root, "missing-ca.crt")
	cfg.EventExportClientCert = filepath.Join(root, "missing-client.crt")
	cfg.EventExportClientKey = filepath.Join(root, "missing-client.key")
	cfg.EventSyslogURL = "syslog://collector.test"
	cfg.EventSyslogFacility = "bad"
	cfg.EventSyslogTag = "bad tag"
	cfg.EventSyslogTimeout = 0
	cfg.EventSyslogCAPath = filepath.Join(root, "missing-syslog-ca.crt")
	cfg.KubernetesEnrich = true
	cfg.KubernetesAPIURL = "http://kubernetes.default.svc"
	cfg.KubernetesTokenPath = filepath.Join(root, "missing-token")
	cfg.KubernetesCAPath = filepath.Join(root, "missing-kube-ca")
	cfg.KubernetesPoll = 0
	cfg.ProcessCacheTTL = 0

	checks := passingChecks(t, root)
	checks.geteuid = func() int { return 1000 }
	checks.checkTracepointPerfAccess = func() error { return errors.New("perf denied") }

	var out bytes.Buffer
	err := runWithChecks(cfg, &out, checks)
	if err == nil {
		t.Fatalf("runWithChecks returned nil; output:\n%s", out.String())
	}
	text := out.String()
	for _, want := range []string{
		"FAIL blocklist-url",
		"FAIL event-export-url",
		"FAIL event-export-ca-path",
		"FAIL event-export-client-cert",
		"FAIL event-export-client-key",
		"FAIL event-syslog-url",
		"FAIL event-syslog-facility",
		"FAIL event-syslog-tag",
		"FAIL event-syslog-timeout",
		"FAIL event-syslog-ca-path",
		"FAIL privileges",
		"FAIL tracepoint-perf-event",
		"FAIL process-cache-ttl",
		"FAIL kubernetes-api-url",
		"FAIL kubernetes-token-path",
		"FAIL kubernetes-ca-path",
		"FAIL kubernetes-poll-interval",
		"doctor found 17 failing checks",
	} {
		if !strings.Contains(text+"\n"+err.Error(), want) {
			t.Fatalf("missing %q\noutput:\n%s\nerr:%v", want, text, err)
		}
	}
}

func TestSummary(t *testing.T) {
	t.Parallel()

	if got := Summary(nil); got != "ok" {
		t.Fatalf("Summary(nil) = %q, want ok", got)
	}
	if got := Summary(errors.New(" failed \n")); got != "failed" {
		t.Fatalf("Summary(error) = %q, want trimmed message", got)
	}
}

func readyConfig(root string) config.Config {
	return config.Config{
		CgroupPath:          filepath.Join(root, "cgroup"),
		LogPath:             filepath.Join(root, "logs", "traceguard.log"),
		LogFormat:           "json",
		MetricsAddr:         "127.0.0.1:0",
		EventExportURL:      "https://collector.test/events",
		EventExportCAPath:   filepath.Join(root, "ca.crt"),
		ProcessCacheTTL:     time.Minute,
		KubernetesNodeName:  "node-a",
		KubernetesPoll:      time.Minute,
		KubernetesAPIURL:    "https://kubernetes.default.svc",
		KubernetesTokenPath: filepath.Join(root, "token"),
		KubernetesCAPath:    filepath.Join(root, "kube-ca.crt"),
	}
}

func passingChecks(t *testing.T, root string) environmentChecks {
	t.Helper()

	for _, path := range []string{
		filepath.Join(root, "cgroup"),
		filepath.Join(root, "logs"),
	} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
	}
	for _, path := range []string{
		filepath.Join(root, "ca.crt"),
		filepath.Join(root, "token"),
		filepath.Join(root, "kube-ca.crt"),
		filepath.Join(root, "client.crt"),
		filepath.Join(root, "client.key"),
	} {
		if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	return environmentChecks{
		stat: os.Stat,
		readFile: func(path string) ([]byte, error) {
			switch path {
			case "/sys/fs/selinux/enforce":
				return []byte("1\n"), nil
			case "/sys/module/apparmor/parameters/enabled":
				return []byte("Y\n"), nil
			default:
				return nil, &fs.PathError{Op: "read", Path: path, Err: fs.ErrNotExist}
			}
		},
		statfs: func(path string, out *unix.Statfs_t) error {
			if _, err := os.Stat(path); err != nil {
				return err
			}
			out.Type = unix.CGROUP2_SUPER_MAGIC
			return nil
		},
		geteuid: func() int { return 0 },
		validateProcRoot: func(path string) error {
			if path != "/proc" {
				return &fs.PathError{Op: "validate", Path: path, Err: fs.ErrNotExist}
			}
			return nil
		},
		checkTracepointPerfAccess: func() error { return nil },
	}
}
