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
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
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
	for _, want := range []string{
		"PASS kernel-release: 7.1.1-test",
		"PASS kernel-at-least-6.12: enabled",
		"PASS kernel-at-least-7.1: enabled",
		"PASS kernel-btf: enabled",
		"PASS kernel-bpf-lsm: enabled",
		"PASS lsm-program-type: enabled",
		"INFO lsm-exec-attached: verified by the real optional attach at daemon startup",
		"INFO cgroup-bind: bind4 and bind6 are verified independently at daemon startup",
		"PASS kernel-bpf-object: traceguardLinux71",
		"PASS kernel-enhanced-telemetry: enabled",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunWarnsAboutHostWideRulesAndRejectsSliceScope(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	policyPath := filepath.Join(root, "policy.yaml")
	payload := []byte("version: 1\nexec:\n  rules:\n    - id: global-exec\n      action: block\n      match: {path_globs: [/tmp/tool]}\n")
	if err := os.WriteFile(policyPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := readyConfig(root)
	cfg.PolicyPath = policyPath
	checks := passingChecks(t, root)
	baseReadFile := checks.readFile
	checks.readFile = func(path string) ([]byte, error) {
		if path == policyPath {
			return payload, nil
		}
		return baseReadFile(path)
	}
	var out bytes.Buffer
	err := runWithChecks(cfg, &out, checks)
	if err == nil {
		t.Fatal("runWithChecks() accepted slice-scoped host-wide LSM policy")
	}
	for _, want := range []string{"FAIL lsm-scope", "WARN exec-host-wide-rule: rule global-exec has no selectors"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunChecksBPFFSWhenPinningEnabled(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cfg := readyConfig(root)
	cfg.PinEBPF = true
	checks := passingChecks(t, root)
	baseStat := checks.stat
	baseStatfs := checks.statfs
	checks.stat = func(path string) (fs.FileInfo, error) {
		if path == "/sys/fs/bpf" {
			return os.Stat(filepath.Join(root, "cgroup"))
		}
		return baseStat(path)
	}
	checks.statfs = func(path string, out *unix.Statfs_t) error {
		if path == "/sys/fs/bpf" {
			out.Type = unix.BPF_FS_MAGIC
			return nil
		}
		return baseStatfs(path, out)
	}
	var out bytes.Buffer
	if err := runWithChecks(cfg, &out, checks); err != nil {
		t.Fatalf("runWithChecks() error = %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "PASS pin-dir: /sys/fs/bpf/traceguard (bpffs=true)") {
		t.Fatalf("pin-dir check missing:\n%s", out.String())
	}
}

func TestRunRejectsExistingOrUnreadablePinsWhenPinningDisabled(t *testing.T) {
	t.Parallel()

	existingInfo, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		lstat      func(string) (fs.FileInfo, error)
		wantDetail string
	}{
		{
			name: "existing pin root",
			lstat: func(string) (fs.FileInfo, error) {
				return existingInfo, nil
			},
			wantDetail: "traceguard -unpin before starting without -pin-ebpf",
		},
		{
			name: "inspection denied",
			lstat: func(path string) (fs.FileInfo, error) {
				return nil, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrPermission}
			},
			wantDetail: "permission denied",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			checks := passingChecks(t, root)
			checks.lstat = test.lstat
			var out bytes.Buffer
			err := runWithChecks(readyConfig(root), &out, checks)
			if err == nil {
				t.Fatalf("runWithChecks accepted unsafe pin state:\n%s", out.String())
			}
			if !strings.Contains(out.String(), "FAIL pin-dir") || !strings.Contains(out.String(), test.wantDetail) {
				t.Fatalf("pin-dir output missing %q:\n%s", test.wantDetail, out.String())
			}
		})
	}
}

func TestRunReportsConfigAndEnvironmentFailures(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := readyConfig(root)
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
		"doctor found 16 failing checks",
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

func TestRunReturnsWriterErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	err := runWithChecks(readyConfig(root), failingWriter{}, passingChecks(t, root))
	if err == nil || !strings.Contains(err.Error(), "write doctor output") {
		t.Fatalf("runWithChecks error = %v, want writer error", err)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func readyConfig(root string) config.Config {
	return config.Config{
		CgroupPath:            filepath.Join(root, "cgroup"),
		PolicyCachePath:       filepath.Join(root, "cache", "policy.yaml"),
		PolicyRefreshInterval: time.Minute,
		LogPath:               filepath.Join(root, "logs", "traceguard.log"),
		LogFormat:             "json",
		MetricsAddr:           "127.0.0.1:0",
		EventExportURL:        "https://collector.test/events",
		EventExportCAPath:     filepath.Join(root, "ca.crt"),
		ProcessCacheTTL:       time.Minute,
		KubernetesNodeName:    "node-a",
		KubernetesPoll:        time.Minute,
		KubernetesAPIURL:      "https://kubernetes.default.svc",
		KubernetesTokenPath:   filepath.Join(root, "token"),
		KubernetesCAPath:      filepath.Join(root, "kube-ca.crt"),
	}
}

func passingChecks(t *testing.T, root string) environmentChecks {
	t.Helper()

	for _, path := range []string{
		filepath.Join(root, "cgroup"),
		filepath.Join(root, "logs"),
	} {
		if err := os.MkdirAll(path, 0o750); err != nil {
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
		lstat: func(path string) (fs.FileInfo, error) {
			if path == ebpfmonitor.DefaultPinPath {
				return nil, &fs.PathError{Op: "lstat", Path: path, Err: fs.ErrNotExist}
			}
			return os.Lstat(path)
		},
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
		detectKernelFeatures: func() ebpfmonitor.KernelFeatures {
			return ebpfmonitor.KernelFeatures{
				Release:            "7.1.1-test",
				KernelAtLeast612:   true,
				KernelAtLeast71:    true,
				BTFAvailable:       true,
				BPFLSMAvailable:    true,
				LSMProgramType:     true,
				EnhancedTelemetry:  true,
				SelectedFeatureSet: "linux71",
				SelectedObject:     "traceguardLinux71",
			}
		},
	}
}

func TestDoctorSanitizesURLsAndWarnsForExposedMetrics(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	cfg := readyConfig(root)
	cfg.PolicyURL = "https://policy.test/v1?token=policy-secret"
	cfg.EventExportURL = "https://collector.test/events?token=export-secret"
	cfg.EventSyslogURL = "syslog+tls://logs.test:6514?token=syslog-secret"
	cfg.EventSyslogFacility = "local0"
	cfg.EventSyslogTag = "traceguard"
	cfg.EventSyslogTimeout = time.Second
	cfg.KubernetesEnrich = true
	cfg.KubernetesAPIURL = "https://kubernetes.test?token=kubernetes-secret"
	cfg.MetricsAddr = ":9091"
	var out bytes.Buffer

	if err := runWithChecks(cfg, &out, passingChecks(t, root)); err != nil {
		t.Fatalf("runWithChecks returned error: %v\n%s", err, out.String())
	}
	rendered := out.String()
	for _, secret := range []string{"policy-secret", "export-secret", "syslog-secret", "kubernetes-secret"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("doctor output retained %q:\n%s", secret, rendered)
		}
	}
	if !strings.Contains(rendered, "WARN metrics-exposure") {
		t.Fatalf("doctor output missing metrics exposure warning:\n%s", rendered)
	}
}

func TestLoopbackListenAddressClassification(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"127.0.0.1:9091", "[::1]:9091", "localhost:9091"} {
		if !isLoopbackListenAddress(address) {
			t.Errorf("isLoopbackListenAddress(%q) = false", address)
		}
	}
	for _, address := range []string{":9091", "0.0.0.0:9091", "[::]:9091", "10.0.0.1:9091"} {
		if isLoopbackListenAddress(address) {
			t.Errorf("isLoopbackListenAddress(%q) = true", address)
		}
	}
}

func writeCachedRemotePolicy(t *testing.T, cfg *config.Config, checks *environmentChecks, payload string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(cfg.PolicyCachePath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.PolicyCachePath, []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	baseReadFile := checks.readFile
	checks.readFile = func(path string) ([]byte, error) {
		if path == cfg.PolicyCachePath {
			return os.ReadFile(path) // #nosec G304 -- test-controlled temporary path.
		}
		return baseReadFile(path)
	}
}

const remoteHostWideExecPolicy = "version: 1\nexec:\n  rules:\n    - id: remote-global-exec\n      action: block\n      match: {path_globs: [/tmp/tool]}\n"

func TestRunEvaluatesCachedRemotePolicyForEnforcementChecks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cfg := readyConfig(root)
	cfg.PolicyURL = "https://policy.test/v1"
	cfg.Block = true
	checks := passingChecks(t, root)
	writeCachedRemotePolicy(t, &cfg, &checks, remoteHostWideExecPolicy)
	baseFeatures := checks.detectKernelFeatures
	checks.detectKernelFeatures = func() ebpfmonitor.KernelFeatures {
		features := baseFeatures()
		features.BPFLSMAvailable = false
		return features
	}
	var out bytes.Buffer
	if err := runWithChecks(cfg, &out, checks); err == nil {
		t.Fatalf("runWithChecks() passed a remote-only exec block rule without LSM readiness or host-wide scope\n%s", out.String())
	}
	for _, want := range []string{
		"PASS policy-remote-cache: " + cfg.PolicyCachePath + " exec_rules=1 file_rules=0",
		"PASS policy-effective: cached remote base merged with local overlay: exec_rules=1 file_rules=0",
		"FAIL lsm-scope",
		"FAIL exec-enforce-ready: disabled",
		"PASS file-enforce-ready",
		"WARN exec-host-wide-rule: rule remote-global-exec has no selectors",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
}

func TestRunHonoursLocalOverlayDisablingCachedRemoteRule(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	cfg := readyConfig(root)
	cfg.PolicyURL = "https://policy.test/v1"
	cfg.PolicyPath = filepath.Join(root, "policy.yaml")
	local := []byte("version: 1\ndisabled_rule_ids: [remote-global-exec]\n")
	if err := os.WriteFile(cfg.PolicyPath, local, 0o600); err != nil {
		t.Fatal(err)
	}
	checks := passingChecks(t, root)
	writeCachedRemotePolicy(t, &cfg, &checks, remoteHostWideExecPolicy)
	baseReadFile := checks.readFile
	checks.readFile = func(path string) ([]byte, error) {
		if path == cfg.PolicyPath {
			return local, nil
		}
		return baseReadFile(path)
	}
	var out bytes.Buffer
	if err := runWithChecks(cfg, &out, checks); err != nil {
		t.Fatalf("runWithChecks() error = %v\n%s", err, out.String())
	}
	for _, want := range []string{"PASS policy-effective: cached remote base merged with local overlay: exec_rules=0 file_rules=0", "PASS lsm-scope"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "exec-host-wide-rule") {
		t.Fatalf("disabled remote rule still reported:\n%s", out.String())
	}
}

func TestRunWarnsWhenRemotePolicyCacheUnavailable(t *testing.T) {
	t.Parallel()
	for name, payload := range map[string]string{
		"missing": "",
		"invalid": "version: 2\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			cfg := readyConfig(root)
			cfg.PolicyURL = "https://policy.test/v1"
			checks := passingChecks(t, root)
			if payload != "" {
				writeCachedRemotePolicy(t, &cfg, &checks, payload)
			}
			var out bytes.Buffer
			if err := runWithChecks(cfg, &out, checks); err != nil {
				t.Fatalf("runWithChecks() error = %v\n%s", err, out.String())
			}
			if !strings.Contains(out.String(), "WARN policy-remote-cache: remote policy is not fetched by doctor and the cache is unavailable") {
				t.Fatalf("output missing remote cache warning:\n%s", out.String())
			}
			if strings.Contains(out.String(), "policy-effective") || strings.Contains(out.String(), "lsm-scope") {
				t.Fatalf("enforcement checks ran without a policy:\n%s", out.String())
			}
		})
	}
}
