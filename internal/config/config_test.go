package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseWildcardPolicyViaFlag(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "*"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !slices.Contains(cfg.ManualDomains, "*") {
		t.Fatalf("ManualDomains = %v, want wildcard deny-all marker", cfg.ManualDomains)
	}
}

func TestParseWildcardPolicyViaEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "*")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !slices.Contains(cfg.ManualDomains, "*") {
		t.Fatalf("ManualDomains = %v, want wildcard deny-all marker", cfg.ManualDomains)
	}
}

func TestParseRejectsUnexpectedPositionalArgs(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "README.md", "LICENSE"}

	clearPolicyEnv(t)

	_, err := Parse()
	if err == nil {
		t.Fatal("Parse succeeded with unexpected positional arguments")
	}
	if !strings.Contains(err.Error(), "quote '*'") || strings.Contains(err.Error(), "-block-all") {
		t.Fatalf("Parse error = %q, want wildcard-only shell-quoting guidance", err)
	}
}

func TestParseRejectsRemovedBlockAllFlag(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block-all"}

	clearPolicyEnv(t)

	_, err := Parse()
	if err == nil {
		t.Fatal("Parse accepted removed -block-all flag")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") || !strings.Contains(err.Error(), "-block-all") {
		t.Fatalf("Parse error = %q, want unknown flag for -block-all", err)
	}
}

func TestParseIgnoresRemovedBlockAllEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_ALL", "true")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	_, err := Parse()
	if err == nil || !strings.Contains(err.Error(), "require at least one policy source") {
		t.Fatalf("Parse error = %v, want missing policy source after ignoring TRACEGUARD_BLOCK_ALL", err)
	}
}

func TestParseDefaultsLogFormatToJSON(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)
	if err := os.Unsetenv("TRACEGUARD_LOG_FORMAT"); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("LogFormat = %q, want json", cfg.LogFormat)
	}
}

func TestParseDefaultsMatchPackagedEnv(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)
	unsetEnv(t,
		"TRACEGUARD_CACHE_PATH",
		"TRACEGUARD_REFRESH_INTERVAL",
		"TRACEGUARD_CGROUP_PATH",
		"TRACEGUARD_LOG_PATH",
		"TRACEGUARD_LOG_FORMAT",
		"TRACEGUARD_METRICS_ADDR",
		"TRACEGUARD_EVENT_EXPORT_AUTHORIZATION",
		"TRACEGUARD_EVENT_EXPORT_SPOOL",
		"TRACEGUARD_EVENT_SYSLOG_URL",
		"TRACEGUARD_EVENT_SYSLOG_FACILITY",
		"TRACEGUARD_EVENT_SYSLOG_TAG",
		"TRACEGUARD_EVENT_SYSLOG_TIMEOUT",
		"TRACEGUARD_EVENT_SYSLOG_CA_PATH",
		"TRACEGUARD_PROCESS_CACHE_TTL",
		"TRACEGUARD_FILE_AUDIT",
		"TRACEGUARD_KUBERNETES_ENRICH",
		"TRACEGUARD_KUBERNETES_API_URL",
		"TRACEGUARD_KUBERNETES_TOKEN_PATH",
		"TRACEGUARD_KUBERNETES_CA_PATH",
		"TRACEGUARD_KUBERNETES_NODE_NAME",
		"TRACEGUARD_KUBERNETES_POLL_INTERVAL",
	)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.CachePath != "/var/lib/traceguard/blocklist.txt" {
		t.Fatalf("CachePath = %q, want packaged default", cfg.CachePath)
	}
	if cfg.RefreshInterval.String() != "6h0m0s" {
		t.Fatalf("RefreshInterval = %s, want 6h", cfg.RefreshInterval)
	}
	if cfg.CgroupPath != "/sys/fs/cgroup" {
		t.Fatalf("CgroupPath = %q, want packaged default", cfg.CgroupPath)
	}
	if cfg.LogPath != "/var/log/traceguard/traceguard.log" || cfg.LogFormat != "json" {
		t.Fatalf("log defaults = path %q format %q, want packaged defaults", cfg.LogPath, cfg.LogFormat)
	}
	if cfg.MetricsAddr != ":9091" {
		t.Fatalf("MetricsAddr = %q, want :9091", cfg.MetricsAddr)
	}
	if cfg.EventExportAuthorization != "" || !cfg.EventExportSpool {
		t.Fatalf("export defaults = authorization %q spool %v, want packaged defaults", cfg.EventExportAuthorization, cfg.EventExportSpool)
	}
	if cfg.EventSyslogURL != "" || cfg.EventSyslogFacility != "local0" || cfg.EventSyslogTag != "traceguard" || cfg.EventSyslogTimeout != 5*time.Second || cfg.EventSyslogCAPath != "" {
		t.Fatalf("syslog defaults = url %q facility %q tag %q timeout %s ca %q, want packaged defaults", cfg.EventSyslogURL, cfg.EventSyslogFacility, cfg.EventSyslogTag, cfg.EventSyslogTimeout, cfg.EventSyslogCAPath)
	}
	if cfg.ProcessCacheTTL.String() != "2m0s" {
		t.Fatalf("ProcessCacheTTL = %s, want 2m", cfg.ProcessCacheTTL)
	}
	if !cfg.FileAudit {
		t.Fatal("FileAudit = false, want packaged default true")
	}
	if cfg.KubernetesEnrich {
		t.Fatal("KubernetesEnrich = true, want packaged default false")
	}
	if cfg.KubernetesAPIURL != "" || cfg.KubernetesNodeName != "" {
		t.Fatalf("Kubernetes defaults = api %q node %q, want empty packaged defaults", cfg.KubernetesAPIURL, cfg.KubernetesNodeName)
	}
	if cfg.KubernetesTokenPath != "/var/run/secrets/kubernetes.io/serviceaccount/token" || cfg.KubernetesCAPath != "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt" || cfg.KubernetesPoll.String() != "2m0s" {
		t.Fatalf("Kubernetes path/poll defaults = token %q ca %q poll %s, want packaged defaults", cfg.KubernetesTokenPath, cfg.KubernetesCAPath, cfg.KubernetesPoll)
	}
}

func TestParseVersionDoesNotRequireUserCacheDir(t *testing.T) {
	originalArgs := os.Args
	originalHome, hadHome := os.LookupEnv("HOME")
	originalXDG, hadXDG := os.LookupEnv("XDG_CACHE_HOME")
	t.Cleanup(func() {
		os.Args = originalArgs
		restoreEnv("HOME", originalHome, hadHome)
		restoreEnv("XDG_CACHE_HOME", originalXDG, hadXDG)
	})
	os.Args = []string{"traceguard", "-v"}
	if err := os.Unsetenv("HOME"); err != nil {
		t.Fatalf("Unsetenv HOME returned error: %v", err)
	}
	if err := os.Unsetenv("XDG_CACHE_HOME"); err != nil {
		t.Fatalf("Unsetenv XDG_CACHE_HOME returned error: %v", err)
	}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.PrintVersion {
		t.Fatal("PrintVersion = false, want true")
	}
}

func TestParseDisablesHTTPSExportSpoolFromEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_EVENT_EXPORT_SPOOL", "false")
	t.Setenv("TRACEGUARD_EVENT_EXPORT_AUTHORIZATION", "Bearer token")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-event-export-url", "https://collector.example/traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.EventExportSpool {
		t.Fatal("EventExportSpool = true, want false")
	}
	if cfg.EventExportAuthorization != "Bearer token" {
		t.Fatalf("EventExportAuthorization = %q, want Bearer token", cfg.EventExportAuthorization)
	}
}

func TestParseRejectsRemovedHTTPSExportFlags(t *testing.T) {
	tests := []string{
		"-event-export-auth-header",
		"-event-export-auth-token",
		"-event-export-batch-size",
		"-event-export-flush-interval",
		"-event-export-spool-path",
		"-event-export-gzip",
	}
	for _, flagName := range tests {
		flagName := flagName
		t.Run(flagName, func(t *testing.T) {
			originalArgs := os.Args
			t.Cleanup(func() { os.Args = originalArgs })
			os.Args = []string{"traceguard", flagName, "value"}

			clearPolicyEnv(t)

			_, err := Parse()
			if err == nil {
				t.Fatalf("Parse accepted removed %s flag", flagName)
			}
			if !strings.Contains(err.Error(), "flag provided but not defined") || !strings.Contains(err.Error(), flagName) {
				t.Fatalf("Parse error = %q, want unknown flag for %s", err, flagName)
			}
		})
	}
}

func TestParseAcceptsRemoteSyslogConfig(t *testing.T) {
	t.Setenv("TRACEGUARD_EVENT_SYSLOG_URL", "syslog+tls://syslog.example:6514")
	t.Setenv("TRACEGUARD_EVENT_SYSLOG_FACILITY", "local1")
	t.Setenv("TRACEGUARD_EVENT_SYSLOG_TAG", "traceguard-node")
	t.Setenv("TRACEGUARD_EVENT_SYSLOG_TIMEOUT", "3s")
	t.Setenv("TRACEGUARD_EVENT_SYSLOG_CA_PATH", "/etc/traceguard/syslog-ca.crt")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.EventSyslogURL != "syslog+tls://syslog.example:6514" || cfg.EventSyslogFacility != "local1" || cfg.EventSyslogTag != "traceguard-node" || cfg.EventSyslogTimeout != 3*time.Second || cfg.EventSyslogCAPath != "/etc/traceguard/syslog-ca.crt" {
		t.Fatalf("syslog config = %#v, want parsed values", cfg)
	}
}

func TestParseRejectsInvalidRemoteSyslogConfig(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "scheme",
			env:  map[string]string{"TRACEGUARD_EVENT_SYSLOG_URL": "udp://syslog.example:514"},
			want: "event-syslog-url must use",
		},
		{
			name: "missing port",
			env:  map[string]string{"TRACEGUARD_EVENT_SYSLOG_URL": "syslog+udp://syslog.example"},
			want: "event-syslog-url must include host and port",
		},
		{
			name: "facility",
			env: map[string]string{
				"TRACEGUARD_EVENT_SYSLOG_URL":      "syslog+udp://syslog.example:514",
				"TRACEGUARD_EVENT_SYSLOG_FACILITY": "bad",
			},
			want: "event-syslog-facility",
		},
		{
			name: "tag",
			env: map[string]string{
				"TRACEGUARD_EVENT_SYSLOG_URL": "syslog+udp://syslog.example:514",
				"TRACEGUARD_EVENT_SYSLOG_TAG": "bad tag",
			},
			want: "event-syslog-tag",
		},
		{
			name: "timeout",
			env: map[string]string{
				"TRACEGUARD_EVENT_SYSLOG_URL":     "syslog+udp://syslog.example:514",
				"TRACEGUARD_EVENT_SYSLOG_TIMEOUT": "0s",
			},
			want: "event-syslog-timeout",
		},
		{
			name: "relative ca",
			env: map[string]string{
				"TRACEGUARD_EVENT_SYSLOG_URL":     "syslog+tls://syslog.example:6514",
				"TRACEGUARD_EVENT_SYSLOG_CA_PATH": "ca.crt",
			},
			want: "event-syslog-ca-path must be an absolute path",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			originalArgs := os.Args
			t.Cleanup(func() { os.Args = originalArgs })
			os.Args = []string{"traceguard"}
			clearPolicyEnv(t)
			for key, value := range tt.env {
				t.Setenv(key, value)
			}

			_, err := Parse()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseEnablesFileAuditFromEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_FILE_AUDIT", "true")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.FileAudit {
		t.Fatal("FileAudit = false, want true")
	}
}

func TestParseLoadsDomainFileFromEnv(t *testing.T) {
	path := writeDomainFile(t, "example.com\n# comment\nbad.example.org,one.one.one.one\n")

	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "@"+path)
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{"example.com", "bad.example.org", "one.one.one.one"}
	if !slices.Equal(cfg.ManualDomains, want) {
		t.Fatalf("ManualDomains = %v, want %v", cfg.ManualDomains, want)
	}
}

func restoreEnv(key, value string, present bool) {
	if present {
		_ = os.Setenv(key, value)
		return
	}
	_ = os.Unsetenv(key)
}

func unsetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		value, present := os.LookupEnv(key)
		t.Cleanup(func() { restoreEnv(key, value, present) })
		if err := os.Unsetenv(key); err != nil {
			t.Fatalf("Unsetenv %s returned error: %v", key, err)
		}
	}
}

func TestParseLoadsDomainFileFromFlag(t *testing.T) {
	path := writeDomainFile(t, "example.com\nbad.example.org\n")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "@" + path, "-allow-domain", "resolver.example.com"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !slices.Equal(cfg.ManualDomains, []string{"example.com", "bad.example.org"}) {
		t.Fatalf("ManualDomains = %v, want file-loaded entries", cfg.ManualDomains)
	}
	if !slices.Equal(cfg.ManualAllow, []string{"resolver.example.com"}) {
		t.Fatalf("ManualAllow = %v, want inline allow entry", cfg.ManualAllow)
	}
}

func TestParseMergesInlineAndFileBackedInputs(t *testing.T) {
	path := writeDomainFile(t, "example.com\nbad.example.org\n")

	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "resolver.example.com")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block-domain", "@" + path, "-block-domain", "*.svc.cluster.local", "-allow-domain", "@" + path}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !slices.Equal(cfg.ManualDomains, []string{"example.com", "bad.example.org", "*.svc.cluster.local"}) {
		t.Fatalf("ManualDomains = %v, want merged inline and file-backed block entries", cfg.ManualDomains)
	}
	if !slices.Equal(cfg.ManualAllow, []string{"resolver.example.com", "example.com", "bad.example.org"}) {
		t.Fatalf("ManualAllow = %v, want merged env and file-backed allow entries", cfg.ManualAllow)
	}
}

func TestParseRejectsRelativeDomainFileFromEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "@relative.txt")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	_, err := Parse()
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("Parse error = %v, want absolute path validation", err)
	}
}

func TestParseRejectsRelativeDomainFileFromFlag(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "@relative.txt"}

	clearPolicyEnv(t)

	_, err := Parse()
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("Parse error = %v, want absolute path validation", err)
	}
}

func TestParseUsesTraceguardKubernetesNodeNameOnly(t *testing.T) {
	t.Setenv("TRACEGUARD_KUBERNETES_NODE_NAME", "worker-a")
	t.Setenv("KUBE_NODE_NAME", "worker-b")
	t.Setenv("NODE_NAME", "worker-c")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.KubernetesNodeName != "worker-a" {
		t.Fatalf("KubernetesNodeName = %q, want worker-a", cfg.KubernetesNodeName)
	}
}

func TestParseAutoDetectsKubernetesAPIWhenEnabled(t *testing.T) {
	t.Setenv("TRACEGUARD_KUBERNETES_ENRICH", "true")
	t.Setenv("TRACEGUARD_KUBERNETES_API_URL", "")
	t.Setenv("TRACEGUARD_KUBERNETES_NODE_NAME", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT_HTTPS", "6443")
	t.Setenv("NODE_NAME", "worker-a")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.KubernetesAPIURL != "https://10.96.0.1:6443" {
		t.Fatalf("KubernetesAPIURL = %q, want detected service endpoint", cfg.KubernetesAPIURL)
	}
	if cfg.KubernetesNodeName != "worker-a" {
		t.Fatalf("KubernetesNodeName = %q, want NODE_NAME fallback", cfg.KubernetesNodeName)
	}
}

func TestParseAutoDetectsKubernetesAPIForDoctor(t *testing.T) {
	t.Setenv("TRACEGUARD_KUBERNETES_API_URL", "")
	t.Setenv("TRACEGUARD_KUBERNETES_NODE_NAME", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT_HTTPS", "6443")
	t.Setenv("NODE_NAME", "worker-a")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-doctor", "-kubernetes-enrich"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !cfg.Doctor {
		t.Fatal("Doctor = false, want true")
	}
	if cfg.KubernetesAPIURL != "https://10.96.0.1:6443" {
		t.Fatalf("KubernetesAPIURL = %q, want detected service endpoint", cfg.KubernetesAPIURL)
	}
	if cfg.KubernetesNodeName != "worker-a" {
		t.Fatalf("KubernetesNodeName = %q, want NODE_NAME fallback", cfg.KubernetesNodeName)
	}
}

func TestParseKubernetesUsesDefaultServiceURLWhenEnabledOutsideClusterEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_KUBERNETES_ENRICH", "true")
	t.Setenv("TRACEGUARD_KUBERNETES_API_URL", "")
	if err := os.Unsetenv("KUBERNETES_SERVICE_HOST"); err != nil {
		t.Fatalf("Unsetenv KUBERNETES_SERVICE_HOST returned error: %v", err)
	}
	if err := os.Unsetenv("KUBERNETES_SERVICE_PORT_HTTPS"); err != nil {
		t.Fatalf("Unsetenv KUBERNETES_SERVICE_PORT_HTTPS returned error: %v", err)
	}
	if err := os.Unsetenv("KUBERNETES_SERVICE_PORT"); err != nil {
		t.Fatalf("Unsetenv KUBERNETES_SERVICE_PORT returned error: %v", err)
	}

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.KubernetesAPIURL != "https://kubernetes.default.svc:443" {
		t.Fatalf("KubernetesAPIURL = %q, want default service endpoint", cfg.KubernetesAPIURL)
	}
}

func TestParseIgnoresLegacyKubernetesNodeAliases(t *testing.T) {
	t.Setenv("KUBE_NODE_NAME", "worker-b")
	t.Setenv("NODE_NAME", "worker-c")
	if err := os.Unsetenv("TRACEGUARD_KUBERNETES_NODE_NAME"); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.KubernetesNodeName != "" {
		t.Fatalf("KubernetesNodeName = %q, want empty when only legacy aliases are set", cfg.KubernetesNodeName)
	}
}

func clearPolicyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TRACEGUARD_BLOCK", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")
	t.Setenv("TRACEGUARD_BLOCK_ALL", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
}

func writeDomainFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}
