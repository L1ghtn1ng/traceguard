package config

import (
	"errors"
	"flag"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultPolicyRefresh   = 5 * time.Minute
	defaultCgroupPath      = "/sys/fs/cgroup"
	defaultPolicyCachePath = "/var/lib/traceguard/policy.yaml"
	defaultLogPath         = "/var/log/traceguard/traceguard.log"
	defaultLogFormat       = "json"
	defaultMetricsAddr     = "127.0.0.1:9091"
	defaultProcessCacheTTL = 5 * time.Minute
	defaultSyslogFacility  = "local0"
	defaultSyslogTag       = "traceguard"
	defaultSyslogTimeout   = 5 * time.Second
	// #nosec G101 -- this is the standard Kubernetes service-account token path, not an embedded credential value.
	defaultKubeTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultKubeCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultKubePoll      = 2 * time.Minute

	defaultHeartbeatInterval      = 5 * time.Minute
	defaultConnectionDedupeWindow = time.Minute
	maxConnectionDedupeWindow     = time.Hour
)

type Config struct {
	Block                        bool
	DryRun                       bool
	EmergencyAllow               bool
	PinEBPF                      bool
	Unpin                        bool
	EBPFStats                    bool
	PolicyPath                   string
	PolicyURL                    string
	PolicyCachePath              string
	PolicyRefreshInterval        time.Duration
	PolicyAuthorization          string
	PolicyAuthorizationFile      string
	PolicyCAPath                 string
	PolicyClientCert             string
	PolicyClientKey              string
	CgroupPath                   string
	LogPath                      string
	LogFormat                    string
	MetricsAddr                  string
	EventArchivePath             string
	EventExportURL               string
	EventExportAuthorization     string
	EventExportAuthorizationFile string
	EventExportSpool             bool
	EventExportCAPath            string
	EventExportClientCert        string
	EventExportClientKey         string
	EventSyslogURL               string
	EventSyslogFacility          string
	EventSyslogTag               string
	EventSyslogTimeout           time.Duration
	EventSyslogCAPath            string
	EventSchema                  string
	ResponseMode                 string
	ProcessCacheTTL              time.Duration
	FileAudit                    bool
	SecurityEvents               bool
	KubernetesEnrich             bool
	KubernetesAPIURL             string
	KubernetesTokenPath          string
	KubernetesCAPath             string
	KubernetesNodeName           string
	KubernetesPoll               time.Duration
	StrictHooks                  bool
	HeartbeatInterval            time.Duration
	PolicySigningKey             string
	ConnectionDedupeWindow       time.Duration
	PrintVersion                 bool
	Doctor                       bool
	ReplayPath                   string
}

func Parse() (Config, error) {
	blockDefault, err := envBool("TRACEGUARD_BLOCK", false)
	if err != nil {
		return Config{}, err
	}
	dryRunDefault, err := envBool("TRACEGUARD_DRY_RUN", false)
	if err != nil {
		return Config{}, err
	}
	emergencyAllowDefault, err := envBool("TRACEGUARD_EMERGENCY_ALLOW", false)
	if err != nil {
		return Config{}, err
	}
	pinEBPFDefault, err := envBool("TRACEGUARD_PIN_EBPF", false)
	if err != nil {
		return Config{}, err
	}
	ebpfStatsDefault, err := envBool("TRACEGUARD_EBPF_STATS", false)
	if err != nil {
		return Config{}, err
	}
	policyRefreshDefault, err := envDuration("TRACEGUARD_POLICY_REFRESH_INTERVAL", defaultPolicyRefresh)
	if err != nil {
		return Config{}, err
	}
	exportSpoolDefault, err := envBool("TRACEGUARD_EVENT_EXPORT_SPOOL", true)
	if err != nil {
		return Config{}, err
	}
	syslogTimeoutDefault, err := envDuration("TRACEGUARD_EVENT_SYSLOG_TIMEOUT", defaultSyslogTimeout)
	if err != nil {
		return Config{}, err
	}
	processCacheDefault, err := envDuration("TRACEGUARD_PROCESS_CACHE_TTL", defaultProcessCacheTTL)
	if err != nil {
		return Config{}, err
	}
	fileAuditDefault, err := envBool("TRACEGUARD_FILE_AUDIT", true)
	if err != nil {
		return Config{}, err
	}
	securityEventsDefault, err := envBool("TRACEGUARD_SECURITY_EVENTS", true)
	if err != nil {
		return Config{}, err
	}
	kubernetesEnrichDefault, err := envBool("TRACEGUARD_KUBERNETES_ENRICH", false)
	if err != nil {
		return Config{}, err
	}
	kubernetesPollDefault, err := envDuration("TRACEGUARD_KUBERNETES_POLL_INTERVAL", defaultKubePoll)
	if err != nil {
		return Config{}, err
	}
	strictHooksDefault, err := envBool("TRACEGUARD_STRICT_HOOKS", false)
	if err != nil {
		return Config{}, err
	}
	heartbeatDefault, err := envDuration("TRACEGUARD_HEARTBEAT_INTERVAL", defaultHeartbeatInterval)
	if err != nil {
		return Config{}, err
	}
	connectionDedupeDefault, err := envDuration("TRACEGUARD_CONNECTION_DEDUPE_WINDOW", defaultConnectionDedupeWindow)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.BoolVar(&cfg.Block, "block", blockDefault, "enforce configured DNS and kernel policy block decisions")
	fs.BoolVar(&cfg.DryRun, "dry-run", dryRunDefault, "evaluate policy and log would-block decisions without enforcing denials")
	fs.BoolVar(&cfg.EmergencyAllow, "emergency-allow", emergencyAllowDefault, "clear persistent policy, ignore policy sources, and keep enforcement fail-open")
	fs.BoolVar(&cfg.PinEBPF, "pin-ebpf", pinEBPFDefault, "pin eBPF maps, programs, and cgroup/tracepoint links across service restarts")
	fs.BoolVar(&cfg.Unpin, "unpin", false, "remove TraceGuard eBPF pins and exit")
	fs.BoolVar(&cfg.EBPFStats, "ebpf-stats", ebpfStatsDefault, "collect eBPF runtime statistics (has a kernel-wide performance cost)")
	fs.StringVar(&cfg.PolicyPath, "policy-path", envString("TRACEGUARD_POLICY_PATH", ""), "absolute path to a strict YAML v1 policy overlay")
	fs.StringVar(&cfg.PolicyURL, "policy-url", envString("TRACEGUARD_POLICY_URL", ""), "HTTPS URL that returns a strict YAML v1 base policy")
	fs.StringVar(&cfg.PolicyCachePath, "policy-cache-path", envString("TRACEGUARD_POLICY_CACHE_PATH", defaultPolicyCachePath), "absolute path to the cached remote YAML policy")
	fs.DurationVar(&cfg.PolicyRefreshInterval, "policy-refresh-interval", policyRefreshDefault, "remote YAML policy refresh interval")
	fs.StringVar(&cfg.PolicyAuthorization, "policy-authorization", envString("TRACEGUARD_POLICY_AUTHORIZATION", ""), "optional Authorization header value for the remote YAML policy; prefer TRACEGUARD_POLICY_AUTHORIZATION, as command-line values are visible in process listings")
	fs.StringVar(&cfg.PolicyAuthorizationFile, "policy-authorization-file", envString("TRACEGUARD_POLICY_AUTHORIZATION_FILE", ""), "absolute path to a root-only file, such as ${CREDENTIALS_DIRECTORY}/policy-authorization, holding the Authorization header value for the remote YAML policy")
	fs.StringVar(&cfg.PolicyCAPath, "policy-ca-path", envString("TRACEGUARD_POLICY_CA_PATH", ""), "path to an optional CA bundle for the remote YAML policy")
	fs.StringVar(&cfg.PolicyClientCert, "policy-client-cert", envString("TRACEGUARD_POLICY_CLIENT_CERT", ""), "path to an optional client certificate for the remote YAML policy")
	fs.StringVar(&cfg.PolicyClientKey, "policy-client-key", envString("TRACEGUARD_POLICY_CLIENT_KEY", ""), "path to an optional client key for the remote YAML policy")
	fs.StringVar(&cfg.CgroupPath, "cgroup-path", envString("TRACEGUARD_CGROUP_PATH", defaultCgroupPath), "cgroup v2 path used for cgroup eBPF attachments; LSM MAC hooks remain host-wide")
	fs.StringVar(&cfg.LogPath, "log-path", envString("TRACEGUARD_LOG_PATH", defaultLogPath), "absolute path to the primary log file")
	fs.StringVar(&cfg.LogFormat, "log-format", envString("TRACEGUARD_LOG_FORMAT", defaultLogFormat), "log format: text or json")
	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", envString("TRACEGUARD_METRICS_ADDR", defaultMetricsAddr), "listen address for /metrics and /health, for example 127.0.0.1:9091")
	fs.StringVar(&cfg.EventArchivePath, "event-archive-path", envString("TRACEGUARD_EVENT_ARCHIVE_PATH", ""), "absolute path to an optional JSONL event archive")
	fs.StringVar(&cfg.EventExportURL, "event-export-url", envString("TRACEGUARD_EVENT_EXPORT_URL", ""), "HTTPS URL to receive JSON event POSTs")
	fs.StringVar(&cfg.EventExportAuthorization, "event-export-authorization", envString("TRACEGUARD_EVENT_EXPORT_AUTHORIZATION", ""), "optional Authorization header value for HTTPS event export, for example 'Bearer token'; prefer TRACEGUARD_EVENT_EXPORT_AUTHORIZATION, as command-line values are visible in process listings")
	fs.StringVar(&cfg.EventExportAuthorizationFile, "event-export-authorization-file", envString("TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE", ""), "absolute path to a root-only file, such as ${CREDENTIALS_DIRECTORY}/event-export-authorization, holding the Authorization header value for HTTPS event export")
	fs.BoolVar(&cfg.EventExportSpool, "event-export-spool", exportSpoolDefault, "durably spool failed HTTPS export batches to disk for replay")
	fs.StringVar(&cfg.EventExportCAPath, "event-export-ca-path", envString("TRACEGUARD_EVENT_EXPORT_CA_PATH", ""), "path to an optional CA bundle for the HTTPS event export endpoint")
	fs.StringVar(&cfg.EventExportClientCert, "event-export-client-cert", envString("TRACEGUARD_EVENT_EXPORT_CLIENT_CERT", ""), "path to an optional client certificate for HTTPS event export")
	fs.StringVar(&cfg.EventExportClientKey, "event-export-client-key", envString("TRACEGUARD_EVENT_EXPORT_CLIENT_KEY", ""), "path to an optional client key for HTTPS event export")
	fs.StringVar(&cfg.EventSyslogURL, "event-syslog-url", envString("TRACEGUARD_EVENT_SYSLOG_URL", ""), "remote syslog URL: syslog+udp://host:514, syslog+tcp://host:514, or syslog+tls://host:6514")
	fs.StringVar(&cfg.EventSyslogFacility, "event-syslog-facility", envString("TRACEGUARD_EVENT_SYSLOG_FACILITY", defaultSyslogFacility), "remote syslog facility, for example local0")
	fs.StringVar(&cfg.EventSyslogTag, "event-syslog-tag", envString("TRACEGUARD_EVENT_SYSLOG_TAG", defaultSyslogTag), "remote syslog app-name/tag")
	fs.DurationVar(&cfg.EventSyslogTimeout, "event-syslog-timeout", syslogTimeoutDefault, "remote syslog connection/write timeout")
	fs.StringVar(&cfg.EventSyslogCAPath, "event-syslog-ca-path", envString("TRACEGUARD_EVENT_SYSLOG_CA_PATH", ""), "path to an optional CA bundle for syslog+tls")
	fs.StringVar(&cfg.ResponseMode, "response-mode", envString("TRACEGUARD_RESPONSE_MODE", "dry-run"), "how policy responses run: off, dry-run (record only), or enforce")
	fs.StringVar(&cfg.EventSchema, "event-schema", envString("TRACEGUARD_EVENT_SCHEMA", "traceguard"), "record format for HTTPS export and syslog: traceguard or ocsf")
	fs.DurationVar(&cfg.ProcessCacheTTL, "process-cache-ttl", processCacheDefault, "how long to cache process metadata from /proc")
	fs.BoolVar(&cfg.FileAudit, "file-audit", fileAuditDefault, "emit file access audit events for open-style syscalls")
	fs.BoolVar(&cfg.SecurityEvents, "security-events", securityEventsDefault, "emit memfd, ptrace, process memory, module load, BPF program load, io_uring, mount, namespace, and privilege-change events")
	fs.BoolVar(&cfg.KubernetesEnrich, "kubernetes-enrich", kubernetesEnrichDefault, "enrich events with Kubernetes pod metadata from the API")
	fs.StringVar(&cfg.KubernetesAPIURL, "kubernetes-api-url", envString("TRACEGUARD_KUBERNETES_API_URL", ""), "HTTPS URL for the Kubernetes API server")
	fs.StringVar(&cfg.KubernetesTokenPath, "kubernetes-token-path", envString("TRACEGUARD_KUBERNETES_TOKEN_PATH", defaultKubeTokenPath), "path to the Kubernetes bearer token file")
	fs.StringVar(&cfg.KubernetesCAPath, "kubernetes-ca-path", envString("TRACEGUARD_KUBERNETES_CA_PATH", defaultKubeCAPath), "path to the Kubernetes CA certificate bundle")
	fs.StringVar(&cfg.KubernetesNodeName, "kubernetes-node-name", envString("TRACEGUARD_KUBERNETES_NODE_NAME", ""), "optional Kubernetes node name used to scope pod metadata listing")
	fs.DurationVar(&cfg.KubernetesPoll, "kubernetes-poll-interval", kubernetesPollDefault, "how often to refresh Kubernetes pod metadata")
	fs.BoolVar(&cfg.StrictHooks, "strict-hooks", strictHooksDefault, "refuse to start when an optional eBPF hook cannot be loaded or attached")
	fs.DurationVar(&cfg.HeartbeatInterval, "heartbeat-interval", heartbeatDefault, "interval between heartbeat events that report policy digest and self-health; 0 disables")
	fs.StringVar(&cfg.PolicySigningKey, "policy-signing-key", envString("TRACEGUARD_POLICY_SIGNING_KEY", ""), "absolute path to a PEM Ed25519 public key; the remote policy must then carry a valid detached signature at <policy-url>.sig")
	fs.DurationVar(&cfg.ConnectionDedupeWindow, "connection-dedupe-window", connectionDedupeDefault, "suppress repeated connection events for the same socket within this window; 0 disables")
	fs.BoolVar(&cfg.PrintVersion, "v", false, "print program version and exit")
	fs.BoolVar(&cfg.Doctor, "doctor", false, "run environment diagnostics and exit")
	fs.StringVar(&cfg.ReplayPath, "replay", "", "evaluate detection rules over an absolute-path JSONL event archive, print alerts and a per-rule summary, and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), ", "))
	}
	normalizeKubernetesConfig(&cfg)
	if cfg.PrintVersion || cfg.Doctor || cfg.Unpin {
		return cfg, nil
	}
	if cfg.ReplayPath != "" {
		if !filepath.IsAbs(cfg.ReplayPath) {
			return Config{}, errors.New("replay must be an absolute path")
		}
		if cfg.PolicyPath != "" && !filepath.IsAbs(cfg.PolicyPath) {
			return Config{}, errors.New("policy-path must be an absolute path")
		}
		return cfg, nil
	}

	if cfg.PolicyRefreshInterval <= 0 {
		return Config{}, errors.New("policy-refresh-interval must be positive")
	}

	if !cfg.EmergencyAllow && (cfg.Block || cfg.DryRun) && cfg.PolicyPath == "" && cfg.PolicyURL == "" {
		return Config{}, errors.New("block and dry-run modes require at least one policy source")
	}

	if cfg.PolicyURL != "" {
		parsed, err := neturl.Parse(strings.TrimSpace(cfg.PolicyURL))
		if err != nil {
			return Config{}, errors.New("policy-url is not a valid URL")
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return Config{}, errors.New("policy-url must use https:// and include a host")
		}
		if parsed.User != nil {
			return Config{}, errors.New("policy-url must not contain user credentials; use policy-authorization or mTLS")
		}
	}

	if cfg.CgroupPath == "" {
		return Config{}, errors.New("cgroup-path must not be empty")
	}
	if cfg.PolicyPath != "" && !filepath.IsAbs(cfg.PolicyPath) {
		return Config{}, errors.New("policy-path must be an absolute path")
	}
	if strings.TrimSpace(cfg.PolicyCachePath) == "" {
		return Config{}, errors.New("policy-cache-path must not be empty")
	}
	if !filepath.IsAbs(cfg.PolicyCachePath) {
		return Config{}, errors.New("policy-cache-path must be an absolute path")
	}
	if err := resolveAuthorizationFile("policy-authorization", cfg.PolicyAuthorization, &cfg.PolicyAuthorizationFile); err != nil {
		return Config{}, err
	}
	if err := resolveAuthorizationFile("event-export-authorization", cfg.EventExportAuthorization, &cfg.EventExportAuthorizationFile); err != nil {
		return Config{}, err
	}
	if cfg.PolicyCAPath != "" && !filepath.IsAbs(cfg.PolicyCAPath) {
		return Config{}, errors.New("policy-ca-path must be an absolute path")
	}
	if cfg.PolicyClientCert != "" && !filepath.IsAbs(cfg.PolicyClientCert) {
		return Config{}, errors.New("policy-client-cert must be an absolute path")
	}
	if cfg.PolicyClientKey != "" && !filepath.IsAbs(cfg.PolicyClientKey) {
		return Config{}, errors.New("policy-client-key must be an absolute path")
	}
	if (cfg.PolicyClientCert == "") != (cfg.PolicyClientKey == "") {
		return Config{}, errors.New("policy-client-cert and policy-client-key must be set together")
	}
	if !filepath.IsAbs(cfg.LogPath) {
		return Config{}, errors.New("log-path must be an absolute path")
	}
	if cfg.EventArchivePath != "" && !filepath.IsAbs(cfg.EventArchivePath) {
		return Config{}, errors.New("event-archive-path must be an absolute path")
	}
	if cfg.EventExportCAPath != "" && !filepath.IsAbs(cfg.EventExportCAPath) {
		return Config{}, errors.New("event-export-ca-path must be an absolute path")
	}
	if cfg.EventExportClientCert != "" && !filepath.IsAbs(cfg.EventExportClientCert) {
		return Config{}, errors.New("event-export-client-cert must be an absolute path")
	}
	if cfg.EventExportClientKey != "" && !filepath.IsAbs(cfg.EventExportClientKey) {
		return Config{}, errors.New("event-export-client-key must be an absolute path")
	}
	if cfg.EventSyslogCAPath != "" && !filepath.IsAbs(cfg.EventSyslogCAPath) {
		return Config{}, errors.New("event-syslog-ca-path must be an absolute path")
	}
	switch strings.ToLower(strings.TrimSpace(cfg.LogFormat)) {
	case "text", "json":
		cfg.LogFormat = strings.ToLower(strings.TrimSpace(cfg.LogFormat))
	default:
		return Config{}, errors.New("log-format must be text or json")
	}
	if cfg.MetricsAddr != "" {
		if _, err := net.ResolveTCPAddr("tcp", cfg.MetricsAddr); err != nil {
			return Config{}, fmt.Errorf("metrics-addr: %w", err)
		}
	}
	if cfg.EventExportURL != "" {
		parsed, err := neturl.Parse(strings.TrimSpace(cfg.EventExportURL))
		if err != nil {
			return Config{}, errors.New("event-export-url is not a valid URL")
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return Config{}, errors.New("event-export-url must use https://")
		}
		if parsed.User != nil {
			return Config{}, errors.New("event-export-url must not contain user credentials; use event-export-authorization or mTLS")
		}
		if (cfg.EventExportClientCert == "") != (cfg.EventExportClientKey == "") {
			return Config{}, errors.New("event-export-client-cert and event-export-client-key must be set together")
		}
	}
	if cfg.EventSyslogURL != "" {
		if err := validateSyslogConfig(cfg); err != nil {
			return Config{}, err
		}
	}
	if cfg.ProcessCacheTTL <= 0 {
		return Config{}, errors.New("process-cache-ttl must be positive")
	}
	cfg.ResponseMode = strings.ToLower(strings.TrimSpace(cfg.ResponseMode))
	if cfg.ResponseMode == "" {
		cfg.ResponseMode = "dry-run"
	}
	switch cfg.ResponseMode {
	case "off", "dry-run", "enforce":
	default:
		return Config{}, errors.New("response-mode must be off, dry-run, or enforce")
	}
	if cfg.EmergencyAllow {
		// Emergency allow keeps every enforcement path open, responses too.
		cfg.ResponseMode = "off"
	}
	cfg.EventSchema = strings.ToLower(strings.TrimSpace(cfg.EventSchema))
	if cfg.EventSchema == "" {
		cfg.EventSchema = "traceguard"
	}
	switch cfg.EventSchema {
	case "traceguard", "ocsf":
	default:
		return Config{}, errors.New("event-schema must be traceguard or ocsf")
	}
	if cfg.HeartbeatInterval < 0 {
		return Config{}, errors.New("heartbeat-interval must not be negative")
	}
	if cfg.ConnectionDedupeWindow < 0 || cfg.ConnectionDedupeWindow > maxConnectionDedupeWindow {
		return Config{}, fmt.Errorf("connection-dedupe-window must be between 0 and %s", maxConnectionDedupeWindow)
	}
	if cfg.PolicySigningKey != "" {
		if !filepath.IsAbs(cfg.PolicySigningKey) {
			return Config{}, errors.New("policy-signing-key must be an absolute path")
		}
		if cfg.PolicyURL == "" {
			return Config{}, errors.New("policy-signing-key requires policy-url; local policy files are trusted by file ownership")
		}
	}
	if cfg.KubernetesEnrich {
		if cfg.KubernetesAPIURL == "" {
			return Config{}, errors.New("kubernetes-api-url must be set when kubernetes-enrich is enabled")
		}
		parsed, err := neturl.Parse(strings.TrimSpace(cfg.KubernetesAPIURL))
		if err != nil {
			return Config{}, errors.New("kubernetes-api-url is not a valid URL")
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return Config{}, errors.New("kubernetes-api-url must use https://")
		}
		if parsed.User != nil {
			return Config{}, errors.New("kubernetes-api-url must not contain user credentials; use the service-account token")
		}
		if !filepath.IsAbs(cfg.KubernetesTokenPath) {
			return Config{}, errors.New("kubernetes-token-path must be an absolute path")
		}
		if !filepath.IsAbs(cfg.KubernetesCAPath) {
			return Config{}, errors.New("kubernetes-ca-path must be an absolute path")
		}
		if cfg.KubernetesPoll <= 0 {
			return Config{}, errors.New("kubernetes-poll-interval must be positive")
		}
	}

	return cfg, nil
}
