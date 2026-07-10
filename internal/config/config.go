package config

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	neturl "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultRefreshInterval = 6 * time.Hour
	defaultCgroupPath      = "/sys/fs/cgroup"
	defaultCachePath       = "/var/lib/traceguard/blocklist.txt"
	defaultLogPath         = "/var/log/traceguard/traceguard.log"
	defaultLogFormat       = "json"
	defaultMetricsAddr     = ":9091"
	defaultProcessCacheTTL = 5 * time.Minute
	defaultSyslogFacility  = "local0"
	defaultSyslogTag       = "traceguard"
	defaultSyslogTimeout   = 5 * time.Second
	// #nosec G101 -- this is the standard Kubernetes service-account token path, not an embedded credential value.
	defaultKubeTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	defaultKubeCAPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	defaultKubePoll      = 2 * time.Minute
)

type domainList []string

func (d *domainList) String() string {
	return strings.Join(*d, ",")
}

func (d *domainList) Set(value string) error {
	entries, err := parseDomainInput(value)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("empty domain value")
	}
	*d = append(*d, entries...)
	return nil
}

type Config struct {
	Block                    bool
	DryRun                   bool
	BlocklistURL             string
	ManualDomains            []string
	ManualAllow              []string
	CachePath                string
	RefreshInterval          time.Duration
	CgroupPath               string
	LogPath                  string
	LogFormat                string
	MetricsAddr              string
	EventArchivePath         string
	EventExportURL           string
	EventExportAuthorization string
	EventExportSpool         bool
	EventExportCAPath        string
	EventExportClientCert    string
	EventExportClientKey     string
	EventSyslogURL           string
	EventSyslogFacility      string
	EventSyslogTag           string
	EventSyslogTimeout       time.Duration
	EventSyslogCAPath        string
	ProcessCacheTTL          time.Duration
	FileAudit                bool
	KubernetesEnrich         bool
	KubernetesAPIURL         string
	KubernetesTokenPath      string
	KubernetesCAPath         string
	KubernetesNodeName       string
	KubernetesPoll           time.Duration
	PrintVersion             bool
	Doctor                   bool
}

func Parse() (Config, error) {
	cfg := Config{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.BoolVar(&cfg.Block, "block", envBool("TRACEGUARD_BLOCK", false), "enable DNS blocking for domains loaded from the configured sources")
	fs.BoolVar(&cfg.DryRun, "dry-run", envBool("TRACEGUARD_DRY_RUN", false), "evaluate block policy and log would-block decisions without enforcing drops")
	fs.StringVar(&cfg.BlocklistURL, "blocklist-url", envString("TRACEGUARD_BLOCKLIST_URL", ""), "HTTPS URL that returns newline-delimited domains or URLs to block")
	var manual domainList
	var manualAllow domainList
	fs.Var(&manual, "block-domain", "exact domain, deny-all marker '*', @/abs/path file, bare resolver IP/CIDR, or DoH/DoT endpoint to block; may be specified more than once")
	fs.Var(&manualAllow, "allow-domain", "exact or wildcard domain, @/abs/path file, bare resolver IP/CIDR, or DoH/DoT endpoint to allow even if it also appears in a block policy; may be specified more than once")
	fs.StringVar(&cfg.CachePath, "cache-path", envString("TRACEGUARD_CACHE_PATH", defaultCachePath), "path to the cached remote blocklist")
	fs.DurationVar(&cfg.RefreshInterval, "refresh-interval", envDuration("TRACEGUARD_REFRESH_INTERVAL", defaultRefreshInterval), "remote blocklist refresh interval")
	fs.StringVar(&cfg.CgroupPath, "cgroup-path", envString("TRACEGUARD_CGROUP_PATH", defaultCgroupPath), "cgroup v2 path used for egress attachment")
	fs.StringVar(&cfg.LogPath, "log-path", envString("TRACEGUARD_LOG_PATH", defaultLogPath), "absolute path to the primary log file")
	fs.StringVar(&cfg.LogFormat, "log-format", envString("TRACEGUARD_LOG_FORMAT", defaultLogFormat), "log format: text or json")
	fs.StringVar(&cfg.MetricsAddr, "metrics-addr", envString("TRACEGUARD_METRICS_ADDR", defaultMetricsAddr), "listen address for /metrics and /health, for example :9091")
	fs.StringVar(&cfg.EventArchivePath, "event-archive-path", envString("TRACEGUARD_EVENT_ARCHIVE_PATH", ""), "absolute path to an optional JSONL event archive")
	fs.StringVar(&cfg.EventExportURL, "event-export-url", envString("TRACEGUARD_EVENT_EXPORT_URL", ""), "HTTPS URL to receive JSON event POSTs")
	fs.StringVar(&cfg.EventExportAuthorization, "event-export-authorization", envString("TRACEGUARD_EVENT_EXPORT_AUTHORIZATION", ""), "optional Authorization header value for HTTPS event export, for example 'Bearer token'")
	fs.BoolVar(&cfg.EventExportSpool, "event-export-spool", envBool("TRACEGUARD_EVENT_EXPORT_SPOOL", true), "durably spool failed HTTPS export batches to disk for replay")
	fs.StringVar(&cfg.EventExportCAPath, "event-export-ca-path", envString("TRACEGUARD_EVENT_EXPORT_CA_PATH", ""), "path to an optional CA bundle for the HTTPS event export endpoint")
	fs.StringVar(&cfg.EventExportClientCert, "event-export-client-cert", envString("TRACEGUARD_EVENT_EXPORT_CLIENT_CERT", ""), "path to an optional client certificate for HTTPS event export")
	fs.StringVar(&cfg.EventExportClientKey, "event-export-client-key", envString("TRACEGUARD_EVENT_EXPORT_CLIENT_KEY", ""), "path to an optional client key for HTTPS event export")
	fs.StringVar(&cfg.EventSyslogURL, "event-syslog-url", envString("TRACEGUARD_EVENT_SYSLOG_URL", ""), "remote syslog URL: syslog+udp://host:514, syslog+tcp://host:514, or syslog+tls://host:6514")
	fs.StringVar(&cfg.EventSyslogFacility, "event-syslog-facility", envString("TRACEGUARD_EVENT_SYSLOG_FACILITY", defaultSyslogFacility), "remote syslog facility, for example local0")
	fs.StringVar(&cfg.EventSyslogTag, "event-syslog-tag", envString("TRACEGUARD_EVENT_SYSLOG_TAG", defaultSyslogTag), "remote syslog app-name/tag")
	fs.DurationVar(&cfg.EventSyslogTimeout, "event-syslog-timeout", envDuration("TRACEGUARD_EVENT_SYSLOG_TIMEOUT", defaultSyslogTimeout), "remote syslog connection/write timeout")
	fs.StringVar(&cfg.EventSyslogCAPath, "event-syslog-ca-path", envString("TRACEGUARD_EVENT_SYSLOG_CA_PATH", ""), "path to an optional CA bundle for syslog+tls")
	fs.DurationVar(&cfg.ProcessCacheTTL, "process-cache-ttl", envDuration("TRACEGUARD_PROCESS_CACHE_TTL", defaultProcessCacheTTL), "how long to cache process metadata from /proc")
	fs.BoolVar(&cfg.FileAudit, "file-audit", envBool("TRACEGUARD_FILE_AUDIT", true), "emit file access audit events for open-style syscalls")
	fs.BoolVar(&cfg.KubernetesEnrich, "kubernetes-enrich", envBool("TRACEGUARD_KUBERNETES_ENRICH", false), "enrich events with Kubernetes pod metadata from the API")
	fs.StringVar(&cfg.KubernetesAPIURL, "kubernetes-api-url", envString("TRACEGUARD_KUBERNETES_API_URL", ""), "HTTPS URL for the Kubernetes API server")
	fs.StringVar(&cfg.KubernetesTokenPath, "kubernetes-token-path", envString("TRACEGUARD_KUBERNETES_TOKEN_PATH", defaultKubeTokenPath), "path to the Kubernetes bearer token file")
	fs.StringVar(&cfg.KubernetesCAPath, "kubernetes-ca-path", envString("TRACEGUARD_KUBERNETES_CA_PATH", defaultKubeCAPath), "path to the Kubernetes CA certificate bundle")
	fs.StringVar(&cfg.KubernetesNodeName, "kubernetes-node-name", envString("TRACEGUARD_KUBERNETES_NODE_NAME", ""), "optional Kubernetes node name used to scope pod metadata listing")
	fs.DurationVar(&cfg.KubernetesPoll, "kubernetes-poll-interval", envDuration("TRACEGUARD_KUBERNETES_POLL_INTERVAL", defaultKubePoll), "how often to refresh Kubernetes pod metadata")
	fs.BoolVar(&cfg.PrintVersion, "v", false, "print program version and exit")
	fs.BoolVar(&cfg.Doctor, "doctor", false, "run environment diagnostics and exit")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return Config{}, err
	}
	if fs.NArg() > 0 {
		return Config{}, fmt.Errorf("unexpected positional arguments: %s; quote '*' as -block-domain '*'", strings.Join(fs.Args(), ", "))
	}
	normalizeKubernetesConfig(&cfg)
	if cfg.PrintVersion || cfg.Doctor {
		return cfg, nil
	}

	var err error
	cfg.ManualDomains, err = loadDomainEnv("TRACEGUARD_BLOCK_DOMAINS")
	if err != nil {
		return Config{}, err
	}
	cfg.ManualAllow, err = loadDomainEnv("TRACEGUARD_ALLOW_DOMAINS")
	if err != nil {
		return Config{}, err
	}
	cfg.ManualDomains = compact(append(cfg.ManualDomains, manual...))
	cfg.ManualAllow = compact(append(cfg.ManualAllow, manualAllow...))
	if cfg.RefreshInterval <= 0 {
		return Config{}, errors.New("refresh-interval must be positive")
	}

	if (cfg.Block || cfg.DryRun) && cfg.BlocklistURL == "" && len(cfg.ManualDomains) == 0 && len(cfg.ManualAllow) == 0 {
		return Config{}, errors.New("block and dry-run modes require at least one policy source")
	}

	if cfg.BlocklistURL != "" && !strings.HasPrefix(cfg.BlocklistURL, "https://") {
		return Config{}, errors.New("blocklist-url must use https://")
	}

	if cfg.CgroupPath == "" {
		return Config{}, errors.New("cgroup-path must not be empty")
	}
	if strings.TrimSpace(cfg.CachePath) == "" {
		return Config{}, errors.New("cache-path must not be empty")
	}
	if !filepath.IsAbs(cfg.CachePath) {
		return Config{}, errors.New("cache-path must be an absolute path")
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
			return Config{}, fmt.Errorf("event-export-url: %w", err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return Config{}, errors.New("event-export-url must use https://")
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
	if cfg.KubernetesEnrich {
		if cfg.KubernetesAPIURL == "" {
			return Config{}, errors.New("kubernetes-api-url must be set when kubernetes-enrich is enabled")
		}
		parsed, err := neturl.Parse(strings.TrimSpace(cfg.KubernetesAPIURL))
		if err != nil {
			return Config{}, fmt.Errorf("kubernetes-api-url: %w", err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return Config{}, errors.New("kubernetes-api-url must use https://")
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

func compact(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func envString(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	return strings.TrimSpace(value)
}

func envBool(key string, fallback bool) bool {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func validateSyslogConfig(cfg Config) error {
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.EventSyslogURL))
	if err != nil {
		return fmt.Errorf("event-syslog-url: %w", err)
	}
	switch parsed.Scheme {
	case "syslog+udp", "syslog+tcp", "syslog+tls":
	default:
		return errors.New("event-syslog-url must use syslog+udp://, syslog+tcp://, or syslog+tls://")
	}
	if parsed.Hostname() == "" || parsed.Port() == "" {
		return errors.New("event-syslog-url must include host and port")
	}
	if _, ok := syslogFacilityCode(cfg.EventSyslogFacility); !ok {
		return errors.New("event-syslog-facility must be one of kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,local0-local7")
	}
	if !validSyslogTag(cfg.EventSyslogTag) {
		return errors.New("event-syslog-tag must be non-empty and must not contain whitespace")
	}
	if cfg.EventSyslogTimeout <= 0 {
		return errors.New("event-syslog-timeout must be positive")
	}
	return nil
}

func syslogFacilityCode(facility string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(facility)) {
	case "kern":
		return 0, true
	case "user":
		return 1, true
	case "mail":
		return 2, true
	case "daemon":
		return 3, true
	case "auth":
		return 4, true
	case "syslog":
		return 5, true
	case "lpr":
		return 6, true
	case "news":
		return 7, true
	case "uucp":
		return 8, true
	case "cron":
		return 9, true
	case "authpriv":
		return 10, true
	case "ftp":
		return 11, true
	case "local0":
		return 16, true
	case "local1":
		return 17, true
	case "local2":
		return 18, true
	case "local3":
		return 19, true
	case "local4":
		return 20, true
	case "local5":
		return 21, true
	case "local6":
		return 22, true
	case "local7":
		return 23, true
	default:
		return 0, false
	}
}

func validSyslogTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	return tag != "" && !strings.ContainsAny(tag, " \t\r\n")
}

func detectKubernetesAPIURL() string {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	if host == "" {
		return "https://kubernetes.default.svc:443"
	}
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT_HTTPS"))
	if port == "" {
		port = strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	}
	if port == "" {
		port = "443"
	}
	return "https://" + net.JoinHostPort(host, port)
}

func normalizeKubernetesConfig(cfg *Config) {
	if !cfg.KubernetesEnrich {
		return
	}
	if cfg.KubernetesAPIURL == "" {
		cfg.KubernetesAPIURL = detectKubernetesAPIURL()
	}
	if cfg.KubernetesNodeName == "" {
		cfg.KubernetesNodeName = firstEnv("NODE_NAME", "KUBE_NODE_NAME")
	}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			return value
		}
	}
	return ""
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}

func loadDomainEnv(key string) ([]string, error) {
	value, ok := os.LookupEnv(key)
	if !ok {
		return nil, nil
	}
	entries, err := parseDomainInput(value)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", key, err)
	}
	return entries, nil
}

func parseDomainInput(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if strings.HasPrefix(value, "@") {
		return loadDomainFile(strings.TrimSpace(value[1:]))
	}
	return splitDomainEntries(value), nil
}

func loadDomainFile(path string) ([]string, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("domain file path %q must be absolute", path)
	}

	// #nosec G304 -- domain files are explicit operator-provided absolute paths.
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read domain file %q: %w", path, err)
	}
	defer file.Close()

	return parseDomainEntries(file)
}

func parseDomainEntries(r io.Reader) ([]string, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	var entries []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, splitDomainEntries(line)...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func splitDomainEntries(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
