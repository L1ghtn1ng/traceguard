package config

import (
	"errors"
	"fmt"
	"net"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func envString(key, fallback string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	return strings.TrimSpace(value)
}

func envBool(key string, fallback bool) (bool, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return parsed, nil
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

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", key, err)
	}
	return parsed, nil
}
