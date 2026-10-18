package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	neturl "net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const redactedValue = "[REDACTED]"

const maxSyslogTagBytes = 48

var urlValueFlags = map[string]struct{}{
	"policy-url":         {},
	"event-export-url":   {},
	"event-syslog-url":   {},
	"kubernetes-api-url": {},
}

// sensitiveNamePattern matches flag, variable, header, and query parameter
// names whose values commonly carry credentials.
const sensitiveNamePattern = `password|passwd|secret|token|authorization|api[-_]?key|access[-_]?key|private[-_]?key|credential|cookie|signature`

// shellWordPiece matches one quoted section or unquoted byte of a shell word,
// so values such as 'a b' or a"b"c are redacted whole.
const shellWordPiece = `'[^']*'|"(?:[^"\\]|\\.)*"|[^\s&;|'"]`

var (
	sensitiveName = regexp.MustCompile(`(?i)` + sensitiveNamePattern)
	// Header values run to the end of the argument or quoted shell word;
	// NAME=value and query parameter values end at an unquoted whitespace or
	// separator. Flags inside shell strings take the next word unless it is
	// another flag.
	sensitiveHeader     = regexp.MustCompile(`(?i)([\w-]*(?:` + sensitiveNamePattern + `)[\w-]*\s*:\s*)[^'"]+`)
	sensitiveAssignment = regexp.MustCompile(`(?i)([\w.-]*(?:` + sensitiveNamePattern + `)[\w.-]*\s*=\s*)(?:` + shellWordPiece + `)+`)
	sensitiveShellFlag  = regexp.MustCompile(`(?i)((?:^|\s)--?[\w.-]*(?:` + sensitiveNamePattern + `)[\w.-]*\s+)` +
		`(?:'[^']*'|"(?:[^"\\]|\\.)*"|[^-\s&;|'"])(?:` + shellWordPiece + `)*`)
	urlUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/?#@\s'"]+@`)
)

// RedactCommandLine returns a copy with credentials removed from TraceGuard
// flags and from common credential forms in monitored command lines: values of
// sensitive-named flags, NAME=value and Header: value pairs, sensitive query
// parameters, and URL userinfo. It understands both "-flag value" and
// "-flag=value" forms, as separate arguments or inside a shell string such as
// the script of sh -c, where quoted values are redacted whole. Redaction is best effort: positional secrets and
// unrecognized spellings are retained.
func RedactCommandLine(args []string) []string {
	redacted := make([]string, 0, len(args))
	redactNext := false
	sanitizeURLNext := false
	for _, arg := range args {
		if redactNext {
			redacted = append(redacted, redactedValue)
			redactNext = false
			continue
		}
		if sanitizeURLNext {
			redacted = append(redacted, SanitizeURL(arg))
			sanitizeURLNext = false
			continue
		}

		name, value, hasValue := splitFlag(arg)
		if name != "" && sensitiveName.MatchString(name) {
			if hasValue {
				redacted = append(redacted, arg[:len(arg)-len(value)]+redactedValue)
			} else {
				redacted = append(redacted, arg)
				redactNext = !readsSecretFromStdin(name)
			}
			continue
		}
		if _, isURL := urlValueFlags[name]; isURL {
			if hasValue {
				redacted = append(redacted, arg[:len(arg)-len(value)]+SanitizeURL(value))
			} else {
				redacted = append(redacted, arg)
				sanitizeURLNext = true
			}
			continue
		}
		redacted = append(redacted, redactCommandLineValue(arg))
	}
	return redacted
}

func redactCommandLineValue(arg string) string {
	if !strings.ContainsAny(arg, ":= \t\n") {
		return arg
	}
	arg = urlUserinfo.ReplaceAllString(arg, "${1}"+redactedValue+"@")
	arg = sensitiveHeader.ReplaceAllString(arg, "${1}"+redactedValue)
	arg = sensitiveShellFlag.ReplaceAllStringFunc(arg, func(match string) string {
		prefix := sensitiveShellFlag.FindStringSubmatch(match)[1]
		if readsSecretFromStdin(strings.TrimLeft(strings.TrimSpace(prefix), "-")) {
			return match
		}
		return prefix + redactedValue
	})
	return sensitiveAssignment.ReplaceAllString(arg, "${1}"+redactedValue)
}

// readsSecretFromStdin reports whether a sensitive-named flag, such as
// docker login --password-stdin, takes no value because the secret is read
// from standard input.
func readsSecretFromStdin(name string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(name)), "-stdin")
}

func splitFlag(arg string) (name, value string, hasValue bool) {
	trimmed := strings.TrimLeft(arg, "-")
	if trimmed == arg || trimmed == "" {
		return "", "", false
	}
	name, value, hasValue = strings.Cut(trimmed, "=")
	return name, value, hasValue
}

// SanitizeURL removes userinfo, query parameters, and fragments while keeping
// the origin and path useful for diagnostics. Invalid input is not echoed.
func SanitizeURL(raw string) string {
	parsed, err := neturl.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "[invalid-url]"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.ForceQuery = false
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

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
		return errors.New("event-syslog-url is not a valid URL")
	}
	switch parsed.Scheme {
	case "syslog+udp", "syslog+tcp", "syslog+tls":
	default:
		return errors.New("event-syslog-url must use syslog+udp://, syslog+tcp://, or syslog+tls://")
	}
	if parsed.Hostname() == "" || parsed.Port() == "" {
		return errors.New("event-syslog-url must include host and port")
	}
	if parsed.User != nil {
		return errors.New("event-syslog-url must not contain user credentials")
	}
	if _, ok := SyslogFacilityCode(cfg.EventSyslogFacility); !ok {
		return errors.New("event-syslog-facility must be one of kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,local0-local7")
	}
	if !validSyslogTag(cfg.EventSyslogTag) {
		return fmt.Errorf("event-syslog-tag must be 1-%d bytes of printable US-ASCII (no whitespace or control characters)", maxSyslogTagBytes)
	}
	if cfg.EventSyslogTimeout <= 0 {
		return errors.New("event-syslog-timeout must be positive")
	}
	return nil
}

// SyslogFacilityCode returns the RFC 5424 code of a syslog facility name.
func SyslogFacilityCode(facility string) (int, bool) {
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

// validSyslogTag matches the RFC 5424 APP-NAME rules the syslog sink enforces.
func validSyslogTag(tag string) bool {
	tag = strings.TrimSpace(tag)
	if tag == "" || len(tag) > maxSyslogTagBytes {
		return false
	}
	for index := range len(tag) {
		if tag[index] < 33 || tag[index] > 126 {
			return false
		}
	}
	return true
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

func envFloat(key string, fallback float64) (float64, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a number: %w", key, err)
	}
	return parsed, nil
}

func envByteSize(key string, fallback uint64) (uint64, error) {
	value, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := ParseByteSize(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return parsed, nil
}

var byteSizeUnits = map[string]uint64{
	"": 1, "b": 1,
	"k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10,
	"m": 1 << 20, "mb": 1 << 20, "mib": 1 << 20,
	"g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30,
}

// ParseByteSize parses a whole number of bytes with an optional binary unit
// suffix, such as 4096, 512KiB, or 64MiB. K, M, and G and their KB, MB, and GB
// spellings are binary units too.
func ParseByteSize(value string) (uint64, error) {
	trimmed := strings.TrimSpace(value)
	digits := strings.IndexFunc(trimmed, func(r rune) bool { return r < '0' || r > '9' })
	if digits < 0 {
		digits = len(trimmed)
	}
	if digits == 0 {
		return 0, fmt.Errorf("byte size %q must start with a whole number", value)
	}
	unit, ok := byteSizeUnits[strings.ToLower(strings.TrimSpace(trimmed[digits:]))]
	if !ok {
		return 0, fmt.Errorf("byte size %q has an unknown unit; use B, KiB, MiB, or GiB", value)
	}
	number, err := strconv.ParseUint(trimmed[:digits], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("byte size %q: %w", value, err)
	}
	if number > math.MaxUint64/unit {
		return 0, fmt.Errorf("byte size %q overflows", value)
	}
	return number * unit, nil
}

// byteSizeFlag is a flag.Value holding a byte count parsed by ParseByteSize.
type byteSizeFlag struct{ value *uint64 }

func (f byteSizeFlag) String() string {
	if f.value == nil {
		return "0"
	}
	return strconv.FormatUint(*f.value, 10)
}

func (f byteSizeFlag) Set(value string) error {
	parsed, err := ParseByteSize(value)
	if err != nil {
		return err
	}
	*f.value = parsed
	return nil
}
