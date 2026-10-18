package detection

import (
	"slices"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

func BaselineRules() []policy.DetectionRule {
	enabled := true
	return []policy.DetectionRule{
		{
			ID:       "baseline.cloud-metadata-access",
			Enabled:  &enabled,
			Severity: "warning",
			Events:   []string{"connection"},
			Match: policy.DetectionMatch{
				Directions: []string{"outbound"},
				DestinationCIDRs: []string{
					"169.254.169.254/32", // AWS, Azure, GCP, OCI and others
					"fd00:ec2::254/128",  // AWS IMDS over IPv6
					"169.254.170.2/32",   // AWS ECS task metadata and credentials
					"169.254.170.23/32",  // AWS EKS Pod Identity
					"fd00:ec2::23/128",   // AWS EKS Pod Identity over IPv6
					"100.100.100.200/32", // Alibaba Cloud
				},
				Ports: []uint16{80, 443},
			},
			// Guest agents poll metadata continuously. A per-process cooldown
			// keeps one agent from hiding another process's first access.
			Cooldown: policy.Duration{Duration: time.Hour},
			Message:  "a process connected to a cloud instance metadata endpoint",
			Tags:     []string{"baseline", "cloud", "credential-access"},
			Threshold: policy.Threshold{
				Count:   1,
				GroupBy: []string{"cgroup", "executable"},
			},
		},
		{
			ID:       "baseline.direct-email-egress",
			Enabled:  &enabled,
			Severity: "notice",
			Events:   []string{"connection"},
			Match: policy.DetectionMatch{
				Directions: []string{"outbound"},
				Protocols:  []string{"tcp"},
				Ports:      []uint16{25, 465, 587},
			},
			Cooldown: policy.Duration{Duration: 5 * time.Minute},
			Message:  "a process opened a direct outbound email connection",
			Tags:     []string{"baseline", "egress", "exfiltration"},
			Threshold: policy.Threshold{
				Count: 1,
			},
		},
		{
			ID:       "baseline.inbound-ssh-bruteforce",
			Enabled:  &enabled,
			Severity: "warning",
			Events:   []string{"connection"},
			Match: policy.DetectionMatch{
				Directions: []string{"inbound"},
				Protocols:  []string{"tcp"},
				LocalPorts: []uint16{22},
			},
			// Inbound TCP telemetry is one event per received SYN, so this
			// counts connection attempts from one remote address.
			Threshold: policy.Threshold{
				Count:   20,
				Within:  policy.Duration{Duration: time.Minute},
				GroupBy: []string{"peer"},
			},
			Cooldown: policy.Duration{Duration: 10 * time.Minute},
			Message:  "a remote address opened repeated SSH connections",
			Tags:     []string{"baseline", "ssh", "brute-force", "credential-access"},
		},
		{
			ID:       "baseline.policy-denial-burst",
			Enabled:  &enabled,
			Severity: "notice",
			Events: []string{
				"resolver_blocked", "egress_blocked", "exec_blocked",
				"file_blocked", "bind_blocked", "unix_blocked", "sockopt_blocked",
			},
			Threshold: policy.Threshold{
				Count:   5,
				Within:  policy.Duration{Duration: time.Minute},
				GroupBy: []string{"cgroup", "executable"},
			},
			Cooldown: policy.Duration{Duration: 5 * time.Minute},
			Message:  "repeated policy denials were observed",
			Tags:     []string{"baseline", "policy"},
		},
	}
}

func effectiveRules(custom []policy.DetectionRule, disabled []string) []policy.DetectionRule {
	rules := make(map[string]policy.DetectionRule, len(custom)+len(BaselineRules()))
	for _, rule := range BaselineRules() {
		rules[rule.ID] = rule
	}
	for _, rule := range custom {
		rules[rule.ID] = rule
	}
	for _, id := range disabled {
		delete(rules, id)
	}
	result := make([]policy.DetectionRule, 0, len(rules))
	for _, rule := range rules {
		if rule.Enabled == nil || *rule.Enabled {
			result = append(result, rule)
		}
	}
	slices.SortFunc(result, func(left, right policy.DetectionRule) int {
		switch {
		case left.ID < right.ID:
			return -1
		case left.ID > right.ID:
			return 1
		default:
			return 0
		}
	})
	return result
}
