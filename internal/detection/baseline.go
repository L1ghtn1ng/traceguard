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
			ID:       "baseline.exec-from-shared-memory",
			Enabled:  &enabled,
			Severity: "warning",
			Events:   []string{"exec"},
			Match: policy.DetectionMatch{
				ExecutableGlobs: []string{"/dev/shm/**", "/run/shm/**"},
			},
			Cooldown: policy.Duration{Duration: 5 * time.Minute},
			Message:  "process executed from a shared-memory filesystem",
			Tags:     []string{"baseline", "execution"},
			Threshold: policy.Threshold{
				Count: 1,
			},
		},
		{
			ID:       "baseline.sensitive-auth-file-write",
			Enabled:  &enabled,
			Severity: "warning",
			Events:   []string{"file_access", "file_created"},
			Match: policy.DetectionMatch{
				FilePathGlobs: []string{
					"/etc/passwd",
					"/etc/shadow",
					"/etc/sudoers",
					"/etc/sudoers.d/**",
					"/root/.ssh/**",
				},
				FileAccess: []string{"write"},
			},
			Cooldown: policy.Duration{Duration: 5 * time.Minute},
			Message:  "sensitive authentication file was opened for writing",
			Tags:     []string{"baseline", "persistence", "privilege-escalation"},
			Threshold: policy.Threshold{
				Count: 1,
			},
		},
		{
			ID:       "baseline.policy-denial-burst",
			Enabled:  &enabled,
			Severity: "notice",
			Events:   []string{"blocked", "resolver_blocked", "egress_blocked"},
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
