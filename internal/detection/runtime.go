package detection

import (
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// RuntimeRules are the opt-in runtime profile: detections over security and
// exec events, enabled with builtin_profiles: [runtime]. Each groups by the
// acting cgroup and executable with a cooldown, so one noisy process cannot
// hide another's first occurrence.
func RuntimeRules() []policy.DetectionRule {
	enabled := true
	perProcess := policy.Threshold{Count: 1, GroupBy: []string{"cgroup", "executable"}}
	rule := func(id, severity string, events []string, match policy.DetectionMatch, cooldown time.Duration, message string, tags []string, mitre policy.MITRE) policy.DetectionRule {
		return policy.DetectionRule{
			ID: id, Enabled: &enabled, Severity: severity, Events: events, Match: match,
			Threshold: perProcess, Cooldown: policy.Duration{Duration: cooldown},
			Message: message, Tags: append([]string{"runtime"}, tags...), MITRE: mitre,
		}
	}
	return []policy.DetectionRule{
		rule("runtime.kernel-module-load", "warning", []string{"module_load"}, policy.DetectionMatch{},
			10*time.Minute, "a process requested a kernel module load",
			[]string{"kernel", "persistence"},
			policy.MITRE{Tactics: []string{"TA0003", "TA0005"}, Techniques: []string{"T1547.006"}}),
		// Container networking and observability agents load BPF programs
		// routinely; add exceptions for them rather than disabling this rule.
		rule("runtime.bpf-program-load", "notice", []string{"bpf_prog_load"}, policy.DetectionMatch{},
			time.Hour, "a process loaded a BPF program",
			[]string{"kernel", "defense-evasion"},
			policy.MITRE{Tactics: []string{"TA0005"}, Techniques: []string{"T1014"}}),
		rule("runtime.ptrace-attach", "warning", []string{"ptrace"},
			policy.DetectionMatch{Operations: []string{"attach", "seize", "poketext", "pokedata", "pokeuser"}},
			10*time.Minute, "a process attached to or wrote into another process with ptrace",
			[]string{"injection"},
			policy.MITRE{Tactics: []string{"TA0004", "TA0005"}, Techniques: []string{"T1055.008"}}),
		rule("runtime.process-memory-write", "warning", []string{"process_vm"},
			policy.DetectionMatch{Operations: []string{"write"}},
			10*time.Minute, "a process wrote into another process's memory",
			[]string{"injection"},
			policy.MITRE{Tactics: []string{"TA0004", "TA0005"}, Techniques: []string{"T1055"}}),
		// runc re-executes itself from a memfd when it starts a container, so
		// container hosts need an exception for it.
		rule("runtime.fileless-exec", "warning", []string{"exec"},
			policy.DetectionMatch{ExecSources: []string{"fd"}},
			10*time.Minute, "a process executed a file descriptor instead of a path",
			[]string{"fileless", "execution"},
			policy.MITRE{Tactics: []string{"TA0005"}, Techniques: []string{"T1620"}}),
		rule("runtime.namespace-join", "notice", []string{"namespace_change"},
			policy.DetectionMatch{Operations: []string{"setns"}},
			time.Hour, "a process joined another namespace",
			[]string{"container", "escape"},
			policy.MITRE{Tactics: []string{"TA0004"}, Techniques: []string{"T1611"}}),
		rule("runtime.sensitive-filesystem-mount", "warning", []string{"mount"},
			policy.DetectionMatch{MountFSTypes: []string{"debugfs", "tracefs", "securityfs"}},
			time.Hour, "a process mounted a kernel debugging or security filesystem",
			[]string{"container", "escape"},
			policy.MITRE{Tactics: []string{"TA0004"}, Techniques: []string{"T1611"}}),
		{
			// File integrity changes may come from a rescan with no acting
			// process, so this rule groups by path. It only fires for paths
			// the policy's file_integrity section watches.
			ID: "runtime.persistence-file-change", Enabled: &enabled, Severity: "warning",
			Events: []string{"file_integrity"},
			Match: policy.DetectionMatch{
				Changes: []string{"created", "modified", "attributes"},
				FilePathGlobs: []string{
					"/etc/crontab", "/etc/cron.d/**", "/etc/cron.hourly/**", "/etc/cron.daily/**", "/var/spool/cron/**",
					"/etc/systemd/system/**", "/etc/init.d/**", "/etc/rc.local",
					"/etc/sudoers", "/etc/sudoers.d/**", "/etc/pam.d/**", "/etc/ld.so.preload",
					"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/ssh/sshd_config", "/root/.ssh/**",
				},
			},
			Threshold: policy.Threshold{Count: 1, GroupBy: []string{"path"}},
			Cooldown:  policy.Duration{Duration: 10 * time.Minute},
			Message:   "a persistence or account configuration file changed",
			Tags:      []string{"runtime", "persistence", "file-integrity"},
			MITRE: policy.MITRE{
				Tactics:    []string{"TA0003", "TA0004"},
				Techniques: []string{"T1053.003", "T1543.002", "T1548.003", "T1556.003", "T1574.006", "T1136.001", "T1098.004"},
			},
		},
		rule("runtime.sensitive-capability-request", "notice", []string{"privilege_change"},
			policy.DetectionMatch{Operations: []string{"capset"}, Capabilities: []string{"sys_admin", "sys_module", "sys_ptrace", "sys_rawio"}},
			time.Hour, "a process requested a sensitive capability",
			[]string{"privilege"},
			policy.MITRE{Tactics: []string{"TA0004"}, Techniques: []string{"T1548"}}),
	}
}
