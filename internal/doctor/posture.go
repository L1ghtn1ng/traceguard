package doctor

import (
	"strings"

	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
)

// postureFinding is an advisory host hardening result. Posture never fails
// the doctor: it describes the host TraceGuard protects, not whether
// TraceGuard can run on it.
type postureFinding struct {
	level, name, detail string
}

// hostPosture reports kernel settings that change how much an attacker with
// local access can do, and how much TraceGuard can see or stop.
func hostPosture(readFile func(string) ([]byte, error), features ebpfmonitor.KernelFeatures) []postureFinding {
	read := func(path string) (string, bool) {
		raw, err := readFile(path)
		if err != nil {
			return "", false
		}
		return strings.TrimSpace(string(raw)), true
	}
	var findings []postureFinding
	add := func(ok bool, name, good, bad string) {
		if ok {
			findings = append(findings, postureFinding{"INFO", name, good})
		} else {
			findings = append(findings, postureFinding{"WARN", name, bad})
		}
	}

	add(features.BPFLSMAvailable, "posture-bpf-lsm",
		"bpf is in the active LSM list; exec and file enforcement can attach",
		"bpf is not in /sys/kernel/security/lsm; exec and file enforcement are unavailable, add lsm=...,bpf to the kernel command line")

	switch value, ok := read("/proc/sys/kernel/unprivileged_bpf_disabled"); {
	case !ok:
		findings = append(findings, postureFinding{"WARN", "posture-unprivileged-bpf", "kernel.unprivileged_bpf_disabled is unreadable"})
	default:
		add(value != "0", "posture-unprivileged-bpf",
			"kernel.unprivileged_bpf_disabled="+value+"; unprivileged users cannot load BPF programs",
			"kernel.unprivileged_bpf_disabled=0; unprivileged users can load BPF programs")
	}

	if value, ok := read("/sys/kernel/security/lockdown"); ok {
		mode := selectedOption(value)
		switch mode {
		case "none":
			findings = append(findings, postureFinding{"WARN", "posture-lockdown", "kernel lockdown is none; root can modify the running kernel"})
		case "confidentiality":
			findings = append(findings, postureFinding{"WARN", "posture-lockdown",
				"kernel lockdown is confidentiality, which restricts eBPF reads of kernel memory; confirm TraceGuard's programs load"})
		default:
			findings = append(findings, postureFinding{"INFO", "posture-lockdown", "kernel lockdown is " + mode})
		}
	} else {
		findings = append(findings, postureFinding{"WARN", "posture-lockdown", "kernel lockdown is not available"})
	}

	if disabled, ok := read("/proc/sys/kernel/modules_disabled"); ok && disabled == "1" {
		findings = append(findings, postureFinding{"INFO", "posture-module-signing", "kernel.modules_disabled=1; no further modules can be loaded"})
	} else if enforce, ok := read("/sys/module/module/parameters/sig_enforce"); ok {
		add(enforce == "Y", "posture-module-signing",
			"module signatures are enforced",
			"module signatures are not enforced; unsigned kernel modules can be loaded")
	} else {
		findings = append(findings, postureFinding{"WARN", "posture-module-signing", "module signature enforcement is not built into this kernel"})
	}

	if scope, ok := read("/proc/sys/kernel/yama/ptrace_scope"); ok {
		add(scope != "0", "posture-ptrace-scope",
			"kernel.yama.ptrace_scope="+scope+"; processes cannot ptrace arbitrary same-user processes",
			"kernel.yama.ptrace_scope=0; any process can ptrace other processes of the same user")
	} else {
		findings = append(findings, postureFinding{"WARN", "posture-ptrace-scope", "Yama ptrace restrictions are not available"})
	}
	return findings
}

// selectedOption returns the bracketed choice from a kernel option list such
// as "none [integrity] confidentiality".
func selectedOption(value string) string {
	for field := range strings.FieldsSeq(value) {
		if strings.HasPrefix(field, "[") && strings.HasSuffix(field, "]") {
			return strings.Trim(field, "[]")
		}
	}
	return value
}
