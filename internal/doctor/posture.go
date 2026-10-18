package doctor

import (
	"errors"
	"io/fs"
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

	switch {
	case !features.BPFLSMAvailable:
		findings = append(findings, postureFinding{"WARN", "posture-bpf-lsm",
			"bpf is not in /sys/kernel/security/lsm; exec and file enforcement are unavailable, add lsm=...,bpf to the kernel command line"})
	case !features.LSMProgramType || !features.TaskStorage:
		findings = append(findings, postureFinding{"WARN", "posture-bpf-lsm",
			"bpf is in the active LSM list, but the kernel lacks LSM program or task storage support; exec and file enforcement are unavailable"})
	default:
		findings = append(findings, postureFinding{"INFO", "posture-bpf-lsm",
			"bpf is in the active LSM list with LSM program and task storage support; exec and file enforcement can attach"})
	}

	switch value, ok := read("/proc/sys/kernel/unprivileged_bpf_disabled"); {
	case !ok:
		findings = append(findings, postureFinding{"WARN", "posture-unprivileged-bpf", "kernel.unprivileged_bpf_disabled is unreadable"})
	default:
		add(value != "0", "posture-unprivileged-bpf",
			"kernel.unprivileged_bpf_disabled="+value+"; unprivileged users cannot load BPF programs",
			"kernel.unprivileged_bpf_disabled=0; unprivileged users can load BPF programs")
	}

	lockdown := ""
	if value, ok := read("/sys/kernel/security/lockdown"); ok {
		mode := selectedOption(value)
		lockdown = mode
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

	findings = append(findings, moduleSigningPosture(readFile, read, lockdown))

	if scope, ok := read("/proc/sys/kernel/yama/ptrace_scope"); ok {
		add(scope != "0", "posture-ptrace-scope",
			"kernel.yama.ptrace_scope="+scope+"; processes cannot ptrace arbitrary same-user processes",
			"kernel.yama.ptrace_scope=0; any process can ptrace other processes of the same user")
	} else {
		findings = append(findings, postureFinding{"WARN", "posture-ptrace-scope", "Yama ptrace restrictions are not available"})
	}
	return findings
}

// moduleSigningPosture reports whether unsigned kernel modules can load.
// Integrity or confidentiality lockdown rejects them when module signing is
// built in, even with sig_enforce off.
func moduleSigningPosture(readFile func(string) ([]byte, error), read func(string) (string, bool), lockdown string) postureFinding {
	const name = "posture-module-signing"
	if disabled, ok := read("/proc/sys/kernel/modules_disabled"); ok && disabled == "1" {
		return postureFinding{"INFO", name, "kernel.modules_disabled=1; no further modules can be loaded"}
	}
	raw, err := readFile("/sys/module/module/parameters/sig_enforce")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return postureFinding{"WARN", name, "module signature enforcement is not built into this kernel"}
	case err != nil:
		return postureFinding{"WARN", name, "module signature enforcement is unreadable: " + err.Error()}
	case strings.TrimSpace(string(raw)) == "Y":
		return postureFinding{"INFO", name, "module signatures are enforced"}
	case lockdown == "integrity" || lockdown == "confidentiality":
		return postureFinding{"INFO", name, "kernel lockdown is " + lockdown + ", which rejects unsigned kernel modules"}
	default:
		return postureFinding{"WARN", name, "module signatures are not enforced; unsigned kernel modules can be loaded"}
	}
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
