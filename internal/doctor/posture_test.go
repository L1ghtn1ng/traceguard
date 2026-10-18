package doctor

import (
	"io/fs"
	"testing"

	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
)

func fakeFiles(files map[string]string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if content, ok := files[path]; ok {
			return []byte(content), nil
		}
		return nil, &fs.PathError{Op: "read", Path: path, Err: fs.ErrNotExist}
	}
}

func postureLevels(findings []postureFinding) map[string]string {
	levels := make(map[string]string, len(findings))
	for _, finding := range findings {
		levels[finding.name] = finding.level
	}
	return levels
}

func TestHostPostureHardenedHost(t *testing.T) {
	t.Parallel()

	levels := postureLevels(hostPosture(fakeFiles(map[string]string{
		"/proc/sys/kernel/unprivileged_bpf_disabled": "2\n",
		"/sys/kernel/security/lockdown":              "none [integrity] confidentiality\n",
		"/sys/module/module/parameters/sig_enforce":  "Y\n",
		"/proc/sys/kernel/yama/ptrace_scope":         "1\n",
	}), ebpfmonitor.KernelFeatures{BPFLSMAvailable: true}))
	for _, name := range []string{"posture-bpf-lsm", "posture-unprivileged-bpf", "posture-lockdown", "posture-module-signing", "posture-ptrace-scope"} {
		if levels[name] != "INFO" {
			t.Errorf("%s = %q, want INFO", name, levels[name])
		}
	}
}

func TestHostPostureWeakHost(t *testing.T) {
	t.Parallel()

	levels := postureLevels(hostPosture(fakeFiles(map[string]string{
		"/proc/sys/kernel/unprivileged_bpf_disabled": "0\n",
		"/sys/kernel/security/lockdown":              "[none] integrity confidentiality\n",
		"/sys/module/module/parameters/sig_enforce":  "N\n",
		"/proc/sys/kernel/yama/ptrace_scope":         "0\n",
	}), ebpfmonitor.KernelFeatures{}))
	for _, name := range []string{"posture-bpf-lsm", "posture-unprivileged-bpf", "posture-lockdown", "posture-module-signing", "posture-ptrace-scope"} {
		if levels[name] != "WARN" {
			t.Errorf("%s = %q, want WARN", name, levels[name])
		}
	}
}

func TestHostPostureEdgeCases(t *testing.T) {
	t.Parallel()

	findings := hostPosture(fakeFiles(map[string]string{
		"/sys/kernel/security/lockdown":     "none integrity [confidentiality]\n",
		"/proc/sys/kernel/modules_disabled": "1\n",
	}), ebpfmonitor.KernelFeatures{BPFLSMAvailable: true})
	levels := postureLevels(findings)
	if levels["posture-lockdown"] != "WARN" || levels["posture-module-signing"] != "INFO" {
		t.Fatalf("levels = %v, want confidentiality warned and disabled modules accepted", levels)
	}
	if levels["posture-unprivileged-bpf"] != "WARN" || levels["posture-ptrace-scope"] != "WARN" {
		t.Fatalf("unreadable settings were not warned: %v", levels)
	}
	if got := selectedOption("none [integrity] confidentiality"); got != "integrity" {
		t.Fatalf("selectedOption = %q", got)
	}
}
