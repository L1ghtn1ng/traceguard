package doctor

import (
	"io/fs"
	"strings"
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
	}), ebpfmonitor.KernelFeatures{BPFLSMAvailable: true, LSMProgramType: true, TaskStorage: true}))
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

func TestHostPostureNeedsLSMProgramsAndTaskStorage(t *testing.T) {
	t.Parallel()

	for name, features := range map[string]ebpfmonitor.KernelFeatures{
		"no LSM programs": {BPFLSMAvailable: true, TaskStorage: true},
		"no task storage": {BPFLSMAvailable: true, LSMProgramType: true},
	} {
		if level := postureLevels(hostPosture(fakeFiles(nil), features))["posture-bpf-lsm"]; level != "WARN" {
			t.Errorf("%s: posture-bpf-lsm = %q, want WARN", name, level)
		}
	}
}

func TestModuleSigningPosture(t *testing.T) {
	t.Parallel()

	const sigEnforce = "/sys/module/module/parameters/sig_enforce"
	denied := func(path string) ([]byte, error) {
		if path == sigEnforce {
			return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrPermission}
		}
		return nil, fs.ErrNotExist
	}
	for name, test := range map[string]struct {
		readFile func(string) ([]byte, error)
		lockdown string
		level    string
		detail   string
	}{
		"lockdown rejects unsigned": {fakeFiles(map[string]string{sigEnforce: "N\n"}), "integrity", "INFO", "rejects unsigned"},
		"no lockdown":               {fakeFiles(map[string]string{sigEnforce: "N\n"}), "none", "WARN", "not enforced"},
		"not built in":              {fakeFiles(nil), "integrity", "WARN", "not built into"},
		"unreadable":                {denied, "none", "WARN", "unreadable"},
	} {
		read := func(path string) (string, bool) {
			raw, err := test.readFile(path)
			return string(raw), err == nil
		}
		finding := moduleSigningPosture(test.readFile, read, test.lockdown)
		if finding.level != test.level || !strings.Contains(finding.detail, test.detail) {
			t.Errorf("%s: finding = %+v, want %s containing %q", name, finding, test.level, test.detail)
		}
	}
}
