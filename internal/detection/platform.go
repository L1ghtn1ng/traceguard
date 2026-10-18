package detection

import (
	"slices"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

// PlatformExceptions are the opt-in platform profile: exceptions for routine
// activity of common cloud guest agents, container runtimes, CNI plugins, and
// BPF-based networking, enabled with builtin_profiles: [platform]. Exceptions
// for runtime rules apply only while the runtime profile is also enabled.
//
// The programs selector matches the kernel comm, which any process can set
// for itself, and command lines are chosen by the caller of exec; so each
// exception is limited to root and narrows a rule rather than authenticating
// the agent it names.
func PlatformExceptions() []policy.DetectionException {
	root := []uint32{0}
	return []policy.DetectionException{
		{
			ID:     "platform.cloud-guest-agent-imds",
			Rules:  []string{"baseline.cloud-metadata-access"},
			Reason: "root-owned AWS SSM and Google guest and OS Config agents poll instance metadata continuously",
			Match: policy.DetectionMatch{
				UIDs: root,
				// Comm is cut to 15 bytes: amazon-ssm-agent, ssm-agent-worker,
				// google_guest_agent, and google_osconfig_agent.
				Programs: []string{"amazon-ssm-agen", "ssm-agent-worke", "google_guest_ag", "google_osconfig"},
			},
		},
		{
			ID:     "platform.container-runtime-setns",
			Rules:  []string{"runtime.namespace-join"},
			Reason: "container runtimes and CNI plugins join container namespaces to start containers and set up their networking",
			Match: policy.DetectionMatch{
				UIDs:       root,
				Operations: []string{"setns"},
				// runc's init stages rename themselves runc:[0:PARENT],
				// runc:[1:CHILD], and runc:[2:INIT]; containerd shims are cut
				// to containerd-shim.
				Programs: []string{
					"runc", "runc:*", "crun", "containerd", "containerd-shim", "dockerd",
					"bridge", "loopback", "portmap", "calico", "cilium-cni",
				},
			},
		},
		{
			ID:     "platform.bpf-loaders",
			Rules:  []string{"runtime.bpf-program-load"},
			Reason: "systemd and container runtimes load cgroup device and firewall programs; Cilium and Calico load their datapath",
			Match: policy.DetectionMatch{
				UIDs:     root,
				Programs: []string{"systemd", "runc", "runc:*", "crun", "cilium-agent", "calico-node"},
			},
		},
		{
			ID:     "platform.runc-self-reexec",
			Rules:  []string{"runtime.fileless-exec"},
			Reason: "runc re-executes itself from a memfd at container start",
			Match: policy.DetectionMatch{
				UIDs:         root,
				ExecSources:  []string{"fd"},
				CommandGlobs: []string{"runc init", "*/runc init"},
			},
		},
	}
}

func builtinExceptions(profiles []string) []policy.DetectionException {
	if !slices.Contains(profiles, policy.ProfilePlatform) {
		return nil
	}
	return PlatformExceptions()
}

// effectiveExceptions adds the enabled profiles' built-in exceptions to a
// policy's; a policy exception with a built-in's ID replaces it.
func effectiveExceptions(profiles []string, custom []policy.DetectionException) []policy.DetectionException {
	builtin := builtinExceptions(profiles)
	if len(builtin) == 0 {
		return custom
	}
	exceptions := make([]policy.DetectionException, 0, len(builtin)+len(custom))
	for _, exception := range builtin {
		if !slices.ContainsFunc(custom, func(candidate policy.DetectionException) bool { return candidate.ID == exception.ID }) {
			exceptions = append(exceptions, exception)
		}
	}
	return append(exceptions, custom...)
}
