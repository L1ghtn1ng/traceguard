package ebpf

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	ebpffeatures "github.com/cilium/ebpf/features"
)

const (
	kernelFeatureSetLegacy  = "legacy"
	kernelFeatureSetLinux71 = "linux71"
)

type KernelFeatures struct {
	Release             string
	KernelAtLeast612    bool
	KernelAtLeast71     bool
	BTFAvailable        bool
	BPFLSMAvailable     bool
	LSMProgramType      bool
	EnhancedTelemetry   bool
	SelectedFeatureSet  string
	SelectedObject      string
	EnhancedLoadFailure string
}

func DetectKernelFeatures() KernelFeatures {
	release, releaseErr := kernelRelease()
	features := kernelFeaturesForRelease(release, releaseErr)
	if _, err := btf.LoadKernelSpec(); err == nil {
		features.BTFAvailable = true
	}
	features.BPFLSMAvailable = detectBPFLSM()
	features.LSMProgramType = featureAvailable(ebpffeatures.HaveProgramType(cebpf.LSM))
	return features
}

func featureAvailable(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, cebpf.ErrNotSupported) {
		return false
	}
	return false
}

func kernelFeaturesForRelease(release string, releaseErr error) KernelFeatures {
	features := KernelFeatures{
		Release:            release,
		SelectedFeatureSet: kernelFeatureSetLegacy,
		SelectedObject:     "none",
	}
	if releaseErr != nil {
		features.EnhancedLoadFailure = fmt.Sprintf("detect kernel release: %v", releaseErr)
		return features
	}
	features.KernelAtLeast612 = isKernelAtLeast(release, 6, 12)
	features.KernelAtLeast71 = isKernelAtLeast(release, 7, 1)
	return features
}

func ProbeKernelFeatures() KernelFeatures {
	detected := DetectKernelFeatures()
	if detected.EnhancedLoadFailure != "" {
		return detected
	}
	if !detected.KernelAtLeast612 {
		detected.EnhancedLoadFailure = ErrUnsupportedKernel.Error()
		return detected
	}
	loadOptions := newCollectionOptions()
	// A non-zero window keeps the verifier checking the deduplication path,
	// which a zero constant would let it prune as dead code.
	objects, features, err := loadMonitorObjects(loadOptions, loadConstants{connectionDedupeWindow: time.Minute})
	if err != nil {
		features.EnhancedLoadFailure = err.Error()
		return features
	}
	_ = objects.Close()
	return features
}

func detectBPFLSM() bool {
	raw, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for lsm := range strings.SplitSeq(strings.TrimSpace(string(raw)), ",") {
		if strings.TrimSpace(lsm) == "bpf" {
			return true
		}
	}
	return false
}

func isKernelAtLeast(release string, wantMajor, wantMinor int) bool {
	major, minor, ok := parseKernelRelease(release)
	if !ok {
		return false
	}
	if major != wantMajor {
		return major > wantMajor
	}
	return minor >= wantMinor
}

func (f KernelFeatures) FeatureGates() map[string]bool {
	return map[string]bool{
		"kernel_at_least_6_12": f.KernelAtLeast612,
		"kernel_at_least_7_1":  f.KernelAtLeast71,
		"btf":                  f.BTFAvailable,
		"bpf_lsm":              f.BPFLSMAvailable,
		"lsm_program_type":     f.LSMProgramType,
		"enhanced_telemetry":   f.EnhancedTelemetry,
	}
}
