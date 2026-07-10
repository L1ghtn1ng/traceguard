package ebpf

import (
	"errors"
	"strings"
	"testing"
)

func TestKernelFeaturesForReleasePreservesDetectionError(t *testing.T) {
	t.Parallel()

	features := kernelFeaturesForRelease("7.1.0", errors.New("uname failed"))
	if features.KernelAtLeast612 || features.KernelAtLeast71 {
		t.Fatal("kernel version flags were derived from a failed release detection")
	}
	if !strings.Contains(features.EnhancedLoadFailure, "detect kernel release: uname failed") {
		t.Fatalf("EnhancedLoadFailure = %q, want release detection error", features.EnhancedLoadFailure)
	}
}
