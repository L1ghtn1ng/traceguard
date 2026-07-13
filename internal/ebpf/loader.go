package ebpf

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

func validateKernelRelease(release string) error {
	if !isKernelAtLeast(release, 6, 12) {
		return fmt.Errorf("%w (running %s)", ErrUnsupportedKernel, release)
	}
	return nil
}

func newCollectionOptions() *ebpf.CollectionOptions {
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel:     ebpf.LogLevelBranch,
			LogSizeStart: 1 << 20,
		},
	}

	kernelTypes, err := btf.LoadKernelSpec()
	if err == nil {
		opts.Programs.KernelTypes = kernelTypes
	}

	return opts
}

func loadMonitorObjects(loadOptions *ebpf.CollectionOptions) (monitorObjects, KernelFeatures, error) {
	features := DetectKernelFeatures()
	release := features.Release
	if features.KernelAtLeast71 {
		objects, nextFeatures, err := loadLinux71MonitorObjects(loadOptions, features)
		if err == nil {
			return objects, nextFeatures, nil
		}
		features = nextFeatures
	}

	if isLinux612x(release) {
		objects, err := loadMonitorVariant(loadTraceguardDNSCompat, loadOptions)
		if err == nil {
			features.SelectedObject = "traceguardDNSCompat"
			return objects, features, nil
		}
		if isRecvmsgContextVerifierError(err) {
			compatObjects, compatErr := loadMonitorVariant(loadTraceguardDNSRecvmsgCompat, loadOptions)
			if compatErr != nil {
				return monitorObjects{}, features, fmt.Errorf("load eBPF objects for kernel %s: dns compat load failed: %v; dns+recvmsg compat retry failed: %w", release, err, compatErr)
			}
			features.SelectedObject = "traceguardDNSRecvmsgCompat"
			return compatObjects, features, nil
		}
		if isDNSHelperVerifierError(err) {
			compatObjects, compatErr := loadMonitorVariant(loadTraceguardDNSRecvmsgCompat, loadOptions)
			if compatErr == nil {
				features.SelectedObject = "traceguardDNSRecvmsgCompat"
				return compatObjects, features, nil
			}
		}
		return monitorObjects{}, features, fmt.Errorf("load eBPF objects for kernel %s: %w", release, err)
	}

	objects, variant, err := loadCompatibleMonitorObjects(loadOptions, monitorVariantLoaders{
		defaultVariant:   variantLoader(loadTraceguard),
		dnsCompat:        variantLoader(loadTraceguardDNSCompat),
		recvmsgCompat:    variantLoader(loadTraceguardRecvmsgCompat),
		dnsRecvmsgCompat: variantLoader(loadTraceguardDNSRecvmsgCompat),
	})
	if err != nil {
		return monitorObjects{}, features, fmt.Errorf("load eBPF objects: %w", err)
	}
	features.SelectedObject = "traceguard" + variant.suffix()
	return objects, features, nil
}

type monitorVariantLoaders struct {
	defaultVariant   func(*ebpf.CollectionOptions) (monitorObjects, error)
	dnsCompat        func(*ebpf.CollectionOptions) (monitorObjects, error)
	recvmsgCompat    func(*ebpf.CollectionOptions) (monitorObjects, error)
	dnsRecvmsgCompat func(*ebpf.CollectionOptions) (monitorObjects, error)
}

func loadLinux71MonitorObjects(loadOptions *ebpf.CollectionOptions, features KernelFeatures) (monitorObjects, KernelFeatures, error) {
	return loadLinux71MonitorObjectsWith(loadOptions, features, monitorVariantLoaders{
		defaultVariant:   variantLoader(loadTraceguardLinux71),
		dnsCompat:        variantLoader(loadTraceguardLinux71DNSCompat),
		recvmsgCompat:    variantLoader(loadTraceguardLinux71RecvmsgCompat),
		dnsRecvmsgCompat: variantLoader(loadTraceguardLinux71DNSRecvmsgCompat),
	})
}

func loadLinux71MonitorObjectsWith(loadOptions *ebpf.CollectionOptions, features KernelFeatures, loaders monitorVariantLoaders) (monitorObjects, KernelFeatures, error) {
	objects, variant, err := loadCompatibleMonitorObjects(loadOptions, loaders)
	if err != nil {
		features.EnhancedLoadFailure = err.Error()
		return monitorObjects{}, features, err
	}
	features.EnhancedTelemetry = true
	features.SelectedFeatureSet = kernelFeatureSetLinux71
	features.SelectedObject = "traceguardLinux71" + variant.suffix()
	features.EnhancedLoadFailure = ""
	return objects, features, nil
}

type monitorVariant uint8

const (
	monitorVariantDefault monitorVariant = iota
	monitorVariantDNSCompat
	monitorVariantRecvmsgCompat
	monitorVariantDNSRecvmsgCompat
)

func (variant monitorVariant) suffix() string {
	switch variant {
	case monitorVariantDNSCompat:
		return "DNSCompat"
	case monitorVariantRecvmsgCompat:
		return "RecvmsgCompat"
	case monitorVariantDNSRecvmsgCompat:
		return "DNSRecvmsgCompat"
	default:
		return ""
	}
}

func variantLoader(loadSpec func() (*ebpf.CollectionSpec, error)) func(*ebpf.CollectionOptions) (monitorObjects, error) {
	return func(opts *ebpf.CollectionOptions) (monitorObjects, error) {
		return loadMonitorVariant(loadSpec, opts)
	}
}

func loadCompatibleMonitorObjects(loadOptions *ebpf.CollectionOptions, loaders monitorVariantLoaders) (monitorObjects, monitorVariant, error) {
	objects, defaultErr := loaders.defaultVariant(loadOptions)
	if defaultErr == nil {
		return objects, monitorVariantDefault, nil
	}

	if isRecvmsgContextVerifierError(defaultErr) {
		objects, recvmsgErr := loaders.recvmsgCompat(loadOptions)
		if recvmsgErr == nil {
			return objects, monitorVariantRecvmsgCompat, nil
		}
		if shouldTryDNSRecvmsgCompat(defaultErr, recvmsgErr) {
			objects, combinedErr := loaders.dnsRecvmsgCompat(loadOptions)
			if combinedErr == nil {
				return objects, monitorVariantDNSRecvmsgCompat, nil
			}
			return monitorObjects{}, monitorVariantDefault, fmt.Errorf("default load failed: %v; recvmsg compat retry failed: %v; dns+recvmsg compat retry failed: %w", defaultErr, recvmsgErr, combinedErr)
		}
		return monitorObjects{}, monitorVariantDefault, fmt.Errorf("default load failed: %v; recvmsg compat retry failed: %w", defaultErr, recvmsgErr)
	}
	if !isDNSHelperVerifierError(defaultErr) {
		return monitorObjects{}, monitorVariantDefault, defaultErr
	}

	objects, dnsErr := loaders.dnsCompat(loadOptions)
	if dnsErr == nil {
		return objects, monitorVariantDNSCompat, nil
	}
	if isRecvmsgContextVerifierError(dnsErr) {
		objects, combinedErr := loaders.dnsRecvmsgCompat(loadOptions)
		if combinedErr == nil {
			return objects, monitorVariantDNSRecvmsgCompat, nil
		}
		return monitorObjects{}, monitorVariantDefault, fmt.Errorf("dns compat retry failed: %v; dns+recvmsg compat retry failed: %w", dnsErr, combinedErr)
	}
	return monitorObjects{}, monitorVariantDefault, fmt.Errorf("default load failed: %v; dns compat retry failed: %w", defaultErr, dnsErr)
}

func shouldTryDNSRecvmsgCompat(errs ...error) bool {
	return slices.ContainsFunc(errs, isDNSHelperVerifierError)
}

func isRecvmsgContextVerifierError(err error) bool {
	if err == nil {
		return false
	}
	return errorContainsAny(err, "trace_recvmsg4", "trace_recvmsg6", "TraceRecvmsg4", "TraceRecvmsg6") &&
		verifierLogContainsAny(err, "invalid bpf_context access off=40", "dereference of modified ctx ptr")
}

func loadMonitorVariant(loadSpec func() (*ebpf.CollectionSpec, error), loadOptions *ebpf.CollectionOptions) (monitorObjects, error) {
	var objects monitorObjects

	spec, err := loadSpec()
	if err != nil {
		return monitorObjects{}, err
	}
	if err := spec.LoadAndAssign(&objects, loadOptions); err != nil {
		_ = objects.Close()
		return monitorObjects{}, err
	}
	return objects, nil
}

func kernelRelease() (string, error) {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "", err
	}
	var builder strings.Builder
	for _, b := range uts.Release {
		if b == 0 {
			break
		}
		builder.WriteByte(byte(b))
	}
	return builder.String(), nil
}

func isLinux612x(release string) bool {
	major, minor, ok := parseKernelRelease(release)
	return ok && major == 6 && minor == 12
}

func parseKernelRelease(release string) (int, int, bool) {
	release = strings.TrimSpace(release)
	if release == "" {
		return 0, 0, false
	}
	var major, minor int
	if _, err := fmt.Sscanf(release, "%d.%d", &major, &minor); err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func isDNSHelperVerifierError(err error) bool {
	if err == nil {
		return false
	}
	return errorContainsAny(err, "trace_dns", "TraceDns") &&
		verifierLogContainsAny(err, "program of this type cannot use helper bpf_get_current_comm#16")
}

func errorContainsAny(err error, needles ...string) bool {
	message := err.Error()
	return slices.ContainsFunc(needles, func(needle string) bool {
		return strings.Contains(message, needle)
	})
}

func verifierLogContainsAny(err error, needles ...string) bool {
	var verifierErr *ebpf.VerifierError
	if !errors.As(err, &verifierErr) {
		return errorContainsAny(err, needles...)
	}
	return slices.ContainsFunc(verifierErr.Log, func(line string) bool {
		return slices.ContainsFunc(needles, func(needle string) bool {
			return strings.Contains(line, needle)
		})
	})
}

func isPermissionDenied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}
