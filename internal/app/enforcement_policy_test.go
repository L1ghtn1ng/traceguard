package app

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/cgroupinfo"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	"github.com/L1ghtn1ng/traceguard/internal/ebpf"
	policyconfig "github.com/L1ghtn1ng/traceguard/internal/policy"
)

func TestNetworkPolicyCompilationCanonicalizesMappedPrefixesBeforeMasking(t *testing.T) {
	t.Parallel()

	compilers := map[string]func(string) ([]netip.Prefix, error){
		"egress": func(cidr string) ([]netip.Prefix, error) {
			compiled, err := compileEgressPolicy(config.Config{}, policyconfig.EgressPolicy{Rules: []policyconfig.EgressRule{{
				ID: "mapped", Action: "block", Destinations: policyconfig.EgressDestinations{CIDRs: []string{cidr}},
			}}}, nil)
			if err != nil {
				return nil, err
			}
			return compiled.Rules[0].CIDRs, nil
		},
		"bind": func(cidr string) ([]netip.Prefix, error) {
			compiled, err := compileBindPolicy(config.Config{}, policyconfig.BindPolicy{Rules: []policyconfig.BindRule{{
				ID: "mapped", Action: "block", Endpoints: policyconfig.EgressDestinations{CIDRs: []string{cidr}},
			}}}, nil)
			if err != nil {
				return nil, err
			}
			return compiled.Rules[0].CIDRs, nil
		},
	}
	for name, compile := range compilers {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := compile("::ffff:192.0.2.129/95"); err == nil || !strings.Contains(err.Error(), "ambiguous below /96") {
				t.Fatalf("below-/96 mapped prefix error = %v, want ambiguity rejection", err)
			}
			cidrs, err := compile("::ffff:192.0.2.129/120")
			if err != nil {
				t.Fatalf("compile mapped subnet: %v", err)
			}
			want := netip.MustParsePrefix("192.0.2.0/24")
			if len(cidrs) != 1 || cidrs[0] != want {
				t.Fatalf("compiled CIDRs = %v, want [%s]", cidrs, want)
			}
		})
	}
}

func TestEnforcementEnabledFormulas(t *testing.T) {
	t.Parallel()
	block := config.Config{Block: true}
	dryRun := config.Config{DryRun: true}
	emergency := config.Config{Block: true, EmergencyAllow: true}

	allowOnly := policyconfig.PathPolicy{Default: "allow", Rules: []policyconfig.PathRule{{ID: "allow", Action: "allow", Match: policyconfig.PathMatch{PathGlobs: []string{"/bin/tool"}}}}}
	if got, err := compilePathPolicy(block, allowOnly, nil); err != nil || got.Enabled {
		t.Fatal("allow-only exec policy was enabled under default allow")
	}
	withBlock := allowOnly
	withBlock.Rules = append(withBlock.Rules, policyconfig.PathRule{ID: "block", Action: "block", Match: policyconfig.PathMatch{PathGlobs: []string{"/tmp/tool"}}})
	if got, err := compilePathPolicy(block, withBlock, nil); err != nil || !got.Enabled || !got.Enforce {
		t.Fatalf("blocking exec policy = %#v, want enabled enforcement", got)
	}
	if got, err := compilePathPolicy(dryRun, withBlock, nil); err != nil || !got.Enabled || got.Enforce {
		t.Fatalf("dry-run exec policy = %#v, want enabled without enforcement", got)
	}
	if got, err := compilePathPolicy(emergency, withBlock, nil); err != nil || got.Enabled || got.Enforce {
		t.Fatalf("emergency exec policy = %#v, want disabled", got)
	}

	unix, err := compileUnixPolicy(block, policyconfig.UnixPolicy{Default: "block"}, nil)
	if err != nil {
		t.Fatalf("compileUnixPolicy() error = %v", err)
	}
	if !unix.Enabled || !unix.Enforce || !unix.DefaultBlock {
		t.Fatalf("default-block unix policy = %#v", unix)
	}
}

func TestFileUnixAndSockoptCompilation(t *testing.T) {
	t.Parallel()
	cgroups := cgroupinfo.NewIndex([]cgroupinfo.Entry{{ID: 42, Path: "/system.slice/example.service"}})
	file, err := compileFilePolicy(config.Config{DryRun: true}, policyconfig.FilePolicy{Rules: []policyconfig.FileRule{
		{ID: "read", Action: "block", Selectors: policyconfig.EgressSelectors{UIDs: []uint32{1000}, CgroupPaths: []string{"/system.slice/example.service"}}, Match: policyconfig.FileMatch{PathGlobs: []string{"/secret"}, Access: []string{"read"}}},
		{ID: "both", Action: "block", Match: policyconfig.FileMatch{PathGlobs: []string{"/data"}, Access: []string{"read", "write"}}},
	}}, cgroups)
	if err != nil {
		t.Fatalf("compileFilePolicy() error = %v", err)
	}
	if got := file.Rules[0].AccessOrOps; len(got) != 1 || got[0] != 1 {
		t.Fatalf("read access keys = %v, want [1]", got)
	}
	if got := file.Rules[1].AccessOrOps; len(got) != 0 {
		t.Fatalf("read+write access keys = %v, want wildcard", got)
	}
	if got := file.Rules[0].CgroupIDs; len(got) != 1 || got[0] != 42 {
		t.Fatalf("selected cgroups = %v, want [42]", got)
	}

	unix, err := compileUnixPolicy(config.Config{Block: true}, policyconfig.UnixPolicy{Rules: []policyconfig.UnixRule{{
		ID: "unix", Action: "block", Match: policyconfig.UnixMatch{PathGlobs: []string{"/run/service.sock"}, Operations: []string{"connect", "recvmsg"}},
	}}}, nil)
	if err != nil {
		t.Fatalf("compileUnixPolicy() error = %v", err)
	}
	if got := unix.Rules[0].AccessOrOps; len(got) != 2 || got[0] != 1 || got[1] != 4 {
		t.Fatalf("unix operation keys = %v, want [1 4]", got)
	}

	sockopt, err := compileSockoptPolicy(config.Config{Block: true}, policyconfig.SockoptPolicy{Rules: []policyconfig.SockoptRule{{
		ID: "options", Action: "block", Match: policyconfig.SockoptMatch{
			Levels: []string{"socket", "sol_ip", "sol_ipv6"}, OptNames: []string{"so_mark", "so_reuseport", "ip_transparent", "ipv6_transparent"},
		},
	}}}, nil)
	if err != nil {
		t.Fatalf("compileSockoptPolicy() error = %v", err)
	}
	want := []ebpf.SockoptOption{{Level: 1, OptName: 36}, {Level: 1, OptName: 15}, {Level: 0, OptName: 19}, {Level: 41, OptName: 75}}
	if got := sockopt.Rules[0].Options; !slices.Equal(got, want) {
		t.Fatalf("sockopt options = %v, want %v", got, want)
	}
}

func TestEnforcementSelectorsIncludeEveryKernelPolicySection(t *testing.T) {
	t.Parallel()
	selector := func(path string) policyconfig.EgressSelectors {
		return policyconfig.EgressSelectors{CgroupPaths: []string{path}}
	}
	bundle := policyconfig.Bundle{
		Egress:  policyconfig.EgressPolicy{Rules: []policyconfig.EgressRule{{Selectors: selector("/egress")}}},
		Exec:    policyconfig.PathPolicy{Rules: []policyconfig.PathRule{{Selectors: selector("/exec")}}},
		File:    policyconfig.FilePolicy{Rules: []policyconfig.FileRule{{Selectors: selector("/file")}}},
		Bind:    policyconfig.BindPolicy{Rules: []policyconfig.BindRule{{Selectors: selector("/bind")}}},
		Unix:    policyconfig.UnixPolicy{Rules: []policyconfig.UnixRule{{Selectors: selector("/unix")}}},
		Sockopt: policyconfig.SockoptPolicy{Rules: []policyconfig.SockoptRule{{Selectors: selector("/sockopt")}}},
	}
	if got := enforcementSelectors(bundle); len(got) != 6 {
		t.Fatalf("selector count = %d, want 6", len(got))
	}
}

func TestEnforcedBlockingRulesRejectRecreatableCgroupSelectors(t *testing.T) {
	t.Parallel()

	selectors := []struct {
		name  string
		value policyconfig.EgressSelectors
	}{
		{name: "exact", value: policyconfig.EgressSelectors{CgroupPaths: []string{"/workloads/api"}}},
		{name: "prefix", value: policyconfig.EgressSelectors{CgroupPrefixes: []string{"/workloads"}}},
	}
	sections := []struct {
		name   string
		bundle func(policyconfig.EgressSelectors) policyconfig.Bundle
	}{
		{name: "egress", bundle: func(s policyconfig.EgressSelectors) policyconfig.Bundle {
			return policyconfig.Bundle{Egress: policyconfig.EgressPolicy{Rules: []policyconfig.EgressRule{{ID: "egress", Action: "block", Selectors: s}}}}
		}},
		{name: "exec", bundle: func(s policyconfig.EgressSelectors) policyconfig.Bundle {
			return policyconfig.Bundle{Exec: policyconfig.PathPolicy{Rules: []policyconfig.PathRule{{ID: "exec", Action: "block", Selectors: s}}}}
		}},
		{name: "file", bundle: func(s policyconfig.EgressSelectors) policyconfig.Bundle {
			return policyconfig.Bundle{File: policyconfig.FilePolicy{Rules: []policyconfig.FileRule{{ID: "file", Action: "block", Selectors: s}}}}
		}},
		{name: "bind", bundle: func(s policyconfig.EgressSelectors) policyconfig.Bundle {
			return policyconfig.Bundle{Bind: policyconfig.BindPolicy{Rules: []policyconfig.BindRule{{ID: "bind", Action: "block", Selectors: s}}}}
		}},
		{name: "unix", bundle: func(s policyconfig.EgressSelectors) policyconfig.Bundle {
			return policyconfig.Bundle{Unix: policyconfig.UnixPolicy{Rules: []policyconfig.UnixRule{{ID: "unix", Action: "block", Selectors: s}}}}
		}},
		{name: "sockopt", bundle: func(s policyconfig.EgressSelectors) policyconfig.Bundle {
			return policyconfig.Bundle{Sockopt: policyconfig.SockoptPolicy{Rules: []policyconfig.SockoptRule{{ID: "sockopt", Action: "block", Selectors: s}}}}
		}},
	}
	for _, selector := range selectors {
		for _, section := range sections {
			t.Run(section.name+" "+selector.name, func(t *testing.T) {
				t.Parallel()
				bundle := section.bundle(selector.value)
				if err := validateEnforcedCgroupSelectors(config.Config{Block: true}, bundle); err == nil {
					t.Fatal("block mode accepted a cgroup-scoped block rule")
				}
				if err := validateEnforcedCgroupSelectors(config.Config{DryRun: true}, bundle); err == nil {
					t.Fatal("dry-run mode accepted a cgroup-scoped block rule")
				}
				if err := validateEnforcedCgroupSelectors(config.Config{}, bundle); err != nil {
					t.Fatalf("observe mode rejected selector: %v", err)
				}
			})
		}
	}

	for _, selector := range selectors {
		t.Run("allow "+selector.name, func(t *testing.T) {
			t.Parallel()
			allowBundle := policyconfig.Bundle{Egress: policyconfig.EgressPolicy{Rules: []policyconfig.EgressRule{{
				ID: "allow", Action: "allow", Selectors: selector.value,
			}}}}
			if err := validateEnforcedCgroupSelectors(config.Config{Block: true}, allowBundle); err != nil {
				t.Fatalf("block mode rejected fail-closed cgroup allow selector: %v", err)
			}
		})
	}
}

func TestCompilationKeepsPrefixRootAsAncestorIdentity(t *testing.T) {
	t.Parallel()

	cgroups := cgroupinfo.NewIndex([]cgroupinfo.Entry{{ID: 42, Path: "/workloads"}})
	compiled, err := compilePathPolicy(config.Config{Block: true}, policyconfig.PathPolicy{Rules: []policyconfig.PathRule{{
		ID: "prefix", Action: "block",
		Selectors: policyconfig.EgressSelectors{CgroupPrefixes: []string{"/workloads"}},
		Match:     policyconfig.PathMatch{PathGlobs: []string{"/tmp/tool"}},
	}}}, cgroups)
	if err != nil {
		t.Fatal(err)
	}
	if got := compiled.Rules[0].CgroupAncestorIDs; !slices.Equal(got, []uint64{42}) {
		t.Fatalf("ancestor IDs = %v, want [42]", got)
	}
	if len(compiled.Rules[0].CgroupIDs) != 0 {
		t.Fatalf("exact IDs = %v, want none", compiled.Rules[0].CgroupIDs)
	}
}
