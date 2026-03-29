package config

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestParseBlockAllAddsWildcardPolicy(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-all"}

	t.Setenv("TRACEGUARD_BLOCK", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")
	t.Setenv("TRACEGUARD_BLOCK_ALL", "")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !slices.Contains(cfg.ManualDomains, "*") {
		t.Fatalf("ManualDomains = %v, want wildcard deny-all marker", cfg.ManualDomains)
	}
}

func TestParseRejectsUnexpectedPositionalArgs(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "README.md", "LICENSE"}

	t.Setenv("TRACEGUARD_BLOCK", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")
	t.Setenv("TRACEGUARD_BLOCK_ALL", "")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")

	_, err := Parse()
	if err == nil {
		t.Fatal("Parse succeeded with unexpected positional arguments")
	}
	if !strings.Contains(err.Error(), "quote '*'") || !strings.Contains(err.Error(), "-block-all") {
		t.Fatalf("Parse error = %q, want shell-quoting guidance", err)
	}
}
