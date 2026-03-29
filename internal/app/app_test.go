package app

import (
	"fmt"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/blocklist"
	"github.com/L1ghtn1ng/traceguard/internal/config"
	ebpfmonitor "github.com/L1ghtn1ng/traceguard/internal/ebpf"
)

func TestIsPermissionErrorMatchesWrappedEBPFError(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("attach execve tracepoint: %w", ebpfmonitor.ErrInsufficientPrivileges)
	if !IsPermissionError(err) {
		t.Fatal("IsPermissionError did not match wrapped privilege error")
	}
}

func TestIsPermissionErrorRejectsOtherErrors(t *testing.T) {
	t.Parallel()

	if IsPermissionError(fmt.Errorf("some other error")) {
		t.Fatal("IsPermissionError matched unrelated error")
	}
}

func TestValidateRulesForModeRejectsSuffixRulesInBlockMode(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		AllowSuffixes: []string{"example.com"},
	})
	if err == nil {
		t.Fatal("validateRulesForMode accepted suffix allow in block mode")
	}
}

func TestValidateRulesForModeAllowsDenyAllWithExactExceptions(t *testing.T) {
	t.Parallel()

	err := validateRulesForMode(config.Config{Block: true}, blocklist.Rules{
		BlockAllDomains:   true,
		BlockAllResolvers: true,
		AllowDomains:      []string{"resolver.example.com"},
	})
	if err != nil {
		t.Fatalf("validateRulesForMode returned error: %v", err)
	}
}
