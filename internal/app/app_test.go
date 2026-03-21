package app

import (
	"fmt"
	"testing"

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
