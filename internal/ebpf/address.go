package ebpf

import (
	"net/netip"

	"github.com/L1ghtn1ng/traceguard/internal/netprefix"
)

func canonicalPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	return netprefix.Canonical(prefix)
}
