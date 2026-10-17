package netprefix

import (
	"fmt"
	"net/netip"
)

// Canonical returns a masked IPv4 or IPv6 prefix. IPv4-mapped IPv6 prefixes
// are converted to IPv4 before masking so their mapped form cannot be erased
// before the address family is selected.
func Canonical(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() {
		return netip.Prefix{}, fmt.Errorf("invalid prefix %q", prefix)
	}
	address := prefix.Addr()
	if !address.Is4In6() {
		return prefix.Masked(), nil
	}
	if prefix.Bits() < 96 {
		return netip.Prefix{}, fmt.Errorf("IPv4-mapped prefix %q is ambiguous below /96", prefix)
	}
	return netip.PrefixFrom(address.Unmap(), prefix.Bits()-96).Masked(), nil
}
