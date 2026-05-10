//go:build linux && cgo

package hardening

/*
#include <stdint.h>

__attribute__((noinline)) uintptr_t traceguard_stack_protector_anchor(uintptr_t value) {
	volatile char buffer[32];
	buffer[0] = (char)value;
	return (uintptr_t)buffer[0];
}
*/
import "C"

func Anchor() {
	_ = C.traceguard_stack_protector_anchor(0)
}
