package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	egressIdentityGlobal = iota
	egressIdentityUID
	egressIdentityCgroup
	egressIdentityUIDCgroup

	egressProtocolTCP = 2
	egressProtocolUDP = 1

	egressIdentityBytes = 17
)

type egressCompiledPolicy struct {
	allow4  map[egress4Key]uint32
	block4  map[egress4Key]uint32
	allow6  map[egress6Key]uint32
	block6  map[egress6Key]uint32
	ruleIDs map[uint32]string
}

type egressIdentity struct {
	kind     uint8
	uid      uint32
	cgroupID uint64
}

func compileEgressPolicy(policy EgressPolicyConfig) (egressCompiledPolicy, error) {
	compiled := egressCompiledPolicy{
		allow4:  make(map[egress4Key]uint32),
		block4:  make(map[egress4Key]uint32),
		allow6:  make(map[egress6Key]uint32),
		block6:  make(map[egress6Key]uint32),
		ruleIDs: make(map[uint32]string, len(policy.Rules)),
	}
	for _, rule := range policy.Rules {
		ruleNumber := egressRuleNumber(rule.ID)
		if previous, exists := compiled.ruleIDs[ruleNumber]; exists && previous != rule.ID {
			return egressCompiledPolicy{}, fmt.Errorf("egress rule id hash collision between %q and %q", previous, rule.ID)
		}
		compiled.ruleIDs[ruleNumber] = rule.ID
		prefixes := slices.Clone(rule.CIDRs)
		if len(prefixes) == 0 {
			prefixes = []netip.Prefix{
				netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				netip.PrefixFrom(netip.IPv6Unspecified(), 0),
			}
		}
		ports := slices.Clone(rule.Ports)
		if len(ports) == 0 {
			ports = []uint16{0}
		}
		protocols, err := encodeEgressProtocols(rule.Protocols)
		if err != nil {
			return egressCompiledPolicy{}, fmt.Errorf("egress rule %q: %w", rule.ID, err)
		}
		identityCount := egressIdentityCount(rule)
		if identityCount == 0 {
			continue
		}
		ipv4Prefixes := 0
		ipv6Prefixes := 0
		for _, prefix := range prefixes {
			if prefix.Addr().Is4() {
				ipv4Prefixes++
			} else if prefix.Addr().Is6() {
				ipv6Prefixes++
			}
		}
		for family, prefixCount := range map[string]int{"IPv4": ipv4Prefixes, "IPv6": ipv6Prefixes} {
			if prefixCount == 0 {
				continue
			}
			if identityCount > egressMaxEntries/prefixCount/len(protocols)/len(ports) {
				return egressCompiledPolicy{}, fmt.Errorf("egress rule %q expands beyond %d %s map entries", rule.ID, egressMaxEntries, family)
			}
		}
		identities := expandEgressIdentities(rule)
		for _, identity := range identities {
			for _, prefix := range prefixes {
				for _, protocol := range protocols {
					for _, port := range ports {
						switch {
						case prefix.Addr().Is4() && rule.Action == "allow":
							compiled.allow4[encodeEgress4Key(identity, protocol, port, prefix)] = ruleNumber
						case prefix.Addr().Is4():
							compiled.block4[encodeEgress4Key(identity, protocol, port, prefix)] = ruleNumber
						case prefix.Addr().Is6() && rule.Action == "allow":
							compiled.allow6[encodeEgress6Key(identity, protocol, port, prefix)] = ruleNumber
						case prefix.Addr().Is6():
							compiled.block6[encodeEgress6Key(identity, protocol, port, prefix)] = ruleNumber
						default:
							return egressCompiledPolicy{}, fmt.Errorf("egress rule %q has invalid prefix %q", rule.ID, prefix)
						}
					}
				}
			}
		}
	}
	for action, count := range map[string]int{
		"IPv4 allow": len(compiled.allow4),
		"IPv4 block": len(compiled.block4),
		"IPv6 allow": len(compiled.allow6),
		"IPv6 block": len(compiled.block6),
	} {
		if count > egressMaxEntries {
			return egressCompiledPolicy{}, fmt.Errorf("%s egress entries %d exceed map capacity %d", action, count, egressMaxEntries)
		}
	}
	return compiled, nil
}

func egressIdentityCount(rule EgressRuleConfig) int {
	switch {
	case !rule.HasUIDSelector && !rule.HasCgroupSelector:
		return 1
	case rule.HasUIDSelector && !rule.HasCgroupSelector:
		return len(rule.UIDs)
	case !rule.HasUIDSelector && rule.HasCgroupSelector:
		return len(rule.CgroupIDs)
	default:
		if len(rule.UIDs) == 0 || len(rule.CgroupIDs) == 0 {
			return 0
		}
		if len(rule.UIDs) > egressMaxEntries/len(rule.CgroupIDs) {
			return egressMaxEntries + 1
		}
		return len(rule.UIDs) * len(rule.CgroupIDs)
	}
}

func expandEgressIdentities(rule EgressRuleConfig) []egressIdentity {
	switch {
	case !rule.HasUIDSelector && !rule.HasCgroupSelector:
		return []egressIdentity{{kind: egressIdentityGlobal}}
	case rule.HasUIDSelector && !rule.HasCgroupSelector:
		identities := make([]egressIdentity, 0, len(rule.UIDs))
		for _, uid := range rule.UIDs {
			identities = append(identities, egressIdentity{kind: egressIdentityUID, uid: uid})
		}
		return identities
	case !rule.HasUIDSelector && rule.HasCgroupSelector:
		identities := make([]egressIdentity, 0, len(rule.CgroupIDs))
		for _, cgroupID := range rule.CgroupIDs {
			identities = append(identities, egressIdentity{kind: egressIdentityCgroup, cgroupID: cgroupID})
		}
		return identities
	default:
		identities := make([]egressIdentity, 0, len(rule.UIDs)*len(rule.CgroupIDs))
		for _, uid := range rule.UIDs {
			for _, cgroupID := range rule.CgroupIDs {
				identities = append(identities, egressIdentity{
					kind:     egressIdentityUIDCgroup,
					uid:      uid,
					cgroupID: cgroupID,
				})
			}
		}
		return identities
	}
}

func encodeEgressProtocols(protocols []string) ([]uint8, error) {
	if len(protocols) == 0 {
		return []uint8{egressProtocolTCP, egressProtocolUDP}, nil
	}
	encoded := make([]uint8, 0, len(protocols))
	for _, protocol := range protocols {
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "tcp":
			encoded = append(encoded, egressProtocolTCP)
		case "udp":
			encoded = append(encoded, egressProtocolUDP)
		default:
			return nil, fmt.Errorf("unsupported protocol %q", protocol)
		}
	}
	return encoded, nil
}

func encodeEgress4Key(identity egressIdentity, protocol uint8, port uint16, prefix netip.Prefix) egress4Key {
	var key egress4Key
	key.PrefixLen = egressIdentityBytes*8 + uint32(prefix.Bits())
	encodeEgressIdentity(key.Data[:], identity, protocol, port)
	address := prefix.Masked().Addr().As4()
	copy(key.Data[egressIdentityBytes:], address[:])
	return key
}

func encodeEgress6Key(identity egressIdentity, protocol uint8, port uint16, prefix netip.Prefix) egress6Key {
	var key egress6Key
	key.PrefixLen = egressIdentityBytes*8 + uint32(prefix.Bits())
	encodeEgressIdentity(key.Data[:], identity, protocol, port)
	address := prefix.Masked().Addr().As16()
	copy(key.Data[egressIdentityBytes:], address[:])
	return key
}

func encodeEgressIdentity(data []byte, identity egressIdentity, protocol uint8, port uint16) {
	data[1] = identity.kind
	binary.NativeEndian.PutUint32(data[2:6], identity.uid)
	binary.NativeEndian.PutUint64(data[6:14], identity.cgroupID)
	data[14] = protocol
	binary.BigEndian.PutUint16(data[15:17], port)
}

func egressRuleNumber(id string) uint32 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(id))
	value := hash.Sum32()
	if value == 0 {
		return 1
	}
	return value
}

func syncEgress4MapSlot(m *ebpf.Map, next map[egress4Key]uint32, slot uint8) error {
	return syncEgressMapSlot(m, next, slot, func(key *egress4Key) *uint8 { return &key.Data[0] })
}

func syncEgress6MapSlot(m *ebpf.Map, next map[egress6Key]uint32, slot uint8) error {
	return syncEgressMapSlot(m, next, slot, func(key *egress6Key) *uint8 { return &key.Data[0] })
}

func syncEgressMapSlot[K comparable](m *ebpf.Map, next map[K]uint32, slot uint8, slotField func(*K) *uint8) error {
	if slot > 1 {
		return fmt.Errorf("invalid policy slot %d", slot)
	}
	iter := m.Iterate()
	var key K
	var value uint32
	var stale []K
	for iter.Next(&key, &value) {
		if *slotField(&key) == slot {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, key := range stale {
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	for key, value := range next {
		*slotField(&key) = slot
		if err := m.Put(key, value); err != nil {
			return err
		}
	}
	return nil
}
