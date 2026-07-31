package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

const maxEnforcedSuffixWireBytes = 64

func (m *Monitor) ApplyPolicy(policy PolicyConfig) error {
	egress, err := compileEgressPolicy(policy.Egress)
	if err != nil {
		return err
	}
	nextBlock := make(map[domainKey]struct{}, len(policy.BlockedDomains))
	for _, domain := range policy.BlockedDomains {
		key, err := encodeDomainKey(domain)
		if err != nil {
			return fmt.Errorf("encode blocklist entry %q: %w", domain, err)
		}
		nextBlock[key] = struct{}{}
	}
	nextAllow := make(map[domainKey]struct{}, len(policy.AllowedDomains))
	for _, domain := range policy.AllowedDomains {
		key, err := encodeDomainKey(domain)
		if err != nil {
			return fmt.Errorf("encode allowlist entry %q: %w", domain, err)
		}
		nextAllow[key] = struct{}{}
	}
	nextAllowSuffixes := make(map[domainSuffixKey]struct{}, len(policy.AllowedSuffixes))
	for _, suffix := range policy.AllowedSuffixes {
		key, err := encodeDomainSuffixKey(suffix)
		if err != nil {
			return fmt.Errorf("encode allow suffix entry %q: %w", suffix, err)
		}
		if policy.BlockEnabled {
			if err := validateEnforcedSuffixKey(key); err != nil {
				return fmt.Errorf("encode allow suffix entry %q: %w", suffix, err)
			}
		}
		nextAllowSuffixes[key] = struct{}{}
	}
	nextBlockSuffixes := make(map[domainSuffixKey]struct{}, len(policy.BlockedSuffixes))
	for _, suffix := range policy.BlockedSuffixes {
		key, err := encodeDomainSuffixKey(suffix)
		if err != nil {
			return fmt.Errorf("encode block suffix entry %q: %w", suffix, err)
		}
		if policy.BlockEnabled {
			if err := validateEnforcedSuffixKey(key); err != nil {
				return fmt.Errorf("encode block suffix entry %q: %w", suffix, err)
			}
		}
		nextBlockSuffixes[key] = struct{}{}
	}
	if len(nextBlock) > blocklistMaxEntries {
		return fmt.Errorf("blocklist contains %d entries, exceeds map capacity %d", len(nextBlock), blocklistMaxEntries)
	}
	if len(nextAllow) > blocklistMaxEntries {
		return fmt.Errorf("allowlist contains %d entries, exceeds map capacity %d", len(nextAllow), blocklistMaxEntries)
	}
	if len(nextAllowSuffixes) > blocklistMaxEntries {
		return fmt.Errorf("allow suffix list contains %d entries, exceeds map capacity %d", len(nextAllowSuffixes), blocklistMaxEntries)
	}
	if len(nextBlockSuffixes) > blocklistMaxEntries {
		return fmt.Errorf("block suffix list contains %d entries, exceeds map capacity %d", len(nextBlockSuffixes), blocklistMaxEntries)
	}
	nextBlock4 := make(map[endpoint4Key]struct{})
	nextBlock6 := make(map[endpoint6Key]struct{})
	nextAllow4 := make(map[endpoint4Key]struct{})
	nextAllow6 := make(map[endpoint6Key]struct{})
	nextBlockCIDR4 := make(map[endpoint4CIDRKey]struct{})
	nextBlockCIDR6 := make(map[endpoint6CIDRKey]struct{})
	nextAllowCIDR4 := make(map[endpoint4CIDRKey]struct{})
	nextAllowCIDR6 := make(map[endpoint6CIDRKey]struct{})

	load := func(endpoints []ResolverEndpoint, ipv4 map[endpoint4Key]struct{}, ipv6 map[endpoint6Key]struct{}) error {
		for _, endpoint := range endpoints {
			transport, ok := encodeResolverTransport(endpoint.Transport)
			if !ok {
				return fmt.Errorf("unsupported resolver transport %q", endpoint.Transport)
			}

			if ip4 := endpoint.IP.To4(); ip4 != nil {
				key := encodeEndpoint4Key(ip4, endpoint.Port, transport)
				ipv4[key] = struct{}{}
				continue
			}

			ip16 := endpoint.IP.To16()
			if ip16 == nil {
				return fmt.Errorf("invalid endpoint IP %q", endpoint.IP)
			}
			key := endpoint6Key{
				Port:      endpoint.Port,
				Transport: transport,
			}
			copy(key.Addr[:], ip16)
			ipv6[key] = struct{}{}
		}
		return nil
	}
	loadCIDRs := func(cidrs []ResolverCIDR, ipv4 map[endpoint4CIDRKey]struct{}, ipv6 map[endpoint6CIDRKey]struct{}) error {
		for _, endpoint := range cidrs {
			transport, ok := encodeResolverTransport(endpoint.Transport)
			if !ok {
				return fmt.Errorf("unsupported resolver transport %q", endpoint.Transport)
			}
			addr := endpoint.Prefix.Addr()
			if !addr.IsValid() {
				return fmt.Errorf("invalid endpoint prefix %q", endpoint.Prefix)
			}
			if addr.Is4() {
				ip := addr.As4()
				prefixBits := endpoint.Prefix.Bits()
				if prefixBits < 0 || prefixBits > 32 {
					return fmt.Errorf("invalid IPv4 endpoint prefix length %d", prefixBits)
				}
				key := endpoint4CIDRKey{
					PrefixLen: 24 + uint32(prefixBits),
					Data:      [7]uint8{transport},
				}
				binary.BigEndian.PutUint16(key.Data[1:3], endpoint.Port)
				copy(key.Data[3:], ip[:])
				ipv4[key] = struct{}{}
				continue
			}
			if !addr.Is6() {
				return fmt.Errorf("invalid endpoint prefix %q", endpoint.Prefix)
			}
			ip := addr.As16()
			prefixBits := endpoint.Prefix.Bits()
			if prefixBits < 0 || prefixBits > 128 {
				return fmt.Errorf("invalid IPv6 endpoint prefix length %d", prefixBits)
			}
			key := endpoint6CIDRKey{
				PrefixLen: 24 + uint32(prefixBits),
				Data:      [19]uint8{transport},
			}
			binary.BigEndian.PutUint16(key.Data[1:3], endpoint.Port)
			copy(key.Data[3:], ip[:])
			ipv6[key] = struct{}{}
		}
		return nil
	}
	if err := load(policy.BlockedEndpoints, nextBlock4, nextBlock6); err != nil {
		return err
	}
	if err := load(policy.AllowedEndpoints, nextAllow4, nextAllow6); err != nil {
		return err
	}
	if err := loadCIDRs(policy.BlockedCIDRs, nextBlockCIDR4, nextBlockCIDR6); err != nil {
		return err
	}
	if err := loadCIDRs(policy.AllowedCIDRs, nextAllowCIDR4, nextAllowCIDR6); err != nil {
		return err
	}

	if len(nextBlock4) > endpointMaxEntries || len(nextAllow4) > endpointMaxEntries {
		return fmt.Errorf("ipv4 resolver endpoints exceed map capacity %d", endpointMaxEntries)
	}
	if len(nextBlock6) > endpointMaxEntries || len(nextAllow6) > endpointMaxEntries {
		return fmt.Errorf("ipv6 resolver endpoints exceed map capacity %d", endpointMaxEntries)
	}
	if len(nextBlockCIDR4) > endpointMaxEntries || len(nextAllowCIDR4) > endpointMaxEntries {
		return fmt.Errorf("ipv4 resolver cidrs exceed map capacity %d", endpointMaxEntries)
	}
	if len(nextBlockCIDR6) > endpointMaxEntries || len(nextAllowCIDR6) > endpointMaxEntries {
		return fmt.Errorf("ipv6 resolver cidrs exceed map capacity %d", endpointMaxEntries)
	}

	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	inactiveSlot := uint8(1)
	if m.activePolicySlot == 1 {
		inactiveSlot = 0
	}
	for _, update := range []struct {
		name string
		fn   func() error
	}{
		{name: "blocklist", fn: func() error { return syncMapSlot(m.objects.Blocklist, nextBlock, inactiveSlot) }},
		{name: "allowlist", fn: func() error { return syncMapSlot(m.objects.Allowlist, nextAllow, inactiveSlot) }},
		{name: "allow suffix list", fn: func() error { return syncSuffixMapSlot(m.objects.AllowSuffixes, nextAllowSuffixes, inactiveSlot) }},
		{name: "block suffix list", fn: func() error { return syncSuffixMapSlot(m.objects.BlockSuffixes, nextBlockSuffixes, inactiveSlot) }},
		{name: "endpoint4 block rules", fn: func() error { return syncMapSlot(m.objects.Endpoint4Rules, nextBlock4, inactiveSlot) }},
		{name: "endpoint6 block rules", fn: func() error { return syncMapSlot(m.objects.Endpoint6Rules, nextBlock6, inactiveSlot) }},
		{name: "endpoint4 allow rules", fn: func() error { return syncMapSlot(m.objects.Endpoint4AllowRules, nextAllow4, inactiveSlot) }},
		{name: "endpoint6 allow rules", fn: func() error { return syncMapSlot(m.objects.Endpoint6AllowRules, nextAllow6, inactiveSlot) }},
		{name: "endpoint4 block cidr rules", fn: func() error { return syncMapSlot(m.objects.Endpoint4CidrRules, nextBlockCIDR4, inactiveSlot) }},
		{name: "endpoint6 block cidr rules", fn: func() error { return syncMapSlot(m.objects.Endpoint6CidrRules, nextBlockCIDR6, inactiveSlot) }},
		{name: "endpoint4 allow cidr rules", fn: func() error { return syncMapSlot(m.objects.Endpoint4CidrAllowRules, nextAllowCIDR4, inactiveSlot) }},
		{name: "endpoint6 allow cidr rules", fn: func() error { return syncMapSlot(m.objects.Endpoint6CidrAllowRules, nextAllowCIDR6, inactiveSlot) }},
		{name: "egress4 allow rules", fn: func() error { return syncEgress4MapSlot(m.objects.Egress4AllowRules, egress.allow4, inactiveSlot) }},
		{name: "egress4 block rules", fn: func() error { return syncEgress4MapSlot(m.objects.Egress4BlockRules, egress.block4, inactiveSlot) }},
		{name: "egress6 allow rules", fn: func() error { return syncEgress6MapSlot(m.objects.Egress6AllowRules, egress.allow6, inactiveSlot) }},
		{name: "egress6 block rules", fn: func() error { return syncEgress6MapSlot(m.objects.Egress6BlockRules, egress.block6, inactiveSlot) }},
	} {
		if err := update.fn(); err != nil {
			return fmt.Errorf("prepare inactive %s: %w", update.name, err)
		}
	}

	settings := runtimeSettings{ActivePolicySlot: inactiveSlot}
	if policy.BlockEnabled {
		settings.BlockEnabled = 1
	}
	if policy.BlockAllDomains {
		settings.BlockAllDomains = 1
	}
	if policy.BlockAllResolvers {
		settings.BlockAllResolvers = 1
	}
	if len(policy.AllowedSuffixes) > 0 {
		settings.AllowSuffixesEnabled = 1
	}
	if len(policy.BlockedSuffixes) > 0 {
		settings.BlockSuffixesEnabled = 1
	}
	if policy.Egress.Enabled {
		settings.EgressEnabled = 1
	}
	if policy.Egress.Enforce {
		settings.EgressEnforce = 1
	}
	if policy.Egress.DefaultBlock {
		settings.EgressDefaultBlock = 1
	}
	ruleIDs := make(map[uint32]string, len(egress.ruleIDs)+len(m.currentRuleIDs))
	for ruleNumber, ruleID := range m.currentRuleIDs {
		ruleIDs[ruleNumber] = ruleID
	}
	for ruleNumber, ruleID := range egress.ruleIDs {
		ruleIDs[ruleNumber] = ruleID
	}
	m.egressRuleIDs.Store(&ruleIDs)
	if err := m.objects.Settings.Put(uint32(0), settings); err != nil {
		return fmt.Errorf("commit policy settings: %w", err)
	}
	m.currentRuleIDs = egress.ruleIDs
	m.activePolicySlot = inactiveSlot
	return nil
}

func encodeEndpoint4Key(ip []byte, port uint16, transport uint8) endpoint4Key {
	return endpoint4Key{
		Addr:      binary.NativeEndian.Uint32(ip),
		Port:      port,
		Transport: transport,
	}
}

func encodeDomainKey(domain string) (domainKey, error) {
	var key domainKey
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" {
		return key, errors.New("empty domain")
	}

	offset := 0
	for label := range strings.SplitSeq(domain, ".") {
		if label == "" {
			return key, errors.New("empty label")
		}
		labelLen := len(label)
		if labelLen > 63 {
			return key, fmt.Errorf("label %q exceeds 63 bytes", label)
		}
		if offset+1+labelLen+1 > maxDNSWireNameBytes {
			return key, errors.New("domain exceeds DNS wire-format limit")
		}

		key.Domain[offset] = byte(labelLen)
		offset++
		copy(key.Domain[offset:], label)
		offset += labelLen
	}

	key.Domain[offset] = 0
	return key, nil
}

func encodeDomainSuffixKey(domain string) (domainSuffixKey, error) {
	encoded, err := encodeDomainKey(domain)
	if err != nil {
		return domainSuffixKey{}, err
	}
	key := domainSuffixKey{Hash: 14695981039346656037}
	for _, value := range encoded.Domain {
		key.Hash ^= uint64(value)
		key.Hash *= 1099511628211
		key.Length++
		if value == 0 {
			return key, nil
		}
	}
	return domainSuffixKey{}, errors.New("domain suffix is missing DNS root terminator")
}

func validateEnforcedSuffixKey(key domainSuffixKey) error {
	if key.Length > maxEnforcedSuffixWireBytes {
		return fmt.Errorf("DNS wire length %d exceeds enforced suffix limit %d", key.Length, maxEnforcedSuffixWireBytes)
	}
	return nil
}

func encodeResolverTransport(transport string) (uint8, bool) {
	switch strings.TrimSpace(strings.ToLower(transport)) {
	case "doh":
		return 4, true
	case "dot":
		return 3, true
	default:
		return 0, false
	}
}

func syncMapSlot[K comparable](m *ebpf.Map, next map[K]struct{}, slot uint8) error {
	if slot > 1 {
		return fmt.Errorf("invalid policy slot %d", slot)
	}
	current := make(map[K]uint8)
	iter := m.Iterate()
	var key K
	var value uint8
	for iter.Next(&key, &value) {
		current[key] = value
	}
	if err := iter.Err(); err != nil {
		return err
	}

	// Clear stale entries from the inactive slot before adding its replacement.
	// The active slot remains present throughout the update.
	for key, value := range current {
		if _, keep := next[key]; keep {
			continue
		}
		newValue, remove := policySlotValue(value, false, slot)
		if newValue == value {
			continue
		}
		if !remove {
			if err := m.Put(key, newValue); err != nil {
				return err
			}
			continue
		}
		if err := m.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	for key := range next {
		value, _ := policySlotValue(current[key], true, slot)
		if err := m.Put(key, value); err != nil {
			return err
		}
	}
	return nil
}

func syncSuffixMapSlot(m *ebpf.Map, next map[domainSuffixKey]struct{}, slot uint8) error {
	if slot > 1 {
		return fmt.Errorf("invalid policy slot %d", slot)
	}
	current := make(map[domainSuffixKey]struct{})
	iter := m.Iterate()
	var key domainSuffixKey
	var value uint8
	for iter.Next(&key, &value) {
		current[key] = struct{}{}
	}
	if err := iter.Err(); err != nil {
		return err
	}

	for key := range current {
		if key.Slot != slot {
			continue
		}
		stored := key
		key.Slot = 0
		if _, keep := next[key]; keep {
			continue
		}
		if err := m.Delete(stored); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
	}
	for key := range next {
		key.Slot = slot
		if _, exists := current[key]; exists {
			continue
		}
		if err := m.Put(key, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

func policySlotValue(current uint8, desired bool, slot uint8) (value uint8, remove bool) {
	mask := uint8(1 << slot)
	if desired {
		return current | mask, false
	}
	value = current &^ mask
	return value, value == 0
}
