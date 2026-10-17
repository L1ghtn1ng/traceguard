package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
)

const (
	maxEnforcedSuffixWireBytes = 64
	maxPolicyRuleIDBytes       = 64
)

const (
	policyReaderDrainTimeout = 30 * time.Second
	policyReaderPollInterval = time.Millisecond
)

func (m *Monitor) ApplyPolicy(policy PolicyConfig) error {
	egress, err := compileEgressPolicy(policy.Egress)
	if err != nil {
		return err
	}
	execPolicy, err := compilePathPolicy(policy.Exec)
	if err != nil {
		return fmt.Errorf("compile exec policy: %w", err)
	}
	filePolicy, err := compilePathPolicy(policy.File)
	if err != nil {
		return fmt.Errorf("compile file policy: %w", err)
	}
	bindPolicy, err := compileEgressPolicy(policy.Bind)
	if err != nil {
		return fmt.Errorf("compile bind policy: %w", err)
	}
	unixPolicy, err := compilePathPolicy(policy.Unix)
	if err != nil {
		return fmt.Errorf("compile unix policy: %w", err)
	}
	sockoptPolicy, err := compileSockoptPolicy(policy.Sockopt)
	if err != nil {
		return fmt.Errorf("compile sockopt policy: %w", err)
	}
	if err := m.validateEnforcementHooks(policy); err != nil {
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
			canonical, err := canonicalPrefix(endpoint.Prefix)
			if err != nil {
				return err
			}
			endpoint.Prefix = canonical
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
	nextRuleIDs, err := mergeCompiledRuleIDs(
		egress.ruleIDs,
		execPolicy.ruleIDs,
		filePolicy.ruleIDs,
		bindPolicy.ruleIDs,
		unixPolicy.ruleIDs,
		sockoptPolicy.ruleIDs,
	)
	if err != nil {
		return err
	}
	encodedRuleNames, err := encodeRuleNames(nextRuleIDs)
	if err != nil {
		return err
	}

	m.policyMu.Lock()
	defer m.policyMu.Unlock()
	inactiveSlot := uint8(1)
	if m.activePolicySlot == 1 {
		inactiveSlot = 0
	}
	if err := waitForPolicyReaders(m.objects.PolicyReaders, inactiveSlot); err != nil {
		return fmt.Errorf("wait to reuse inactive policy slot %d: %w", inactiveSlot, err)
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
		{name: "exec allow paths", fn: func() error { return syncPathMapSlot(m.objects.ExecAllowPaths, execPolicy.allow, inactiveSlot) }},
		{name: "exec block paths", fn: func() error { return syncPathMapSlot(m.objects.ExecBlockPaths, execPolicy.block, inactiveSlot) }},
		{name: "file allow paths", fn: func() error { return syncPathMapSlot(m.objects.FileAllowPaths, filePolicy.allow, inactiveSlot) }},
		{name: "file block paths", fn: func() error { return syncPathMapSlot(m.objects.FileBlockPaths, filePolicy.block, inactiveSlot) }},
		{name: "bind4 allow rules", fn: func() error { return syncEgress4MapSlot(m.objects.Bind4AllowRules, bindPolicy.allow4, inactiveSlot) }},
		{name: "bind4 block rules", fn: func() error { return syncEgress4MapSlot(m.objects.Bind4BlockRules, bindPolicy.block4, inactiveSlot) }},
		{name: "bind6 allow rules", fn: func() error { return syncEgress6MapSlot(m.objects.Bind6AllowRules, bindPolicy.allow6, inactiveSlot) }},
		{name: "bind6 block rules", fn: func() error { return syncEgress6MapSlot(m.objects.Bind6BlockRules, bindPolicy.block6, inactiveSlot) }},
		{name: "unix allow paths", fn: func() error { return syncPathMapSlot(m.objects.UnixAllowPaths, unixPolicy.allow, inactiveSlot) }},
		{name: "unix block paths", fn: func() error { return syncPathMapSlot(m.objects.UnixBlockPaths, unixPolicy.block, inactiveSlot) }},
		{name: "sockopt allow rules", fn: func() error { return syncSockoptMapSlot(m.objects.SockoptAllow, sockoptPolicy.allow, inactiveSlot) }},
		{name: "sockopt block rules", fn: func() error { return syncSockoptMapSlot(m.objects.SockoptBlock, sockoptPolicy.block, inactiveSlot) }},
		{name: "rule names", fn: func() error { return syncRuleNameMapSlot(m.objects.RuleNames, encodedRuleNames, inactiveSlot) }},
	} {
		if err := update.fn(); err != nil {
			return fmt.Errorf("prepare inactive %s: %w", update.name, err)
		}
	}

	nextGeneration := m.policyGeneration + 1
	if nextGeneration == 0 {
		nextGeneration = 1
	}
	settings := runtimeSettings{
		ActivePolicySlot: inactiveSlot,
		PolicyGeneration: nextGeneration,
	}
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
	setPathSettings(&settings.ExecEnabled, &settings.ExecEnforce, &settings.ExecDefaultBlock, policy.Exec)
	setPathSettings(&settings.FileEnabled, &settings.FileEnforce, &settings.FileDefaultBlock, policy.File)
	setEgressSettings(&settings.BindEnabled, &settings.BindEnforce, &settings.BindDefaultBlock, policy.Bind)
	setPathSettings(&settings.UnixEnabled, &settings.UnixEnforce, &settings.UnixDefaultBlock, policy.Unix)
	if policy.Sockopt.Enabled {
		settings.SockoptEnabled = 1
	}
	if policy.Sockopt.Enforce {
		settings.SockoptEnforce = 1
	}
	if policy.Sockopt.DefaultBlock {
		settings.SockoptDefaultBlock = 1
	}
	if err := m.objects.Settings.Put(uint32(inactiveSlot), settings); err != nil {
		return fmt.Errorf("write immutable policy settings slot %d: %w", inactiveSlot, err)
	}
	selector := encodePolicySelector(inactiveSlot, nextGeneration)
	if err := m.objects.PolicySelector.Put(uint32(0), selector); err != nil {
		return fmt.Errorf("publish policy selector: %w", err)
	}
	m.activePolicySlot = inactiveSlot
	m.policyGeneration = nextGeneration
	return nil
}

func waitForPolicyReaders(readers *ebpf.Map, slot uint8) error {
	if readers == nil {
		return errors.New("policy reader map is unavailable")
	}
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return fmt.Errorf("count possible CPUs: %w", err)
	}
	deadline := time.Now().Add(policyReaderDrainTimeout)
	values := make([]uint64, possibleCPUs)
	for {
		clear(values)
		if err := readers.Lookup(uint32(slot), &values); err != nil {
			return fmt.Errorf("read slot counters: %w", err)
		}
		if !slices.ContainsFunc(values, func(value uint64) bool { return value != 0 }) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out after %s with active kernel readers", policyReaderDrainTimeout)
		}
		time.Sleep(policyReaderPollInterval)
	}
}

func setPathSettings(enabled, enforce, defaultBlock *uint8, policy PathPolicyConfig) {
	if policy.Enabled {
		*enabled = 1
	}
	if policy.Enforce {
		*enforce = 1
	}
	if policy.DefaultBlock {
		*defaultBlock = 1
	}
}

func setEgressSettings(enabled, enforce, defaultBlock *uint8, policy EgressPolicyConfig) {
	if policy.Enabled {
		*enabled = 1
	}
	if policy.Enforce {
		*enforce = 1
	}
	if policy.DefaultBlock {
		*defaultBlock = 1
	}
}

func mergeCompiledRuleIDs(groups ...map[uint32]string) (map[uint32]string, error) {
	merged := make(map[uint32]string)
	for _, group := range groups {
		for number, id := range group {
			if previous, exists := merged[number]; exists && previous != id {
				return nil, fmt.Errorf("policy rule id hash collision between %q and %q", previous, id)
			}
			merged[number] = id
		}
	}
	return merged, nil
}

func encodeRuleNames(ruleIDs map[uint32]string) (map[uint32]ruleNameValue, error) {
	if len(ruleIDs) > policyMaxEntries {
		return nil, fmt.Errorf("policy contains %d rule names, exceeds map capacity per slot %d", len(ruleIDs), policyMaxEntries)
	}
	encoded := make(map[uint32]ruleNameValue, len(ruleIDs))
	for number, id := range ruleIDs {
		if number == 0 {
			return nil, fmt.Errorf("policy rule %q uses reserved rule number zero", id)
		}
		if len(id) == 0 || len(id) > maxPolicyRuleIDBytes || strings.IndexByte(id, 0) >= 0 {
			return nil, fmt.Errorf("policy rule id %q must contain 1 to %d non-NUL bytes", id, maxPolicyRuleIDBytes)
		}
		var value ruleNameValue
		copy(value.Name[:], id)
		encoded[number] = value
	}
	return encoded, nil
}

func syncRuleNameMapSlot(m *ebpf.Map, next map[uint32]ruleNameValue, slot uint8) error {
	if m == nil {
		return errors.New("rule name map is unavailable")
	}
	if slot > 1 {
		return fmt.Errorf("invalid policy slot %d", slot)
	}

	var stale []ruleNameKey
	iter := m.Iterate()
	var key ruleNameKey
	var value ruleNameValue
	for iter.Next(&key, &value) {
		if key.PolicySlot == slot {
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
	for number, value := range next {
		key := ruleNameKey{PolicySlot: slot, RuleID: number}
		if err := m.Put(key, value); err != nil {
			return err
		}
	}
	return nil
}

func (m *Monitor) validateEnforcementHooks(policy PolicyConfig) error {
	const hostCgroupRoot = "/sys/fs/cgroup"
	for _, domain := range []struct {
		name, hook string
		policy     PathPolicyConfig
		attached   bool
	}{
		{name: "exec", hook: "bprm_check_security", policy: policy.Exec, attached: m.attachState.LSMExecAttached},
		{name: "file", hook: "file_open", policy: policy.File, attached: m.attachState.LSMFileAttached},
	} {
		if !domain.policy.Enabled {
			continue
		}
		if m.cgroupPath != hostCgroupRoot {
			return fmt.Errorf("%s enforcement requires cgroup-path %s because LSM MAC is host-wide", domain.name, hostCgroupRoot)
		}
		if !domain.attached {
			return fmt.Errorf("%s enforcement requested but LSM %s is not attached", domain.name, domain.hook)
		}
		if m.daemonNamespaceErr != nil {
			return fmt.Errorf("%s enforcement requires the host PID and time namespaces so TraceGuard can exempt itself: %w", domain.name, m.daemonNamespaceErr)
		}
	}
	if policy.Bind.Enabled {
		require4, require6 := policy.Bind.DefaultBlock, policy.Bind.DefaultBlock
		for _, rule := range policy.Bind.Rules {
			if len(rule.CIDRs) == 0 {
				require4, require6 = true, true
			}
			for _, prefix := range rule.CIDRs {
				// IPv4-mapped and dual-stack wildcard binds reach IPv4 policy
				// through bind6, so IPv4 rules need both hooks.
				isIPv4 := prefix.Addr().Unmap().Is4()
				require4 = require4 || isIPv4
				require6 = true
			}
		}
		if require4 && !m.attachState.Bind4Attached {
			return errors.New("bind IPv4 enforcement requested but cgroup/bind4 is not attached")
		}
		if require6 && !m.attachState.Bind6Attached {
			return errors.New("bind IPv6 enforcement requested but cgroup/bind6 is not attached")
		}
	}
	if policy.Unix.Enabled {
		// recvmsg is audit-only because cgroup/recvmsg_unix cannot deny, so a
		// missing recvmsg attachment does not weaken enforcement.
		requireConnect, requireSendmsg := policy.Unix.DefaultBlock, policy.Unix.DefaultBlock
		for _, rule := range policy.Unix.Rules {
			if len(rule.AccessOrOps) == 0 {
				requireConnect, requireSendmsg = true, true
			}
			for _, operation := range rule.AccessOrOps {
				switch operation {
				case unixOpConnect:
					requireConnect = true
				case unixOpSendmsg:
					requireSendmsg = true
				}
			}
		}
		if requireConnect && !m.attachState.UnixConnectAttached {
			return errors.New("unix connect enforcement requested but cgroup/connect_unix is not attached")
		}
		if requireSendmsg && !m.attachState.UnixSendmsgAttached {
			return errors.New("unix sendmsg enforcement requested but cgroup/sendmsg_unix is not attached")
		}
	}
	if policy.Sockopt.Enabled && !m.attachState.SockoptAttached {
		return errors.New("sockopt enforcement requested but cgroup/setsockopt is not attached")
	}
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
