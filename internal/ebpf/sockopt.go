package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

type sockoptKey struct {
	Slot     uint8
	Kind     uint8
	_        [2]uint8
	UID      uint32
	CgroupID uint64
	Level    uint32
	OptName  uint32
}

type sockoptCompiledPolicy struct {
	allow   map[sockoptKey]uint32
	block   map[sockoptKey]uint32
	ruleIDs map[uint32]string
}

func compileSockoptPolicy(policy SockoptPolicyConfig) (sockoptCompiledPolicy, error) {
	compiled := sockoptCompiledPolicy{
		allow: make(map[sockoptKey]uint32), block: make(map[sockoptKey]uint32),
		ruleIDs: make(map[uint32]string, len(policy.Rules)),
	}
	plannedAllow, plannedBlock := 0, 0
	for _, rule := range policy.Rules {
		ruleNumber := egressRuleNumber(rule.ID)
		if previous, exists := compiled.ruleIDs[ruleNumber]; exists && previous != rule.ID {
			return sockoptCompiledPolicy{}, fmt.Errorf("sockopt rule id hash collision between %q and %q", previous, rule.ID)
		}
		compiled.ruleIDs[ruleNumber] = rule.ID
		identityRule := EgressRuleConfig{
			UIDs: rule.UIDs, CgroupIDs: rule.CgroupIDs, CgroupAncestorIDs: rule.CgroupAncestorIDs,
			HasUIDSelector: rule.HasUIDSelector, HasCgroupSelector: rule.HasCgroupSelector,
		}
		identityCount := egressIdentityCount(identityRule)
		if identityCount == 0 {
			continue
		}
		if len(rule.Options) == 0 || identityCount > policyMaxEntries/len(rule.Options) {
			return sockoptCompiledPolicy{}, fmt.Errorf("sockopt rule %q expands beyond %d map entries", rule.ID, policyMaxEntries)
		}
		expandedEntries := identityCount * len(rule.Options)
		planned := &plannedBlock
		if rule.Action == "allow" {
			planned = &plannedAllow
		}
		if *planned > policyMaxEntries-expandedEntries {
			return sockoptCompiledPolicy{}, fmt.Errorf("sockopt %s entries exceed map capacity %d", rule.Action, policyMaxEntries)
		}
		*planned += expandedEntries
		for _, identity := range expandEgressIdentities(identityRule) {
			for _, option := range rule.Options {
				key := sockoptKey{
					Kind: identity.kind, UID: identity.uid, CgroupID: identity.cgroupID,
					Level: option.Level, OptName: option.OptName,
				}
				if rule.Action == "allow" {
					compiled.allow[key] = ruleNumber
				} else {
					compiled.block[key] = ruleNumber
				}
			}
		}
	}
	if len(compiled.allow) > policyMaxEntries {
		return sockoptCompiledPolicy{}, fmt.Errorf("sockopt allow entries %d exceed map capacity %d", len(compiled.allow), policyMaxEntries)
	}
	if len(compiled.block) > policyMaxEntries {
		return sockoptCompiledPolicy{}, fmt.Errorf("sockopt block entries %d exceed map capacity %d", len(compiled.block), policyMaxEntries)
	}
	return compiled, nil
}

func syncSockoptMapSlot(m *ebpf.Map, next map[sockoptKey]uint32, slot uint8) error {
	if m == nil {
		return errors.New("sockopt policy map is unavailable")
	}
	return syncEgressMapSlot(m, next, slot, func(key *sockoptKey) *uint8 { return &key.Slot })
}
