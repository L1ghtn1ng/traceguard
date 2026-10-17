package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	pathLPMFixedBytes = 15
	pathLPMMaxBytes   = 241

	unixOpConnect = 1
	unixOpSendmsg = 2
	unixOpRecvmsg = 4
)

type pathLPMKey struct {
	PrefixLen uint32
	Data      [256]uint8
}

type pathPolicyCompiled struct {
	allow   map[pathLPMKey]uint32
	block   map[pathLPMKey]uint32
	ruleIDs map[uint32]string
}

func compilePathPolicy(policy PathPolicyConfig) (pathPolicyCompiled, error) {
	compiled := pathPolicyCompiled{
		allow: make(map[pathLPMKey]uint32), block: make(map[pathLPMKey]uint32),
		ruleIDs: make(map[uint32]string, len(policy.Rules)),
	}
	for _, rule := range policy.Rules {
		ruleNumber := egressRuleNumber(rule.ID)
		if previous, exists := compiled.ruleIDs[ruleNumber]; exists && previous != rule.ID {
			return pathPolicyCompiled{}, fmt.Errorf("path rule id hash collision between %q and %q", previous, rule.ID)
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
		accessOrOps := rule.AccessOrOps
		if len(accessOrOps) == 0 {
			accessOrOps = []uint8{0}
		}
		pathKeys := 0
		for _, pattern := range rule.PathGlobs {
			pathKeys++
			if strings.HasSuffix(pattern, "/**") {
				pathKeys++
			}
		}
		if pathKeys == 0 || identityCount > policyMaxEntries/len(accessOrOps)/pathKeys {
			return pathPolicyCompiled{}, fmt.Errorf("path rule %q expands beyond %d map entries", rule.ID, policyMaxEntries)
		}
		expandedEntries := identityCount * len(accessOrOps) * pathKeys
		target := compiled.block
		if rule.Action == "allow" {
			target = compiled.allow
		}
		if len(target) > policyMaxEntries-expandedEntries {
			return pathPolicyCompiled{}, fmt.Errorf("path %s entries exceed map capacity %d", rule.Action, policyMaxEntries)
		}
		identities := expandEgressIdentities(identityRule)
		for _, identity := range identities {
			for _, accessOrOp := range accessOrOps {
				for _, pattern := range rule.PathGlobs {
					keys, err := encodePathPattern(identity, accessOrOp, pattern)
					if err != nil {
						return pathPolicyCompiled{}, fmt.Errorf("path rule %q: %w", rule.ID, err)
					}
					for _, key := range keys {
						target[key] = ruleNumber
					}
				}
			}
		}
	}
	if len(compiled.allow) > policyMaxEntries {
		return pathPolicyCompiled{}, fmt.Errorf("path allow entries %d exceed map capacity %d", len(compiled.allow), policyMaxEntries)
	}
	if len(compiled.block) > policyMaxEntries {
		return pathPolicyCompiled{}, fmt.Errorf("path block entries %d exceed map capacity %d", len(compiled.block), policyMaxEntries)
	}
	return compiled, nil
}

func encodePathPattern(identity egressIdentity, accessOrOp uint8, pattern string) ([]pathLPMKey, error) {
	if before, ok := strings.CutSuffix(pattern, "/**"); ok {
		stem := before
		if stem == "" || len(stem) > pathLPMMaxBytes-1 {
			return nil, fmt.Errorf("path prefix stem %q exceeds %d bytes", stem, pathLPMMaxBytes-1)
		}
		prefix := stem + "/"
		return []pathLPMKey{
			encodePathLPMKey(identity, 0, accessOrOp, prefix, false),
			encodePathLPMKey(identity, 0, accessOrOp, stem, true),
		}, nil
	}
	if strings.Contains(pattern, "*") {
		return nil, fmt.Errorf("unsupported path glob %q", pattern)
	}
	if pattern == "" || len(pattern) > pathLPMMaxBytes-1 {
		return nil, fmt.Errorf("exact path %q exceeds %d bytes", pattern, pathLPMMaxBytes-1)
	}
	return []pathLPMKey{encodePathLPMKey(identity, 0, accessOrOp, pattern, true)}, nil
}

func encodePathLPMKey(identity egressIdentity, slot, accessOrOp uint8, path string, exact bool) pathLPMKey {
	var key pathLPMKey
	key.Data[0] = slot
	key.Data[1] = identity.kind
	binary.NativeEndian.PutUint32(key.Data[2:6], identity.uid)
	binary.NativeEndian.PutUint64(key.Data[6:14], identity.cgroupID)
	key.Data[14] = accessOrOp
	copy(key.Data[pathLPMFixedBytes:], path)
	pathBytes := len(path)
	if exact {
		pathBytes++
	}
	key.PrefixLen = uint32((pathLPMFixedBytes + pathBytes) * 8) //nolint:gosec // policy validation caps paths to 240 bytes
	return key
}

func syncPathMapSlot(m *ebpf.Map, next map[pathLPMKey]uint32, slot uint8) error {
	if m == nil {
		return errors.New("path policy map is unavailable")
	}
	return syncEgressMapSlot(m, next, slot, func(key *pathLPMKey) *uint8 { return &key.Data[0] })
}
