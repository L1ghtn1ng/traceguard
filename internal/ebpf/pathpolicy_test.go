package ebpf

import (
	"bytes"
	"testing"
)

func TestPathPolicyExactAndPrefixMatching(t *testing.T) {
	t.Parallel()
	compiled, err := compilePathPolicy(PathPolicyConfig{Rules: []PathRuleConfig{
		{ID: "exact", Action: "block", PathGlobs: []string{"/etc/shadow"}},
		{ID: "prefix", Action: "block", PathGlobs: []string{"/tmp/**"}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]bool{
		"/etc/shadow":     true,
		"/etc/shadow.bak": false,
		"/tmp":            true,
		"/tmp/foo":        true,
		"/tmp2":           false,
	}
	for path, want := range tests {
		if got := pathPolicyMapMatches(compiled.block, path); got != want {
			t.Errorf("match(%q) = %t, want %t", path, got, want)
		}
	}
}

func TestPathPolicyAccessKeysUseWildcardForBothAccessModes(t *testing.T) {
	t.Parallel()
	compiled, err := compilePathPolicy(PathPolicyConfig{Rules: []PathRuleConfig{
		{ID: "wildcard", Action: "block", PathGlobs: []string{"/data/file"}},
		{ID: "read", Action: "block", PathGlobs: []string{"/data/read"}, AccessOrOps: []uint8{1}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[uint8]int)
	for key := range compiled.block {
		seen[key.Data[14]]++
	}
	if seen[0] != 1 || seen[1] != 1 || seen[2] != 0 {
		t.Fatalf("access keys = %#v, want one wildcard and one read key", seen)
	}
}

func TestPathPolicyRejectsOversizedExpansionBeforeBuildingKeys(t *testing.T) {
	t.Parallel()
	uids := make([]uint32, 256)
	for index := range uids {
		uids[index] = uint32(index)
	}
	paths := make([]string, 65)
	for index := range paths {
		paths[index] = "/tmp/path-" + string(rune('a'+index%26)) + string(rune('A'+index/26))
	}
	_, err := compilePathPolicy(PathPolicyConfig{Rules: []PathRuleConfig{{
		ID: "too-large", Action: "block", UIDs: uids, HasUIDSelector: true, PathGlobs: paths,
	}}})
	if err == nil {
		t.Fatal("compilePathPolicy() accepted expansion beyond map capacity")
	}
}

func pathPolicyMapMatches(entries map[pathLPMKey]uint32, path string) bool {
	query := encodePathLPMKey(egressIdentity{kind: egressIdentityGlobal}, 0, 0, path, true)
	for key := range entries {
		if key.PrefixLen > query.PrefixLen || key.PrefixLen%8 != 0 {
			continue
		}
		bytesToCompare := int(key.PrefixLen / 8)
		if bytes.Equal(key.Data[:bytesToCompare], query.Data[:bytesToCompare]) {
			return true
		}
	}
	return false
}
