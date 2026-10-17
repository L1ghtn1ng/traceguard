package policy

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

const (
	maxPathPolicyBytes   = 240
	maxUnixAbstractBytes = 107
)

func validateAction(action string) error {
	if action != "allow" && action != "block" {
		return fmt.Errorf("action must be allow or block")
	}
	return nil
}

func validateSelectors(selectors EgressSelectors) error {
	for name, count := range map[string]int{
		"uids": len(selectors.UIDs), "cgroup paths": len(selectors.CgroupPaths),
		"cgroup prefixes": len(selectors.CgroupPrefixes),
	} {
		if count > MaxRuleListValues {
			return fmt.Errorf("%s count %d exceeds %d", name, count, MaxRuleListValues)
		}
	}
	if err := validateUnique(selectors.UIDs, "uid"); err != nil {
		return err
	}
	if err := validateUnique(selectors.CgroupPaths, "cgroup path"); err != nil {
		return err
	}
	if err := validateUnique(selectors.CgroupPrefixes, "cgroup prefix"); err != nil {
		return err
	}
	paths := append(slices.Clone(selectors.CgroupPaths), selectors.CgroupPrefixes...)
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("cgroup selector %q must be a clean absolute cgroup path", path)
		}
	}
	return nil
}

func validateUnique[T comparable](values []T, name string) error {
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, exists := seen[value]; exists {
			return fmt.Errorf("duplicate %s %v", name, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func (r PathRule) validate(allowAbstract bool) error {
	if err := validateAction(r.Action); err != nil {
		return err
	}
	if err := validateSelectors(r.Selectors); err != nil {
		return err
	}
	if len(r.Match.PathGlobs) == 0 {
		return fmt.Errorf("match.path_globs must not be empty")
	}
	if len(r.Match.PathGlobs) > MaxRuleListValues {
		return fmt.Errorf("path globs count %d exceeds %d", len(r.Match.PathGlobs), MaxRuleListValues)
	}
	for _, pattern := range r.Match.PathGlobs {
		if err := validateEnforcedPathGlob(pattern, allowAbstract); err != nil {
			return err
		}
	}
	return nil
}

func (r FileRule) validate() error {
	pathRule := PathRule{ID: r.ID, Action: r.Action, Selectors: r.Selectors, Match: PathMatch{PathGlobs: r.Match.PathGlobs}}
	if err := pathRule.validate(false); err != nil {
		return err
	}
	if len(r.Match.Access) > 2 {
		return fmt.Errorf("access count %d exceeds 2", len(r.Match.Access))
	}
	seen := make(map[string]struct{}, len(r.Match.Access))
	for _, access := range r.Match.Access {
		if access != "read" && access != "write" {
			return fmt.Errorf("unsupported access %q", access)
		}
		if _, exists := seen[access]; exists {
			return fmt.Errorf("duplicate access %q", access)
		}
		seen[access] = struct{}{}
	}
	return nil
}

func (r BindRule) validate() error {
	return (EgressRule{ID: r.ID, Action: r.Action, Selectors: r.Selectors, Destinations: r.Endpoints}).validate()
}

func (r UnixRule) validate() error {
	pathRule := PathRule{ID: r.ID, Action: r.Action, Selectors: r.Selectors, Match: PathMatch{PathGlobs: r.Match.PathGlobs}}
	if err := pathRule.validate(true); err != nil {
		return err
	}
	if len(r.Match.Operations) > 3 {
		return fmt.Errorf("operations count %d exceeds 3", len(r.Match.Operations))
	}
	seen := make(map[string]struct{}, len(r.Match.Operations))
	for _, operation := range r.Match.Operations {
		if operation != "connect" && operation != "sendmsg" && operation != "recvmsg" {
			return fmt.Errorf("unsupported operation %q", operation)
		}
		if _, exists := seen[operation]; exists {
			return fmt.Errorf("duplicate operation %q", operation)
		}
		seen[operation] = struct{}{}
	}
	return nil
}

func (r SockoptRule) validate() error {
	if err := validateAction(r.Action); err != nil {
		return err
	}
	if err := validateSelectors(r.Selectors); err != nil {
		return err
	}
	if len(r.Match.Levels) == 0 {
		return fmt.Errorf("match.levels must not be empty")
	}
	if len(r.Match.OptNames) == 0 {
		return fmt.Errorf("match.optnames must not be empty")
	}
	for name, count := range map[string]int{"levels": len(r.Match.Levels), "optnames": len(r.Match.OptNames)} {
		if count > MaxRuleListValues {
			return fmt.Errorf("%s count %d exceeds %d", name, count, MaxRuleListValues)
		}
	}
	seenLevels := make(map[string]struct{}, len(r.Match.Levels))
	for _, level := range r.Match.Levels {
		canonical, ok := sockoptLevelAliases[level]
		if !ok {
			return fmt.Errorf("unsupported socket option level %q", level)
		}
		if _, exists := seenLevels[canonical]; exists {
			return fmt.Errorf("duplicate socket option level %q", level)
		}
		seenLevels[canonical] = struct{}{}
	}
	seenOptNames := make(map[string]struct{}, len(r.Match.OptNames))
	usedLevels := make(map[string]struct{}, len(seenLevels))
	for _, optname := range r.Match.OptNames {
		level, ok := SockoptOptionLevel(optname)
		if !ok {
			return fmt.Errorf("unsupported socket option name %q", optname)
		}
		if _, exists := seenOptNames[optname]; exists {
			return fmt.Errorf("duplicate socket option name %q", optname)
		}
		seenOptNames[optname] = struct{}{}
		// Kernel option numbers are only meaningful within their own level, so
		// a name is never matched at another listed level.
		if _, listed := seenLevels[level]; !listed {
			return fmt.Errorf("socket option name %q requires level %q", optname, level)
		}
		usedLevels[level] = struct{}{}
	}
	for _, level := range r.Match.Levels {
		if _, used := usedLevels[sockoptLevelAliases[level]]; !used {
			return fmt.Errorf("socket option level %q has no matching option name", level)
		}
	}
	return nil
}

var sockoptLevelAliases = map[string]string{
	"socket": "socket", "sol_socket": "socket",
	"ip": "ip", "sol_ip": "ip",
	"ipv6": "ipv6", "sol_ipv6": "ipv6",
}

// SockoptOptionLevel returns the canonical level that defines a supported
// socket option name.
func SockoptOptionLevel(optname string) (string, bool) {
	switch optname {
	case "so_mark", "so_reuseport":
		return "socket", true
	case "ip_transparent":
		return "ip", true
	case "ipv6_transparent":
		return "ipv6", true
	default:
		return "", false
	}
}

func validateEnforcedPathGlob(pattern string, allowAbstract bool) error {
	if pattern == "" {
		return fmt.Errorf("path glob must not be empty")
	}
	if strings.IndexByte(pattern, 0) >= 0 {
		return fmt.Errorf("path glob must not contain NUL bytes")
	}
	prefix := strings.HasSuffix(pattern, "/**")
	stem := pattern
	if prefix {
		stem = strings.TrimSuffix(pattern, "/**")
	}
	if strings.Contains(stem, "*") {
		return fmt.Errorf("unsupported path glob %q; only exact paths and /** prefixes are allowed", pattern)
	}
	if strings.HasPrefix(stem, "@") {
		if !allowAbstract {
			return fmt.Errorf("path glob %q must be an absolute filesystem path", pattern)
		}
		if len(stem) < 2 {
			return fmt.Errorf("abstract unix path %q must include a name", pattern)
		}
		if !prefix && len(stem)-1 > maxUnixAbstractBytes {
			return fmt.Errorf("abstract unix path %q exceeds %d bytes", pattern, maxUnixAbstractBytes)
		}
		if prefix && (len(stem) < 4 || len(stem) > maxPathPolicyBytes) {
			return fmt.Errorf("unix path prefix stem %q must be between 4 and %d bytes", stem, maxPathPolicyBytes)
		}
		return nil
	}
	if !filepath.IsAbs(stem) || filepath.Clean(stem) != stem {
		return fmt.Errorf("path glob %q must use a clean absolute path", pattern)
	}
	if prefix {
		if stem == "/" || len(stem) < 4 || len(stem) > maxPathPolicyBytes {
			return fmt.Errorf("path prefix stem %q must be between 4 and %d bytes and not root", stem, maxPathPolicyBytes)
		}
		return nil
	}
	if stem == "/" {
		return fmt.Errorf("exact root path is not allowed")
	}
	if len(stem) > maxPathPolicyBytes {
		return fmt.Errorf("exact path %q exceeds %d bytes", stem, maxPathPolicyBytes)
	}
	return nil
}
