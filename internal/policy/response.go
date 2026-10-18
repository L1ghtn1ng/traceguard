package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	MaxResponses        = 64
	MaxResponseDuration = 24 * time.Hour
)

// Response actions. Both are reversible: each lasts for its duration and is
// undone when it expires, when its response is removed from policy, or when
// TraceGuard stops.
const (
	// ResponseBlockPeer drops traffic to and from the alert's peer address.
	ResponseBlockPeer = "block_peer"
	// ResponseFreezeCgroup freezes the alert's acting cgroup.
	ResponseFreezeCgroup = "freeze_cgroup"
)

// Response runs an action when one of its rules alerts.
type Response struct {
	ID       string   `yaml:"id"`
	Rules    []string `yaml:"rules"`
	Action   string   `yaml:"action"`
	Duration Duration `yaml:"duration"`
}

func (r Response) validate() error {
	if len(r.Rules) == 0 {
		return fmt.Errorf("rules must not be empty")
	}
	if len(r.Rules) > MaxRuleListValues {
		return fmt.Errorf("rules count %d exceeds %d", len(r.Rules), MaxRuleListValues)
	}
	if err := validateIDs(r.Rules, "response rule"); err != nil {
		return err
	}
	if r.Action != ResponseBlockPeer && r.Action != ResponseFreezeCgroup {
		return fmt.Errorf("action must be %s or %s", ResponseBlockPeer, ResponseFreezeCgroup)
	}
	if r.Duration.Duration <= 0 || r.Duration.Duration > MaxResponseDuration {
		return fmt.Errorf("duration must be between 1ns and %s", MaxResponseDuration)
	}
	return nil
}

func validateResponses(responses []Response) error {
	if len(responses) > MaxResponses {
		return fmt.Errorf("response count %d exceeds %d", len(responses), MaxResponses)
	}
	ids := make(map[string]struct{}, len(responses))
	for index, response := range responses {
		if err := validateRuleID(response.ID); err != nil {
			return fmt.Errorf("response %d: %w", index, err)
		}
		if _, exists := ids[response.ID]; exists {
			return fmt.Errorf("duplicate response id %q", response.ID)
		}
		ids[response.ID] = struct{}{}
		if err := response.validate(); err != nil {
			return fmt.Errorf("response %q: %w", response.ID, err)
		}
	}
	return nil
}

// mergeResponsesByID lets an overlay response replace a base one with the
// same ID.
func mergeResponsesByID(base, overlay []Response) []Response {
	merged := make(map[string]Response, len(base)+len(overlay))
	for _, response := range base {
		merged[response.ID] = response
	}
	for _, response := range overlay {
		merged[response.ID] = response
	}
	out := make([]Response, 0, len(merged))
	for _, response := range merged {
		out = append(out, response)
	}
	slices.SortFunc(out, func(left, right Response) int { return strings.Compare(left.ID, right.ID) })
	return out
}
