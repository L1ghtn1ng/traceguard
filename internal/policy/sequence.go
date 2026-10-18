package policy

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	MaxDetectionSequences = 64
	MaxSequenceSteps      = 8
	MaxSequenceWindow     = time.Hour
	// MaxSequenceStates bounds in-progress sequences across all keys.
	MaxSequenceStates = 16384
)

// Sequence keys correlate steps that come from the same process, or from the
// same cgroup such as one container or service.
const (
	SequenceKeyProcess = "process"
	SequenceKeyCgroup  = "cgroup"
)

// DetectionSequence alerts when its steps match in order for one key within
// a time window, such as a web server spawning a shell that then connects
// out.
type DetectionSequence struct {
	ID         string         `yaml:"id"`
	Enabled    *bool          `yaml:"enabled,omitempty"`
	Severity   string         `yaml:"severity"`
	Key        string         `yaml:"key"`
	Within     Duration       `yaml:"within"`
	Steps      []SequenceStep `yaml:"steps"`
	Cooldown   Duration       `yaml:"cooldown,omitempty"`
	Message    string         `yaml:"message"`
	Tags       []string       `yaml:"tags,omitempty"`
	MITRE      MITRE          `yaml:"mitre,omitempty"`
	Compliance []string       `yaml:"compliance,omitempty"`
}

// SequenceStep is one ordered condition of a sequence.
type SequenceStep struct {
	Events  []string       `yaml:"events"`
	Match   DetectionMatch `yaml:"match,omitempty"`
	Exclude DetectionMatch `yaml:"exclude,omitempty"`
}

// Active reports whether the sequence is enabled.
func (s DetectionSequence) Active() bool { return s.Enabled == nil || *s.Enabled }

func (s DetectionSequence) validate() error {
	if !s.Active() {
		return nil
	}
	if err := validateAlertMetadata(s.Severity, s.Message, s.Tags, s.MITRE, s.Compliance); err != nil {
		return err
	}
	if s.Key != SequenceKeyProcess && s.Key != SequenceKeyCgroup {
		return fmt.Errorf("key must be %s or %s", SequenceKeyProcess, SequenceKeyCgroup)
	}
	if s.Within.Duration <= 0 || s.Within.Duration > MaxSequenceWindow {
		return fmt.Errorf("within must be between 1ns and %s", MaxSequenceWindow)
	}
	if s.Cooldown.Duration < 0 {
		return fmt.Errorf("cooldown must not be negative")
	}
	if len(s.Steps) < 2 || len(s.Steps) > MaxSequenceSteps {
		return fmt.Errorf("steps must number between 2 and %d", MaxSequenceSteps)
	}
	for index, step := range s.Steps {
		if err := step.validate(); err != nil {
			return fmt.Errorf("step %d: %w", index+1, err)
		}
	}
	return nil
}

func (s SequenceStep) validate() error {
	if err := validateEventNames(s.Events); err != nil {
		return err
	}
	// Both keys come from the kernel's event-time snapshot, so every step
	// needs one.
	if err := validateDetectionProcessIdentity(s.Events, "sequence keys", s.Match); err != nil {
		return err
	}
	if err := s.Match.validate(); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if err := s.Exclude.validate(); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	if err := validateDetectionEventFields(s.Events, s.Match, s.Match); err != nil {
		return fmt.Errorf("match: %w", err)
	}
	if err := validateDetectionEventFields(s.Events, s.Exclude, s.Match, s.Exclude); err != nil {
		return fmt.Errorf("exclude: %w", err)
	}
	return nil
}

// FinalStepRule describes a sequence's last step as a rule, the shape an
// exception's match is validated against.
func (s DetectionSequence) FinalStepRule() DetectionRule {
	last := s.Steps[len(s.Steps)-1]
	return DetectionRule{ID: s.ID, Events: last.Events, Match: last.Match}
}

// mergeSequencesByID lets an overlay sequence or rule replace a base
// sequence with the same ID, and drops disabled IDs and disabled sequences.
func mergeSequencesByID(base, overlay []DetectionSequence, overlayIDs, disabled map[string]struct{}) []DetectionSequence {
	merged := make(map[string]DetectionSequence, len(base)+len(overlay))
	for _, sequence := range base {
		if _, replaced := overlayIDs[sequence.ID]; replaced {
			continue
		}
		merged[sequence.ID] = sequence
	}
	for _, sequence := range overlay {
		merged[sequence.ID] = sequence
	}
	out := make([]DetectionSequence, 0, len(merged))
	for id, sequence := range merged {
		if _, skip := disabled[id]; skip || !sequence.Active() {
			continue
		}
		out = append(out, sequence)
	}
	slices.SortFunc(out, func(left, right DetectionSequence) int { return strings.Compare(left.ID, right.ID) })
	return out
}
