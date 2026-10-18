package detection

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/policy"
)

type compiledSequence struct {
	sequence   policy.DetectionSequence
	steps      []compiledStep
	exceptions []compiledException
}

type compiledStep struct {
	step         policy.SequenceStep
	matchCIDRs   []netip.Prefix
	excludeCIDRs []netip.Prefix
}

// sequenceState tracks one key's progress through one sequence.
type sequenceState struct {
	next    int
	started time.Time
}

func compileSequences(sequences []policy.DetectionSequence) ([]compiledSequence, error) {
	compiled := make([]compiledSequence, 0, len(sequences))
	for _, sequence := range sequences {
		steps := make([]compiledStep, 0, len(sequence.Steps))
		for index, step := range sequence.Steps {
			matchCIDRs, err := parseCIDRs(step.Match.DestinationCIDRs)
			if err != nil {
				return nil, fmt.Errorf("compile detection sequence %q step %d match: %w", sequence.ID, index+1, err)
			}
			excludeCIDRs, err := parseCIDRs(step.Exclude.DestinationCIDRs)
			if err != nil {
				return nil, fmt.Errorf("compile detection sequence %q step %d exclude: %w", sequence.ID, index+1, err)
			}
			steps = append(steps, compiledStep{step: step, matchCIDRs: matchCIDRs, excludeCIDRs: excludeCIDRs})
		}
		compiled = append(compiled, compiledSequence{sequence: sequence, steps: steps})
	}
	return compiled, nil
}

func (s *compiledStep) matches(name string, context *eventMatchContext) bool {
	return slices.Contains(s.step.Events, name) &&
		matches(s.step.Match, s.matchCIDRs, context) &&
		(s.step.Exclude.Empty() || !matches(s.step.Exclude, s.excludeCIDRs, context))
}

// sequenceKey identifies the process or cgroup a sequence follows, from the
// kernel's event-time identity only.
func sequenceKey(sequenceID, key string, fields map[string]any) (groupKey, bool) {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "sequence\x00"+sequenceID+"\x00"+key+"\x00")
	switch key {
	case policy.SequenceKeyCgroup:
		cgroup, ok := fields["cgroup_id"]
		if !ok || cgroup == nil {
			return groupKey{}, false
		}
		_, _ = fmt.Fprint(hash, cgroup)
	default:
		pid, hasPID := fields["pid"]
		start, hasStart := fields["process_start_ticks"]
		if !hasPID || !hasStart {
			return groupKey{}, false
		}
		_, _ = fmt.Fprintf(hash, "%v:%v", pid, start)
	}
	var out groupKey
	copy(out[:], hash.Sum(nil))
	return out, true
}

// evaluateSequences advances every sequence the event matches a step of and
// returns alerts for sequences it completes. The caller holds e.mu.
func (e *Engine) evaluateSequences(event Event, context *eventMatchContext) []Alert {
	var alerts []Alert
	for index := range e.sequences {
		sequence := &e.sequences[index]
		key, ok := sequenceKey(sequence.sequence.ID, sequence.sequence.Key, event.Fields)
		if !ok {
			continue
		}
		state := e.sequenceStates[key]
		if state != nil && event.Timestamp.Sub(state.started) > sequence.sequence.Within.Duration {
			delete(e.sequenceStates, key)
			state = nil
		}
		next := 0
		if state != nil {
			next = state.next
		}
		if !sequence.steps[next].matches(event.Name, context) {
			continue
		}
		if state == nil {
			if len(e.sequenceStates) >= e.maxSequenceStates {
				e.pruneSequenceStates(event.Timestamp)
				if len(e.sequenceStates) >= e.maxSequenceStates {
					continue
				}
			}
			state = &sequenceState{started: event.Timestamp}
			e.sequenceStates[key] = state
		}
		state.next++
		if state.next < len(sequence.steps) {
			continue
		}
		started := state.started
		delete(e.sequenceStates, key)
		if id, suppressed := suppressingException(sequence.exceptions, event.Timestamp, context); suppressed {
			e.suppressed[id]++
			continue
		}
		if cooldown := sequence.sequence.Cooldown.Duration; cooldown > 0 {
			if last, ok := e.sequenceAlerts[key]; ok && event.Timestamp.Sub(last) < cooldown {
				continue
			}
			if len(e.sequenceAlerts) >= e.maxSequenceStates {
				e.pruneSequenceStates(event.Timestamp)
			}
			if len(e.sequenceAlerts) < e.maxSequenceStates {
				e.sequenceAlerts[key] = event.Timestamp
			}
		}
		alert := Alert{
			RuleID: sequence.sequence.ID, Severity: sequence.sequence.Severity, Message: sequence.sequence.Message,
			Tags: slices.Clone(sequence.sequence.Tags), Tactics: slices.Clone(sequence.sequence.MITRE.Tactics),
			Techniques: slices.Clone(sequence.sequence.MITRE.Techniques), Compliance: slices.Clone(sequence.sequence.Compliance),
			Count: len(sequence.steps), Window: sequence.sequence.Within.Duration,
			Timestamp: event.Timestamp, Fields: cloneFields(event.Fields),
		}
		alert.Fields["sequence_started"] = started.Format(time.RFC3339Nano)
		alerts = append(alerts, alert)
	}
	return alerts
}

// pruneSequenceStates drops progress older than every sequence's window and
// cooldown records older than every cooldown.
func (e *Engine) pruneSequenceStates(now time.Time) {
	var longestWindow, longestCooldown time.Duration
	for _, sequence := range e.sequences {
		longestWindow = max(longestWindow, sequence.sequence.Within.Duration)
		longestCooldown = max(longestCooldown, sequence.sequence.Cooldown.Duration)
	}
	for key, state := range e.sequenceStates {
		if now.Sub(state.started) > longestWindow {
			delete(e.sequenceStates, key)
		}
	}
	for key, last := range e.sequenceAlerts {
		if now.Sub(last) >= longestCooldown {
			delete(e.sequenceAlerts, key)
		}
	}
}

func suppressingException(exceptions []compiledException, at time.Time, context *eventMatchContext) (string, bool) {
	for index := range exceptions {
		exception := &exceptions[index]
		if exception.exception.Active(at) && matches(exception.exception.Match, exception.cidrs, context) {
			return exception.exception.ID, true
		}
	}
	return "", false
}
