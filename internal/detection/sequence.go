package detection

import (
	"crypto/rand"
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
	// events holds every event name a step can match, so other events
	// skip the sequence before any key is hashed.
	events map[string]struct{}
}

type compiledStep struct {
	step         policy.SequenceStep
	matchCIDRs   []netip.Prefix
	excludeCIDRs []netip.Prefix
}

// sequenceState tracks one key's partial matches of one sequence. partial[i]
// is the match with i+1 steps done that started latest, which is the one most
// likely to finish within the window; a later first step therefore never
// waits on an older one.
type sequenceState struct {
	window  time.Duration
	partial []partialMatch
}

type partialMatch struct {
	started, last time.Time
	ok            bool
}

// expire drops partial matches whose window has passed and reports whether
// any remain.
func (s *sequenceState) expire(now time.Time) bool {
	remaining := false
	for index := range s.partial {
		if s.partial[index].ok && now.Sub(s.partial[index].started) > s.window {
			s.partial[index] = partialMatch{}
		}
		remaining = remaining || s.partial[index].ok
	}
	return remaining
}

// cooldownRecord is when a key's sequence last alerted and for how long that
// suppresses another alert.
type cooldownRecord struct {
	at       time.Time
	cooldown time.Duration
}

func (r cooldownRecord) until() time.Time { return r.at.Add(r.cooldown) }

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
		events := make(map[string]struct{})
		for _, step := range sequence.Steps {
			for _, name := range step.Events {
				events[name] = struct{}{}
			}
		}
		compiled = append(compiled, compiledSequence{sequence: sequence, steps: steps, events: events})
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
		cgroup := fields["cgroup_id"]
		if !identityValue(cgroup) {
			return groupKey{}, false
		}
		_, _ = fmt.Fprint(hash, cgroup)
	default:
		pid, start := fields["pid"], fields["process_start_ticks"]
		if !identityValue(pid) || !identityValue(start) {
			return groupKey{}, false
		}
		_, _ = fmt.Fprintf(hash, "%v:%v", pid, start)
	}
	var out groupKey
	copy(out[:], hash.Sum(nil))
	return out, true
}

// identityValue reports whether an identity field holds a usable value. A
// replayed record can carry null or zero, which would make unrelated
// processes share a key.
func identityValue(value any) bool {
	switch text := fmt.Sprint(value); text {
	case "<nil>", "", "0":
		return false
	}
	return true
}

// evaluateSequences advances every sequence the event matches a step of and
// returns alerts for sequences it completes. The caller holds e.mu.
func (e *Engine) evaluateSequences(event Event, context *eventMatchContext) []Alert {
	var alerts []Alert
	for index := range e.sequences {
		sequence := &e.sequences[index]
		if _, used := sequence.events[event.Name]; !used {
			continue
		}
		key, ok := sequenceKey(sequence.sequence.ID, sequence.sequence.Key, event.Fields)
		if !ok {
			continue
		}
		started, completed := e.advanceSequence(sequence, key, event, context)
		if !completed {
			continue
		}
		if id, suppressed := suppressingException(sequence.exceptions, event.Timestamp, context); suppressed {
			e.suppressed[id]++
			continue
		}
		if cooldown := sequence.sequence.Cooldown.Duration; cooldown > 0 {
			if last, ok := e.sequenceAlerts[key]; ok && event.Timestamp.Before(last.until()) {
				continue
			}
			e.recordSequenceAlert(key, cooldownRecord{at: event.Timestamp, cooldown: cooldown})
		}
		alert := Alert{
			ID: rand.Text(), RuleID: sequence.sequence.ID, Severity: sequence.sequence.Severity, Message: sequence.sequence.Message,
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

// advanceSequence applies one event to a key's partial matches and reports
// the start of a match it completes. Steps are tried from last to first, so
// one event advances a match by at most one step. A step must not precede
// the step before it, and must fall within the window of the first.
func (e *Engine) advanceSequence(sequence *compiledSequence, key groupKey, event Event, context *eventMatchContext) (time.Time, bool) {
	window := sequence.sequence.Within.Duration
	state := e.sequenceStates[key]
	if state != nil && !state.expire(event.Timestamp) {
		delete(e.sequenceStates, key)
		state = nil
	}
	final := len(sequence.steps) - 1
	for step := final; step >= 0; step-- {
		if !sequence.steps[step].matches(event.Name, context) {
			continue
		}
		candidate := partialMatch{started: event.Timestamp, last: event.Timestamp, ok: true}
		if step > 0 {
			if state == nil {
				continue
			}
			previous := state.partial[step-1]
			if !previous.ok || event.Timestamp.Before(previous.last) || event.Timestamp.Sub(previous.started) > window {
				continue
			}
			candidate.started = previous.started
		}
		if step == final {
			// A completed sequence starts over, so one run alerts once.
			delete(e.sequenceStates, key)
			return candidate.started, true
		}
		if state == nil {
			if len(e.sequenceStates) >= e.maxSequenceStates {
				e.pruneSequenceProgress(event.Timestamp)
				if len(e.sequenceStates) >= e.maxSequenceStates {
					continue
				}
			}
			state = &sequenceState{window: window, partial: make([]partialMatch, final)}
			e.sequenceStates[key] = state
			// A new key may expire before every key the last prune kept.
			if expiry := event.Timestamp.Add(window); !e.nextProgressPrune.IsZero() && expiry.Before(e.nextProgressPrune) {
				e.nextProgressPrune = expiry
			}
		}
		if current := state.partial[step]; !current.ok || !candidate.started.Before(current.started) {
			state.partial[step] = candidate
		}
	}
	return time.Time{}, false
}

// recordSequenceAlert stores a cooldown record. When the records are full
// after pruning, the one that expires soonest makes room.
func (e *Engine) recordSequenceAlert(key groupKey, record cooldownRecord) {
	if _, ok := e.sequenceAlerts[key]; !ok && len(e.sequenceAlerts) >= e.maxSequenceStates {
		e.pruneSequenceCooldowns(record.at)
		if len(e.sequenceAlerts) >= e.maxSequenceStates {
			var soonest groupKey
			var soonestUntil time.Time
			for candidate, existing := range e.sequenceAlerts {
				if soonestUntil.IsZero() || existing.until().Before(soonestUntil) {
					soonest, soonestUntil = candidate, existing.until()
				}
			}
			delete(e.sequenceAlerts, soonest)
		}
	}
	e.sequenceAlerts[key] = record
	if !e.nextCooldownPrune.IsZero() && record.until().Before(e.nextCooldownPrune) {
		e.nextCooldownPrune = record.until()
	}
}

// pruneSequenceStates drops partial matches past their own sequence's window
// and cooldown records past their own cooldown.
func (e *Engine) pruneSequenceStates(now time.Time) {
	e.nextProgressPrune, e.nextCooldownPrune = time.Time{}, time.Time{}
	e.pruneSequenceProgress(now)
	e.pruneSequenceCooldowns(now)
}

// pruneSequenceProgress drops expired partial matches. Until the earliest
// remaining one can expire, a full table has nothing to drop, so later calls
// return at once instead of walking every key for each matching event.
func (e *Engine) pruneSequenceProgress(now time.Time) {
	if now.Before(e.nextProgressPrune) {
		return
	}
	var next time.Time
	for key, state := range e.sequenceStates {
		if !state.expire(now) {
			delete(e.sequenceStates, key)
			continue
		}
		for _, partial := range state.partial {
			if expiry := partial.started.Add(state.window); partial.ok && (next.IsZero() || expiry.Before(next)) {
				next = expiry
			}
		}
	}
	e.nextProgressPrune = next
}

// pruneSequenceCooldowns drops ended cooldown records, skipping the walk
// until the earliest remaining one ends.
func (e *Engine) pruneSequenceCooldowns(now time.Time) {
	if now.Before(e.nextCooldownPrune) {
		return
	}
	var next time.Time
	for key, record := range e.sequenceAlerts {
		if !now.Before(record.until()) {
			delete(e.sequenceAlerts, key)
			continue
		}
		if next.IsZero() || record.until().Before(next) {
			next = record.until()
		}
	}
	e.nextCooldownPrune = next
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
