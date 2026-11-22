// Package commands long-polls a manager for operator commands and runs the
// few this agent allows: starting or lifting a response, and refreshing
// policy now.
//
// Commands are opt-in. They are fetched from the event export host with the
// event export credentials, every one is checked against the agent's own
// allow-list and limits, and each is recorded and its result reported back.
package commands

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	neturl "net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
)

// Actions.
const (
	ActionBlockPeer     = "block_peer"
	ActionFreezeCgroup  = "freeze_cgroup"
	ActionLiftResponse  = "lift_response"
	ActionRefreshPolicy = "refresh_policy"
)

// Result statuses.
const (
	StatusDone    = "done"
	StatusFailed  = "failed"
	StatusRefused = "refused"
	StatusExpired = "expired"
)

const (
	userAgent = "traceguard-commands/1"
	// pollWait asks the manager to hold a poll open this long when it has
	// nothing to send; requestTimeout leaves room past it.
	pollWait       = 25 * time.Second
	requestTimeout = pollWait + 15*time.Second
	resultTimeout  = 15 * time.Second
	maxPollBytes   = 64 << 10
	maxCommands    = 16
	maxDetailBytes = 512
	minBackoff     = 5 * time.Second
	// minPollInterval spaces out polls that return quickly, so a server
	// that answers at once, or keeps answering with nothing to do, is never
	// polled in a tight loop.
	minPollInterval = 2 * time.Second
	maxBackoff      = 5 * time.Minute
	// Results are kept until their command can no longer be redelivered,
	// which is after it expires, so a command delivered twice, after its
	// result was lost or the agent restarted, is answered without running
	// again. rememberedResults bounds them.
	resultRetention   = time.Hour
	rememberedResults = 1024
	maxUnreported     = 256
	// maxReportAttempts bounds retries of one result, about 25 minutes at
	// the longest backoff.
	maxReportAttempts = 10
	// exhaustedCooldown spaces out re-sends of a result given up on.
	exhaustedCooldown = 5 * time.Minute
	maxStateBytes     = 4 << 20
	// maxCommandLifetime bounds how far ahead a command may expire, so a
	// manager bug cannot pin journal entries for good.
	maxCommandLifetime = 24 * time.Hour
	maxDurationSecs    = 24 * 60 * 60
)

var commandIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// interruptedDetail is the result kept while a command runs, which is what
// a redelivery is answered with if the agent stopped before it finished.
const interruptedDetail = "the agent stopped while running this command; check its response records"

// malformedAction marks a command whose fields could not be decoded.
const malformedAction = "\x00malformed"

// restartedDetail replaces a block or freeze's note after a restart, which
// undoes every response.
const restartedDetail = "done; the response ended when the agent restarted"

// Handler carries out commands.
type Handler interface {
	// Apply starts a block_peer or freeze_cgroup response, returning a
	// note for the result, such as that it was only a dry run.
	Apply(commandID, action, target string, duration time.Duration) (string, error)
	// Lift ends an active response, for the command commandID.
	Lift(commandID, action, target string) error
	// RefreshPolicy fetches and applies policy now.
	RefreshPolicy() error
}

// Config configures the poller.
type Config struct {
	URL           string
	Client        *http.Client
	Authorization string
	// Actions lists the actions this agent accepts; others are refused.
	Actions []string
	// StatePath, when set, keeps command results across restarts.
	StatePath string
	// Record receives one record per command and for poll failures.
	Record func(level, message string, fields map[string]any)
	Now    func() time.Time
	// Sleep waits between failed polls; it returns false when ctx ends.
	Sleep func(ctx context.Context, delay time.Duration) bool
}

// Command is one instruction from the manager.
type Command struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	// Target is a peer address, a cgroup ID, or for lift_response the
	// target of the action to lift.
	Target string `json:"target"`
	// ResponseAction names the action lift_response ends.
	ResponseAction  string    `json:"response_action"`
	DurationSeconds int64     `json:"duration_seconds"`
	ExpiresAt       time.Time `json:"expires_at"`
	// replyBy is a malformed command's own valid deadline, used only to
	// deliver its refusal; it never lengthens the journal's retention.
	replyBy time.Time
}

// deliverBy is the deadline for reporting this command's result.
func (c Command) deliverBy() time.Time {
	if !c.ExpiresAt.IsZero() {
		return c.ExpiresAt
	}
	return c.replyBy
}

// Result is what the agent reports for a command.
type Result struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type pollReply struct {
	Commands []json.RawMessage `json:"commands"`
}

// exhaustedResult is a result given up on: which result, when, and when it
// was last re-sent on a redelivery.
type exhaustedResult struct {
	result   Result
	since    time.Time
	lastSent time.Time
	// expires is when the command stops being redelivered, if known.
	expires time.Time
}

// remembered is a command's result, kept until keepUntil.
type remembered struct {
	Result    Result    `json:"result"`
	KeepUntil time.Time `json:"keep_until"`
	Action    string    `json:"action,omitempty"`
}

// Poller fetches and runs commands.
type Poller struct {
	cfg     Config
	handler Handler
	// peer is the address the last poll connected to, the manager or a
	// proxy in front of it, which a command must never block.
	peer    atomic.Pointer[netip.Addr]
	results map[string]remembered
	// journalErr, when set, is why an existing journal could not be read;
	// every command is refused until it is fixed, since running one could
	// repeat a command recorded there.
	journalErr error
	// unreported holds results whose report failed and may succeed on a
	// retry before the next poll; attempts counts the tries for each.
	unreported map[string]settled
	attempts   map[string]int
	// exhausted holds results given up on after maxReportAttempts, so a
	// redelivery of their command is answered once, not retried again.
	exhausted map[string]exhaustedResult
}

// New returns a poller. It validates the URL so a misconfiguration fails
// at start rather than on every poll.
func New(cfg Config, handler Handler) (*Poller, error) {
	parsed, err := neturl.Parse(strings.TrimSpace(cfg.URL))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("command url must be an https URL")
	}
	if cfg.Client == nil {
		return nil, errors.New("command poller needs an HTTP client")
	}
	// A redirect could turn a result POST into a bodiless GET whose 2xx
	// looks like an acknowledgement; commands and results never follow one.
	client := *cfg.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.Client = &client
	cfg.URL = strings.TrimRight(parsed.String(), "/")
	if cfg.Record == nil {
		cfg.Record = func(string, string, map[string]any) {}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Sleep == nil {
		cfg.Sleep = sleep
	}
	poller := &Poller{
		cfg: cfg, handler: handler,
		results: make(map[string]remembered), unreported: make(map[string]settled), attempts: make(map[string]int),
		exhausted: make(map[string]exhaustedResult),
	}
	poller.load()
	return poller, nil
}

// load reads the results kept by an earlier run. A missing or unreadable
// file starts empty: losing it only risks running a redelivered command.
func (p *Poller) load() {
	if p.cfg.StatePath == "" {
		return
	}
	payload, err := safefile.ReadFile(p.cfg.StatePath, maxStateBytes)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			p.journalErr = fmt.Errorf("the command journal %s cannot be read; fix or remove it, then restart the agent", p.cfg.StatePath)
			p.cfg.Record("error", "read manager command state", map[string]any{"error": err.Error()})
		}
		return
	}
	var saved map[string]remembered
	if err := json.Unmarshal(payload, &saved); err != nil {
		p.journalErr = fmt.Errorf("the command journal %s is not valid JSON; fix or remove it, then restart the agent", p.cfg.StatePath)
		p.cfg.Record("error", "read manager command state", map[string]any{"error": "the file is not valid JSON"})
		return
	}
	now := p.cfg.Now()
	for id, entry := range saved {
		if !commandIDPattern.MatchString(id) || !now.Before(entry.KeepUntil) {
			continue
		}
		// TraceGuard undoes every response when it stops, so a block or
		// freeze from before this start is no longer in force; a repeated
		// answer must not suggest it is.
		// A dry run's note already says nothing was changed; keep it.
		if entry.Result.Status == StatusDone && entry.Result.Detail == "" && (entry.Action == ActionBlockPeer || entry.Action == ActionFreezeCgroup) {
			entry.Result.Detail = restartedDetail
		}
		p.results[id] = entry
	}
	p.prune()
	// A journal written by an older build may exceed the bound; keep the
	// newest entries so the bound holds.
	for len(p.results) > rememberedResults {
		oldest := ""
		for id, entry := range p.results {
			if oldest == "" || entry.KeepUntil.Before(p.results[oldest].KeepUntil) {
				oldest = id
			}
		}
		delete(p.results, oldest)
	}
}

func (p *Poller) save() error {
	if p.cfg.StatePath == "" {
		return nil
	}
	payload, err := json.Marshal(p.results)
	if err == nil && len(payload) > maxStateBytes {
		// load could not read it back; refuse rather than write it.
		err = fmt.Errorf("the command journal would exceed %d bytes", maxStateBytes)
	}
	if err == nil {
		err = safefile.WriteFileAtomic(p.cfg.StatePath, payload, 0o600)
	}
	if err != nil {
		p.cfg.Record("error", "save manager command state", map[string]any{"error": err.Error()})
	}
	return err
}

// prune drops results past their keep-until time. Results that can still
// be needed are never evicted; remember refuses new commands instead.
func (p *Poller) prune() {
	now := p.cfg.Now()
	for id, entry := range p.results {
		if !now.Before(entry.KeepUntil) {
			delete(p.results, id)
		}
	}
	// A marker lasts as long as its command could be redelivered, whether
	// or not the command was journalled.
	for id, given := range p.exhausted {
		if !now.Before(given.since.Add(maxCommandLifetime + resultRetention)) {
			delete(p.exhausted, id)
		}
	}
}

// Run polls until ctx ends, backing off after failures.
func (p *Poller) Run(ctx context.Context) {
	backoff := minBackoff
	for ctx.Err() == nil {
		reported := p.reportPending(ctx)
		started := time.Now()
		commands, err := p.poll(ctx)
		received := p.cfg.Now()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			p.cfg.Record("error", "poll manager commands", map[string]any{"error": err.Error()})
			if !p.cfg.Sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		// Run every command in the reply first, then report: a stalled
		// result endpoint must not delay, or expire, the commands behind it.
		results := make([]settled, 0, len(commands))
		for _, command := range commands {
			// Never start a command once shutdown has begun: its result
			// could not be reported, and shutdown undoes what it applies.
			if ctx.Err() != nil {
				return
			}
			if result, ok := p.handle(command); ok {
				results = append(results, settled{id: command.ID, result: result, expires: command.deliverBy(), received: received})
			}
		}
		failed := false
		for _, done := range results {
			if !p.deliver(ctx, done.id, done.result, done.expires, done.received) {
				failed = true
			}
		}
		if failed {
			// The manager takes polls but not results: back off, even for a
			// result no longer retried.
			reported = false
		}
		if !reported || len(p.unreported) > 0 {
			// The manager is taking polls but not results; slow down
			// rather than fetch the same commands again at once.
			if !p.cfg.Sleep(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		backoff = minBackoff
		if elapsed := time.Since(started); elapsed < minPollInterval {
			if !p.cfg.Sleep(ctx, minPollInterval-elapsed) {
				return
			}
		}
	}
}

func (p *Poller) poll(ctx context.Context) ([]Command, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	target := p.cfg.URL + "?wait=" + fmt.Sprint(int(pollWait/time.Second))
	request, err := http.NewRequestWithContext(p.traced(ctx), http.MethodGet, target, nil)
	if err != nil {
		return nil, errors.New("build command poll request")
	}
	p.headers(request)
	request.Header.Set("Accept", "application/json")
	response, err := p.cfg.Client.Do(request)
	if err != nil {
		// Never include the *url.Error: it repeats the URL.
		return nil, errors.New("command poll request failed")
	}
	defer func() { _ = response.Body.Close() }()
	switch {
	case response.StatusCode == http.StatusNoContent:
		return nil, nil
	case response.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("command poll: unexpected status %s", response.Status)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxPollBytes+1))
	if err != nil {
		return nil, errors.New("read command poll reply")
	}
	if len(body) > maxPollBytes {
		return nil, fmt.Errorf("command poll reply exceeds %d bytes", maxPollBytes)
	}
	var reply pollReply
	if err := json.Unmarshal(body, &reply); err != nil {
		return nil, errors.New("command poll reply is not valid JSON")
	}
	if len(reply.Commands) > maxCommands {
		reply.Commands = reply.Commands[:maxCommands]
	}
	// Each command is decoded on its own, so one malformed item cannot keep
	// the others from running. One that cannot be read is answered by id
	// when it has one.
	commands := make([]Command, 0, len(reply.Commands))
	for _, raw := range reply.Commands {
		var command Command
		if err := json.Unmarshal(raw, &command); err != nil {
			var named struct {
				ID        string          `json:"id"`
				ExpiresAt json.RawMessage `json:"expires_at"`
			}
			if json.Unmarshal(raw, &named) == nil && commandIDPattern.MatchString(named.ID) {
				malformed := Command{ID: named.ID, Action: malformedAction}
				// Kept when it is itself valid, so the refusal's delivery
				// still knows the deadline.
				_ = json.Unmarshal(named.ExpiresAt, &malformed.replyBy)
				commands = append(commands, malformed)
			}
			continue
		}
		commands = append(commands, command)
	}
	return commands, nil
}

func (p *Poller) headers(request *http.Request) {
	request.Header.Set("User-Agent", userAgent)
	if p.cfg.Authorization != "" {
		request.Header.Set("Authorization", p.cfg.Authorization)
	}
}

// handle runs a command once and reports its result. A command seen
// before is not run again; its earlier result is reported.
// settled is a command's result waiting to be reported.
type settled struct {
	id     string
	result Result
	// expires is the command's own deadline; zero when it has none.
	expires time.Time
	// received is when the poll that carried it was answered.
	received time.Time
}

// handle runs a command once and returns its result to report. A command
// seen before is not run again; its earlier result is returned.
func (p *Poller) handle(command Command) (Result, bool) {
	if !commandIDPattern.MatchString(command.ID) {
		p.cfg.Record("error", "manager command refused", map[string]any{
			"event": "command", "status": StatusRefused, "detail": "command id is not valid",
		})
		return Result{}, false
	}
	entry, seen := p.results[command.ID]
	result := entry.Result
	if !seen && p.journalErr != nil {
		// Never write over a journal that could not be read.
		result = Result{Status: StatusRefused, Detail: bounded(p.journalErr.Error(), maxDetailBytes)}
		p.cfg.Record("error", "manager command", map[string]any{
			"event": "command", "command_id": command.ID, "action": command.Action, "status": result.Status, "detail": result.Detail,
		})
		return result, true
	}
	if !seen {
		// Record the command before running it, so an agent that stops
		// part way never runs it again on redelivery.
		if err := p.remember(command, Result{Status: StatusFailed, Detail: interruptedDetail}, true); err != nil {
			result = Result{Status: StatusRefused, Detail: bounded(err.Error(), maxDetailBytes)}
		} else {
			result = p.execute(command)
			// Kept in memory even if this write fails: the real result must
			// never be replaced by the marker written before running.
			_ = p.remember(command, result, false)
		}
		fields := map[string]any{
			"event": "command", "command_id": command.ID, "action": command.Action, "status": result.Status,
		}
		if command.Target != "" {
			fields["target"] = command.Target
		}
		if command.ResponseAction != "" {
			fields["response_action"] = command.ResponseAction
		}
		if result.Detail != "" {
			fields["detail"] = result.Detail
		}
		level := "info"
		if result.Status != StatusDone {
			level = "error"
		}
		p.cfg.Record(level, "manager command", fields)
	}
	return result, true
}

// deliver reports a result, keeping it for a retry when that may succeed.
// It returns false when a report failed in a way that may clear later.
func (p *Poller) deliver(ctx context.Context, id string, result Result, expires, received time.Time) bool {
	// A marker covers only the result it gave up on: a different result for
	// the same command, such as one run after the journal recovered, is
	// reported and retried normally.
	marker, given := p.exhausted[id]
	given = given && marker.result == result
	if given {
		now := p.cfg.Now()
		// Never skip what may be the last chance before the command expires,
		// judged by when the redelivery arrived, not by when its turn to be
		// posted came.
		if received.IsZero() {
			received = now
		}
		inFinalWindow := func(at time.Time) bool {
			return at.Before(marker.expires) && marker.expires.Sub(at) <= exhaustedCooldown
		}
		// Either moment in the final window counts: the redelivery may have
		// arrived just before it, then waited behind other posts.
		lastChance := !marker.expires.IsZero() && (inFinalWindow(received) || inFinalWindow(now))
		if now.Before(marker.lastSent.Add(exhaustedCooldown)) && !lastChance {
			// Answered recently; do not add load to a struggling manager.
			return true
		}
		marker.lastSent = now
		p.exhausted[id] = marker
	}
	retry, err := p.report(ctx, id, result)
	// One result already given up on must not slow every other command:
	// only failures of results still being retried drive the backoff.
	transient := err != nil && retry && !given
	if given {
		retry = false
	}
	if err != nil && retry && len(p.unreported) < maxUnreported {
		p.unreported[id] = settled{id: id, result: result, expires: expires, received: received}
	} else if err != nil {
		p.cfg.Record("error", "report manager command result", map[string]any{"command_id": id, "error": err.Error()})
	}
	return !transient
}

func (p *Poller) execute(command Command) Result {
	if p.journalErr != nil {
		return Result{Status: StatusRefused, Detail: bounded(p.journalErr.Error(), maxDetailBytes)}
	}
	if command.Action == malformedAction {
		return Result{Status: StatusRefused, Detail: "the command could not be read"}
	}
	if command.ExpiresAt.IsZero() {
		return Result{Status: StatusRefused, Detail: "the command has no expiry"}
	}
	if !p.cfg.Now().Before(command.ExpiresAt) {
		return Result{Status: StatusExpired, Detail: "the command expired before it arrived"}
	}
	if command.ExpiresAt.After(p.cfg.Now().Add(maxCommandLifetime)) {
		return Result{Status: StatusRefused, Detail: "the command expires more than 24 hours ahead"}
	}
	if !slices.Contains(p.cfg.Actions, command.Action) {
		return Result{Status: StatusRefused, Detail: fmt.Sprintf("action %q is not enabled on this agent", bounded(command.Action, 64))}
	}
	var (
		err    error
		detail string
	)
	switch command.Action {
	case ActionBlockPeer, ActionFreezeCgroup:
		// Checked before converting, so a huge value cannot wrap around to
		// a short duration that passes the responder's bounds.
		if command.DurationSeconds < 1 || command.DurationSeconds > maxDurationSecs {
			return Result{Status: StatusRefused, Detail: "duration_seconds must be between 1 and 86400"}
		}
		detail, err = p.handler.Apply(command.ID, command.Action, command.Target, time.Duration(command.DurationSeconds)*time.Second)
	case ActionLiftResponse:
		if command.ResponseAction != ActionBlockPeer && command.ResponseAction != ActionFreezeCgroup {
			return Result{Status: StatusRefused, Detail: "response_action must be block_peer or freeze_cgroup"}
		}
		err = p.handler.Lift(command.ID, command.ResponseAction, command.Target)
	case ActionRefreshPolicy:
		err = p.handler.RefreshPolicy()
	default:
		return Result{Status: StatusRefused, Detail: "unknown action"}
	}
	if err != nil {
		return Result{Status: StatusFailed, Detail: bounded(err.Error(), maxDetailBytes)}
	}
	return Result{Status: StatusDone, Detail: bounded(detail, maxDetailBytes)}
}

// remember keeps a result, on disk too, until its command can no longer be
// redelivered. It refuses a new command when the journal is full of ones
// that still could be, or when the journal cannot be written.
func (p *Poller) remember(command Command, result Result, rollback bool) error {
	now := p.cfg.Now()
	keepUntil := now.Add(resultRetention)
	// execute refuses expiries beyond maxCommandLifetime, so this is bounded.
	if expires := command.ExpiresAt; !expires.IsZero() && expires.Before(now.Add(maxCommandLifetime)) && expires.Add(resultRetention).After(keepUntil) {
		keepUntil = expires.Add(resultRetention)
	}
	p.prune()
	if _, known := p.results[command.ID]; !known && len(p.results) >= rememberedResults {
		return errors.New("too many recent commands to remember another; try again later")
	}
	previous, had := p.results[command.ID]
	p.results[command.ID] = remembered{Result: result, KeepUntil: keepUntil, Action: command.Action}
	if err := p.save(); err != nil {
		if rollback {
			if had {
				p.results[command.ID] = previous
			} else {
				delete(p.results, command.ID)
			}
		}
		return errors.New("cannot record the command before running it")
	}
	return nil
}

// reportPending retries results whose report failed. It stops at the first
// failure that may clear later, and reports whether every one was settled.
func (p *Poller) reportPending(ctx context.Context) bool {
	for id, pending := range p.unreported {
		result := pending.result
		retry, err := p.report(ctx, id, result)
		if err != nil && retry {
			p.attempts[id]++
			if p.attempts[id] < maxReportAttempts {
				return false
			}
			// The manager keeps refusing this one result; give it up rather
			// than slow every later command for good.
			err = fmt.Errorf("gave up after %d attempts: %w", p.attempts[id], err)
		}
		if err != nil {
			p.cfg.Record("error", "report manager command result", map[string]any{"command_id": id, "error": err.Error()})
		}
		_, marked := p.exhausted[id]
		if p.attempts[id] >= maxReportAttempts && (marked || len(p.exhausted) < maxUnreported) {
			now := p.cfg.Now()
			// The command's own deadline; a command without one has none.
			p.exhausted[id] = exhaustedResult{result: result, since: now, lastSent: now, expires: pending.expires}
		}
		delete(p.unreported, id)
		delete(p.attempts, id)
	}
	return true
}

// report sends a result. retry is true for a failure that may clear later:
// no reply, throttling, or a server error.
func (p *Poller) report(ctx context.Context, id string, result Result) (retry bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, resultTimeout)
	defer cancel()
	payload, err := json.Marshal(result)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.cfg.URL+"/"+id+"/result", bytes.NewReader(payload))
	if err != nil {
		return false, errors.New("build command result request")
	}
	p.headers(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := p.cfg.Client.Do(request)
	if err != nil {
		return true, errors.New("command result request failed")
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxPollBytes))
	_ = response.Body.Close()
	switch code := response.StatusCode; {
	case code >= 200 && code < 300:
		return false, nil
	case code == http.StatusNotFound || code == http.StatusConflict:
		// The manager no longer wants this result.
		return false, nil
	case code == http.StatusRequestTimeout || code == http.StatusTooEarly || code == http.StatusTooManyRequests || code >= 500:
		return true, fmt.Errorf("command result: unexpected status %s", response.Status)
	default:
		// Any other refusal will be the same next time.
		return false, fmt.Errorf("command result: unexpected status %s", response.Status)
	}
}

func bounded(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return strings.ToValidUTF8(text[:limit], "")
}

func sleep(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// traced notes the address each poll connects to.
func (p *Poller) traced(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn == nil {
				return
			}
			if address, err := netip.ParseAddrPort(info.Conn.RemoteAddr().String()); err == nil {
				peer := address.Addr().Unmap()
				p.peer.Store(&peer)
			}
		},
	})
}

// ConnectedPeer returns the address the last poll connected to, if any.
func (p *Poller) ConnectedPeer() (netip.Addr, bool) {
	if peer := p.peer.Load(); peer != nil {
		return *peer, true
	}
	return netip.Addr{}, false
}
