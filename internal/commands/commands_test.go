package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type call struct {
	kind, id, action, target string
	duration                 time.Duration
}

type fakeHandler struct {
	mu     sync.Mutex
	calls  []call
	err    error
	detail string
}

func (f *fakeHandler) Apply(id, action, target string, duration time.Duration) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{"apply", id, action, target, duration})
	return f.detail, f.err
}

func (f *fakeHandler) Lift(_, action, target string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{kind: "lift", action: action, target: target})
	return f.err
}

func (f *fakeHandler) RefreshPolicy() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{kind: "refresh"})
	return f.err
}

type manager struct {
	mu       sync.Mutex
	pending  [][]Command
	results  map[string]Result
	auth     []string
	waits    []string
	resultOK bool
	// resultStatus, when set, is the status every result POST gets.
	resultStatus int
}

func newManager(batches ...[]Command) *manager {
	return &manager{pending: batches, results: map[string]Result{}, resultOK: true}
}

func (m *manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auth = append(m.auth, r.Header.Get("Authorization"))
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/result") {
		if m.resultStatus != 0 {
			w.WriteHeader(m.resultStatus)
			return
		}
		if !m.resultOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/commands/"), "/result")
		var result Result
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &result)
		m.results[id] = result
		w.WriteHeader(http.StatusNoContent)
		return
	}
	m.waits = append(m.waits, r.URL.Query().Get("wait"))
	if len(m.pending) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	batch := m.pending[0]
	m.pending = m.pending[1:]
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"commands": batch}); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// future is a command expiry the fixed test clock has not reached.
var future = time.Unix(2000, 0)

func newPoller(t *testing.T, server *httptest.Server, handler Handler, actions []string, statePath ...string) *Poller {
	t.Helper()
	cfg := Config{
		URL: server.URL + "/api/v1/commands", Client: server.Client(), Authorization: "Bearer agent-token",
		Actions: actions, Now: func() time.Time { return time.Unix(1000, 0) },
	}
	if len(statePath) > 0 {
		cfg.StatePath = statePath[0]
	}
	poller, err := New(cfg, handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return poller
}

var allActions = []string{ActionBlockPeer, ActionFreezeCgroup, ActionLiftResponse, ActionRefreshPolicy}

func pollOnce(t *testing.T, poller *Poller) {
	t.Helper()
	poller.reportPending(t.Context())
	commands, err := poller.poll(t.Context())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	for _, command := range commands {
		if result, ok := poller.handle(command); ok {
			poller.deliver(t.Context(), command.ID, result, command.ExpiresAt, time.Time{})
		}
	}
}

func TestPollerRunsCommandsAndReportsResults(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{
		{ID: "c1", Action: ActionBlockPeer, Target: "203.0.113.7", DurationSeconds: 600, ExpiresAt: future},
		{ID: "c2", Action: ActionLiftResponse, ResponseAction: ActionFreezeCgroup, Target: "42", ExpiresAt: future},
		{ID: "c3", Action: ActionRefreshPolicy, ExpiresAt: future},
		{ID: "c4", Action: ActionBlockPeer, Target: "203.0.113.8", DurationSeconds: 60, ExpiresAt: time.Unix(999, 0)},
		{ID: "c5", Action: "run_shell", Target: "rm -rf /", ExpiresAt: future},
		{ID: "c6", Action: ActionLiftResponse, ResponseAction: "reboot", ExpiresAt: future},
		{ID: "c7", Action: ActionBlockPeer, Target: "203.0.113.9", DurationSeconds: 18446744074, ExpiresAt: future},
		{ID: "c8", Action: ActionRefreshPolicy},
	})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, allActions))

	want := []call{
		{"apply", "c1", ActionBlockPeer, "203.0.113.7", 10 * time.Minute},
		{kind: "lift", action: ActionFreezeCgroup, target: "42"},
		{kind: "refresh"},
	}
	if len(handler.calls) != len(want) {
		t.Fatalf("handler calls = %+v, want %+v", handler.calls, want)
	}
	for index := range want {
		if handler.calls[index] != want[index] {
			t.Fatalf("call %d = %+v, want %+v", index, handler.calls[index], want[index])
		}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	for id, status := range map[string]string{
		"c1": StatusDone, "c2": StatusDone, "c3": StatusDone, "c4": StatusExpired, "c5": StatusRefused, "c6": StatusRefused,
		"c7": StatusRefused, "c8": StatusRefused,
	} {
		if got := mgr.results[id].Status; got != status {
			t.Errorf("result %s = %q, want %q", id, got, status)
		}
	}
	for _, auth := range mgr.auth {
		if auth != "Bearer agent-token" {
			t.Fatalf("request authorization = %q", auth)
		}
	}
	if mgr.waits[0] != "25" {
		t.Fatalf("poll wait = %q, want 25", mgr.waits[0])
	}
}

func TestPollerRefusesActionsNotEnabled(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{{ID: "c1", Action: ActionFreezeCgroup, Target: "42", DurationSeconds: 60, ExpiresAt: future}})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, []string{ActionLiftResponse}))
	if len(handler.calls) != 0 {
		t.Fatalf("handler ran a disabled action: %+v", handler.calls)
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if got := mgr.results["c1"]; got.Status != StatusRefused || !strings.Contains(got.Detail, "not enabled") {
		t.Fatalf("result = %+v, want refused", got)
	}
}

func TestPollerReportsFailuresAndNeverRunsACommandTwice(t *testing.T) {
	t.Parallel()

	command := Command{ID: "c1", Action: ActionBlockPeer, Target: "203.0.113.7", DurationSeconds: 60, ExpiresAt: future}
	mgr := newManager([]Command{command}, []Command{command})
	mgr.resultOK = false
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{err: errors.New("peer blocking is unavailable")}
	poller := newPoller(t, server, handler, allActions)

	pollOnce(t, poller)
	if len(poller.unreported) != 1 {
		t.Fatalf("unreported = %d, want the failed report kept", len(poller.unreported))
	}
	mgr.mu.Lock()
	mgr.resultOK = true
	mgr.mu.Unlock()
	// The manager redelivers the command; the agent answers with the
	// result it already has.
	pollOnce(t, poller)
	if len(handler.calls) != 1 {
		t.Fatalf("handler calls = %d, want the command run once", len(handler.calls))
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if got := mgr.results["c1"]; got.Status != StatusFailed || got.Detail != "peer blocking is unavailable" {
		t.Fatalf("result = %+v, want the failure reported", got)
	}
	if len(poller.unreported) != 0 {
		t.Fatalf("unreported = %d after a successful report", len(poller.unreported))
	}
}

func TestPollerIgnoresInvalidCommandIDs(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{{ID: "../../etc", Action: ActionRefreshPolicy}, {ID: strings.Repeat("a", 65), Action: ActionRefreshPolicy}})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, allActions))
	if len(handler.calls) != 0 {
		t.Fatalf("handler ran commands with invalid ids: %+v", handler.calls)
	}
}

func TestPollerBacksOffAfterFailures(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()
	var delays []time.Duration
	ctx, cancel := context.WithCancel(t.Context())
	poller, err := New(Config{
		URL: server.URL, Client: server.Client(), Actions: allActions,
		Sleep: func(_ context.Context, delay time.Duration) bool {
			delays = append(delays, delay)
			if len(delays) == 4 {
				cancel()
				return false
			}
			return true
		},
	}, &fakeHandler{})
	if err != nil {
		t.Fatal(err)
	}
	poller.Run(ctx)
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second}
	for index := range want {
		if delays[index] != want[index] {
			t.Fatalf("backoff delays = %v, want %v", delays, want)
		}
	}
}

func TestNewRejectsNonHTTPSURL(t *testing.T) {
	t.Parallel()

	if _, err := New(Config{URL: "http://manager.example/api/v1/commands", Client: http.DefaultClient}, &fakeHandler{}); err == nil {
		t.Fatal("New accepted an http URL")
	}
}

func TestResultsSurviveARestart(t *testing.T) {
	t.Parallel()

	command := Command{ID: "c1", Action: ActionBlockPeer, Target: "203.0.113.7", DurationSeconds: 60, ExpiresAt: future}
	statePath := filepath.Join(t.TempDir(), "commands.json")
	first := newManager([]Command{command})
	server := httptest.NewTLSServer(first)
	defer server.Close()
	handler := &fakeHandler{detail: "dry-run: nothing was changed"}
	pollOnce(t, newPoller(t, server, handler, allActions, statePath))
	info, err := os.Stat(statePath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", info, err)
	}

	// The manager lost the result and redelivers to a restarted agent.
	first.mu.Lock()
	first.pending = [][]Command{{command}}
	first.results = map[string]Result{}
	first.mu.Unlock()
	pollOnce(t, newPoller(t, server, handler, allActions, statePath))
	if len(handler.calls) != 1 {
		t.Fatalf("handler calls = %d, want the command run once across the restart", len(handler.calls))
	}
	first.mu.Lock()
	defer first.mu.Unlock()
	// A dry run's note survives the restart: it never changed anything.
	if got := first.results["c1"]; got.Status != StatusDone || got.Detail != "dry-run: nothing was changed" {
		t.Fatalf("result = %+v", got)
	}
}

func TestARefusedResultIsNotRetriedForever(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future}})
	mgr.resultStatus = http.StatusBadRequest
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	pollOnce(t, poller)
	if len(poller.unreported) != 0 {
		t.Fatalf("unreported = %d, want a 400 result dropped rather than retried", len(poller.unreported))
	}

	mgr.mu.Lock()
	mgr.resultStatus = http.StatusServiceUnavailable
	mgr.pending = [][]Command{{{ID: "c2", Action: ActionRefreshPolicy, ExpiresAt: future}}}
	mgr.mu.Unlock()
	pollOnce(t, poller)
	if len(poller.unreported) != 1 {
		t.Fatalf("unreported = %d, want a 503 result kept for retry", len(poller.unreported))
	}
}

func TestPollsAreSpacedOutWhenTheServerAnswersAtOnce(t *testing.T) {
	t.Parallel()

	// Every poll returns a command with an invalid id, which does no work.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"commands":[{"id":"../bad","action":"refresh_policy"}]}`))
	}))
	defer server.Close()
	var slept []time.Duration
	ctx, cancel := context.WithCancel(t.Context())
	poller, err := New(Config{
		URL: server.URL, Client: server.Client(), Actions: allActions,
		Sleep: func(_ context.Context, delay time.Duration) bool {
			slept = append(slept, delay)
			if len(slept) == 3 {
				cancel()
				return false
			}
			return true
		},
	}, &fakeHandler{})
	if err != nil {
		t.Fatal(err)
	}
	poller.Run(ctx)
	for _, delay := range slept {
		if delay <= 0 || delay > minPollInterval {
			t.Fatalf("pause = %s, want up to %s between quick polls", delay, minPollInterval)
		}
	}
	if len(slept) != 3 {
		t.Fatalf("pauses = %v, want one per quick poll", slept)
	}
}

func TestACommandIsJournalledBeforeItRuns(t *testing.T) {
	t.Parallel()

	command := Command{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future}
	mgr := newManager([]Command{command})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	// A journal that cannot be written: the path is a directory.
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, allActions, t.TempDir()))
	if len(handler.calls) != 0 {
		t.Fatal("ran a command it could not journal first")
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if got := mgr.results["c1"]; got.Status != StatusRefused {
		t.Fatalf("result = %+v, want refused", got)
	}
}

func TestAFullJournalRefusesRatherThanForgets(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(newManager())
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	for index := range rememberedResults {
		if err := poller.remember(Command{ID: fmt.Sprintf("c%d", index), ExpiresAt: future}, Result{Status: StatusDone}, true); err != nil {
			t.Fatal(err)
		}
	}
	if err := poller.remember(Command{ID: "one-more", ExpiresAt: future}, Result{Status: StatusDone}, true); err == nil {
		t.Fatal("a full journal evicted a result that can still be redelivered")
	}
	if _, kept := poller.results["c0"]; !kept {
		t.Fatal("the oldest live result was evicted")
	}
}

func TestNoCommandStartsAfterShutdownBegins(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future}, {ID: "c2", Action: ActionRefreshPolicy, ExpiresAt: future}})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	ctx, cancel := context.WithCancel(t.Context())
	handler := &cancelOnFirst{cancel: cancel}
	poller := newPoller(t, server, handler, allActions)
	poller.Run(ctx)
	if handler.calls != 1 {
		t.Fatalf("ran %d commands, want the second skipped once shutdown began", handler.calls)
	}
}

type cancelOnFirst struct {
	cancel context.CancelFunc
	calls  int
}

func (c *cancelOnFirst) Apply(string, string, string, time.Duration) (string, error) { return "", nil }
func (c *cancelOnFirst) Lift(string, string, string) error                           { return nil }
func (c *cancelOnFirst) RefreshPolicy() error {
	c.calls++
	c.cancel()
	return nil
}

func TestAJournalledBlockSaysTheRestartEndedIt(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "journal.json")
	command := Command{ID: "c1", Action: ActionBlockPeer, Target: "203.0.113.7", DurationSeconds: 60, ExpiresAt: future}
	mgr := newManager([]Command{command})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	pollOnce(t, newPoller(t, server, &fakeHandler{}, allActions, statePath))
	restarted := newPoller(t, server, &fakeHandler{}, allActions, statePath)
	if got := restarted.results["c1"].Result; got.Status != StatusDone || got.Detail != restartedDetail {
		t.Fatalf("result after restart = %+v, want done with the restart noted", got)
	}
}

func TestFarFutureExpiriesAreRefused(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: time.Unix(1000, 0).Add(48 * time.Hour)}})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, allActions))
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if len(handler.calls) != 0 || mgr.results["c1"].Status != StatusRefused {
		t.Fatalf("calls %v result %+v, want a far-future expiry refused", handler.calls, mgr.results["c1"])
	}
}

func TestAStalledResultEndpointDoesNotDelayLaterCommands(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{
		{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future},
		{ID: "c2", Action: ActionRefreshPolicy, ExpiresAt: future},
	})
	mgr.resultStatus = http.StatusServiceUnavailable
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{}
	poller := newPoller(t, server, handler, allActions)
	commands, err := poller.poll(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var ran []string
	for _, command := range commands {
		if _, ok := poller.handle(command); ok {
			ran = append(ran, command.ID)
		}
	}
	// Both ran without any result being posted in between.
	if len(ran) != 2 || len(handler.calls) != 2 {
		t.Fatalf("ran %v, calls %d", ran, len(handler.calls))
	}
}

func TestAnUnreadableJournalRefusesCommands(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "journal.json")
	if err := os.WriteFile(statePath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	mgr := newManager([]Command{{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future}})
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, allActions, statePath))
	if len(handler.calls) != 0 {
		t.Fatal("ran a command with an unreadable journal")
	}
	if payload, _ := os.ReadFile(statePath); string(payload) != "{not json" { //nolint:gosec // a test temp file
		t.Fatal("the unreadable journal was overwritten")
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if got := mgr.results["c1"]; got.Status != StatusRefused || !strings.Contains(got.Detail, "journal") {
		t.Fatalf("result = %+v", got)
	}
}

func TestAMalformedCommandDoesNotBlockItsNeighbours(t *testing.T) {
	t.Parallel()

	reply := `{"commands":[{"id":"bad","action":"block_peer","duration_seconds":"soon"},` +
		`{"id":"good","action":"refresh_policy","expires_at":"` + future.UTC().Format(time.RFC3339) + `"}]}`
	results := map[string]Result{}
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/result") {
			var result Result
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &result)
			mu.Lock()
			results[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/commands/"), "/result")] = result
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = w.Write([]byte(reply))
	}))
	defer server.Close()
	handler := &fakeHandler{}
	pollOnce(t, newPoller(t, server, handler, allActions))
	mu.Lock()
	defer mu.Unlock()
	if len(handler.calls) != 1 || results["good"].Status != StatusDone || results["bad"].Status != StatusRefused ||
		results["bad"].Detail != "the command could not be read" {
		t.Fatalf("calls %v results %+v", handler.calls, results)
	}
}

func TestResultsNeverFollowARedirect(t *testing.T) {
	t.Parallel()

	gets := 0
	var mu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		mu.Lock()
		gets++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	retry, err := poller.report(t.Context(), "c1", Result{Status: StatusDone})
	if err == nil {
		t.Fatalf("a redirected result counted as reported (retry %t)", retry)
	}
	mu.Lock()
	defer mu.Unlock()
	if gets != 0 {
		t.Fatal("the redirect was followed as a GET")
	}
}

func TestAResultTheManagerKeepsRefusingIsGivenUp(t *testing.T) {
	t.Parallel()

	mgr := newManager([]Command{{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future}})
	mgr.resultStatus = http.StatusInternalServerError
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	pollOnce(t, poller)
	for range maxReportAttempts {
		poller.reportPending(t.Context())
	}
	if len(poller.unreported) != 0 {
		t.Fatalf("unreported = %d after %d attempts, want it given up", len(poller.unreported), maxReportAttempts)
	}
}

func TestAGivenUpResultIsNotRequeuedOnRedelivery(t *testing.T) {
	t.Parallel()

	command := Command{ID: "c1", Action: ActionRefreshPolicy, ExpiresAt: future}
	mgr := newManager([]Command{command})
	mgr.resultStatus = http.StatusInternalServerError
	server := httptest.NewTLSServer(mgr)
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	pollOnce(t, poller)
	for range maxReportAttempts {
		poller.reportPending(t.Context())
	}
	mgr.mu.Lock()
	mgr.pending = [][]Command{{command}}
	mgr.mu.Unlock()
	pollOnce(t, poller)
	if len(poller.unreported) != 0 {
		t.Fatal("a result given up on was queued for retry again")
	}
}

func TestAnExhaustedMarkerCoversOnlyItsResult(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	posts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	refused := Result{Status: StatusRefused, Detail: "journal full"}
	poller.exhausted["c1"] = exhaustedResult{result: refused, since: time.Unix(1000, 0), lastSent: time.Unix(1000, 0), expires: time.Unix(1000, 0).Add(time.Hour)}
	// The same result inside the cooldown is not posted again.
	if !poller.deliver(t.Context(), "c1", refused, time.Time{}, time.Time{}) {
		t.Fatal("an exhausted result inside its cooldown reported a failure")
	}
	mu.Lock()
	if posts != 0 {
		t.Fatalf("posted %d times inside the cooldown", posts)
	}
	mu.Unlock()
	// A different, real result for the command is posted and kept for retry.
	if poller.deliver(t.Context(), "c1", Result{Status: StatusDone}, time.Time{}, time.Time{}) {
		t.Fatal("a failing new result did not report a transient failure")
	}
	if _, queued := poller.unreported["c1"]; !queued {
		t.Fatal("a new result was not queued for retry")
	}
	// Close to expiry, the cooldown does not suppress the last chance.
	poller.exhausted["c2"] = exhaustedResult{result: refused, since: time.Unix(1000, 0), lastSent: time.Unix(1000, 0), expires: time.Unix(1000, 0).Add(time.Minute)}
	poller.deliver(t.Context(), "c2", refused, time.Time{}, time.Time{})
	mu.Lock()
	defer mu.Unlock()
	if posts != 2 {
		t.Fatalf("posts = %d, want the new result and the last-chance repost", posts)
	}
}

func TestTheLastChanceWindowClosesAtExpiry(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	posts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	refused := Result{Status: StatusRefused}
	// Expired already: the cooldown applies again.
	poller.exhausted["c1"] = exhaustedResult{result: refused, since: time.Unix(1000, 0), lastSent: time.Unix(1000, 0), expires: time.Unix(900, 0)}
	for range 3 {
		poller.deliver(t.Context(), "c1", refused, time.Time{}, time.Time{})
	}
	mu.Lock()
	defer mu.Unlock()
	if posts != 0 {
		t.Fatalf("posted %d times after expiry inside the cooldown", posts)
	}
}

func TestTheLastChanceUsesWhenTheRedeliveryArrived(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	posts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	refused := Result{Status: StatusRefused}
	// The test clock (1000) is past the deadline, but the redelivery arrived before it.
	poller.exhausted["c1"] = exhaustedResult{result: refused, since: time.Unix(990, 0), lastSent: time.Unix(990, 0), expires: time.Unix(995, 0)}
	poller.deliver(t.Context(), "c1", refused, time.Unix(995, 0), time.Unix(994, 0))
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Fatalf("posts = %d, want the final redelivery answered", posts)
	}
}

func TestAMalformedCommandKeepsAValidDeadline(t *testing.T) {
	t.Parallel()

	expires := future.UTC().Format(time.RFC3339)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"commands":[{"id":"bad","duration_seconds":"soon","expires_at":"` + expires + `"}]}`))
	}))
	defer server.Close()
	commands, err := newPoller(t, server, &fakeHandler{}, allActions).poll(t.Context())
	if err != nil || len(commands) != 1 || !commands[0].deliverBy().Equal(future) || !commands[0].ExpiresAt.IsZero() {
		t.Fatalf("commands = %+v, %v; want the malformed one with its deadline kept for delivery only", commands, err)
	}
}

func TestTheFinalWindowCountsAtReceiptOrAtPosting(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	posts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		posts++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	poller := newPoller(t, server, &fakeHandler{}, allActions)
	refused := Result{Status: StatusRefused}
	// Received just outside the window, posted (test clock 1000) inside it.
	expires := time.Unix(1000, 0).Add(exhaustedCooldown - time.Second)
	poller.exhausted["c1"] = exhaustedResult{result: refused, since: time.Unix(990, 0), lastSent: time.Unix(990, 0), expires: expires}
	poller.deliver(t.Context(), "c1", refused, expires, expires.Add(-exhaustedCooldown-time.Second))
	mu.Lock()
	defer mu.Unlock()
	if posts != 1 {
		t.Fatalf("posts = %d, want the post inside the final window sent", posts)
	}
}
