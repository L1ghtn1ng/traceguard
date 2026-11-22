package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/response"
	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestHeartbeatReportsAgentAndExportStatus(t *testing.T) {
	t.Parallel()

	status := newTestHeartbeatStatus(t, nil)
	status.version = "1.9.0"
	status.kernelRelease = "6.12.1"
	status.osName = "Debian GNU/Linux 13"
	status.responseMode = "enforce"
	status.commands = true
	status.remoteDigest = func() string { return "feed" }
	status.export = func() telemetry.EventExportStatus {
		return telemetry.EventExportStatus{Dropped: 5, DroppedPriority: 2, Rejected: 1, SpoolFiles: 3, QueueDepth: 7}
	}
	until := time.Unix(2000, 0)
	status.responses = func(limit int) []response.ActiveAction {
		actions := make([]response.ActiveAction, 0, limit)
		for range limit + 5 {
			actions = append(actions, response.ActiveAction{Action: "block_peer", Target: "203.0.113.9", Until: until, Applied: true})
		}
		return actions[:limit]
	}
	fields := status.fields(time.Unix(1090, 0))
	for name, want := range map[string]any{
		"agent_version": "1.9.0", "kernel_release": "6.12.1", "os_name": "Debian GNU/Linux 13",
		"response_mode": "enforce", "commands_enabled": true, "policy_remote_sha256": "feed",
		"export_dropped_records": int64(7), "export_dropped_alerts": int64(2), "export_rejected_batches": int64(1),
		"export_spool_batches": int64(3), "export_queue_depth": int64(7), "active_responses_truncated": true,
	} {
		if fields[name] != want {
			t.Errorf("%s = %#v, want %#v", name, fields[name], want)
		}
	}
	listed, ok := fields["active_responses"].([]any)
	if !ok || len(listed) != maxHeartbeatResponses {
		t.Fatalf("active_responses = %#v, want %d entries", fields["active_responses"], maxHeartbeatResponses)
	}
	first, ok := listed[0].(map[string]any)
	if !ok || first["target"] != "203.0.113.9" || first["until"] != "1970-01-01T00:33:20Z" || first["manual"] != false {
		t.Fatalf("first active response = %#v", first)
	}
}

func TestOSPrettyName(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "os-release")
	if err := os.WriteFile(path, []byte("NAME=Debian\nPRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nID=debian\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := osPrettyName(path); got != "Debian GNU/Linux 13 (trixie)" {
		t.Fatalf("osPrettyName = %q", got)
	}
	if got := osPrettyName(filepath.Join(t.TempDir(), "missing")); got != "" {
		t.Fatalf("osPrettyName of a missing file = %q", got)
	}
}

func TestHeartbeatActiveResponsesSurviveTheRecorder(t *testing.T) {
	t.Parallel()

	recorder, output := newTestRecorder(t)
	status := newTestHeartbeatStatus(t, nil)
	status.responses = func(int) []response.ActiveAction {
		return []response.ActiveAction{{Action: "block_peer", Target: "203.0.113.9", Until: time.Unix(2000, 0), Applied: true}}
	}
	recorder.Info("heartbeat", status.fields(time.Unix(1090, 0)))
	if !strings.Contains(output.String(), `"active_responses":[{"action":"block_peer","applied":true,"manual":false,"target":"203.0.113.9","until":"1970-01-01T00:33:20Z"}]`) {
		t.Fatalf("recorded heartbeat lost its active responses: %s", output.String())
	}
}
