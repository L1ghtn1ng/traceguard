package config

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestParseCommandAndExportEventSettings(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	clearPolicyEnv(t)
	os.Args = []string{
		"traceguard",
		"-event-export-url", "https://manager.example/api/v1/events",
		"-event-export-events", "Alerts",
		// An explicit :443 is the same origin as the export URL's default port.
		"-command-url", "https://manager.example:443/api/v1/commands",
		"-command-actions", "lift_response, refresh_policy,lift_response",
	}
	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.EventExportEvents != "alerts" || cfg.CommandURL != "https://manager.example:443/api/v1/commands" {
		t.Fatalf("export events %q command url %q", cfg.EventExportEvents, cfg.CommandURL)
	}
	if want := []string{"lift_response", "refresh_policy"}; !reflect.DeepEqual(cfg.CommandActions, want) {
		t.Fatalf("command actions = %v, want %v", cfg.CommandActions, want)
	}
}

func TestParseCommandDefaults(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	clearPolicyEnv(t)
	os.Args = []string{"traceguard"}
	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if cfg.CommandURL != "" || cfg.EventExportEvents != "all" || !reflect.DeepEqual(cfg.CommandActions, DefaultCommandActions) {
		t.Fatalf("defaults: command url %q export events %q actions %v", cfg.CommandURL, cfg.EventExportEvents, cfg.CommandActions)
	}
}

func TestParseRejectsBadCommandSettings(t *testing.T) {
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"no export":   {[]string{"-command-url", "https://manager.example/api/v1/commands"}, "requires event-export-url"},
		"plain http":  {[]string{"-event-export-url", "https://manager.example/e", "-command-url", "http://manager.example/c"}, "https://"},
		"other host":  {[]string{"-event-export-url", "https://manager.example/e", "-command-url", "https://evil.example/c"}, "same host"},
		"other port":  {[]string{"-event-export-url", "https://manager.example/e", "-command-url", "https://manager.example:8443/c"}, "same host"},
		"query":       {[]string{"-event-export-url", "https://manager.example/e", "-command-url", "https://manager.example/c?token=x"}, "query"},
		"no journal":  {[]string{"-event-export-url", "https://manager.example/e", "-command-url", "https://manager.example/c", "-response-state-path", ""}, "response-state-path"},
		"empty query": {[]string{"-event-export-url", "https://manager.example/e", "-command-url", "https://manager.example/c?"}, "query"},
		"action":      {[]string{"-command-actions", "block_peer,run_shell"}, "unknown action"},
		"events":      {[]string{"-event-export-events", "some"}, "all or alerts"},
	} {
		t.Run(name, func(t *testing.T) {
			originalArgs := os.Args
			t.Cleanup(func() { os.Args = originalArgs })
			clearPolicyEnv(t)
			os.Args = append([]string{"traceguard"}, test.args...)
			_, err := Parse()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want %q", err, test.want)
			}
		})
	}
}
