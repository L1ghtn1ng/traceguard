package config

import (
	"os"
	"strings"
	"testing"
)

func clearAuthorizationEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"TRACEGUARD_POLICY_AUTHORIZATION",
		"TRACEGUARD_POLICY_AUTHORIZATION_FILE",
		"TRACEGUARD_EVENT_EXPORT_AUTHORIZATION",
		"TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE",
		"CREDENTIALS_DIRECTORY",
	} {
		t.Setenv(key, "")
	}
}

func TestParseAuthorizationFilesFromFlagsAndEnv(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	clearPolicyEnv(t)
	clearAuthorizationEnv(t)
	t.Setenv("TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE", "/etc/traceguard/export-authorization")
	os.Args = []string{
		"traceguard",
		"-policy-url", "https://policy.example/v1",
		"-policy-authorization-file", "/etc/traceguard//policy-authorization",
		"-event-export-url", "https://collector.example/traceguard",
	}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got, want := cfg.PolicyAuthorizationFile, "/etc/traceguard/policy-authorization"; got != want {
		t.Fatalf("PolicyAuthorizationFile = %q, want %q", got, want)
	}
	if got, want := cfg.EventExportAuthorizationFile, "/etc/traceguard/export-authorization"; got != want {
		t.Fatalf("EventExportAuthorizationFile = %q, want %q", got, want)
	}
	if cfg.PolicyAuthorization != "" || cfg.EventExportAuthorization != "" {
		t.Fatalf("authorization values = %q, %q, want empty", cfg.PolicyAuthorization, cfg.EventExportAuthorization)
	}
}

func TestParseExpandsCredentialsDirectory(t *testing.T) {
	for _, value := range []string{
		"${CREDENTIALS_DIRECTORY}/policy-authorization",
		"$CREDENTIALS_DIRECTORY/policy-authorization",
	} {
		t.Run(value, func(t *testing.T) {
			originalArgs := os.Args
			t.Cleanup(func() { os.Args = originalArgs })
			clearPolicyEnv(t)
			clearAuthorizationEnv(t)
			t.Setenv("CREDENTIALS_DIRECTORY", "/run/credentials/traceguard.service")
			t.Setenv("TRACEGUARD_POLICY_AUTHORIZATION_FILE", value)
			os.Args = []string{"traceguard"}

			cfg, err := Parse()
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got, want := cfg.PolicyAuthorizationFile, "/run/credentials/traceguard.service/policy-authorization"; got != want {
				t.Fatalf("PolicyAuthorizationFile = %q, want %q", got, want)
			}
		})
	}
}

func TestParseRejectsInvalidAuthorizationFiles(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{
			name: "policy value and file",
			env:  map[string]string{"TRACEGUARD_POLICY_AUTHORIZATION": "Bearer env"},
			args: []string{"-policy-authorization-file", "/etc/traceguard/policy-authorization"},
			want: "policy-authorization and policy-authorization-file must not both be set",
		},
		{
			name: "policy flag value and env file",
			env:  map[string]string{"TRACEGUARD_POLICY_AUTHORIZATION_FILE": "/etc/traceguard/policy-authorization"},
			args: []string{"-policy-authorization", "Bearer flag"},
			want: "policy-authorization and policy-authorization-file must not both be set",
		},
		{
			name: "export value and file",
			env: map[string]string{
				"TRACEGUARD_EVENT_EXPORT_AUTHORIZATION":      "Bearer env",
				"TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE": "/etc/traceguard/export-authorization",
			},
			want: "event-export-authorization and event-export-authorization-file must not both be set",
		},
		{
			name: "relative policy file",
			args: []string{"-policy-authorization-file", "policy-authorization"},
			want: "policy-authorization-file must be an absolute path",
		},
		{
			name: "relative export file",
			args: []string{"-event-export-authorization-file", "./export-authorization"},
			want: "event-export-authorization-file must be an absolute path",
		},
		{
			name: "credentials directory unset",
			env:  map[string]string{"TRACEGUARD_EVENT_EXPORT_AUTHORIZATION_FILE": "${CREDENTIALS_DIRECTORY}/export-authorization"},
			want: "CREDENTIALS_DIRECTORY, which is not set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalArgs := os.Args
			t.Cleanup(func() { os.Args = originalArgs })
			clearPolicyEnv(t)
			clearAuthorizationEnv(t)
			for key, value := range tt.env {
				t.Setenv(key, value)
			}
			os.Args = append([]string{"traceguard"}, tt.args...)

			_, err := Parse()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %v, want %q", err, tt.want)
			}
			if err != nil && strings.Contains(err.Error(), "Bearer") {
				t.Fatalf("Parse() error %q exposes the authorization value", err)
			}
		})
	}
}
