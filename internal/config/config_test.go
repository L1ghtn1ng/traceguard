package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestParseWildcardPolicyViaFlag(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "*"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !slices.Contains(cfg.ManualDomains, "*") {
		t.Fatalf("ManualDomains = %v, want wildcard deny-all marker", cfg.ManualDomains)
	}
}

func TestParseWildcardPolicyViaEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "*")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !slices.Contains(cfg.ManualDomains, "*") {
		t.Fatalf("ManualDomains = %v, want wildcard deny-all marker", cfg.ManualDomains)
	}
}

func TestParseRejectsUnexpectedPositionalArgs(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "README.md", "LICENSE"}

	clearPolicyEnv(t)

	_, err := Parse()
	if err == nil {
		t.Fatal("Parse succeeded with unexpected positional arguments")
	}
	if !strings.Contains(err.Error(), "quote '*'") || strings.Contains(err.Error(), "-block-all") {
		t.Fatalf("Parse error = %q, want wildcard-only shell-quoting guidance", err)
	}
}

func TestParseRejectsRemovedBlockAllFlag(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block-all"}

	clearPolicyEnv(t)

	_, err := Parse()
	if err == nil {
		t.Fatal("Parse accepted removed -block-all flag")
	}
	if !strings.Contains(err.Error(), "flag provided but not defined") || !strings.Contains(err.Error(), "-block-all") {
		t.Fatalf("Parse error = %q, want unknown flag for -block-all", err)
	}
}

func TestParseIgnoresRemovedBlockAllEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_ALL", "true")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	_, err := Parse()
	if err == nil || !strings.Contains(err.Error(), "require at least one policy source") {
		t.Fatalf("Parse error = %v, want missing policy source after ignoring TRACEGUARD_BLOCK_ALL", err)
	}
}

func TestParseDefaultsLogFormatToJSON(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)
	if err := os.Unsetenv("TRACEGUARD_LOG_FORMAT"); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.LogFormat != "json" {
		t.Fatalf("LogFormat = %q, want json", cfg.LogFormat)
	}
}

func TestParseLoadsDomainFileFromEnv(t *testing.T) {
	path := writeDomainFile(t, "example.com\n# comment\nbad.example.org,one.one.one.one\n")

	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "@"+path)
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	want := []string{"example.com", "bad.example.org", "one.one.one.one"}
	if !slices.Equal(cfg.ManualDomains, want) {
		t.Fatalf("ManualDomains = %v, want %v", cfg.ManualDomains, want)
	}
}

func TestParseLoadsDomainFileFromFlag(t *testing.T) {
	path := writeDomainFile(t, "example.com\nbad.example.org\n")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "@" + path, "-allow-domain", "resolver.example.com"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !slices.Equal(cfg.ManualDomains, []string{"example.com", "bad.example.org"}) {
		t.Fatalf("ManualDomains = %v, want file-loaded entries", cfg.ManualDomains)
	}
	if !slices.Equal(cfg.ManualAllow, []string{"resolver.example.com"}) {
		t.Fatalf("ManualAllow = %v, want inline allow entry", cfg.ManualAllow)
	}
}

func TestParseMergesInlineAndFileBackedInputs(t *testing.T) {
	path := writeDomainFile(t, "example.com\nbad.example.org\n")

	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "resolver.example.com")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block-domain", "@" + path, "-block-domain", "*.svc.cluster.local", "-allow-domain", "@" + path}

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !slices.Equal(cfg.ManualDomains, []string{"example.com", "bad.example.org", "*.svc.cluster.local"}) {
		t.Fatalf("ManualDomains = %v, want merged inline and file-backed block entries", cfg.ManualDomains)
	}
	if !slices.Equal(cfg.ManualAllow, []string{"resolver.example.com", "example.com", "bad.example.org"}) {
		t.Fatalf("ManualAllow = %v, want merged env and file-backed allow entries", cfg.ManualAllow)
	}
}

func TestParseRejectsRelativeDomainFileFromEnv(t *testing.T) {
	t.Setenv("TRACEGUARD_BLOCK", "true")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "@relative.txt")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	_, err := Parse()
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("Parse error = %v, want absolute path validation", err)
	}
}

func TestParseRejectsRelativeDomainFileFromFlag(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard", "-block", "-block-domain", "@relative.txt"}

	clearPolicyEnv(t)

	_, err := Parse()
	if err == nil || !strings.Contains(err.Error(), "must be absolute") {
		t.Fatalf("Parse error = %v, want absolute path validation", err)
	}
}

func TestParseUsesTraceguardKubernetesNodeNameOnly(t *testing.T) {
	t.Setenv("TRACEGUARD_KUBERNETES_NODE_NAME", "worker-a")
	t.Setenv("KUBE_NODE_NAME", "worker-b")
	t.Setenv("NODE_NAME", "worker-c")

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.KubernetesNodeName != "worker-a" {
		t.Fatalf("KubernetesNodeName = %q, want worker-a", cfg.KubernetesNodeName)
	}
}

func TestParseIgnoresLegacyKubernetesNodeAliases(t *testing.T) {
	t.Setenv("KUBE_NODE_NAME", "worker-b")
	t.Setenv("NODE_NAME", "worker-c")
	if err := os.Unsetenv("TRACEGUARD_KUBERNETES_NODE_NAME"); err != nil {
		t.Fatalf("Unsetenv returned error: %v", err)
	}

	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })
	os.Args = []string{"traceguard"}

	clearPolicyEnv(t)

	cfg, err := Parse()
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if cfg.KubernetesNodeName != "" {
		t.Fatalf("KubernetesNodeName = %q, want empty when only legacy aliases are set", cfg.KubernetesNodeName)
	}
}

func clearPolicyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TRACEGUARD_BLOCK", "")
	t.Setenv("TRACEGUARD_DRY_RUN", "")
	t.Setenv("TRACEGUARD_BLOCK_ALL", "")
	t.Setenv("TRACEGUARD_BLOCKLIST_URL", "")
	t.Setenv("TRACEGUARD_BLOCK_DOMAINS", "")
	t.Setenv("TRACEGUARD_ALLOW_DOMAINS", "")
}

func writeDomainFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "domains.txt")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	return path
}
