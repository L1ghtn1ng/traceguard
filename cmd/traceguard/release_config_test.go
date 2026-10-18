package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestPackagedEnvironmentFileIsRootOnly(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../.goreleaser.yaml")
	if err != nil {
		t.Fatalf("read GoReleaser config: %v", err)
	}
	var config struct {
		NFPMs []struct {
			Contents []struct {
				Dst      string `yaml:"dst"`
				FileInfo struct {
					Mode  uint32 `yaml:"mode"`
					Owner string `yaml:"owner"`
					Group string `yaml:"group"`
				} `yaml:"file_info"`
			} `yaml:"contents"`
		} `yaml:"nfpms"`
	}
	if err := yaml.Unmarshal(raw, &config); err != nil {
		t.Fatalf("parse GoReleaser config: %v", err)
	}
	if len(config.NFPMs) == 0 {
		t.Fatal("GoReleaser config has no nfpms packages")
	}
	for _, pkg := range config.NFPMs {
		found := false
		for _, content := range pkg.Contents {
			if content.Dst != "/etc/traceguard/traceguard.env" {
				continue
			}
			found = true
			info := content.FileInfo
			if info.Mode != 0o600 || info.Owner != "root" || info.Group != "root" {
				t.Fatalf("traceguard.env file_info = %04o %s:%s, want 0600 root:root", info.Mode, info.Owner, info.Group)
			}
		}
		if !found {
			t.Fatal("package does not install /etc/traceguard/traceguard.env")
		}
	}
}

func TestReleaseWorkflowPinsGoReleaserVersion(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]string `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &workflow); err != nil {
		t.Fatalf("parse release workflow: %v", err)
	}
	exactVersion := regexp.MustCompile(`^v\d+\.\d+\.\d+$`)
	found := false
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "goreleaser/goreleaser-action@") {
				continue
			}
			found = true
			if version := step.With["version"]; !exactVersion.MatchString(version) {
				t.Fatalf("goreleaser-action version = %q, want an exact vX.Y.Z release", version)
			}
		}
	}
	if !found {
		t.Fatal("release workflow does not run goreleaser-action")
	}
}
