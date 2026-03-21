package version

import (
	"fmt"
	"runtime/debug"
)

const Program = "1.0.2"

func String() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return fmt.Sprintf("traceguard %s (commit=unknown)", Program)
	}

	revision := setting(info, "vcs.revision", "unknown")
	if len(revision) > 12 {
		revision = revision[:12]
	}

	return fmt.Sprintf("traceguard %s (commit=%s)", Program, revision)
}

func setting(info *debug.BuildInfo, key, fallback string) string {
	for _, value := range info.Settings {
		if value.Key == key {
			return value.Value
		}
	}
	return fallback
}
