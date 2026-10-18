package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolveAuthorizationFile validates the -<name>-file option and expands a
// leading $CREDENTIALS_DIRECTORY, which systemd sets for LoadCredential= but
// does not substitute inside EnvironmentFile= values.
func resolveAuthorizationFile(name, value string, path *string) error {
	if *path == "" {
		return nil
	}
	if strings.TrimSpace(value) != "" {
		return fmt.Errorf("%s and %s-file must not both be set", name, name)
	}
	for _, prefix := range []string{"${CREDENTIALS_DIRECTORY}", "$CREDENTIALS_DIRECTORY"} {
		rest, found := strings.CutPrefix(*path, prefix)
		if !found {
			continue
		}
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if dir == "" {
			return fmt.Errorf("%s-file references $CREDENTIALS_DIRECTORY, which is not set; configure LoadCredential= for the service", name)
		}
		*path = dir + rest
		break
	}
	if !filepath.IsAbs(*path) {
		return fmt.Errorf("%s-file must be an absolute path", name)
	}
	*path = filepath.Clean(*path)
	return nil
}
