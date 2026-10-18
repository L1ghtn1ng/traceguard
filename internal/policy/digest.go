package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// EmptyBundle returns the effective policy without any source, normalized as
// Merge normalizes a loaded document, so running without a policy reports the
// same digest as an empty policy file.
func EmptyBundle() (Bundle, error) {
	return Merge(Document{Version: Version}, Document{Version: Version})
}

// Digest returns the hex SHA-256 of the bundle's JSON encoding. It identifies
// the effective merged policy, so hosts running the same rules report the same
// digest whatever the source documents' formatting or overlay split.
func (b Bundle) Digest() (string, error) {
	encoded, err := json.Marshal(b) //nolint:musttag // the encoding is only hashed, never decoded, so Go field names are stable keys
	if err != nil {
		return "", fmt.Errorf("encode policy bundle: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
