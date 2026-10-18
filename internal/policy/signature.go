package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
)

const (
	// SignatureSuffix is appended to the remote policy URL path and the cache
	// path to locate the detached signature.
	SignatureSuffix    = ".sig"
	maxSigningKeyBytes = 16 << 10
	maxSignatureBytes  = 1 << 10
)

var errSignatureInvalid = errors.New("policy signature does not verify with the configured signing key")

// loadSigningKey reads a PEM "PUBLIC KEY" block holding an Ed25519 key.
func loadSigningKey(path string) (ed25519.PublicKey, error) {
	payload, err := safefile.ReadFile(path, maxSigningKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("read policy signing key: %w", err)
	}
	block, _ := pem.Decode(payload)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("policy signing key must be a PEM PUBLIC KEY block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse policy signing key: %w", err)
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("policy signing key is %T, want Ed25519", parsed)
	}
	return key, nil
}

// verifySignature checks a base64 Ed25519 signature over the exact payload
// bytes, as produced by `openssl pkeyutl -sign -rawin | base64`.
func verifySignature(key ed25519.PublicKey, payload, encoded []byte) error {
	signature, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil {
		return fmt.Errorf("decode policy signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("policy signature is %d bytes, want %d", len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(key, payload, signature) {
		return errSignatureInvalid
	}
	return nil
}

func signatureURL(policyURL string) (string, error) {
	parsed, err := url.Parse(policyURL)
	if err != nil {
		return "", errors.New("policy url is not valid")
	}
	// Extend the escaped form too, so separators encoded as %2F stay encoded.
	parsed.Path += SignatureSuffix
	if parsed.RawPath != "" {
		parsed.RawPath += SignatureSuffix
	}
	return parsed.String(), nil
}
