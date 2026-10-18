package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const signedPolicy = "version: 1\ndns:\n  block: [signed.example]\n"

func writeSigningKey(t *testing.T, public any) string {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "policy.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newSigningKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return private, writeSigningKey(t, public)
}

func sign(private ed25519.PrivateKey, payload string) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(private, []byte(payload))) + "\n"
}

func newSignedManager(t *testing.T, keyPath, cachePath string, serve func(path string) *http.Response) *Manager {
	t.Helper()
	manager, err := NewManager(Config{URL: "https://policy.example/v1?tenant=a", CachePath: cachePath, SigningKeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}
	manager.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.RawQuery != "tenant=a" {
			t.Errorf("request %s lost the policy URL query", request.URL)
		}
		return serve(request.URL.Path), nil
	})
	return manager
}

func TestManagerAcceptsSignedRemotePolicyAndCachesSignature(t *testing.T) {
	t.Parallel()
	private, keyPath := newSigningKey(t)
	cachePath := filepath.Join(t.TempDir(), "policy.yaml")
	manager := newSignedManager(t, keyPath, cachePath, func(path string) *http.Response {
		if path == "/v1.sig" {
			return response(http.StatusOK, sign(private, signedPolicy), nil)
		}
		return response(http.StatusOK, signedPolicy, nil)
	})

	bundle, _, err := manager.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got := bundle.DNS.BlockDomains; len(got) != 1 || got[0] != "signed.example" {
		t.Fatalf("block domains = %v, want signed policy", got)
	}
	signature, err := os.ReadFile(cachePath + SignatureSuffix) //nolint:gosec // path is rooted in t.TempDir
	if err != nil {
		t.Fatalf("cached signature missing: %v", err)
	}
	if string(signature) != sign(private, signedPolicy) {
		t.Fatalf("cached signature = %q, want fetched signature", signature)
	}
}

func TestManagerRejectsUnsignedOrForgedRemotePolicy(t *testing.T) {
	t.Parallel()
	private, keyPath := newSigningKey(t)
	otherPrivate, _ := newSigningKey(t)
	tests := map[string]struct {
		status    int
		signature string
		want      string
	}{
		"missing signature": {http.StatusNotFound, "", "unexpected HTTP status"},
		"other key":         {http.StatusOK, sign(otherPrivate, signedPolicy), "does not verify"},
		"other payload":     {http.StatusOK, sign(private, "version: 1\n"), "does not verify"},
		"not base64":        {http.StatusOK, "not a signature", "decode policy signature"},
		"truncated":         {http.StatusOK, base64.StdEncoding.EncodeToString([]byte("short")), "want 64"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cachePath := filepath.Join(t.TempDir(), "policy.yaml")
			manager := newSignedManager(t, keyPath, cachePath, func(path string) *http.Response {
				if path == "/v1.sig" {
					return response(test.status, test.signature, nil)
				}
				return response(http.StatusOK, signedPolicy, nil)
			})
			_, _, err := manager.Load(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Load() error = %v, want %q", err, test.want)
			}
			if _, statErr := os.Stat(cachePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("rejected policy was cached: %v", statErr)
			}
		})
	}
}

func TestManagerVerifiesStaleCacheSignature(t *testing.T) {
	t.Parallel()
	private, keyPath := newSigningKey(t)
	offline := func(string) *http.Response { return response(http.StatusServiceUnavailable, "", nil) }

	valid := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(valid, []byte(signedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(valid+SignatureSuffix, []byte(sign(private, signedPolicy)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, metadata, err := newSignedManager(t, keyPath, valid, offline).Load(context.Background()); err != nil || metadata.RemoteSource != LoadSourceCache {
		t.Fatalf("signed stale cache: source %q error %v, want cache", metadata.RemoteSource, err)
	}

	tampered := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(tampered, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tampered+SignatureSuffix, []byte(sign(private, signedPolicy)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newSignedManager(t, keyPath, tampered, offline).Load(context.Background()); err == nil || !strings.Contains(err.Error(), "verify policy cache") {
		t.Fatalf("tampered cache error = %v, want signature rejection", err)
	}

	unsigned := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(unsigned, []byte(signedPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := newSignedManager(t, keyPath, unsigned, offline).Load(context.Background()); err == nil || !strings.Contains(err.Error(), "cache signature") {
		t.Fatalf("unsigned cache error = %v, want missing signature rejection", err)
	}
}

func TestLoadSigningKeyRejectsNonEd25519Keys(t *testing.T) {
	t.Parallel()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigningKey(writeSigningKey(t, &rsaKey.PublicKey)); err == nil || !strings.Contains(err.Error(), "want Ed25519") {
		t.Fatalf("RSA key error = %v, want Ed25519 requirement", err)
	}
	notPEM := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(notPEM, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSigningKey(notPEM); err == nil || !strings.Contains(err.Error(), "PEM PUBLIC KEY") {
		t.Fatalf("non-PEM key error = %v, want PEM requirement", err)
	}
	if _, err := NewManager(Config{SigningKeyPath: notPEM}); err == nil || !strings.Contains(err.Error(), "requires a policy url") {
		t.Fatalf("signing key without URL error = %v", err)
	}
}

func TestSignatureURLAppendsSuffixToPathOnly(t *testing.T) {
	t.Parallel()
	got, err := signatureURL("https://policy.example/v1/traceguard.yaml?tenant=a")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://policy.example/v1/traceguard.yaml.sig?tenant=a"; got != want {
		t.Fatalf("signatureURL = %q, want %q", got, want)
	}
}
