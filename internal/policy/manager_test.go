package policy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestManagerRemoteBaseLocalOverlayAndConditionalFetch(t *testing.T) {
	t.Parallel()
	temp := t.TempDir()
	localPath := filepath.Join(temp, "local.yaml")
	cachePath := filepath.Join(temp, "cache.yaml")
	if err := os.WriteFile(localPath, []byte("version: 1\ndns:\n  block: [local.example]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{
		Path:      localPath,
		URL:       "https://policy.example/v1",
		CachePath: cachePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	manager.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if got, want := request.Header.Get("Authorization"), "Bearer secret"; got != want {
			t.Fatalf("authorization = %q, want %q", got, want)
		}
		if requests == 2 {
			if got, want := request.Header.Get("If-None-Match"), `"v1"`; got != want {
				t.Fatalf("If-None-Match = %q, want %q", got, want)
			}
			return response(http.StatusNotModified, "", nil), nil
		}
		return response(http.StatusOK, "version: 1\ndns:\n  block: [remote.example]\n", map[string]string{"ETag": `"v1"`}), nil
	})
	manager.cfg.Authorization = "Bearer secret"

	bundle, metadata, err := manager.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if metadata.RemoteSource != LoadSourceRemote {
		t.Fatalf("source = %q, want %q", metadata.RemoteSource, LoadSourceRemote)
	}
	if got, want := len(bundle.DNS.BlockDomains), 2; got != want {
		t.Fatalf("block domain count = %d, want %d", got, want)
	}
	info, err := os.Stat(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("cache mode = %#o, want 0600", got)
	}

	_, metadata, err = manager.Load(context.Background())
	if err != nil {
		t.Fatalf("second Load() error = %v", err)
	}
	if metadata.RemoteSource != LoadSourceNotChanged {
		t.Fatalf("second source = %q, want %q", metadata.RemoteSource, LoadSourceNotChanged)
	}
}

func TestManagerUsesValidatedStaleCache(t *testing.T) {
	t.Parallel()
	cachePath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(cachePath, []byte("version: 1\ndns:\n  block: [cached.example]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{
		URL:       "https://policy.example/v1",
		CachePath: cachePath,
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	bundle, metadata, err := manager.Load(context.Background())
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if metadata.RemoteSource != LoadSourceCache {
		t.Fatalf("source = %q, want %q", metadata.RemoteSource, LoadSourceCache)
	}
	if !metadata.StaleFallback || metadata.RemoteError == "" {
		t.Fatalf("metadata = %+v, want stale fallback details", metadata)
	}
	if got, want := bundle.DNS.BlockDomains[0], "cached.example"; got != want {
		t.Fatalf("domain = %q, want %q", got, want)
	}
}

func response(status int, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     header,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}
