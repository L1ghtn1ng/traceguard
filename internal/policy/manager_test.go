package policy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestManagerDoesNotRollBackActivePolicyToStaleCache(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "policy.yaml")
	manager, err := NewManager(Config{URL: "https://policy.example/v1", CachePath: cachePath})
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	manager.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return response(http.StatusOK, "version: 1\ndns:\n  block: [current.example]\n", nil), nil
		}
		return nil, errors.New("offline")
	})
	if _, _, err := manager.Load(context.Background()); err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	if err := os.WriteFile(cachePath, []byte("version: 1\ndns:\n  block: [stale.example]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, metadata, err := manager.Load(context.Background())
	if err != nil {
		t.Fatalf("refresh Load() error = %v", err)
	}
	if metadata.RemoteSource != LoadSourceLastKnown || !metadata.StaleFallback || metadata.RemoteError == "" {
		t.Fatalf("refresh metadata = %+v, want last known remote base", metadata)
	}
	if got := bundle.DNS.BlockDomains; len(got) != 1 || got[0] != "current.example" {
		t.Fatalf("block domains = %v, want active remote policy without cache rollback", got)
	}
}

func TestManagerAppliesLocalOverlayDuringRemoteOutage(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	localPath := filepath.Join(dir, "local.yaml")
	if err := os.WriteFile(localPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := NewManager(Config{URL: "https://policy.example/v1", CachePath: filepath.Join(dir, "cache.yaml"), Path: localPath})
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	manager.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return response(http.StatusOK, "version: 1\ndns:\n  block: [remote.example]\n", nil), nil
		}
		return nil, errors.New("offline")
	})
	if _, _, err := manager.Load(context.Background()); err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	if err := os.WriteFile(localPath, []byte("version: 1\ndns:\n  allow: [urgent.example]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, _, err := manager.Load(context.Background())
	if err != nil {
		t.Fatalf("reload during outage error = %v", err)
	}
	if !slices.Contains(bundle.DNS.BlockDomains, "remote.example") || !slices.Contains(bundle.DNS.AllowDomains, "urgent.example") {
		t.Fatalf("bundle DNS = %+v, want remote base plus new local overlay", bundle.DNS)
	}
}

func TestManagerCommitsRemoteStateOnlyAfterValidation(t *testing.T) {
	t.Parallel()

	cachePath := filepath.Join(t.TempDir(), "policy.yaml")
	reject := errors.New("rejected by mode")
	manager, err := NewManager(Config{
		URL: "https://policy.example/v1", CachePath: cachePath,
		Validate: func(bundle Bundle) error {
			if slices.Contains(bundle.DNS.BlockDomains, "bad.example") {
				return reject
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var lastIfNoneMatch string
	requests := 0
	manager.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		lastIfNoneMatch = request.Header.Get("If-None-Match")
		body := "version: 1\ndns:\n  block: [good.example]\n"
		etag := `"good"`
		if requests == 2 {
			body, etag = "version: 1\ndns:\n  block: [bad.example]\n", `"bad"`
		}
		resp := response(http.StatusOK, body, nil)
		resp.Header.Set("ETag", etag)
		return resp, nil
	})
	if _, _, err := manager.Load(context.Background()); err != nil {
		t.Fatalf("initial Load() error = %v", err)
	}
	if _, _, err := manager.Load(context.Background()); !errors.Is(err, reject) {
		t.Fatalf("invalid refresh error = %v, want validator error", err)
	}
	cached, err := os.ReadFile(cachePath) //nolint:gosec // test-owned temporary path
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cached), "good.example") {
		t.Fatalf("cache = %q, want last valid remote document", cached)
	}
	if _, _, err := manager.Load(context.Background()); err != nil {
		t.Fatalf("third Load() error = %v", err)
	}
	if lastIfNoneMatch != `"good"` {
		t.Fatalf("If-None-Match = %q, want ETag of the last valid document", lastIfNoneMatch)
	}
}

func TestManagerRequestErrorsDoNotExposeURLQuery(t *testing.T) {
	t.Parallel()

	manager, err := NewManager(Config{
		URL:       "https://policy.example/v1?token=query-secret",
		CachePath: filepath.Join(t.TempDir(), "missing.yaml"),
	})
	if err != nil {
		t.Fatal(err)
	}
	manager.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, &url.Error{Op: "Get", URL: request.URL.String(), Err: errors.New("query-secret transport failure")}
	})
	_, _, loadErr := manager.Load(context.Background())
	if loadErr == nil {
		t.Fatal("Load() returned nil error")
	}
	if strings.Contains(loadErr.Error(), "query-secret") {
		t.Fatalf("Load() error exposed URL query: %v", loadErr)
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
