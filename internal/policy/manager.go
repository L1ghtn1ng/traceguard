package policy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/L1ghtn1ng/traceguard/internal/safefile"
)

const userAgent = "traceguard-policy/1"

type Config struct {
	Path           string
	URL            string
	CachePath      string
	RefreshPeriod  time.Duration
	Authorization  string
	CAPath         string
	ClientCertPath string
	ClientKeyPath  string
	// Validate, when set, checks the merged bundle before a fetched remote
	// document replaces the cache, conditional-request state, or the last
	// known good remote base.
	Validate func(Bundle) error
}

type LoadSource string

const (
	LoadSourceNone       LoadSource = "none"
	LoadSourceRemote     LoadSource = "remote"
	LoadSourceCache      LoadSource = "cache"
	LoadSourceNotChanged LoadSource = "not_modified"
	// LoadSourceLastKnown reuses the last validated remote document after a
	// refresh failure, so local overlay changes can still be applied.
	LoadSourceLastKnown LoadSource = "last_known"
)

type LoadMetadata struct {
	RemoteSource      LoadSource
	RemoteError       string
	StaleFallback     bool
	CachePersistError string
}

type Manager struct {
	cfg    Config
	client *http.Client

	mu         sync.Mutex
	etag       string
	modified   string
	lastRemote *Document
}

func NewManager(cfg Config) (*Manager, error) {
	if strings.TrimSpace(cfg.Path) != "" {
		if err := validatePath(cfg.Path, "policy path"); err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(cfg.URL) != "" {
		parsed, err := url.Parse(cfg.URL)
		if err != nil {
			return nil, errors.New("policy url is not valid")
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			return nil, errors.New("policy url must use https and include a host")
		}
		if parsed.User != nil {
			return nil, errors.New("policy url must not contain user credentials; use the authorization header or mTLS")
		}
		if err := validatePath(cfg.CachePath, "policy cache path"); err != nil {
			return nil, err
		}
	}
	for path, name := range map[string]string{
		cfg.CAPath:         "policy ca path",
		cfg.ClientCertPath: "policy client certificate path",
		cfg.ClientKeyPath:  "policy client key path",
	} {
		if strings.TrimSpace(path) != "" {
			if err := validatePath(path, name); err != nil {
				return nil, err
			}
		}
	}
	if (strings.TrimSpace(cfg.ClientCertPath) == "") != (strings.TrimSpace(cfg.ClientKeyPath) == "") {
		return nil, errors.New("policy client certificate and key must be configured together")
	}
	transport, err := newTransport(cfg)
	if err != nil {
		return nil, err
	}
	return &Manager{
		cfg: cfg,
		client: &http.Client{
			Timeout:       30 * time.Second,
			Transport:     transport,
			CheckRedirect: checkHTTPSRedirect,
		},
	}, nil
}

func (m *Manager) Load(ctx context.Context) (Bundle, LoadMetadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	remote := Document{Version: Version}
	metadata := LoadMetadata{RemoteSource: LoadSourceNone}
	var fetched *remoteResponse
	if strings.TrimSpace(m.cfg.URL) != "" {
		document, response, source, err := m.fetch(ctx)
		if err != nil {
			fetchErr := err
			if m.lastRemote != nil {
				// Never roll back to an older on-disk cache once a remote
				// document has been accepted, but keep the accepted base so
				// local overlay edits still load during an outage.
				document = *m.lastRemote
				source = LoadSourceLastKnown
			} else {
				document, err = m.readCache()
				if err != nil {
					return Bundle{}, metadata, fmt.Errorf("load remote policy and stale cache: %w", errors.Join(fetchErr, err))
				}
				source = LoadSourceCache
			}
			metadata.RemoteError = fetchErr.Error()
			metadata.StaleFallback = true
		} else if source == LoadSourceRemote {
			fetched = response
		}
		remote = document
		metadata.RemoteSource = source
	}

	local := Document{Version: Version}
	if strings.TrimSpace(m.cfg.Path) != "" {
		payload, err := safefile.ReadFile(m.cfg.Path, MaxDocumentBytes)
		if err != nil {
			return Bundle{}, metadata, fmt.Errorf("read local policy %q: %w", m.cfg.Path, err)
		}
		document, err := Parse(payload)
		if err != nil {
			return Bundle{}, metadata, fmt.Errorf("parse local policy %q: %w", m.cfg.Path, err)
		}
		local = document
	}

	bundle, err := Merge(remote, local)
	if err != nil {
		return Bundle{}, metadata, err
	}
	if m.cfg.Validate != nil {
		if err := m.cfg.Validate(bundle); err != nil {
			return Bundle{}, metadata, err
		}
	}
	if strings.TrimSpace(m.cfg.URL) != "" {
		// Commit remote state only after the effective policy validated, so a
		// rejected document is neither cached nor suppressed by a later 304.
		if fetched != nil {
			if err := safefile.WriteFileAtomic(m.cfg.CachePath, fetched.payload, 0o600); err != nil {
				metadata.CachePersistError = err.Error()
			}
			m.etag = fetched.etag
			m.modified = fetched.modified
		}
		copy := remote
		m.lastRemote = &copy
	}
	return bundle, metadata, nil
}

type remoteResponse struct {
	payload  []byte
	etag     string
	modified string
}

func (m *Manager) Watch(ctx context.Context, apply func(Bundle, LoadMetadata, error)) {
	if strings.TrimSpace(m.cfg.URL) == "" || m.cfg.RefreshPeriod <= 0 {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(m.cfg.RefreshPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			bundle, metadata, err := m.Load(ctx)
			apply(bundle, metadata, err)
		}
	}
}

func (m *Manager) fetch(ctx context.Context) (document Document, response *remoteResponse, source LoadSource, fetchErr error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.cfg.URL, nil)
	if err != nil {
		return Document{}, nil, LoadSourceNone, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/yaml, text/yaml, application/x-yaml")
	req.Header.Set("User-Agent", userAgent)
	if authorization := strings.TrimSpace(m.cfg.Authorization); authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	if m.etag != "" {
		req.Header.Set("If-None-Match", m.etag)
	}
	if m.modified != "" {
		req.Header.Set("If-Modified-Since", m.modified)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return Document{}, nil, LoadSourceNone, safeRemoteRequestError(err)
	}
	defer func() {
		fetchErr = errors.Join(fetchErr, resp.Body.Close())
	}()
	if resp.StatusCode == http.StatusNotModified {
		if m.lastRemote != nil {
			return *m.lastRemote, nil, LoadSourceNotChanged, nil
		}
		document, err := m.readCache()
		return document, nil, LoadSourceNotChanged, err
	}
	if resp.StatusCode != http.StatusOK {
		return Document{}, nil, LoadSourceNone, fmt.Errorf("unexpected HTTP status %s", resp.Status)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, MaxDocumentBytes+1))
	if err != nil {
		return Document{}, nil, LoadSourceNone, fmt.Errorf("read response: %w", err)
	}
	if int64(len(payload)) > MaxDocumentBytes {
		return Document{}, nil, LoadSourceNone, fmt.Errorf("response exceeds %d bytes", MaxDocumentBytes)
	}
	document, err = Parse(payload)
	if err != nil {
		return Document{}, nil, LoadSourceNone, fmt.Errorf("parse response: %w", err)
	}
	return document, &remoteResponse{
		payload:  payload,
		etag:     strings.TrimSpace(resp.Header.Get("ETag")),
		modified: strings.TrimSpace(resp.Header.Get("Last-Modified")),
	}, LoadSourceRemote, nil
}

func safeRemoteRequestError(err error) error {
	if networkError, ok := errors.AsType[net.Error](err); ok {
		return fmt.Errorf("remote policy HTTPS request failed (timeout=%t)", networkError.Timeout())
	}
	return fmt.Errorf("remote policy HTTPS request failed (%T)", err)
}

func (m *Manager) readCache() (Document, error) {
	payload, err := safefile.ReadFile(m.cfg.CachePath, MaxDocumentBytes)
	if err != nil {
		return Document{}, fmt.Errorf("read policy cache %q: %w", m.cfg.CachePath, err)
	}
	document, err := Parse(payload)
	if err != nil {
		return Document{}, fmt.Errorf("parse policy cache %q: %w", m.cfg.CachePath, err)
	}
	return document, nil
}

func newTransport(cfg Config) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if strings.TrimSpace(cfg.CAPath) != "" {
		pem, err := safefile.ReadFile(cfg.CAPath, MaxDocumentBytes)
		if err != nil {
			return nil, fmt.Errorf("read policy ca: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("append policy ca: no certificates found")
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs}
	if strings.TrimSpace(cfg.ClientCertPath) != "" || strings.TrimSpace(cfg.ClientKeyPath) != "" {
		certificatePEM, err := safefile.ReadFile(cfg.ClientCertPath, MaxDocumentBytes)
		if err != nil {
			return nil, fmt.Errorf("read policy client certificate: %w", err)
		}
		keyPEM, err := safefile.ReadFile(cfg.ClientKeyPath, MaxDocumentBytes)
		if err != nil {
			return nil, fmt.Errorf("read policy client key: %w", err)
		}
		certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("load policy client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{certificate}
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       tlsConfig,
	}, nil
}

func checkHTTPSRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many redirects")
	}
	if req.URL == nil || req.URL.Scheme != "https" || len(via) == 0 || !sameOrigin(req.URL, via[0].URL) {
		return errors.New("redirect target must keep the original HTTPS origin")
	}
	return nil
}

func sameOrigin(left, right *url.URL) bool {
	return left != nil && right != nil &&
		strings.EqualFold(left.Scheme, right.Scheme) &&
		strings.EqualFold(left.Host, right.Host)
}

func validatePath(path, name string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s is empty", name)
	}
	if !strings.HasPrefix(path, string(os.PathSeparator)) {
		return fmt.Errorf("%s %q must be absolute", name, path)
	}
	return nil
}
