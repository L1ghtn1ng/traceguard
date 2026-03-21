package kubeinfo

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"traceguard/internal/telemetry"
)

const podListPageSize = 500

type Config struct {
	APIURL    string
	TokenPath string
	CAPath    string
	NodeName  string
	PollEvery time.Duration
}

type Metadata struct {
	Namespace      string
	PodName        string
	NodeName       string
	PodIP          string
	ServiceAccount string
	OwnerKind      string
	OwnerName      string
	App            string
	Containers     []string
	Images         []string
}

type Enricher struct {
	client    *http.Client
	apiURL    string
	tokenPath string
	nodeName  string
	pollEvery time.Duration
	metrics   *telemetry.Registry
	onError   func(error)

	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu   sync.RWMutex
	pods map[string]Metadata
}

type podListResponse struct {
	Metadata struct {
		Continue string `json:"continue"`
	} `json:"metadata"`
	Items []podItem `json:"items"`
}

type podItem struct {
	Metadata struct {
		UID             string            `json:"uid"`
		Name            string            `json:"name"`
		Namespace       string            `json:"namespace"`
		Labels          map[string]string `json:"labels"`
		OwnerReferences []ownerReference  `json:"ownerReferences"`
	} `json:"metadata"`
	Spec struct {
		NodeName           string          `json:"nodeName"`
		ServiceAccountName string          `json:"serviceAccountName"`
		Containers         []containerSpec `json:"containers"`
	} `json:"spec"`
	Status struct {
		PodIP string `json:"podIP"`
	} `json:"status"`
}

type containerSpec struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type ownerReference struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Controller *bool  `json:"controller"`
}

func New(ctx context.Context, cfg Config, metrics *telemetry.Registry, onError func(error)) (*Enricher, error) {
	transport, err := newTransport(cfg.CAPath)
	if err != nil {
		return nil, err
	}

	sinkCtx, cancel := context.WithCancel(ctx)
	enricher := &Enricher{
		client: &http.Client{
			Timeout:   20 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL == nil || req.URL.Scheme != "https" {
					return errors.New("redirect target must use https")
				}
				return nil
			},
		},
		apiURL:    strings.TrimRight(cfg.APIURL, "/"),
		tokenPath: cfg.TokenPath,
		nodeName:  strings.TrimSpace(cfg.NodeName),
		pollEvery: cfg.PollEvery,
		metrics:   metrics,
		onError:   onError,
		cancel:    cancel,
		pods:      make(map[string]Metadata),
	}

	if err := enricher.Refresh(sinkCtx); err != nil {
		cancel()
		return nil, err
	}

	enricher.wg.Add(1)
	go func() {
		defer enricher.wg.Done()
		enricher.run(sinkCtx)
	}()

	return enricher, nil
}

func (e *Enricher) Close() error {
	if e == nil {
		return nil
	}
	e.cancel()
	e.wg.Wait()
	if transport, ok := e.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
	return nil
}

func (e *Enricher) Lookup(uid string) (Metadata, bool) {
	uid = strings.TrimSpace(uid)
	if uid == "" {
		return Metadata{}, false
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	metadata, ok := e.pods[uid]
	if !ok {
		return Metadata{}, false
	}
	return cloneMetadata(metadata), true
}

func (e *Enricher) Refresh(ctx context.Context) error {
	pods, err := e.fetchPods(ctx)
	if err != nil {
		if e.metrics != nil {
			e.metrics.IncKubernetesRefresh(false)
		}
		return err
	}

	e.mu.Lock()
	e.pods = pods
	e.mu.Unlock()

	if e.metrics != nil {
		e.metrics.SetKubernetesPodCount(len(pods))
		e.metrics.IncKubernetesRefresh(true)
	}
	return nil
}

func (e *Enricher) run(ctx context.Context) {
	ticker := time.NewTicker(e.pollEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := e.Refresh(ctx); err != nil && e.onError != nil {
				e.onError(err)
			}
		}
	}
}

func (e *Enricher) fetchPods(ctx context.Context) (map[string]Metadata, error) {
	pods := make(map[string]Metadata)
	continueToken := ""
	for {
		page, nextToken, err := e.fetchPodsPage(ctx, continueToken)
		if err != nil {
			return nil, err
		}
		for _, item := range page {
			uid := strings.TrimSpace(item.Metadata.UID)
			if uid == "" {
				continue
			}
			pods[uid] = Metadata{
				Namespace:      strings.TrimSpace(item.Metadata.Namespace),
				PodName:        strings.TrimSpace(item.Metadata.Name),
				NodeName:       strings.TrimSpace(item.Spec.NodeName),
				PodIP:          strings.TrimSpace(item.Status.PodIP),
				ServiceAccount: strings.TrimSpace(item.Spec.ServiceAccountName),
				OwnerKind:      ownerKind(item.Metadata.OwnerReferences),
				OwnerName:      ownerName(item.Metadata.OwnerReferences),
				App:            appLabel(item.Metadata.Labels),
				Containers:     collectContainers(item.Spec.Containers),
				Images:         collectImages(item.Spec.Containers),
			}
		}
		if nextToken == "" {
			return pods, nil
		}
		continueToken = nextToken
	}
}

func (e *Enricher) fetchPodsPage(ctx context.Context, continueToken string) ([]podItem, string, error) {
	token, err := readToken(e.tokenPath)
	if err != nil {
		return nil, "", fmt.Errorf("read kubernetes token: %w", err)
	}

	endpoint := e.apiURL + "/api/v1/pods"
	parsed, err := neturl.Parse(endpoint)
	if err != nil {
		return nil, "", fmt.Errorf("build pod list url: %w", err)
	}
	query := parsed.Query()
	query.Set("limit", fmt.Sprintf("%d", podListPageSize))
	if e.nodeName != "" {
		query.Set("fieldSelector", "spec.nodeName="+e.nodeName)
	}
	if continueToken != "" {
		query.Set("continue", continueToken)
	}
	parsed.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("create pod list request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("list kubernetes pods: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return nil, "", fmt.Errorf("read kubernetes response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("list kubernetes pods: unexpected status %d", resp.StatusCode)
	}

	var payload podListResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, "", fmt.Errorf("decode kubernetes response: %w", err)
	}
	return payload.Items, payload.Metadata.Continue, nil
}

func newTransport(caPath string) (*http.Transport, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil || rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}
	if strings.TrimSpace(caPath) != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read kubernetes ca: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(pem) {
			return nil, errors.New("append kubernetes ca: no certificates found")
		}
	}

	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			RootCAs:    rootCAs,
		},
	}, nil
}

func readToken(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if token == "" {
		return "", errors.New("empty token")
	}
	return token, nil
}

func collectContainers(containers []containerSpec) []string {
	out := make([]string, 0, len(containers))
	for _, container := range containers {
		name := strings.TrimSpace(container.Name)
		if name != "" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func collectImages(containers []containerSpec) []string {
	unique := make(map[string]struct{}, len(containers))
	for _, container := range containers {
		image := strings.TrimSpace(container.Image)
		if image != "" {
			unique[image] = struct{}{}
		}
	}
	out := make([]string, 0, len(unique))
	for image := range unique {
		out = append(out, image)
	}
	sort.Strings(out)
	return out
}

func cloneMetadata(metadata Metadata) Metadata {
	metadata.Containers = append([]string(nil), metadata.Containers...)
	metadata.Images = append([]string(nil), metadata.Images...)
	return metadata
}

func ownerKind(refs []ownerReference) string {
	if ref := controllerReference(refs); ref != nil {
		return strings.TrimSpace(ref.Kind)
	}
	return ""
}

func ownerName(refs []ownerReference) string {
	if ref := controllerReference(refs); ref != nil {
		return strings.TrimSpace(ref.Name)
	}
	return ""
}

func controllerReference(refs []ownerReference) *ownerReference {
	for idx := range refs {
		if refs[idx].Controller != nil && *refs[idx].Controller {
			return &refs[idx]
		}
	}
	for idx := range refs {
		if strings.TrimSpace(refs[idx].Kind) != "" && strings.TrimSpace(refs[idx].Name) != "" {
			return &refs[idx]
		}
	}
	return nil
}

func appLabel(labels map[string]string) string {
	for _, key := range []string{
		"app.kubernetes.io/name",
		"k8s-app",
		"app",
	} {
		if value := strings.TrimSpace(labels[key]); value != "" {
			return value
		}
	}
	return ""
}
