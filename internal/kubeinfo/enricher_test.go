package kubeinfo

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"traceguard/internal/telemetry"
)

func TestEnricherIndexesPodsByUID(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Fatalf("Authorization = %q, want Bearer test-token", got)
		}
		if got := r.URL.Query().Get("fieldSelector"); got != "spec.nodeName=worker-1" {
			t.Fatalf("fieldSelector = %q, want node selector", got)
		}
		switch r.URL.Query().Get("continue") {
		case "":
			_, _ = w.Write([]byte(`{
				"metadata":{"continue":"page-2"},
				"items":[
					{
						"metadata":{
							"uid":"pod-uid-1",
							"name":"dns-client",
							"namespace":"default",
							"labels":{"app.kubernetes.io/name":"dns-client"},
							"ownerReferences":[{"kind":"ReplicaSet","name":"dns-client-7f4b6d","controller":true}]
						},
						"spec":{"nodeName":"worker-1","serviceAccountName":"dns-client","containers":[
							{"name":"app","image":"example/app:v1"},
							{"name":"sidecar","image":"example/sidecar:v2"}
						]},
						"status":{"podIP":"10.0.0.12"}
					}
				]
			}`))
		case "page-2":
			_, _ = w.Write([]byte(`{
				"metadata":{"continue":""},
				"items":[
					{
						"metadata":{
							"uid":"pod-uid-2",
							"name":"resolver",
							"namespace":"dns",
							"labels":{"app":"resolver"},
							"ownerReferences":[{"kind":"DaemonSet","name":"node-resolver","controller":true}]
						},
						"spec":{"nodeName":"worker-1","serviceAccountName":"resolver","containers":[
							{"name":"resolver","image":"example/resolver:v3"},
							{"name":"resolver-copy","image":"example/resolver:v3"}
						]},
						"status":{"podIP":"10.0.0.53"}
					}
				]
			}`))
		default:
			t.Fatalf("unexpected continue token %q", r.URL.Query().Get("continue"))
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-token\n"), 0o600); err != nil {
		t.Fatalf("WriteFile token: %v", err)
	}
	caPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caPath, encodeCertPEM(t, server), 0o644); err != nil {
		t.Fatalf("WriteFile ca: %v", err)
	}

	metrics := telemetry.NewRegistry()
	enricher, err := New(context.Background(), Config{
		APIURL:    server.URL,
		TokenPath: tokenPath,
		CAPath:    caPath,
		NodeName:  "worker-1",
		PollEvery: time.Hour,
	}, metrics, nil)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer enricher.Close()

	first, ok := enricher.Lookup("pod-uid-1")
	if !ok {
		t.Fatal("Lookup(pod-uid-1) = false, want true")
	}
	if first.Namespace != "default" || first.PodName != "dns-client" || first.NodeName != "worker-1" {
		t.Fatalf("unexpected first pod metadata: %+v", first)
	}
	if first.PodIP != "10.0.0.12" || first.ServiceAccount != "dns-client" {
		t.Fatalf("unexpected first pod network/account metadata: %+v", first)
	}
	if first.OwnerKind != "ReplicaSet" || first.OwnerName != "dns-client-7f4b6d" || first.App != "dns-client" {
		t.Fatalf("unexpected first pod owner metadata: %+v", first)
	}
	if strings.Join(first.Containers, ",") != "app,sidecar" {
		t.Fatalf("Containers = %v, want sorted names", first.Containers)
	}
	if strings.Join(first.Images, ",") != "example/app:v1,example/sidecar:v2" {
		t.Fatalf("Images = %v, want sorted unique images", first.Images)
	}

	second, ok := enricher.Lookup("pod-uid-2")
	if !ok {
		t.Fatal("Lookup(pod-uid-2) = false, want true")
	}
	if second.OwnerKind != "DaemonSet" || second.OwnerName != "node-resolver" || second.App != "resolver" {
		t.Fatalf("unexpected second pod owner metadata: %+v", second)
	}
	if strings.Join(second.Images, ",") != "example/resolver:v3" {
		t.Fatalf("Images = %v, want deduplicated images", second.Images)
	}
	if requests != 2 {
		t.Fatalf("request count = %d, want 2", requests)
	}

	rendered := metrics.Render()
	for _, want := range []string{
		`traceguard_kubernetes_refresh_total{status="success"} 1`,
		`traceguard_kubernetes_pods 2`,
	} {
		if !strings.Contains(rendered, want) {
			t.Fatalf("Render() missing %q in %q", want, rendered)
		}
	}
}

func encodeCertPEM(t *testing.T, server *httptest.Server) []byte {
	t.Helper()

	if server.Certificate() == nil {
		t.Fatal("server certificate is nil")
	}
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	}
	return pem.EncodeToMemory(block)
}

func TestNewRejectsInvalidCA(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	tokenPath := filepath.Join(tempDir, "token")
	if err := os.WriteFile(tokenPath, []byte("test-token"), 0o600); err != nil {
		t.Fatalf("WriteFile token: %v", err)
	}
	caPath := filepath.Join(tempDir, "ca.crt")
	if err := os.WriteFile(caPath, []byte("not-a-certificate"), 0o644); err != nil {
		t.Fatalf("WriteFile ca: %v", err)
	}

	_, err := New(context.Background(), Config{
		APIURL:    "https://127.0.0.1:6443",
		TokenPath: tokenPath,
		CAPath:    caPath,
		PollEvery: time.Hour,
	}, telemetry.NewRegistry(), nil)
	if err == nil || !strings.Contains(err.Error(), "append kubernetes ca") {
		t.Fatalf("New error = %v, want append kubernetes ca", err)
	}
}

func TestEncodeCertPEMProducesParsableCert(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	pemBytes := encodeCertPEM(t, server)
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("pem.Decode returned nil block")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("ParseCertificate returned error: %v", err)
	}
}
