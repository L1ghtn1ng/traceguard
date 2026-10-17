package eventsink

import (
	"context"
	"strings"
	"testing"

	"github.com/L1ghtn1ng/traceguard/internal/telemetry"
)

func TestNewExportSinkErrorsDoNotLeakURLSecrets(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-export-token"
	tests := []struct {
		url     string
		wantErr string
	}{
		// url.Parse fails on these with a *url.Error that embeds the full URL.
		{url: "https://exa\x7fmple.com/ingest?token=" + secret, wantErr: "export url is not valid"},
		{url: " https://example.com:bad-port/ingest?token=" + secret + " ", wantErr: "export url is not valid"},
		{url: "http://example.com/ingest?token=" + secret, wantErr: "export url must use https://"},
		{url: "https://user:" + secret + "@example.com/ingest", wantErr: "export url must not contain user credentials"},
	}
	for _, tt := range tests {
		sink, err := newExportSink(context.Background(), Config{ExportURL: tt.url}, telemetry.NewRegistry())
		if err == nil {
			_ = sink.Close()
			t.Fatal("newExportSink accepted invalid url")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("newExportSink error leaks url secret: %q", err)
		}
		if !strings.HasPrefix(err.Error(), tt.wantErr) {
			t.Fatalf("newExportSink error = %q, want prefix %q", err, tt.wantErr)
		}
	}
}

func TestNewExportSinkTrimsURL(t *testing.T) {
	t.Parallel()

	sink, err := newExportSink(context.Background(), Config{ExportURL: "  https://example.com/ingest?token=abc \n"}, telemetry.NewRegistry())
	if err != nil {
		t.Fatalf("newExportSink returned error: %v", err)
	}
	closeTestResource(t, sink)
	if sink.target != "https://example.com/ingest?token=abc" {
		t.Fatalf("export target = %q, want trimmed url", sink.target)
	}
}
