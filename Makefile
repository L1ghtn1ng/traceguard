GO ?= go

.PHONY: generate test test-ebpf build snapshot tidy

generate:
	$(GO) generate ./internal/ebpf

test:
	$(GO) test ./...

test-ebpf:
	$(GO) test -tags ebpfintegration ./internal/ebpf

build: generate
	$(GO) build ./cmd/traceguard

tidy:
	$(GO) mod tidy

snapshot:
	goreleaser release --snapshot --clean
