GO ?= go

.PHONY: generate test test-ebpf test-ebpf-c build snapshot tidy

generate:
	$(GO) generate ./internal/ebpf

test:
	$(GO) test ./...

test-ebpf:
	$(GO) test -tags ebpfintegration ./internal/ebpf

test-ebpf-c:
	./internal/ebpf/check.sh

build: generate
	$(GO) build ./cmd/traceguard

tidy:
	$(GO) mod tidy

snapshot:
	goreleaser release --snapshot --clean
