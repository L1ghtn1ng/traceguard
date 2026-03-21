GO ?= go

.PHONY: generate test build snapshot tidy

generate:
	$(GO) generate ./internal/ebpf

test:
	$(GO) test ./...

build: generate
	$(GO) build ./cmd/traceguard

tidy:
	$(GO) mod tidy

snapshot:
	goreleaser release --snapshot --clean
