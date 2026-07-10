GO ?= go
BINARY ?= traceguard

CGO_ENABLED ?= 1
CGO_CFLAGS ?= -O2 -flto -D_FORTIFY_SOURCE=2 -fstack-protector-all -fPIE
CGO_LDFLAGS ?= -flto -Wl,-z,relro,-z,now -Wl,-z,noexecstack -pie
GO_BUILD_FLAGS ?= -trimpath -buildmode=pie
GO_LDFLAGS ?= -s -w -linkmode=external -extldflags "$(CGO_LDFLAGS)"

.PHONY: generate test test-ebpf test-ebpf-c build snapshot tidy

generate:
	$(GO) generate ./internal/ebpf

test:
	$(GO) test ./...
	$(GO) test -race ./...

test-ebpf:
	$(GO) test -tags ebpfintegration ./internal/ebpf

test-ebpf-c:
	./internal/ebpf/check.sh

build: generate
	CGO_ENABLED=$(CGO_ENABLED) CGO_CFLAGS='$(CGO_CFLAGS)' CGO_LDFLAGS='$(CGO_LDFLAGS)' \
		$(GO) build $(GO_BUILD_FLAGS) -ldflags '$(GO_LDFLAGS)' -o $(BINARY) ./cmd/traceguard

tidy:
	$(GO) mod tidy

snapshot:
	goreleaser release --snapshot --clean
