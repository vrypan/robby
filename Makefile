# robby build and release Makefile.

BINARY  := robby
PKG     := ./cmd/robby
DIST    := dist
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

# The project depends on modernc.org/sqlite (pure Go), so every target
# cross-compiles cleanly with cgo disabled.
GO      := CGO_ENABLED=0 go

# Release targets: <name> => <GOOS> <GOARCH>
PLATFORMS := linux_arm64 linux_x86 darwin_aarch64
linux_arm64_GOOS    := linux
linux_arm64_GOARCH  := arm64
linux_x86_GOOS      := linux
linux_x86_GOARCH    := amd64
darwin_aarch64_GOOS   := darwin
darwin_aarch64_GOARCH := arm64

.PHONY: all build test vet fmt clean release $(PLATFORMS)

all: build

## build: compile the binary for the host platform into ./
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(PKG)

## test: run the full test suite
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: report any unformatted files
fmt:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

## release: build and archive every release platform
release: $(PLATFORMS)

# Per-platform release build. The build directory is version-free so the
# binary path stays stable across rebuilds (dist/<binary>_<name>/<binary>);
# the version still lands in the tarball name and is stamped into the binary
# itself (robby --version). Produces:
#   dist/<binary>_<name>/<binary>
#   dist/<binary>_<version>_<name>.tar.gz
$(PLATFORMS):
	@echo "building $@ ($(VERSION))"
	@mkdir -p $(DIST)/$(BINARY)_$@
	CGO_ENABLED=0 GOOS=$($@_GOOS) GOARCH=$($@_GOARCH) \
		go build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BINARY)_$@/$(BINARY) $(PKG)
	@cp README.md $(DIST)/$(BINARY)_$@/ 2>/dev/null || true
	@cp -r deploy $(DIST)/$(BINARY)_$@/ 2>/dev/null || true
	@tar -czf $(DIST)/$(BINARY)_$(VERSION)_$@.tar.gz \
		-C $(DIST) $(BINARY)_$@
	@echo "  -> $(DIST)/$(BINARY)_$(VERSION)_$@.tar.gz"

## clean: remove build artifacts
clean:
	rm -rf $(DIST) $(BINARY)
