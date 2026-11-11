.PHONY: all build vet test clean cross

BINARY_DIR := bin
GO_FLAGS := CGO_ENABLED=0

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
ifeq ($(strip $(VERSION)),)
VERSION := dev
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
TEST_LDFLAGS := -ldflags="-linkmode=external"
else
TEST_LDFLAGS :=
endif

BUILD_FLAGS := -trimpath -ldflags="-s -w -X 'main.version=$(VERSION)'"
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

all: vet test build

build:
	mkdir -p $(BINARY_DIR)
	$(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/dtfm ./cmd/dtfm
	$(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/lmdtfy ./cmd/lmdtfy
	$(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/relay ./cmd/relay

vet:
	go vet ./...

cross:
	mkdir -p $(BINARY_DIR)/dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		echo "Building for $${os}-$${arch}..."; \
		GOOS=$${os} GOARCH=$${arch} $(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/dist/dtfm-$${os}-$${arch} ./cmd/dtfm || exit 1; \
		GOOS=$${os} GOARCH=$${arch} $(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/dist/lmdtfy-$${os}-$${arch} ./cmd/lmdtfy || exit 1; \
		GOOS=$${os} GOARCH=$${arch} $(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/dist/relay-$${os}-$${arch} ./cmd/relay || exit 1; \
	done

test:
	go test -v -race $(TEST_LDFLAGS) ./...
	python3 -W error scripts/test_extract_changelog.py

clean:
	rm -rf $(BINARY_DIR) dist artifacts RELEASE_NOTES.md
