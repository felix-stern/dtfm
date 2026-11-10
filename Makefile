.PHONY: all build vet test clean cross

BINARY_DIR := bin
GO_FLAGS := CGO_ENABLED=0
BUILD_FLAGS := -trimpath -ldflags="-s -w"
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

all: vet test build

build:
	mkdir -p $(BINARY_DIR)
	$(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/dtfm ./cmd/dtfm
	$(GO_FLAGS) go build $(BUILD_FLAGS) -o $(BINARY_DIR)/lmdtfy ./cmd/lmdtfy

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
	done

test:
	go test -v -race ./...

clean:
	rm -rf $(BINARY_DIR)
