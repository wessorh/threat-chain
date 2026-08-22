# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

# =============================================================================
# ThreatAttest Chain — Makefile
# =============================================================================
#
# Usage:
#   make                  — build the binary (default)
#   make build            — build threatattestd into ./bin/
#   make install          — install to $(GOPATH)/bin
#   make test             — run all Go unit tests
#   make test-shell       — run shell + Node integration test scripts
#   make lint             — run golangci-lint
#   make fmt              — gofmt + goimports
#   make proto-gen        — regenerate protobuf Go bindings
#   make localnet-init    — initialise single-node devnet
#   make localnet-start   — start the devnet node
#   make localnet-stop    — stop the devnet node
#   make localnet-reset   — wipe state and re-init devnet
#   make docker-build     — build Docker image
#   make docker-run       — run node in Docker
#   make docker-compose-up — start full stack via compose
#   make clean            — remove build artefacts
#   make release-snapshot — dry-run GoReleaser snapshot build
#
# =============================================================================

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := build

# ─── Project metadata ────────────────────────────────────────────────────────
BINARY        := threatattestd
MODULE        := github.com/threatattest/chain
CMD_PATH      := ./cmd/threatattestd
BIN_DIR       := ./bin
DIST_DIR      := ./dist

# ─── Version / ldflags ───────────────────────────────────────────────────────
# Derive version from git; fall back to "dev" when not in a git repo.
GIT_VERSION   := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT    := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH    := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
BUILD_DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
BUILD_HOST    := $(shell hostname -s 2>/dev/null || echo "unknown")

COSMOS_VERSION_PKG := github.com/cosmos/cosmos-sdk/version

LDFLAGS := -X $(COSMOS_VERSION_PKG).Name=$(BINARY) \
           -X $(COSMOS_VERSION_PKG).AppName=$(BINARY) \
           -X $(COSMOS_VERSION_PKG).Version=$(GIT_VERSION) \
           -X $(COSMOS_VERSION_PKG).Commit=$(GIT_COMMIT) \
           -X $(COSMOS_VERSION_PKG).BuildTags=$(BUILD_TAGS)

# ─── Build tags ──────────────────────────────────────────────────────────────
# Override with: make build BUILD_TAGS=osusergo,netgo
BUILD_TAGS    ?=

# ─── Go toolchain ────────────────────────────────────────────────────────────
GO            := $(shell command -v go 2>/dev/null || echo "/usr/local/go/bin/go")
GOPATH        := $(shell $(GO) env GOPATH)
GOBIN         := $(GOPATH)/bin

# ─── Docker ──────────────────────────────────────────────────────────────────
DOCKER        := docker
IMAGE_NAME    := threatattest/threatattestd
IMAGE_TAG     := $(GIT_VERSION)
DOCKER_FILE   := Dockerfile
COMPOSE_FILE  := docker-compose.yml

# ─── Localnet config ─────────────────────────────────────────────────────────
CHAIN_ID      := threatattest-local-1
MONIKER       := localnode
KEY_NAME      := localkey
DENOM         := utatst
HOME_DIR      := $(HOME)/.threatattestd-local

# ─── Lint ────────────────────────────────────────────────────────────────────
LINT          := $(GOBIN)/golangci-lint
LINT_VERSION  := v1.59.1

# ─── Tools ───────────────────────────────────────────────────────────────────
GOIMPORTS     := $(GOBIN)/goimports
MOCKGEN       := $(GOBIN)/mockgen

# =============================================================================
# PRIMARY TARGETS
# =============================================================================

## build: Compile threatattestd and txwatch binaries → bin/
.PHONY: build
build: build-txwatch
	@echo "  ► Building $(BINARY) $(GIT_VERSION) ($(GIT_COMMIT))"
	@mkdir -p $(BIN_DIR)
	$(GO) build \
		-mod=readonly \
		-tags "$(BUILD_TAGS)" \
		-ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY) \
		$(CMD_PATH)
	@echo "  ✓ $(BIN_DIR)/$(BINARY)"

## build-txwatch: Compile the tx event listener → bin/txwatch
.PHONY: build-txwatch
build-txwatch: go-mod-verify
	@echo "  ► Building txwatch"
	@mkdir -p $(BIN_DIR)
	$(GO) build \
		-mod=readonly \
		-tags "$(BUILD_TAGS)" \
		-ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/txwatch \
		./cmd/txwatch
	@echo "  ✓ $(BIN_DIR)/txwatch"

## build-race: Build with -race detector enabled
.PHONY: build-race
build-race: go-mod-verify
	@echo "  ► Building $(BINARY) with -race"
	@mkdir -p $(BIN_DIR)
	$(GO) build \
		-race \
		-tags "$(BUILD_TAGS)" \
		-ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-race \
		$(CMD_PATH)

## build-static: Build a fully static binary (Linux only)
.PHONY: build-static
build-static: go-mod-verify
	@echo "  ► Building static $(BINARY)"
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build \
		-mod=readonly \
		-tags "osusergo,netgo,$(BUILD_TAGS)" \
		-ldflags "-w -s -extldflags '-static' $(LDFLAGS)" \
		-o $(BIN_DIR)/$(BINARY)-static \
		$(CMD_PATH)

## install: Install binary to $(GOBIN)
.PHONY: install
install: go-mod-verify
	@echo "  ► Installing $(BINARY) to $(GOBIN)"
	$(GO) install \
		-mod=readonly \
		-tags "$(BUILD_TAGS)" \
		-ldflags "$(LDFLAGS)" \
		$(CMD_PATH)
	@echo "  ✓ $(GOBIN)/$(BINARY)"

# =============================================================================
# TESTING
# =============================================================================

## test: Run all Go unit tests
.PHONY: test
test:
	@echo "  ► Running Go unit tests"
	$(GO) test \
		-mod=readonly \
		-timeout 120s \
		-race \
		./...

## test-short: Run tests excluding slow integration tests
.PHONY: test-short
test-short:
	@echo "  ► Running short Go unit tests"
	$(GO) test \
		-mod=readonly \
		-short \
		-timeout 60s \
		./...

## test-cover: Run tests with coverage report
.PHONY: test-cover
test-cover:
	@echo "  ► Running tests with coverage"
	@mkdir -p $(DIST_DIR)
	$(GO) test \
		-mod=readonly \
		-timeout 120s \
		-coverprofile=$(DIST_DIR)/coverage.out \
		-covermode=atomic \
		./...
	$(GO) tool cover -html=$(DIST_DIR)/coverage.out -o $(DIST_DIR)/coverage.html
	@echo "  ✓ Coverage report: $(DIST_DIR)/coverage.html"

## test-module: Run tests for a specific module (MODULE=x/identity)
.PHONY: test-module
test-module:
	@echo "  ► Testing ./$(MODULE)/..."
	$(GO) test -mod=readonly -v -timeout 60s ./$(MODULE)/...

## test-shell: Run shell integration test scripts (no node required)
.PHONY: test-shell
test-shell:
	@echo "  ► Running shell tests"
	@BINARY=$(BIN_DIR)/$(BINARY) bash tests/test_identity_module.sh
	@BINARY=$(BIN_DIR)/$(BINARY) bash tests/test_attester_domain.sh
	@BINARY=$(BIN_DIR)/$(BINARY) bash tests/test_compliance_tiers.sh
	@echo "  ✓ Shell tests complete"

## test-js: Run Node.js extension badge tests
.PHONY: test-js
test-js:
	@echo "  ► Running Node.js extension tests"
	@node tests/test_extension_badges.js
	@echo "  ✓ JS tests complete"

## test-all: Run Go tests + shell tests + JS tests
.PHONY: test-all
test-all: test test-shell test-js
	@echo "  ✓ All tests complete"

## test-integration: Run integration tests against a live local node
.PHONY: test-integration
test-integration:
	@echo "  ► Running integration tests (requires running node)"
	@BINARY=$(BIN_DIR)/$(BINARY) NODE=http://localhost:26657 \
		bash tests/test_identity_module.sh
	@BINARY=$(BIN_DIR)/$(BINARY) NODE=http://localhost:26657 \
		bash tests/test_attester_domain.sh

# =============================================================================
# CODE QUALITY
# =============================================================================

## fmt: Format Go source files
.PHONY: fmt
fmt:
	@echo "  ► Formatting Go files"
	$(GO) fmt ./...
	@if command -v $(GOIMPORTS) &>/dev/null; then \
		$(GOIMPORTS) -w -local $(MODULE) $$(find . -name "*.go" -not -path "*/vendor/*"); \
	fi

## vet: Run go vet
.PHONY: vet
vet:
	@echo "  ► go vet"
	$(GO) vet ./...

## lint: Run golangci-lint
.PHONY: lint
lint: lint-install
	@echo "  ► golangci-lint"
	$(LINT) run --timeout 5m ./...

## lint-fix: Run golangci-lint with auto-fix
.PHONY: lint-fix
lint-fix: lint-install
	@echo "  ► golangci-lint --fix"
	$(LINT) run --fix --timeout 5m ./...

## lint-install: Install golangci-lint if not present
.PHONY: lint-install
lint-install:
	@if ! command -v $(LINT) &>/dev/null; then \
		echo "  ► Installing golangci-lint $(LINT_VERSION)"; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
			| sh -s -- -b $(GOBIN) $(LINT_VERSION); \
	fi

# =============================================================================
# PROTOBUF
# =============================================================================

## proto-gen: Regenerate protobuf Go bindings
.PHONY: proto-gen
proto-gen:
	@echo "  ► Regenerating protobuf bindings"
	@bash scripts/protocgen.sh

## proto-lint: Lint proto files with buf
.PHONY: proto-lint
proto-lint:
	@echo "  ► Linting proto files"
	@if command -v buf &>/dev/null; then \
		buf lint proto/; \
	else \
		echo "  ⚠  buf not installed — skipping proto lint"; \
	fi

# =============================================================================
# LOCAL DEVNET
# =============================================================================

## localnet-init: Initialise a fresh single-node local devnet
.PHONY: localnet-init
localnet-init: build
	@echo "  ► Initialising localnet (chain-id: $(CHAIN_ID))"
	@bash scripts/init-localnet.sh \
		--binary  $(BIN_DIR)/$(BINARY) \
		--home    $(HOME_DIR) \
		--chain   $(CHAIN_ID) \
		--moniker $(MONIKER) \
		--key     $(KEY_NAME) \
		--denom   $(DENOM)

## localnet-start: Start the local devnet node (background)
.PHONY: localnet-start
localnet-start:
	@echo "  ► Starting localnet"
	@bash scripts/start-localnet.sh \
		--binary $(BIN_DIR)/$(BINARY) \
		--home   $(HOME_DIR)

## localnet-stop: Stop the local devnet node
.PHONY: localnet-stop
localnet-stop:
	@echo "  ► Stopping localnet"
	@pkill -f "$(BINARY) [s]tart" 2>/dev/null || true
	@echo "  ✓ Localnet stopped"

## localnet-reset: Wipe state and re-initialise devnet
.PHONY: localnet-reset
localnet-reset: localnet-stop
	@echo "  ► Resetting localnet"
	@bash scripts/reset-localnet.sh \
		--binary  $(BIN_DIR)/$(BINARY) \
		--home    $(HOME_DIR) \
		--chain   $(CHAIN_ID) \
		--moniker $(MONIKER) \
		--key     $(KEY_NAME) \
		--denom   $(DENOM)

## localnet-log: Tail the localnet log
.PHONY: localnet-log
localnet-log:
	@tail -f /tmp/threatattestd-local.log

## localnet-status: Query localnet node status
.PHONY: localnet-status
localnet-status:
	@$(BIN_DIR)/$(BINARY) status --node tcp://localhost:26657 2>&1 | \
		python3 -c "import sys,json; d=json.load(sys.stdin); \
			r=d.get('result',d); \
			print('Chain ID :', r.get('node_info',{}).get('network','?')); \
			print('Height   :', r.get('sync_info',{}).get('latest_block_height','?')); \
			print('Catching :', r.get('sync_info',{}).get('catching_up','?'))" 2>/dev/null \
		|| $(BIN_DIR)/$(BINARY) status --node tcp://localhost:26657

# =============================================================================
# DOCKER
# =============================================================================

## docker-build: Build Docker image
.PHONY: docker-build
docker-build:
	@echo "  ► Building Docker image $(IMAGE_NAME):$(IMAGE_TAG)"
	$(DOCKER) build \
		--build-arg GIT_VERSION=$(GIT_VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-f $(DOCKER_FILE) \
		-t $(IMAGE_NAME):$(IMAGE_TAG) \
		-t $(IMAGE_NAME):latest \
		.

## docker-run: Run a single-node devnet in Docker
.PHONY: docker-run
docker-run:
	@echo "  ► Starting $(IMAGE_NAME):$(IMAGE_TAG) devnet"
	$(DOCKER) run --rm -it \
		-p 26656:26656 \
		-p 26657:26657 \
		-p 1317:1317 \
		-p 9090:9090 \
		-e CHAIN_ID=$(CHAIN_ID) \
		-e MONIKER=$(MONIKER) \
		-e KEY_NAME=$(KEY_NAME) \
		-e DENOM=$(DENOM) \
		--name threatattestd-local \
		$(IMAGE_NAME):$(IMAGE_TAG)

## docker-push: Push Docker image to registry
.PHONY: docker-push
docker-push:
	@echo "  ► Pushing $(IMAGE_NAME):$(IMAGE_TAG)"
	$(DOCKER) push $(IMAGE_NAME):$(IMAGE_TAG)
	$(DOCKER) push $(IMAGE_NAME):latest

## docker-compose-up: Start full stack (node + monitor) via docker-compose
.PHONY: docker-compose-up
docker-compose-up:
	@echo "  ► Starting docker-compose stack"
	$(DOCKER) compose -f $(COMPOSE_FILE) up -d

## docker-compose-down: Stop docker-compose stack
.PHONY: docker-compose-down
docker-compose-down:
	$(DOCKER) compose -f $(COMPOSE_FILE) down

## docker-compose-logs: Follow docker-compose logs
.PHONY: docker-compose-logs
docker-compose-logs:
	$(DOCKER) compose -f $(COMPOSE_FILE) logs -f

# =============================================================================
# RELEASE
# =============================================================================

## release-snapshot: GoReleaser dry-run snapshot (no publish)
.PHONY: release-snapshot
release-snapshot:
	@echo "  ► GoReleaser snapshot"
	@if command -v goreleaser &>/dev/null; then \
		goreleaser release --snapshot --clean; \
	else \
		echo "  ⚠  goreleaser not installed — running manual multi-arch build"; \
		bash scripts/build.sh --all; \
	fi

## release-check: Validate .goreleaser.yaml config
.PHONY: release-check
release-check:
	@command -v goreleaser &>/dev/null && goreleaser check || \
		echo "  ⚠  goreleaser not installed"

# =============================================================================
# DEPENDENCY MANAGEMENT
# =============================================================================

## go-mod-verify: Verify module graph integrity
.PHONY: go-mod-verify
go-mod-verify:
	@$(GO) mod verify

## go-mod-tidy: Tidy go.mod / go.sum
.PHONY: go-mod-tidy
go-mod-tidy:
	@echo "  ► go mod tidy"
	@$(GO) mod tidy

## go-mod-download: Pre-download all dependencies
.PHONY: go-mod-download
go-mod-download:
	@echo "  ► go mod download"
	@$(GO) mod download

## deps-update: Update all direct dependencies to latest minor/patch
.PHONY: deps-update
deps-update:
	@echo "  ► Updating direct dependencies"
	$(GO) get -u ./...
	$(GO) mod tidy

# =============================================================================
# TOOLS
# =============================================================================

## tools: Install all development tools
.PHONY: tools
tools: lint-install tools-goimports tools-mockgen
	@echo "  ✓ All tools installed"

.PHONY: tools-goimports
tools-goimports:
	@if ! command -v $(GOIMPORTS) &>/dev/null; then \
		echo "  ► Installing goimports"; \
		$(GO) install golang.org/x/tools/cmd/goimports@latest; \
	fi

.PHONY: tools-mockgen
tools-mockgen:
	@if ! command -v $(MOCKGEN) &>/dev/null; then \
		echo "  ► Installing mockgen"; \
		$(GO) install github.com/golang/mock/mockgen@v1.6.0; \
	fi

# =============================================================================
# CLEAN
# =============================================================================

## clean: Remove build artefacts
.PHONY: clean
clean:
	@echo "  ► Cleaning build artefacts"
	@rm -rf $(BIN_DIR) $(DIST_DIR)
	@echo "  ✓ Clean"

## clean-all: Remove build artefacts + Go build cache
.PHONY: clean-all
clean-all: clean
	@echo "  ► Purging Go build cache"
	$(GO) clean -cache -testcache -modcache

# =============================================================================
# UTILITY
# =============================================================================

## version: Print build metadata
.PHONY: version
version:
	@echo "Binary     : $(BINARY)"
	@echo "Module     : $(MODULE)"
	@echo "Go version : $(shell $(GO) version)"
	@echo "Git version: $(GIT_VERSION)"
	@echo "Git commit : $(GIT_COMMIT)"
	@echo "Git branch : $(GIT_BRANCH)"
	@echo "Build date : $(BUILD_DATE)"
	@echo "Build tags : $(BUILD_TAGS)"
	@echo "GOPATH     : $(GOPATH)"

## help: Print this help message
.PHONY: help
help:
	@echo ""
	@echo "ThreatAttest Chain — Build Targets"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | \
		sed 's/^## //' | \
		column -t -s ':' | \
		sed 's/^/  /'
	@echo ""

# =============================================================================
# INTERNAL GUARDS
# =============================================================================

# Ensure Go is available
.PHONY: _require-go
_require-go:
	@command -v $(GO) &>/dev/null || \
		(echo "ERROR: go not found — install from https://go.dev/dl/"; exit 1)

# Ensure git is available (for version stamping)
.PHONY: _require-git
_require-git:
	@command -v git &>/dev/null || \
		(echo "WARNING: git not found — version will be 'dev'")