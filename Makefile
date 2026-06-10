# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

# =============================================================================
# ThreatAttest — Root Makefile
# =============================================================================
#
# Orchestrates the chain node (chain/) and browser extension (extension/).
#
# Usage:
#   make                — build everything (chain binary + extension)
#   make build          — build both
#   make build-chain    — build threatattestd only
#   make build-ext      — build browser extension only
#   make test           — run all tests (Go + shell + JS)
#   make test-chain     — Go unit tests
#   make test-shell     — shell integration tests (offline)
#   make test-js        — Node.js extension tests
#   make lint           — lint Go + validate extension
#   make localnet       — init + start single-node devnet
#   make docker-build   — build Docker image
#   make clean          — remove all build artefacts
#   make help           — print all targets
# =============================================================================

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := build

CHAIN_DIR := chain
EXT_DIR   := extension

# ── Build ─────────────────────────────────────────────────────────────────────

## build: Build chain binary + extension
.PHONY: build
build: build-chain build-ext

## build-chain: Build threatattestd binary
.PHONY: build-chain
build-chain:
	$(MAKE) -C $(CHAIN_DIR) build

## build-ext: Build browser extension (production)
.PHONY: build-ext
build-ext:
	$(MAKE) -C $(EXT_DIR) build

## build-ext-dev: Build browser extension (development / local API)
.PHONY: build-ext-dev
build-ext-dev:
	$(MAKE) -C $(EXT_DIR) build-dev

## install: Install chain binary to GOPATH/bin
.PHONY: install
install:
	$(MAKE) -C $(CHAIN_DIR) install

# ── Packaging ─────────────────────────────────────────────────────────────────

## pack-ext: Package browser extension into a zip for distribution
.PHONY: pack-ext
pack-ext:
	$(MAKE) -C $(EXT_DIR) pack

## release-snapshot: Build all release artefacts locally (no publish)
.PHONY: release-snapshot
release-snapshot:
	$(MAKE) -C $(CHAIN_DIR) release-snapshot

# ── Testing ───────────────────────────────────────────────────────────────────

## test: Run all tests (Go unit + shell scripts + Node.js)
.PHONY: test
test: test-chain test-shell test-js
	@echo ""
	@echo "✓ All tests complete"

## test-chain: Run Go unit tests
.PHONY: test-chain
test-chain:
	$(MAKE) -C $(CHAIN_DIR) test

## test-shell: Run offline shell integration tests (no node required)
.PHONY: test-shell
test-shell:
	$(MAKE) -C $(CHAIN_DIR) test-shell

## test-js: Run Node.js extension badge tests (151 tests)
.PHONY: test-js
test-js:
	$(MAKE) -C $(CHAIN_DIR) test-js

## test-cover: Run Go tests with coverage report
.PHONY: test-cover
test-cover:
	$(MAKE) -C $(CHAIN_DIR) test-cover

## test-integration: Run integration tests against a live local node
.PHONY: test-integration
test-integration:
	$(MAKE) -C $(CHAIN_DIR) test-integration

## validate-ext: Validate extension manifest + sources
.PHONY: validate-ext
validate-ext:
	$(MAKE) -C $(EXT_DIR) validate

# ── Code quality ──────────────────────────────────────────────────────────────

## lint: Lint Go sources + validate extension
.PHONY: lint
lint: lint-chain validate-ext

## lint-chain: Run golangci-lint on chain sources
.PHONY: lint-chain
lint-chain:
	$(MAKE) -C $(CHAIN_DIR) lint

## lint-fix: Auto-fix lint issues where possible
.PHONY: lint-fix
lint-fix:
	$(MAKE) -C $(CHAIN_DIR) lint-fix

## fmt: Format Go source files
.PHONY: fmt
fmt:
	$(MAKE) -C $(CHAIN_DIR) fmt

# ── Protobuf ──────────────────────────────────────────────────────────────────

## proto-gen: Regenerate protobuf Go bindings
.PHONY: proto-gen
proto-gen:
	$(MAKE) -C $(CHAIN_DIR) proto-gen

# ── Local devnet ──────────────────────────────────────────────────────────────

## localnet: Init + start single-node local devnet
.PHONY: localnet
localnet: localnet-init localnet-start

## localnet-init: Initialise local devnet (run once)
.PHONY: localnet-init
localnet-init:
	$(MAKE) -C $(CHAIN_DIR) localnet-init

## localnet-start: Start local devnet node
.PHONY: localnet-start
localnet-start:
	$(MAKE) -C $(CHAIN_DIR) localnet-start

## localnet-stop: Stop local devnet node
.PHONY: localnet-stop
localnet-stop:
	$(MAKE) -C $(CHAIN_DIR) localnet-stop

## localnet-reset: Wipe and reinitialise local devnet
.PHONY: localnet-reset
localnet-reset:
	$(MAKE) -C $(CHAIN_DIR) localnet-reset

## localnet-status: Query local node status
.PHONY: localnet-status
localnet-status:
	$(MAKE) -C $(CHAIN_DIR) localnet-status

## localnet-log: Tail local node log
.PHONY: localnet-log
localnet-log:
	$(MAKE) -C $(CHAIN_DIR) localnet-log

# ── Docker ────────────────────────────────────────────────────────────────────

## docker-build: Build Docker image
.PHONY: docker-build
docker-build:
	$(MAKE) -C $(CHAIN_DIR) docker-build

## docker-run: Run single-node devnet in Docker
.PHONY: docker-run
docker-run:
	$(MAKE) -C $(CHAIN_DIR) docker-run

## docker-compose-up: Start full stack (node + optional monitoring)
.PHONY: docker-compose-up
docker-compose-up:
	$(MAKE) -C $(CHAIN_DIR) docker-compose-up

## docker-compose-down: Stop docker-compose stack
.PHONY: docker-compose-down
docker-compose-down:
	$(MAKE) -C $(CHAIN_DIR) docker-compose-down

# ── Tools ─────────────────────────────────────────────────────────────────────

## tools: Install all development tools (golangci-lint, goreleaser, etc.)
.PHONY: tools
tools:
	$(MAKE) -C $(CHAIN_DIR) tools

## install-ext-deps: Install extension npm dependencies
.PHONY: install-ext-deps
install-ext-deps:
	$(MAKE) -C $(EXT_DIR) install-deps

# ── Clean ─────────────────────────────────────────────────────────────────────

## clean: Remove all build artefacts
.PHONY: clean
clean:
	$(MAKE) -C $(CHAIN_DIR) clean
	$(MAKE) -C $(EXT_DIR) clean

## clean-all: Remove artefacts + Go build cache
.PHONY: clean-all
clean-all:
	$(MAKE) -C $(CHAIN_DIR) clean-all
	$(MAKE) -C $(EXT_DIR) clean

# ── Info ──────────────────────────────────────────────────────────────────────

## version: Print build metadata
.PHONY: version
version:
	$(MAKE) -C $(CHAIN_DIR) version

## help: Print all available targets
.PHONY: help
help:
	@echo ""
	@echo "ThreatAttest — Available Make Targets"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | \
		sed 's/^## //' | \
		column -t -s ':' | \
		sed 's/^/  /'
	@echo ""
	@echo "Sub-project targets:"
	@echo "  make -C chain     <target>   chain-specific targets"
	@echo "  make -C extension <target>   extension-specific targets"
	@echo ""