# Copyright (c) 2026 by Support Intelligence, Inc. All rights reserved.

# =============================================================================
# ThreatAttest Shield — Extension Makefile
# =============================================================================
#
# Usage:
#   make                  — validate + build (production)
#   make build            — production build → dist/
#   make build-dev        — development build (localhost API)
#   make pack             — build + zip → build/threatattest-shield-<ver>.zip
#   make pack-dev         — dev build + zip
#   make validate         — validate manifest + sources
#   make test             — run Node.js badge unit tests
#   make lint             — run ESLint
#   make clean            — remove dist/ build/
#   make install-deps     — npm install
# =============================================================================

SHELL    := /usr/bin/env bash
NODE     := node
NPM      := npm
.DEFAULT_GOAL := all

# ─── Targets ─────────────────────────────────────────────────────────────────

## all: validate then build
.PHONY: all
all: validate build

## build: Production build → dist/
.PHONY: build
build:
	@echo "  ► Building extension (production)"
	$(NODE) scripts/build.js
	@echo "  ✓ dist/ ready"

## build-dev: Development build (local API endpoint) → dist/
.PHONY: build-dev
build-dev:
	@echo "  ► Building extension (development)"
	$(NODE) scripts/build.js --dev
	@echo "  ✓ dist/ ready (dev)"

## pack: Build + zip for distribution
.PHONY: pack
pack:
	@echo "  ► Packing extension (production)"
	$(NODE) scripts/build.js
	$(NODE) scripts/pack.js
	@echo "  ✓ build/ ready"

## pack-dev: Dev build + zip
.PHONY: pack-dev
pack-dev:
	@echo "  ► Packing extension (development)"
	$(NODE) scripts/build.js --dev
	$(NODE) scripts/pack.js --dev
	@echo "  ✓ build/ ready (dev)"

## validate: Validate extension sources
.PHONY: validate
validate:
	@echo "  ► Validating extension sources"
	$(NODE) scripts/validate.js

## validate-dist: Validate built dist/ output
.PHONY: validate-dist
validate-dist:
	@echo "  ► Validating dist/"
	$(NODE) scripts/validate.js --dist

## test: Run Node.js unit tests
.PHONY: test
test:
	@echo "  ► Running extension tests"
	$(NODE) ../threatattest/tests/test_extension_badges.js

## lint: Run ESLint (requires npm install)
.PHONY: lint
lint:
	@if [ -d node_modules/.bin ]; then \
		echo "  ► ESLint"; \
		./node_modules/.bin/eslint src/ popup.js --ext .js; \
	else \
		echo "  ⚠  node_modules not found — run: make install-deps"; \
	fi

## lint-fix: Run ESLint with --fix
.PHONY: lint-fix
lint-fix:
	@if [ -d node_modules/.bin ]; then \
		./node_modules/.bin/eslint src/ popup.js --ext .js --fix; \
	else \
		echo "  ⚠  node_modules not found — run: make install-deps"; \
	fi

## install-deps: Install npm dev dependencies
.PHONY: install-deps
install-deps:
	$(NPM) install

## clean: Remove dist/ and build/
.PHONY: clean
clean:
	@echo "  ► Cleaning"
	@rm -rf dist/ build/
	@echo "  ✓ Cleaned"

## help: Print this help
.PHONY: help
help:
	@echo ""
	@echo "ThreatAttest Shield Extension — Build Targets"
	@echo ""
	@grep -E '^## ' $(MAKEFILE_LIST) | \
		sed 's/^## //' | \
		column -t -s ':' | \
		sed 's/^/  /'
	@echo ""