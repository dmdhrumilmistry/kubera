# Kubera developer tasks. Run `make help` for the list.
#
# Install location follows the usual conventions: `make install` puts the
# binary in $(DESTDIR)$(PREFIX)/bin. Termux exports PREFIX
# (/data/data/com.termux/files/usr), so on Termux it lands on your PATH
# without sudo; elsewhere the default is /usr/local.

CARGO       ?= cargo
PREFIX      ?= /usr/local
BINDIR      ?= $(PREFIX)/bin
DESTDIR     ?=
BIN         := kubera
RELEASE_BIN := target/release/$(BIN)
TERMUX_IMAGE ?= termux/termux-docker:x86_64
# Extra `docker run` flags (e.g. --network host). Note: the image's entrypoint
# resets the environment, so variables passed with -e do not reach the build.
TERMUX_DOCKER_ARGS ?=
DOCKER      ?= docker

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "; printf "Usage: make <target>\n\nTargets:\n"} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Debug build
	$(CARGO) build --locked

.PHONY: release
release: ## Optimised release build (target/release/kubera)
	$(CARGO) build --release --locked

.PHONY: install
install: release ## Install to $(DESTDIR)$(BINDIR) (Termux: $PREFIX/bin)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(RELEASE_BIN)" "$(DESTDIR)$(BINDIR)/$(BIN)"
	@echo "installed $(DESTDIR)$(BINDIR)/$(BIN)"

.PHONY: uninstall
uninstall: ## Remove the installed binary
	rm -f "$(DESTDIR)$(BINDIR)/$(BIN)"

.PHONY: test
test: ## Unit + integration tests
	$(CARGO) test --locked --all-targets

.PHONY: templates-test
templates-test: ## Run every template's positive/negative samples
	$(CARGO) run --locked -q -- templates test

.PHONY: fmt
fmt: ## Format the code
	$(CARGO) fmt --all

.PHONY: lint
lint: ## rustfmt check + clippy (warnings are errors)
	$(CARGO) fmt --all --check
	$(CARGO) clippy --all-targets --locked -- -D warnings

.PHONY: scan
scan: release ## Scan this repository (files and history) with kubera itself
	./$(RELEASE_BIN) scan fs . --exclude-path 'target/**' --exclude-path 'docs/book/**' --fail
	./$(RELEASE_BIN) scan git . --fail

.PHONY: audit
audit: ## Check dependencies for known vulnerabilities (needs cargo-audit)
	$(CARGO) audit

.PHONY: check
check: lint test templates-test scan ## Everything CI runs (except audit/MSRV/Termux)

.PHONY: docs
docs: ## Build the documentation site (needs mdbook)
	mdbook build docs

.PHONY: docs-serve
docs-serve: ## Serve the docs with live reload on http://localhost:3000
	mdbook serve docs --open

.PHONY: tui
tui: build ## Launch the interactive TUI (debug build)
	./target/debug/$(BIN)

.PHONY: screenshots
screenshots: ## Regenerate the docs images from the real TUI/CLI code
	$(CARGO) run --locked -q --example screenshots -- docs/src/images

.PHONY: test-termux
test-termux: ## Build + test inside a Termux (Android) container (needs Docker)
	$(DOCKER) run --rm $(TERMUX_DOCKER_ARGS) -v "$(CURDIR):/src:ro" $(TERMUX_IMAGE) bash -c '\
		set -e; mkdir -p $$HOME/kubera; \
		tar -C /src --exclude=./target --exclude=./docs/book -cf - . | tar -C $$HOME/kubera -xf -; \
		cd $$HOME/kubera && bash scripts/termux-test.sh'

.PHONY: clean
clean: ## Remove build artefacts
	$(CARGO) clean
	rm -rf docs/book
