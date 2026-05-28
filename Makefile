# Telltale - Agent Detection and Response
# Build and install without root. Logs default to the repo's logs/ dir.

PREFIX ?= $(HOME)/.local
BINDIR = $(PREFIX)/bin
SYSTEMD_USER_DIR = $(HOME)/.config/systemd/user
PROJECT_DIR = $(shell pwd)
LOG_DIR = $(PROJECT_DIR)/logs
STATE_DIR = $(PROJECT_DIR)/state
LOG_PATH = $(LOG_DIR)/adr-events.jsonl
STATE_PATH = $(STATE_DIR)/adr-state.json
SCAN_ROOT = $(HOME)
PUBLIC_RELEASE_BRANCH ?= public-main
PUBLIC_RELEASE_REMOTE ?= git@github.com:Dark-Roast-Cyber/telltale.git

.PHONY: build install uninstall clean test fmt clippy check release-tree-clean release-context release-staged-review release-preflight status logs scan-dry scan help

## Show this help
help:
	@echo "Telltale - Agent Detection and Response"
	@echo ""
	@echo "Targets:"
	@grep -h '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | sort

## Build release binary
build:
	cargo build --release
	@echo "Binary: target/release/adr"

## Install binary + systemd user service + timer
install: build
	@echo "Installing adr to $(BINDIR)..."
	mkdir -p $(BINDIR)
	install -m 0755 target/release/adr $(BINDIR)/adr
	@echo "Installing systemd user units..."
	mkdir -p $(SYSTEMD_USER_DIR)
	@sed \
		-e 's|__PROJECT_DIR__|$(PROJECT_DIR)|g' \
		-e 's|__LOG_PATH__|$(LOG_PATH)|g' \
		-e 's|__STATE_PATH__|$(STATE_PATH)|g' \
		-e 's|__SCAN_ROOT__|$(SCAN_ROOT)|g' \
		-e 's|__BINDIR__|$(BINDIR)|g' \
		config/examples/adr-scan.service.in > $(SYSTEMD_USER_DIR)/adr-scan.service
	@sed \
		-e 's|__PROJECT_DIR__|$(PROJECT_DIR)|g' \
		config/examples/adr-scan.timer.in > $(SYSTEMD_USER_DIR)/adr-scan.timer
	@echo "Enabling timer..."
	systemctl --user daemon-reload
	systemctl --user enable adr-scan.timer
	@echo ""
	@echo "Installed. To start now:"
	@echo "  systemctl --user start adr-scan.timer"
	@echo "  systemctl --user status adr-scan.timer"
	@echo ""
	@echo "To view logs:"
	@echo "  journalctl --user -u adr-scan.service -f"

## Uninstall systemd units (binary stays in BINDIR)
uninstall:
	-systemctl --user stop adr-scan.timer 2>/dev/null
	-systemctl --user disable adr-scan.timer 2>/dev/null
	rm -f $(SYSTEMD_USER_DIR)/adr-scan.service
	rm -f $(SYSTEMD_USER_DIR)/adr-scan.timer
	systemctl --user daemon-reload
	@echo "Uninstalled. Binary still at $(BINDIR)/adr"

## Run tests
test:
	cargo test

## Format check
fmt:
	cargo fmt --check

## Lint
clippy:
	cargo clippy --all-targets -- -D warnings

## Full verification
check: fmt clippy test
	@echo "All checks passed."

## Verify the release working tree is clean
release-tree-clean:
	@test -z "$$(git status --short)" || { git status --short; echo "Working tree must be clean before release preflight."; exit 1; }

## Verify the public release branch and remote
release-context:
	@test -n "$(strip $(PUBLIC_RELEASE_BRANCH))" || { echo "PUBLIC_RELEASE_BRANCH must be set."; exit 1; }
	@test -n "$(strip $(PUBLIC_RELEASE_REMOTE))" || { echo "PUBLIC_RELEASE_REMOTE must be set."; exit 1; }
	@branch="$$(git branch --show-current)"; \
	if [ "$$branch" != "$(PUBLIC_RELEASE_BRANCH)" ]; then \
		echo "Expected release branch $(PUBLIC_RELEASE_BRANCH), got $$branch."; \
		exit 1; \
	fi
	@fetch_url="$$(git remote get-url origin 2>/dev/null || true)"; \
	push_url="$$(git remote get-url --push origin 2>/dev/null || true)"; \
	if [ "$$fetch_url" != "$(PUBLIC_RELEASE_REMOTE)" ] || [ "$$push_url" != "$(PUBLIC_RELEASE_REMOTE)" ]; then \
		echo "Expected origin fetch/push URL $(PUBLIC_RELEASE_REMOTE)."; \
		git remote -v; \
		exit 1; \
	fi
	@echo "Release context: branch $(PUBLIC_RELEASE_BRANCH), origin $(PUBLIC_RELEASE_REMOTE)"

## Show staged paths reviewed for public release
release-staged-review:
	@staged="$$(git diff --cached --name-only)"; \
	if [ -n "$$staged" ]; then \
		echo "$$staged"; \
	else \
		echo "Staged paths: none"; \
	fi

## Public release preflight
release-preflight: release-tree-clean release-context release-staged-review check
	cargo run -- scan --once --dry-run --root tests/fixtures/session_stores
	cargo run -- rules validate --rules config/rules/tool-call-regex.yaml

## Show timer status
status:
	@systemctl --user status adr-scan.timer 2>/dev/null || echo "Timer not installed"
	@echo ""
	@echo "Log: $(LOG_PATH)"
	@echo "State: $(STATE_PATH)"
	@echo "Scan root: $(SCAN_ROOT)"
	@ls -lh $(LOG_PATH) 2>/dev/null || echo "No log file yet"

## Tail the Telltale event log
logs:
	@tail -f $(LOG_PATH) 2>/dev/null || echo "No log file yet"

## One-shot scan (dry run, fixture-safe)
scan-dry:
	$(BINDIR)/adr scan --once --dry-run --root tests/fixtures/session_stores

## One-shot scan (real, writes to log)
scan:
	$(BINDIR)/adr scan --once --emit-activity --root $(SCAN_ROOT) --log-path $(LOG_PATH) --state-path $(STATE_PATH)

## Clean build artifacts
clean:
	cargo clean
