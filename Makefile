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

.PHONY: build install uninstall clean test fmt clippy status logs help

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
