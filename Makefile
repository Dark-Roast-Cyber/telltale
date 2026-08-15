# Telltale - Agent Detection and Response
# Build and install without root. Logs default to the repo's logs/ dir.

PREFIX ?= $(HOME)/.local
BINDIR = $(PREFIX)/bin
CONFIG_ROOT ?= $(if $(XDG_CONFIG_HOME),$(XDG_CONFIG_HOME),$(HOME)/.config)
SYSTEMD_USER_DIR = $(CONFIG_ROOT)/systemd/user
TELLTALE_ENV_PATH = $(CONFIG_ROOT)/telltale/telltale.env
PROJECT_DIR = $(shell pwd)
LOG_DIR = $(PROJECT_DIR)/logs
STATE_DIR = $(PROJECT_DIR)/state
LOG_PATH = $(LOG_DIR)/telltale-events.jsonl
STATE_PATH = $(STATE_DIR)/telltale-state.json
SCAN_ROOT = $(HOME)
PUBLIC_RELEASE_BRANCH ?= main
PUBLIC_RELEASE_REMOTE ?= git@github.com:Dark-Roast-Cyber/telltale.git
PUBLIC_RELEASE_UPSTREAM ?= origin/$(PUBLIC_RELEASE_BRANCH)
RELEASE_ARTIFACT_DIR ?= release-downloads
CARGO_LOCKED ?=
PACKAGE_ORDER = telltale-schema telltale-rules telltale-sources telltale-detect telltale-core telltale-cli

.PHONY: build install uninstall clean test fmt clippy check public-push-review release-context-check release-tag-review release-crate-manifest release-artifact-manifest release-canonical-identity-check release-public-docs-check release-fixture-smoke release-preflight package-manifest package-verify status logs scan-dry scan help

## Show this help
help:
	@echo "Telltale - Agent Detection and Response"
	@echo ""
	@echo "Targets:"
	@grep -h '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | sort

## Build release binaries
build:
	cargo build $(CARGO_LOCKED) --release
	@echo "Binary: target/release/telltale"

## Install the canonical developer binary without activating schedules
install: build
	@echo "Installing telltale to $(BINDIR)..."
	mkdir -p "$(BINDIR)"
	install -m 0755 target/release/telltale "$(BINDIR)/telltale"
	@echo ""
	@echo "Installed canonical developer binary: $(BINDIR)/telltale"
	@echo "This target does not install or activate a user schedule."
	@echo "Use scripts/install-telltale --with-timer for canonical schedule setup."
	@echo ""
	@echo "To view logs:"
	@echo "  journalctl --user -u telltale-scan.service -f"

## Uninstall systemd units (binary stays in BINDIR)
uninstall:
	-systemctl --user stop telltale-scan.timer 2>/dev/null
	-systemctl --user disable telltale-scan.timer 2>/dev/null
	rm -f $(SYSTEMD_USER_DIR)/telltale-scan.service
	rm -f $(SYSTEMD_USER_DIR)/telltale-scan.timer
	systemctl --user daemon-reload
	@echo "Uninstalled units. Binary remains at $(BINDIR)/telltale"

## Run tests
test:
	cargo test $(CARGO_LOCKED)

## Format check
fmt:
	cargo fmt --check

## Lint
clippy:
	cargo clippy $(CARGO_LOCKED) --all-targets -- -D warnings

## Full verification
check: fmt clippy test
	@echo "All checks passed."

## Show public push review context
public-push-review:
	@echo "Public branch: $$(git branch --show-current)"
	@echo "Origin fetch: $$(git remote get-url origin 2>/dev/null || echo '(none)')"
	@echo "Origin push: $$(git remote get-url --push origin 2>/dev/null || echo '(none)')"
	@echo ""
	@echo "Working tree status:"
	@status="$$(git status --short)"; \
	if [ -n "$$status" ]; then printf '%s\n' "$$status" | sed 's/^/  /'; else echo "  clean"; fi
	@echo ""
	@echo "Staged paths:"
	@staged="$$(git diff --cached --name-only)"; \
	if [ -n "$$staged" ]; then printf '%s\n' "$$staged" | sed 's/^/  /'; else echo "  none"; fi
	@echo ""
	@echo "Before pushing public history, review docs/release-readiness.md and run make release-preflight."

## Verify release context: clean tree, correct branch/remote, upstream alignment, staged paths
release-context-check:
	@echo "=== Release context check ==="
	@echo ""
	@echo "-- 1. Working tree clean --"
	@test -z "$$(git status --short)" || { git status --short; echo "Working tree must be clean before release preflight."; exit 1; }
	@echo ""
	@echo "-- 2. Release branch and remote --"
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
	@echo ""
	@echo "-- 3. Public branch alignment --"
	@test -n "$(strip $(PUBLIC_RELEASE_BRANCH))" || { echo "PUBLIC_RELEASE_BRANCH must be set."; exit 1; }
	@test -n "$(strip $(PUBLIC_RELEASE_UPSTREAM))" || { echo "PUBLIC_RELEASE_UPSTREAM must be set."; exit 1; }
	@git rev-parse --verify --quiet "$(PUBLIC_RELEASE_UPSTREAM)^{commit}" >/dev/null || { \
		echo "Missing public upstream $(PUBLIC_RELEASE_UPSTREAM). Run git fetch before release preflight."; \
		exit 1; \
	}
	@set -- $$(git rev-list --left-right --count "$(PUBLIC_RELEASE_UPSTREAM)...HEAD"); \
	behind="$$1"; ahead="$$2"; \
	if [ "$$behind" -gt 0 ]; then \
		echo "Public branch alignment: HEAD is behind $(PUBLIC_RELEASE_UPSTREAM) by $$behind commit(s). Fetch and reconcile before release."; \
		exit 1; \
	fi; \
	if [ "$$ahead" -gt 0 ]; then \
		echo "Public branch alignment: HEAD is ahead of $(PUBLIC_RELEASE_UPSTREAM) by $$ahead commit(s); review before pushing."; \
	else \
		echo "Public branch alignment: $(PUBLIC_RELEASE_UPSTREAM) matches HEAD."; \
	fi
	@echo ""
	@echo "-- 4. Staged paths --"
	@staged="$$(git diff --cached --name-only)"; \
	if [ -n "$$staged" ]; then \
		echo "$$staged"; \
	else \
		echo "Staged paths: none"; \
	fi

## Verify the public release tag matches the Cargo package version
release-tag-review:
	@package_version="$$(cargo metadata --no-deps $(CARGO_LOCKED) --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"; \
	test -n "$$package_version" || { echo "Could not determine Cargo package version."; exit 1; }; \
	expected_tag="v$$package_version"; \
	release_tag="$(PUBLIC_RELEASE_TAG)"; \
	if [ -z "$$release_tag" ]; then release_tag="$$expected_tag"; fi; \
	if [ "$$release_tag" != "$$expected_tag" ]; then \
		echo "Expected public release tag $$expected_tag for package version $$package_version, got $$release_tag."; \
		exit 1; \
	fi; \
	if git rev-parse --verify --quiet "refs/tags/$$release_tag" >/dev/null; then \
		echo "Public release tag $$release_tag already exists locally."; \
		exit 1; \
	fi; \
	echo "Public release tag: $$release_tag (package $$package_version)"

## List and validate Cargo source package contents
release-crate-manifest:
	@$(MAKE) --no-print-directory package-manifest

## List and validate all Phase 0.6 Cargo package inventories
package-manifest:
	@set -eu; \
	for package in $(PACKAGE_ORDER); do \
		echo "=== $$package ==="; \
		manifest="$$(cargo package $(CARGO_LOCKED) --list --allow-dirty -p "$$package")"; \
		printf '%s\n' "$$manifest"; \
		case "$$manifest" in *"Cargo.toml"*) ;; *) echo "$$package is missing Cargo.toml"; exit 1 ;; esac; \
		case "$$manifest" in *"README.md"*) ;; *) echo "$$package is missing README.md"; exit 1 ;; esac; \
		case "$$package" in \
			telltale-rules) case "$$manifest" in *"data/tool-call-regex.yaml"*) ;; *) echo "$$package is missing packaged rules data"; exit 1 ;; esac ;; \
		telltale-schema|telltale-rules|telltale-sources|telltale-detect|telltale-core) \
			for path in $$manifest; do \
				case "$$path" in \
					.cargo_vcs_info.json|Cargo.lock|Cargo.toml|Cargo.toml.orig|README.md|LICENSE|build.rs|src/*|examples/*|data/*|tests/fixtures/*) ;; \
					*) echo "$$package includes unexpected path: $$path"; exit 1 ;; \
				 esac; \
			done ;; \
			telltale-cli) \
			for path in $$manifest; do \
				case "$$path" in \
					.cargo_vcs_info.json|Cargo.lock|Cargo.toml|Cargo.toml.orig|crates/telltale-cli/README.md|LICENSE|build.rs|benches/benchmarks.rs|src/*|schemas/event.schema.json|schemas/historical/*|config/rules/tool-call-regex.yaml|tests/fixtures/*) ;; \
					*) echo "$$package includes unexpected path: $$path"; exit 1 ;; \
				 esac; \
			done; \
			case "$$manifest" in *"crates/telltale-cli/README.md"*) ;; *) echo "$$package is missing its package README"; exit 1 ;; esac; \
			case "$$manifest" in *"src/main.rs"*) ;; *) echo "$$package is missing the telltale binary source"; exit 1 ;; esac; \
			case "$$manifest" in *"benches/benchmarks.rs"*) ;; *) echo "$$package is missing the declared benchmark source"; exit 1 ;; esac; \
			case "$$manifest" in *"config/rules/tool-call-regex.yaml"*) ;; *) echo "$$package is missing canonical rules"; exit 1 ;; esac ;; \
		esac; \
		done

## Verify normalized packages, an external consumer, and the packaged CLI
package-verify:
	@scripts/package-verify

## List and validate downloaded public release archives
release-artifact-manifest:
	@RELEASE_ARTIFACT_DIR="$(RELEASE_ARTIFACT_DIR)" python3 scripts/release-artifact-manifest

## Run focused public documentation boundary checks
release-public-docs-check:
	cargo test $(CARGO_LOCKED) --quiet public_docs_

## Run fixture-safe release smoke checks
release-fixture-smoke:
	@set -eu; \
	 smoke_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/telltale-fixture-smoke.XXXXXX")"; \
	 trap 'rm -rf "$$smoke_dir"' EXIT INT TERM; \
		 cargo run $(CARGO_LOCKED) --bin telltale -- scan --once --dry-run --no-local-config --emit-activity --emit-session-risk-summary --root tests/fixtures/session_stores --state-path "$$smoke_dir/state.json" --log-path "$$smoke_dir/events.jsonl"; \
		 cargo run $(CARGO_LOCKED) --bin telltale -- rules validate --no-local-config

## Verify active release surfaces use only canonical Telltale identities
release-canonical-identity-check:
	@for expected in config/examples/telltale-scan.service config/examples/telltale-scan.timer config/examples/telltale-scan-task.xml; do test -f "$$expected" || { echo "missing canonical release example: $$expected"; exit 1; }; done
	@grep -Eq 'target/.*/release/telltale|telltale-[^[:space:]]+\.(tar\.gz|zip)' .github/workflows/release.yml
	@grep -q 'telltale-scan.service' .github/workflows/release.yml

## Public release preflight
release-preflight: release-context-check release-tag-review release-crate-manifest release-canonical-identity-check package-verify release-public-docs-check release-artifact-manifest check release-fixture-smoke

## Show timer status
status:
	@systemctl --user status telltale-scan.timer 2>/dev/null || echo "Timer not installed"
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
	$(BINDIR)/telltale scan --once --dry-run --root tests/fixtures/session_stores

## One-shot scan (real, writes to log)
scan:
	$(BINDIR)/telltale scan --once --emit-activity --root $(SCAN_ROOT) --log-path $(LOG_PATH) --state-path $(STATE_PATH)

## Clean build artifacts
clean:
	cargo clean
