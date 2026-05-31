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
PUBLIC_RELEASE_UPSTREAM ?= origin/$(PUBLIC_RELEASE_BRANCH)
RELEASE_ARTIFACT_DIR ?= release-downloads

.PHONY: build install uninstall clean test fmt clippy check public-push-review release-tree-clean release-context release-public-alignment release-tag-review release-staged-review release-crate-manifest release-artifact-manifest release-public-docs-check release-fixture-smoke release-preflight status logs scan-dry scan help

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

## Review public branch alignment before release
release-public-alignment:
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

## Verify the public release tag matches the Cargo package version
release-tag-review:
	@package_version="$$(cargo metadata --no-deps --format-version 1 | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"; \
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

## Show staged paths reviewed for public release
release-staged-review:
	@staged="$$(git diff --cached --name-only)"; \
	if [ -n "$$staged" ]; then \
		echo "$$staged"; \
	else \
		echo "Staged paths: none"; \
	fi

## List and validate Cargo source package contents
release-crate-manifest:
	@manifest="$$(cargo package --list --allow-dirty)"; \
	printf '%s\n' "$$manifest"; \
	unexpected="$$(printf '%s\n' "$$manifest" | while IFS= read -r path; do \
		case "$$path" in \
			AGENTS.md|PLAN.md|VISION.md|IDEAS.md|docs/internal/*|docs/CHANGELOG.md|docs/research-urls.md|docs/siem-logging.md|docs/splunk-content.md|skills/*|.ai/*|scripts/ralph*|scripts/inspiration/*|tasks/*|.opencode/*|logs/*|state/*|artifacts/*|release-downloads/*|runtime/ralph/*|config/examples/splunk-*.conf|config/examples/splunk-*.xml) \
				printf '%s\n' "$$path" ;; \
		esac; \
	done)"; \
	if [ -n "$$unexpected" ]; then \
		echo "Cargo package includes host-only release material:"; \
		printf '%s\n' "$$unexpected"; \
		exit 1; \
	fi

## List and validate downloaded public release archives
release-artifact-manifest:
	@test -d "$(RELEASE_ARTIFACT_DIR)" || { echo "Release artifact directory not found: $(RELEASE_ARTIFACT_DIR)"; exit 1; }
	@archives="$$(find "$(RELEASE_ARTIFACT_DIR)" -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) | sort)"; \
	test -n "$$archives" || { echo "No release archives found in $(RELEASE_ARTIFACT_DIR)."; exit 1; }; \
	checksum_file="$(RELEASE_ARTIFACT_DIR)/SHA256SUMS"; \
	if [ -f "$$checksum_file" ]; then \
		expected="$$(for archive in $$archives; do basename "$$archive"; done | sort)"; \
		listed="$$(awk '{ print $$2 }' "$$checksum_file" | sed 's/^\*//' | sort)"; \
		if [ "$$expected" != "$$listed" ]; then \
			echo "SHA256SUMS entries must match release archives in $(RELEASE_ARTIFACT_DIR)."; \
			echo "Expected archives:"; printf '%s\n' "$$expected"; \
			echo "Checksum entries:"; printf '%s\n' "$$listed"; \
			exit 1; \
		fi; \
		(cd "$(RELEASE_ARTIFACT_DIR)" && sha256sum --check SHA256SUMS); \
	fi; \
	for archive in $$archives; do \
		echo "Archive: $$archive"; \
		case "$$archive" in \
			*.tar.gz) entries="$$(tar -tzf "$$archive")" ;; \
			*.zip) command -v unzip >/dev/null || { echo "unzip is required to inspect $$archive."; exit 1; }; entries="$$(unzip -Z1 "$$archive")" ;; \
			*) echo "Unsupported release archive: $$archive"; exit 1 ;; \
		esac; \
		printf '%s\n' "$$entries" | sed 's/^/  /'; \
		entry_count="$$(printf '%s\n' "$$entries" | sed '/^$$/d' | wc -l | tr -d ' ')"; \
		if [ "$$entry_count" -ne 1 ]; then \
			echo "Release archive $$archive must contain exactly one binary entry."; \
			exit 1; \
		fi; \
		unexpected="$$(printf '%s\n' "$$entries" | awk '$$0 != "adr" && $$0 != "adr.exe" { print }')"; \
		if [ -n "$$unexpected" ]; then \
			echo "Unexpected release archive entries in $$archive:"; \
			printf '%s\n' "$$unexpected"; \
			exit 1; \
		fi; \
	done

## Run focused public documentation boundary checks
release-public-docs-check:
	cargo test --quiet readme_local_markdown_links_resolve
	cargo test --quiet public_docs_local_markdown_links_resolve
	cargo test --quiet public_docs_local_markdown_links_target_tracked_content
	cargo test --quiet public_surfaces_do_not_reintroduce_split_checkout_guidance
	cargo test --quiet public_release_workflows_do_not_reference_host_only_paths
	cargo test --quiet public_docs_do_not_contain_host_absolute_home_paths
	cargo test --quiet public_docs_do_not_link_to_host_only_paths
	cargo test --quiet host_only_release_paths_remain_ignored
	cargo test --quiet public_docs_linked_example_configs_are_public_safe

## Run fixture-safe release smoke checks
release-fixture-smoke:
	cargo run -- scan --once --dry-run --emit-activity --emit-session-risk-summary --root tests/fixtures/session_stores
	cargo run -- rules validate --rules config/rules/tool-call-regex.yaml

## Public release preflight
release-preflight: release-tree-clean release-context release-public-alignment release-tag-review release-staged-review release-crate-manifest release-public-docs-check check release-fixture-smoke

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
