BINARY  := opencti-lookup
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

# macOS Developer ID signing / notarization (see nlink-jp/.github
# CONVENTIONS.md §Code Signing). Defaults match any Developer ID
# Application cert in the keychain and the org-standard notary
# profile. Builds without these fall back to ad-hoc / un-notarized
# with a one-line warning — see scripts/codesign-darwin.sh.
CODESIGN_IDENTITY ?= Developer ID Application
NOTARY_PROFILE    ?= nlink-jp-notary

# darwin ships arm64 only (no amd64, no universal). linux/windows keep their matrix.
PLATFORMS := \
	linux/amd64 \
	linux/arm64 \
	darwin/arm64 \
	windows/amd64

# Development OpenCTI stack (Phase 0, see docs/ja/opencti-lookup-phase0.ja.md).
COMPOSE     := podman compose --env-file dev/.env -f dev/compose.yaml
MINIO_IMAGE := localhost/opencti-lookup-dev/minio:RELEASE.2024-05-28T17-19-04Z

.PHONY: build build-all test lint check e2e package verify-release clean help vuln \
	dev-env dev-minio dev-up dev-down dev-ps dev-logs dev-health dev-reset

## build: Build for the current platform
build:
	@mkdir -p dist
	go build $(LDFLAGS) -o dist/$(BINARY) .
	@scripts/codesign-darwin.sh dist/$(BINARY) "$(CODESIGN_IDENTITY)"

## build-all: Cross-compile for all target platforms
build-all:
	@mkdir -p dist
	@for p in $(PLATFORMS); do os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = windows ] && ext=".exe"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o dist/$(BINARY)-$$os-$$arch$$ext . ; \
	done
	@scripts/codesign-darwin.sh dist/$(BINARY)-darwin-arm64 "$(CODESIGN_IDENTITY)" "$(BINARY)"

## test: Run the full test suite (offline). The e2e tests need the development
## stack and are not run here, but they are type-checked.
test:
	go test -race -cover ./...
	go vet -tags e2e ./...

## lint: Run golangci-lint
lint:
	golangci-lint run ./...

## check: Run lint + test + build-all
check: lint test build-all

## e2e: Live tests against the development OpenCTI 6.7.4 stack (make dev-up,
## seeded per docs/ja/opencti-lookup-phase0.ja.md). Runs as the read-only user
## and as admin; the tokens are read from dev/.env and never printed.
e2e: build
	@test -f dev/.env || { echo "e2e: dev/.env missing — run make dev-up and seed the stack first"; exit 2; }
	@. dev/.env && OPENCTI_E2E_URL=http://127.0.0.1:8080 \
		OPENCTI_E2E_ADMIN_TOKEN="$$OPENCTI_ADMIN_TOKEN" \
		OPENCTI_E2E_READONLY_TOKEN="$$OPENCTI_READONLY_TOKEN" \
		OPENCTI_E2E_BINARY="$(CURDIR)/dist/$(BINARY)" \
		go test -tags e2e -count=1 -v ./e2e/...

## vuln: known vulnerabilities in the modules and the standard library this
## build uses (govulncheck). `package` depends on it, so a release cannot be
## built past a finding. It needs the network, and its database changes under
## an unchanged tree: a finding can appear without a commit.
vuln:
	govulncheck ./...

## package: Build all platforms, archive with version suffix (zip for
## darwin/windows, tar.gz for linux), bundle the canonical binary +
## README.md + LICENSE, and notarize the darwin build. Asset naming
## follows the org Release Archive Standard
## (opencti-lookup-vX.Y.Z-<os>-<arch>.<ext>).
package: vuln build-all
	@cd dist && for p in $(PLATFORMS); do os=$${p%/*}; arch=$${p#*/}; \
		ext=""; [ "$$os" = windows ] && ext=".exe"; \
		stage=_pkg; rm -rf $$stage; mkdir -p $$stage; \
		cp "$(BINARY)-$$os-$$arch$$ext" "$$stage/$(BINARY)$$ext"; \
		cp ../README.md ../LICENSE $$stage/; \
		base="$(BINARY)-$(VERSION)-$$os-$$arch"; \
		if [ "$$os" = linux ]; then ( cd $$stage && COPYFILE_DISABLE=1 tar --no-xattrs -czf "../$$base.tar.gz" * ); \
		else ( cd $$stage && zip -q "../$$base.zip" * ); fi; \
		rm -rf $$stage; \
	done
	@scripts/notarize-darwin.sh dist/$(BINARY)-$(VERSION)-darwin-arm64.zip "$(NOTARY_PROFILE)"

## verify-release: refuse to release a zip that is un-notarized, stale, does
## not unpack, does not run, or holds a build from another tag, and a linux
## archive that carries macOS metadata or anything but its canonical files.
## Every step fails closed; only the spctl line is informational.
verify-release:
	@test -f "dist/$(BINARY)-$(VERSION)-darwin-arm64.zip.notarized" || { \
		echo "verify-release: FAIL — $(BINARY)-$(VERSION)-darwin-arm64.zip has no notarization marker."; \
		echo "  make package must end with '[notarize] ...: Accepted'. Do not upload this zip."; \
		exit 1; }
	@test "dist/$(BINARY)-$(VERSION)-darwin-arm64.zip.notarized" -nt "dist/$(BINARY)-$(VERSION)-darwin-arm64.zip" || { \
		echo "verify-release: FAIL — the zip was rebuilt after its marker (re-run make package)."; \
		exit 1; }
	@tmp=$$(mktemp -d); rc=0; \
		if ! unzip -oq "dist/$(BINARY)-$(VERSION)-darwin-arm64.zip" -d "$$tmp"; then \
			echo "verify-release: FAIL — the zip does not unpack. Do not upload it."; rc=1; \
		elif ! out=$$("$$tmp/$(BINARY)" --version 2>&1); then \
			echo "verify-release: FAIL — the packaged binary does not run:"; \
			echo "  $$out"; rc=1; \
		elif ! printf '%s\n' "$$out" | grep -qF "$(VERSION)"; then \
			echo "verify-release: FAIL — the packaged binary reports \"$$out\", not $(VERSION)."; \
			echo "  The zip holds a build from another tag (re-run make package)."; rc=1; \
		else \
			echo "  $$out"; \
			spctl -a -vv -t install "$$tmp/$(BINARY)" 2>&1 | head -2 || true; \
		fi; \
		rm -rf "$$tmp"; \
		exit $$rc
	@for p in $(PLATFORMS); do os=$${p%/*}; arch=$${p#*/}; \
		[ "$$os" = linux ] || continue; \
		f="dist/$(BINARY)-$(VERSION)-$$os-$$arch.tar.gz"; \
		names=$$(tar --options 'tar:!mac-ext' -tzf "$$f") || { echo "verify-release: FAIL — $$f does not list."; exit 1; }; \
		if printf '%s\n' "$$names" | grep -qE '(^|/)(\._|PaxHeader|__MACOSX)'; then \
			echo "verify-release: FAIL — $$f carries macOS metadata entries."; \
			echo "  macOS tar writes ._ members unless COPYFILE_DISABLE=1 is set, and lists them only with !mac-ext."; \
			exit 1; fi; \
		xh=$$(python3 -c 'import sys, tarfile; print(" ".join(m.name for m in tarfile.open(sys.argv[1]) if any(k.startswith(("LIBARCHIVE.xattr.", "SCHILY.xattr.")) for k in m.pax_headers)))' "$$f") || { \
			echo "verify-release: FAIL — $$f cannot be read for its pax headers (python3 tarfile)."; exit 1; }; \
		if [ -n "$$xh" ]; then \
			echo "verify-release: FAIL — $$f carries extended attributes as pax headers ($$xh)."; \
			echo "  macOS tar writes them unless called with --no-xattrs; COPYFILE_DISABLE alone does not."; \
			exit 1; fi; \
		got=$$(printf '%s\n' "$$names" | LC_ALL=C sort | tr '\n' ' '); \
		want=$$(printf '%s\n' "$(BINARY)" README.md LICENSE | LC_ALL=C sort | tr '\n' ' '); \
		if [ "$$got" != "$$want" ]; then \
			echo "verify-release: FAIL — $$f holds $$got; expected $$want"; exit 1; fi; \
	done
	@echo "verify-release: OK ($(VERSION), notarized, unpacks, runs, reports its version, clean linux archives)"

## clean: Remove build artifacts
clean:
	rm -rf dist/

## help: Show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'

## dev-env: Generate dev/.env with random local secrets (once)
dev-env:
	@bash dev/gen-env.sh

## dev-minio: Build MinIO from the archived official source (once)
dev-minio:
	@podman image exists $(MINIO_IMAGE) || podman build -t $(MINIO_IMAGE) -f dev/minio/Containerfile dev/minio

## dev-up: Start the OpenCTI 6.7.4 development stack
dev-up: dev-env dev-minio
	$(COMPOSE) up -d

## dev-down: Stop the stack, keeping its data
dev-down:
	$(COMPOSE) down

## dev-ps: Show container state
dev-ps:
	$(COMPOSE) ps

## dev-logs: Follow the platform log
dev-logs:
	$(COMPOSE) logs -f opencti

## dev-health: One-shot health probe of the platform
dev-health:
	@. dev/.env && curl -sf "http://127.0.0.1:8080/health?health_access_key=$$OPENCTI_HEALTHCHECK_ACCESS_KEY" && echo || { echo "not healthy yet"; exit 1; }

## dev-reset: Stop the stack AND delete its volumes (all ingested data)
dev-reset:
	$(COMPOSE) down -v

# Homebrew tap generation (see scripts/release-brew.mk). After `make package`,
# `make brew` generates this formula from the built darwin-arm64 zip into the
# local nlink-jp/homebrew-tap checkout. The package target is unchanged.
BREW_KIND := formula
BREW_DESC := Read-only threat-intelligence lookups against your OpenCTI instance
include scripts/release-brew.mk
