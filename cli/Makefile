GO ?= go
MAINTAINER ?= go run ./cmd/prufyx-maintainer
RELEASE_POLICY := release/community-shipping-policy-v2.json

.PHONY: release-gate-test release-manifest

release-gate-test:
	$(GO) test ./internal/maintainer/...

release-manifest:
	@test -n "$(OUTPUT)" || { echo "OUTPUT=/absolute/path/SOURCE-MANIFEST.json is required" >&2; exit 2; }
	$(MAINTAINER) release-gate generate --source-root .. --policy $(RELEASE_POLICY) --go $(GO) --output "$(OUTPUT)"
