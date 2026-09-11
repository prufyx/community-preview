PYTHON ?= python3
GO ?= go
RELEASE_POLICY := release/community-shipping-policy-v2.json

.PHONY: release-gate-test release-manifest

release-gate-test:
	$(PYTHON) -B -m unittest release/test_community_release_gate.py
	$(PYTHON) -B -m unittest release/test_community_staging_receipt.py
	$(PYTHON) -B -m unittest release/test_community_publisher_contract.py
	$(PYTHON) -B -m unittest scripts/test_package_knowledge.py
	$(PYTHON) -B -m unittest scripts/test_contribution_packet.py
	$(PYTHON) -B -m unittest scripts/test_contribution_candidates.py
	$(PYTHON) -B -m unittest scripts/test_source_corpus.py
	$(PYTHON) -B scripts/test_public_source_capture.py
	$(PYTHON) -B scripts/test_support_inventory.py

release-manifest:
	@test -n "$(OUTPUT)" || { echo "OUTPUT=/absolute/path/SOURCE-MANIFEST.json is required" >&2; exit 2; }
	$(PYTHON) -B release/community-release-gate.py --source-root .. --policy $(RELEASE_POLICY) --go $(GO) generate --output "$(OUTPUT)"
