#!/usr/bin/env python3
"""Integration checks for the generated Community support inventory."""
from __future__ import annotations

import importlib.util
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/generate_support_inventory.py"
MANIFEST = ROOT / "docs/data/selected-source-records-v1.json"
OUTPUT = ROOT / "docs/generated/community-support-inventory.json"
MARKDOWN = ROOT / "docs/generated/community-support-inventory.md"
RULES = ROOT / "internal/cncfcheck/data/rules.json"
CERT = ROOT / "internal/certmanagervalues/source-contract-v1.json"
PROMETHEUS = ROOT / "internal/prometheusmode/source-contract-v1.json"
SPIFFE = ROOT / "internal/spiffex509svid/data/profile.json"
CLOUDEVENTS = ROOT / "internal/cloudeventsstructuredjson/data/profile.json"
TIKV = ROOT / "internal/tikvgcpv2/data/profile.json"
SPEC = importlib.util.spec_from_file_location("support_inventory", SCRIPT)
assert SPEC and SPEC.loader
inventory_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory_module)


def read(path: Path) -> dict:
    return json.loads(path.read_text())


class SupportInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run([
            sys.executable, str(SCRIPT), "--selected-source-manifest", str(MANIFEST),
            "--json-output", str(OUTPUT), "--markdown-output", str(MARKDOWN), "--check",
        ], check=True)
        cls.inventory = read(OUTPUT)
        cls.rules = read(RULES)
        cls.manifest = read(MANIFEST)

    def test_rule_pack_and_named_contracts_are_all_represented(self):
        projects = {item["projectID"]: item for item in self.inventory["projects"]}
        expected_rules = {entry["rule"]["id"] for entry in self.rules["entries"]}
        inventory_rules = {
            rule["ruleID"]
            for project in projects.values()
            for capability in project["capabilities"]
            for rule in capability.get("rules", [])
        }
        self.assertEqual(inventory_rules, expected_rules)
        self.assertEqual(
            {entry["project"] for entry in self.rules["entries"]},
            {project_id for project_id, project in projects.items()
             if any(capability["kind"] == "embedded_cncf_source_rule" for capability in project["capabilities"])}
        )
        preflight = [
            capability for project in projects.values() for capability in project["capabilities"]
            if capability["kind"] == "target_preflight_profile"
        ]
        self.assertEqual(len(preflight), 1)
        self.assertEqual(preflight[0]["command"], ["check", "tikv-gcp-v2-wif-backup"])
        self.assertEqual(preflight[0]["profileDigest"], "sha256:" + hashlib.sha256(TIKV.read_bytes()).hexdigest())
        named = {
            capability["command"][-1]: capability
            for project in projects.values()
            for capability in project["capabilities"]
            if capability["kind"] == "named_local_check"
        }
        self.assertEqual(set(named), {"cert-manager-values", "prometheus-mode"})
        self.assertEqual(
            named["cert-manager-values"]["transitions"][0]["from"], read(CERT)["current"]["version"]
        )
        self.assertEqual(
            named["prometheus-mode"]["transitions"][0]["to"], read(PROMETHEUS)["proposed"]["version"]
        )
        conformance = [
            capability for project in projects.values() for capability in project["capabilities"]
            if capability["kind"] == "standards_conformance_profile"
        ]
        by_command = {tuple(item["command"]): item for item in conformance}
        self.assertEqual(set(by_command), {
            ("check", "spiffe-x509-svid"),
            ("check", "cloudevents-structured-json"),
        })
        self.assertEqual(by_command[("check", "spiffe-x509-svid")]["profileDigest"], "sha256:" + hashlib.sha256(SPIFFE.read_bytes()).hexdigest())
        self.assertEqual(by_command[("check", "cloudevents-structured-json")]["profileDigest"], "sha256:" + hashlib.sha256(CLOUDEVENTS.read_bytes()).hexdigest())
        self.assertEqual(
            {item["id"] for item in by_command[("check", "cloudevents-structured-json")]["evidence"]},
            {"cloudevents-structured-json-spec-profile", "cloudevents-structured-json-json-format-profile"},
        )

    def test_counts_are_set_derived_and_source_only_has_no_support_badge(self):
        projects = self.inventory["projects"]
        executable = {item["projectID"] for item in projects if item["capabilities"]}
        source_projects = {record["projectID"] for record in self.manifest["records"]}
        source_only = {item["projectID"] for item in projects if item["supportState"] == "selected_source_only"}
        generic = {entry["project"] for entry in self.rules["entries"]}
        named = {
            item["projectID"] for item in projects
            if any(capability["kind"] == "named_local_check" for capability in item["capabilities"])
        }
        conformance = {
            item["projectID"] for item in projects
            if any(capability["kind"] == "standards_conformance_profile" for capability in item["capabilities"])
        }
        target_preflight = {
            item["projectID"] for item in projects
            if any(capability["kind"] == "target_preflight_profile" for capability in item["capabilities"])
        }
        counts = self.inventory["counts"]
        self.assertEqual(counts["cncfSourceRules"], len(self.rules["entries"]))
        self.assertEqual(counts["cncfRuleProjects"], len(generic))
        self.assertEqual(counts["namedChecks"], len(named))
        self.assertEqual(counts["namedCheckProjects"], len(named))
        self.assertEqual(counts["conformanceProfiles"], len(conformance))
        self.assertEqual(counts["conformanceProjects"], len(conformance))
        self.assertEqual(counts["targetPreflightProfiles"], len(target_preflight))
        self.assertEqual(counts["targetPreflightProjects"], len(target_preflight))
        self.assertEqual(counts["executableProjects"], len(executable))
        self.assertEqual(counts["selectedSourceRecords"], len(self.manifest["records"]))
        self.assertEqual(counts["selectedSourceProjects"], len(source_projects))
        self.assertEqual(counts["selectedSourceOnlyProjects"], len(source_projects - executable))
        self.assertEqual(source_only, source_projects - executable)
        for project in projects:
            if project["supportState"] == "selected_source_only":
                self.assertEqual(project["capabilities"], [])
                self.assertTrue(project["selectedSourceRecords"])
                self.assertTrue(all(record["referenceState"] == "reference_only" and record["licenseState"] == "license_unreviewed" for record in project["selectedSourceRecords"]))

    def test_executable_evidence_and_preparers_are_backed_by_actual_inputs(self):
        projects = self.inventory["projects"]
        evidence_ids = {
            item.get("id") or item.get("sourceId")
            for entry in self.rules["entries"]
            for item in entry["rule"]["evidence"]["sources"]
        }
        for project in projects:
            for capability in project["capabilities"]:
                self.assertIn(capability["kind"], {"embedded_cncf_source_rule", "named_local_check", "standards_conformance_profile", "target_preflight_profile"})
                self.assertTrue(capability["command"])
                for rule in capability.get("rules", []):
                    for source in rule["evidence"]:
                        self.assertIn(source["id"], evidence_ids)
                        self.assertTrue(source["url"].startswith("https://"))
                for source in capability.get("evidence", []):
                    self.assertTrue(source["id"])
                    self.assertTrue(source["url"].startswith("https://"))
                preparer = capability.get("localPreparer")
                if preparer:
                    self.assertEqual(preparer["command"][:2], ["prepare", "cncf"])
        self.assertEqual(
            {
                project["projectID"]
                for project in projects
                for capability in project["capabilities"]
                if capability.get("localPreparer")
            },
            inventory_module.preparer_projects(ROOT / "internal/communityapp/cncf_prepare.go"),
        )

    def test_preparer_inventory_reads_only_the_callable_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "cncf_prepare.go"
            source.write_text('''switch *project {
\tcase "validation-only":
}
var prepared cncfprepare.Prepared
switch *project {
\tcase "callable":
\tprepared, err = cncfprepare.PrepareCallable(raw)
\t}
''')
            self.assertEqual(inventory_module.preparer_projects(source), {"callable"})

    def test_selected_reference_metadata_excludes_captured_content_and_review_fields(self):
        forbidden = {"capture", "capturedAt", "object", "packetDigest", "ruleIDs", "manifestPath", "receipt", "review", "timestamp"}
        def visit(value):
            if isinstance(value, dict):
                for key, nested in value.items():
                    self.assertFalse(any(term.lower() in key.lower() for term in forbidden), key)
                    visit(nested)
            elif isinstance(value, list):
                for nested in value:
                    visit(nested)
        visit(self.manifest)

    def test_prometheus_contract_spans_are_reduced_to_bounded_coordinates_and_digests(self):
        source = read(PROMETHEUS)["sources"][0]
        normalized = inventory_module.source_record(source, "prometheus")
        self.assertEqual(
            set(normalized["spans"][0]), {"startLine", "endLine", "textDigest"}
        )
        with self.assertRaises(inventory_module.Invalid):
            inventory_module.source_record({**source, "spans": [{"startLine": 1, "endLine": 1, "textDigest": "sha256:" + "0" * 64, "unexpected": "raw"}]}, "prometheus")
        with self.assertRaises(inventory_module.Invalid):
            inventory_module.source_record({**source, "id": "ambiguous-alias"}, "prometheus")
        with self.assertRaises(inventory_module.Invalid):
            inventory_module.source_record({**source, "immutableCommit": "0" * 40}, "prometheus")
        with self.assertRaises(inventory_module.Invalid):
            inventory_module.source_record({**source, "revision": source["immutableCommit"]}, "prometheus")

    def test_generated_markdown_exposes_evidence_and_reference_limits(self):
        markdown = MARKDOWN.read_text()
        self.assertIn("Pinned evidence", markdown)
        self.assertIn("reference-only", markdown)
        self.assertIn("license-unreviewed", markdown)
        self.assertIn("Catalogue discovery identities are not support entries.", markdown)


if __name__ == "__main__":
    unittest.main()
