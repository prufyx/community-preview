#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("contribution_packet.py")
EXAMPLES = SCRIPT.parents[1] / "examples" / "contributions"
spec = importlib.util.spec_from_file_location("contribution_packet", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ContributionPacketTests(unittest.TestCase):
    def packet(self) -> dict:
        return json.loads((EXAMPLES / "synthetic-new-identity-packet.json").read_text())

    def existing_packet(self) -> dict:
        packet = self.packet()
        packet["submission"] = {"kind": "existing_project_transition"}
        packet["project"] = {"slug": "kyverno", "displayName": "Kyverno", "canonicalRepositoryURL": "https://github.com/kyverno/kyverno"}
        packet["transition"] = {"currentVersion": "1.12.5", "proposedVersion": "1.13.0"}
        packet["tagBindings"] = [
            {"version": "1.12.5", "tag": "v1.12.5", "commit": "0123456789abcdef0123456789abcdef01234567", "assertion": "DECLARED_UNVERIFIED"},
            {"version": "1.13.0", "tag": "v1.13.0", "commit": "89abcdef0123456789abcdef0123456789abcdef", "assertion": "DECLARED_UNVERIFIED"},
        ]
        source = packet["sources"][0]
        source["version"] = "1.13.0"
        source["commit"] = "89abcdef0123456789abcdef0123456789abcdef"
        source["immutableURL"] = "https://github.com/kyverno/kyverno/blob/89abcdef0123456789abcdef0123456789abcdef/README.md"
        return packet

    def tikv_target_packet(self) -> dict:
        return json.loads((EXAMPLES / "tikv-8.5.8-gcp-v2-wif-backup-candidate.json").read_text())

    def test_tikv_target_preflight_packet_and_sources_are_closed(self):
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        packet = self.tikv_target_packet()
        receipt = module.validate_packet(packet, landscape)
        self.assertEqual(receipt["submissionKind"], "existing_project_target_preflight")
        self.assertEqual(receipt["workflowState"], "CANDIDATE")
        verified = module.verify_packet_sources(packet, landscape, SCRIPT.parents[1] / "examples/corpus/objects")
        self.assertEqual((verified["sourceCount"], verified["uniqueObjectCount"], verified["spanCount"]), (3, 3, 4))
        for mutate in (
            lambda value: value["target"].update({"targetVersion": "8.5.7"}),
            lambda value: value["target"].update({"operation": "restore"}),
            lambda value: value["project"].update({"slug": "pd"}),
            lambda value: value["tagBindings"].append(copy.deepcopy(value["tagBindings"][0])),
            lambda value: value["sources"].pop(),
            lambda value: value["sources"][0].update({"evidenceRole": "operator_action_guidance"}),
            lambda value: value["sources"][0].update({"commit": "8d85871d64efa8bcad2d3c3c4c7edc2f4f3045be"}),
            lambda value: value["sources"][2].update({"immutableURL": value["sources"][0]["immutableURL"]}),
        ):
            invalid = copy.deepcopy(packet)
            mutate(invalid)
            with self.assertRaises(module.PacketError):
                module.validate_packet(invalid, landscape)

    def test_tikv_target_preflight_scaffold_and_cross_kind_flags(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(os.path.realpath(directory)) / "tikv.json"
            command = [sys.executable, str(SCRIPT), "scaffold", "--kind", "existing_project_target_preflight",
                       "--project-slug", "tikv", "--display-name", "TiKV", "--repository", "https://github.com/tikv/tikv",
                       "--target-version", "8.5.8", "--operation", "gcs-full-backup-wif", "--output", str(output)]
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            packet = json.loads(output.read_text())
            self.assertEqual(packet["schema"], module.SCHEMA_V2)
            self.assertEqual(packet["target"], {"targetVersion": "8.5.8", "operation": "gcs-full-backup-wif"})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            bad = subprocess.run(command[:-2] + ["--current-version", "8.5.7"] + command[-2:], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(bad.returncode, 2)

            v1_output = Path(directory) / "v1.json"
            v1 = subprocess.run([sys.executable, str(SCRIPT), "scaffold", "--kind", "new_catalogue_identity_proposal",
                                 "--project-slug", "synthetic-widget", "--display-name", "Synthetic Widget",
                                 "--repository", "https://github.com/example/synthetic-widget", "--target-version", "8.5.8",
                                 "--output", str(v1_output)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(v1.returncode, 2)

    def source_packet(self, data: bytes, *, start: int = 1, end: int | None = None, excerpt: str | None = None) -> dict:
        packet = self.packet()
        lines = data.split(b"\n")
        end = len(lines) if end is None else end
        source = packet["sources"][0]
        source["fileDigest"] = "sha256:" + hashlib.sha256(data).hexdigest()
        source["spans"] = [{"startLine": start, "endLine": end, "excerpt": excerpt if excerpt is not None else b"\n".join(lines[start - 1:end]).decode("utf-8")}]
        return packet

    def object_root(self, root: Path, data: bytes, *, name: str | None = None) -> Path:
        objects = Path(os.path.realpath(root)) / "source-root" / "sha256"
        objects.mkdir(parents=True)
        leaf = name or hashlib.sha256(data).hexdigest()
        path = objects / leaf
        path.write_bytes(data)
        path.chmod(0o600)
        return objects.parent

    def test_synthetic_packet_has_stable_candidate_receipt(self):
        packet = self.packet()
        first = module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
        second = module.validate_packet(copy.deepcopy(packet), SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
        self.assertEqual(module._canonical(first), module._canonical(second))
        self.assertEqual(first["workflowState"], "CANDIDATE")
        self.assertEqual(first["consistency"], "VALID")
        self.assertIn("not authentication", " ".join(first["limitations"]))

    def test_crossplane_candidate_binds_the_exact_pinned_landscape_bytes(self):
        packet = json.loads((EXAMPLES / "crossplane-1.20.0-to-2.0.0-candidate.json").read_text())
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        receipt = module.validate_packet(packet, landscape)
        self.assertEqual(receipt["workflowState"], "CANDIDATE")
        self.assertEqual(receipt["landscapeDigest"], "sha256:" + __import__("hashlib").sha256(landscape.read_bytes()).hexdigest())
        self.assertEqual(packet["review"]["state"], "NOT_REVIEWED")

    def test_buildpacks_lifecycle_is_the_only_cross_repository_component_source(self):
        packet = self.existing_packet()
        packet["project"] = {"slug": "buildpacks", "displayName": "Buildpacks Lifecycle", "canonicalRepositoryURL": "https://github.com/buildpacks/lifecycle"}
        packet["transition"] = {"currentVersion": "0.16.5", "proposedVersion": "0.17.7"}
        packet["tagBindings"] = [
            {"version": "0.16.5", "tag": "v0.16.5", "commit": "7679c6870a4b9672d357b9ad7cac5fa8ecfce56e", "assertion": "DECLARED_UNVERIFIED"},
            {"version": "0.17.7", "tag": "v0.17.7", "commit": "54767cc833f84066226cb87ae8e23e69cec8668f", "assertion": "DECLARED_UNVERIFIED"},
        ]
        source = packet["sources"][0]
        source.update({"version": "0.17.7", "commit": "54767cc833f84066226cb87ae8e23e69cec8668f", "immutableURL": "https://github.com/buildpacks/lifecycle/blob/54767cc833f84066226cb87ae8e23e69cec8668f/api/apis.go"})
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        self.assertEqual(module.validate_packet(packet, landscape)["consistency"], "VALID")

        for slug, repository in (
            ("buildpacks", "https://github.com/buildpacks/unknown"),
            ("kyverno", "https://github.com/buildpacks/lifecycle"),
        ):
            invalid = copy.deepcopy(packet)
            invalid["project"]["slug"] = slug
            invalid["project"]["canonicalRepositoryURL"] = repository
            with self.assertRaises(module.PacketError):
                module.validate_packet(invalid, landscape)

        pack = copy.deepcopy(packet)
        pack["project"]["canonicalRepositoryURL"] = "https://github.com/buildpacks/pack"
        pack["sources"][0]["immutableURL"] = "https://github.com/buildpacks/pack/blob/54767cc833f84066226cb87ae8e23e69cec8668f/README.md"
        self.assertEqual(module.validate_packet(pack, landscape)["consistency"], "VALID")
        pack["sources"][0]["immutableURL"] = "https://github.com/buildpacks/lifecycle/blob/54767cc833f84066226cb87ae8e23e69cec8668f/api/apis.go"
        with self.assertRaises(module.PacketError):
            module.validate_packet(pack, landscape)

    def test_kubeflow_kfp_packet_closes_component_and_migration_guide_repositories(self):
        path = EXAMPLES / "kubeflow-kfp-sdk-1.8.22-to-2.0.0-candidate.json"
        packet = json.loads(path.read_text())
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        self.assertEqual(module.validate_packet(packet, landscape)["consistency"], "VALID")

        guide = next(source for source in packet["sources"] if source["sourceKind"] == "migration_guide")
        for mutate in (
            lambda value: value["project"].update({"slug": "kyverno"}),
            lambda value: value["project"].update({"canonicalRepositoryURL": "https://github.com/kubeflow/unknown"}),
            lambda value: next(source for source in value["sources"] if source["sourceKind"] == "migration_guide").update({"sourceKind": "source_code"}),
            lambda value: next(source for source in value["sources"] if source["sourceKind"] == "migration_guide").update({"version": "1.8.22"}),
            lambda value: next(source for source in value["sources"] if source["sourceKind"] == "migration_guide").update({"commit": "0123456789abcdef0123456789abcdef01234567"}),
            lambda value: next(source for source in value["sources"] if source["sourceKind"] == "migration_guide").update({"immutableURL": guide["immutableURL"].replace("migration.md", "other.md")}),
        ):
            invalid = copy.deepcopy(packet)
            mutate(invalid)
            with self.assertRaises(module.PacketError):
                module.validate_packet(invalid, landscape)

        guide_only = copy.deepcopy(packet)
        guide_only["sources"] = [copy.deepcopy(guide)]
        with self.assertRaises(module.PacketError):
            module.validate_packet(guide_only, landscape)

        missing_target_endpoint = copy.deepcopy(packet)
        missing_target_endpoint["sources"] = [source for source in missing_target_endpoint["sources"] if source["sourceKind"] == "migration_guide" or source["version"] == "1.8.22"]
        with self.assertRaises(module.PacketError):
            module.validate_packet(missing_target_endpoint, landscape)

        duplicate_guide = copy.deepcopy(packet)
        second = copy.deepcopy(guide)
        second["id"] = "kubeflow-kfp-v2-migration-create-component-copy"
        duplicate_guide["sources"].append(second)
        with self.assertRaises(module.PacketError):
            module.validate_packet(duplicate_guide, landscape)

        wrong_endpoint_commit = copy.deepcopy(packet)
        ordinary = next(source for source in wrong_endpoint_commit["sources"] if source["sourceKind"] == "source_code")
        ordinary["commit"] = "0123456789abcdef0123456789abcdef01234567"
        ordinary["immutableURL"] = ordinary["immutableURL"].replace("f5ba0212fc316aff38d4a3129bc6f2a7b54f97b5", ordinary["commit"])
        with self.assertRaises(module.PacketError):
            module.validate_packet(wrong_endpoint_commit, landscape)

    def test_keycloak_fragment_candidate_is_consistency_only(self):
        packet = json.loads((EXAMPLES / "keycloak-26.7.2-to-26.7.3-candidate.json").read_text())
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        receipt = module.validate_packet(packet, landscape)
        self.assertEqual(receipt["workflowState"], "CANDIDATE")
        self.assertEqual(receipt["consistency"], "VALID")
        self.assertEqual(packet["review"]["state"], "NOT_REVIEWED")
        self.assertEqual(packet["transition"], {"currentVersion": "26.7.2", "proposedVersion": "26.7.3"})
        self.assertEqual(len(packet["sources"]), 4)

    def test_dapr_candidate_preserves_exact_long_destructive_source_line(self):
        packet = json.loads((EXAMPLES / "dapr-1.14.0-to-1.15.0-candidate.json").read_text())
        destructive = next(
            span["excerpt"]
            for source in packet["sources"]
            for span in source["spans"]
            if span["startLine"] == 479 and span["endLine"] == 479
        )
        self.assertEqual(len(destructive), 595)
        self.assertIn("loss of all jobs", destructive)
        receipt = module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
        self.assertEqual(receipt["workflowState"], "CANDIDATE")

    def test_excerpt_rejects_text_beyond_dedicated_bound(self):
        packet = self.source_packet(b"x" * (module.MAX_EXCERPT_LINE_CHARS + 1))
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")

    def test_negative_examples_reject(self):
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        for name in ("source-commit-mismatch.json", "claimed-approval.json"):
            with self.subTest(name=name):
                packet = json.loads((EXAMPLES / "negative" / name).read_text())
                with self.assertRaises(module.PacketError):
                    module.validate_packet(packet, landscape)

    def test_existing_project_requires_pinned_landscape_identity_and_declared_tags(self):
        packet = self.existing_packet()
        receipt = module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
        self.assertEqual(receipt["workflowState"], "CANDIDATE")
        packet["sources"][0]["commit"] = "fedcba9876543210fedcba9876543210fedcba98"
        packet["sources"][0]["immutableURL"] = "https://github.com/kyverno/kyverno/blob/fedcba9876543210fedcba9876543210fedcba98/README.md"
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
        packet = self.packet()
        packet["submission"] = {"kind": "existing_project_transition"}
        packet["project"] = {"slug": "kyverno", "displayName": "Kyverno", "canonicalRepositoryURL": "https://github.com/attacker/kyverno"}
        packet["transition"] = {"currentVersion": "1.12.5", "proposedVersion": "1.13.0"}
        packet["tagBindings"] = []
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")

    def test_immutable_source_url_allows_leading_underscore_only_in_file_path_segment(self):
        commit = "6d7b233a54d59c8473803901768153f6e4353d02"
        repository = "https://github.com/karmada-io/karmada"
        url = f"{repository}/blob/{commit}/charts/karmada/_crds/bases/policy/policy.karmada.io_propagationpolicies.yaml"
        self.assertEqual(module._immutable_source_url(url, repository, commit), url)
        with self.assertRaises(module.PacketError):
            module._github_repository("https://github.com/_karmada-io/karmada")

    def test_rejects_duplicate_keys_undeclared_source_version_and_extra_fields(self):
        with self.assertRaises(module.PacketError):
            module._load_json(b'{"schema":"x","schema":"y"}')
        packet = self.packet()
        packet["sources"][0]["version"] = "9.9.9"
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
        packet = self.packet()
        packet["customerConfiguration"] = "must-not-be-accepted"
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")

    def test_rejects_adversarial_urls_enums_versions_numbers_and_unicode(self):
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        for suffix in ("?", "#", "%2e%2e", "\\README.md"):
            with self.subTest(suffix=suffix):
                packet = self.packet()
                packet["sources"][0]["immutableURL"] += suffix
                with self.assertRaises(module.PacketError):
                    module.validate_packet(packet, landscape)
        packet = self.packet()
        packet["sources"][0]["sourceKind"] = []
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, landscape)
        with self.assertRaises(module.PacketError):
            module._load_json(b'{"number":999999999999999999999999999999999999999999999999999999999999}')
        with self.assertRaises(module.PacketError):
            module._load_json(b'{"text":"\\ud800"}')
        with self.assertRaises(module.PacketError):
            module._load_json(("[" * 40 + "0" + "]" * 40).encode())
        packet = self.packet()
        packet["submission"] = {"kind": "existing_project_transition"}
        packet["project"] = {"slug": "kyverno", "displayName": "Kyverno", "canonicalRepositoryURL": "https://github.com/kyverno/kyverno"}
        packet["transition"] = {"currentVersion": "main", "proposedVersion": "1.13.0"}
        packet["tagBindings"] = []
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, landscape)

    def test_rejects_duplicate_tags_clone_urls_and_ambiguous_tag_syntax(self):
        landscape = SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json"
        packet = self.existing_packet()
        packet["tagBindings"][1]["tag"] = packet["tagBindings"][0]["tag"]
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, landscape)
        for tag in ("v1..2", "v1//2", "v1/", "v1.", "v1.lock"):
            with self.subTest(tag=tag):
                packet = self.existing_packet()
                packet["tagBindings"][0]["tag"] = tag
                with self.assertRaises(module.PacketError):
                    module.validate_packet(packet, landscape)
        packet = self.packet()
        packet["project"]["canonicalRepositoryURL"] = "https://github.com/example/synthetic-widget.git"
        packet["sources"][0]["immutableURL"] = packet["sources"][0]["immutableURL"].replace("synthetic-widget/", "synthetic-widget.git/")
        with self.assertRaises(module.PacketError):
            module.validate_packet(packet, landscape)

    def test_safe_read_rejects_symlink_and_fifo_without_reading_them(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            target = root / "target.json"
            target.write_bytes(b"{}")
            target.chmod(0o600)
            link = root / "link.json"
            link.symlink_to(target)
            with self.assertRaises(module.PacketError):
                module._safe_read(link, 1024)
            fifo = root / "packet.fifo"
            try:
                os.mkfifo(fifo)
            except (AttributeError, NotImplementedError):
                self.skipTest("FIFO creation unavailable")
            with self.assertRaises(module.PacketError):
                module._safe_read(fifo, 1024)

    def test_cli_output_is_receipt_only_and_errors_are_redacted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            valid = root / "valid.json"
            valid.write_bytes((EXAMPLES / "synthetic-new-identity-packet.json").read_bytes())
            result = subprocess.run([sys.executable, str(SCRIPT), "validate", "--packet", str(valid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(result.returncode, 0)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["workflowState"], "CANDIDATE")
            self.assertEqual(result.stderr, "")
            invalid = root / "PRIVATE_URL_CANARY.json"
            invalid.write_text('{"schema":"https://private.example/CANARY"}')
            rejected = subprocess.run([sys.executable, str(SCRIPT), "validate", "--packet", str(invalid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, "")
            self.assertEqual(rejected.stderr.strip(), "contribution-packet: packet rejected")
            self.assertNotIn("CANARY", rejected.stderr)
            usage = subprocess.run([sys.executable, str(SCRIPT), "PRIVATE_ARGUMENT_CANARY"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(usage.returncode, 2)
            self.assertEqual(usage.stdout, "")
            self.assertEqual(usage.stderr.strip(), "contribution-packet: usage rejected")
            self.assertNotIn("CANARY", usage.stderr)
            duplicate = self.existing_packet()
            duplicate["tagBindings"][0]["tag"] = "TAG_CANARY"
            duplicate["tagBindings"][1]["tag"] = "TAG_CANARY"
            duplicate_path = root / "duplicate.json"
            duplicate_path.write_text(json.dumps(duplicate))
            rejected_duplicate = subprocess.run([sys.executable, str(SCRIPT), "validate", "--packet", str(duplicate_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(rejected_duplicate.returncode, 2)
            self.assertEqual(rejected_duplicate.stdout, "")
            self.assertEqual(rejected_duplicate.stderr.strip(), "contribution-packet: packet rejected")
            self.assertNotIn("TAG_CANARY", rejected_duplicate.stderr)

    def test_verify_sources_matches_literal_bytes_spans_and_reuses_duplicate_object(self):
        data = b" leading space\ntrailing space "
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data)
            duplicate = copy.deepcopy(packet["sources"][0])
            duplicate["id"] = "repository-overview-copy"
            packet["sources"].append(duplicate)
            receipt = module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", self.object_root(root, data))
            self.assertEqual(receipt["workflowState"], "CANDIDATE")
            self.assertEqual(receipt["admissionState"], "NOT_ADMITTED")
            self.assertEqual(receipt["sourceCount"], 2)
            self.assertEqual(receipt["uniqueObjectCount"], 1)
            self.assertEqual(receipt["aggregateVerifiedByteLength"], len(data))
            self.assertNotIn("repository-overview", module._canonical(receipt).decode())
            packet_path = root / "packet.json"
            packet_path.write_text(json.dumps(packet))
            object_root = root / "source-root"
            command = [sys.executable, str(SCRIPT), "verify-sources", "--packet", str(packet_path), "--source-root", str(object_root)]
            first = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            second = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual(first.returncode, 0)
            self.assertEqual(first.stderr, b"")
            self.assertEqual(first.stdout, second.stdout)
            self.assertNotIn(b"repository-overview", first.stdout)
            self.assertNotIn(str(root).encode(), first.stdout)

    def test_verify_sources_rejects_missing_changed_and_out_of_range_objects(self):
        data = b"first\nsecond"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data)
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", root / "missing")
            object_root = self.object_root(root, b"changed", name=hashlib.sha256(data).hexdigest())
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", object_root)
            packet = self.source_packet(data, end=3, excerpt="first\nsecond\nthird")
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", object_root)

    def test_verify_sources_preserves_excerpt_whitespace_and_raw_lf_eof_rules(self):
        for data, start, end, excerpt in ((b"one\ntwo", 2, 2, "two"), (b"one\ntwo\n", 2, 2, "two")):
            with self.subTest(data=data):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(os.path.realpath(directory))
                    packet = self.source_packet(data, start=start, end=end, excerpt=excerpt)
                    module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", self.object_root(root, data))
                    packet["sources"][0]["spans"][0]["excerpt"] = "two "
                    with self.assertRaises(module.PacketError):
                        module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", root / "source-root")

    def test_verify_sources_rejects_cr_and_invalid_utf8_selected_bytes(self):
        for data, excerpt in ((b"one\r\ntwo", "one\ntwo"), (b"\xff", "x")):
            with self.subTest(data=data):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(os.path.realpath(directory))
                    packet = self.source_packet(data, excerpt=excerpt)
                    with self.assertRaises(module.PacketError):
                        module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", self.object_root(root, data))

    def test_tab_is_allowed_only_in_literal_source_excerpt(self):
        data = b"func\tmain()"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data, excerpt="func\tmain()")
            parsed = module._load_json(json.dumps(packet).encode())
            module.verify_packet_sources(parsed, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", self.object_root(root, data))
            parsed["sources"][0]["spans"][0]["excerpt"] = "func main()"
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(parsed, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", root / "source-root")
            metadata = self.source_packet(data, excerpt="func\tmain()")
            metadata["declaration"]["statement"] = "tab\tmetadata"
            with self.assertRaises(module.PacketError):
                module.validate_packet(module._load_json(json.dumps(metadata).encode()), SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")
            key = json.dumps(packet).replace('"id": "repository-overview"', '"id\\t": "repository-overview"')
            with self.assertRaises(module.PacketError):
                module._load_json(key.encode())
            url = self.source_packet(data, excerpt="func\tmain()")
            url["sources"][0]["immutableURL"] += "\t"
            with self.assertRaises(module.PacketError):
                module.validate_packet(module._load_json(json.dumps(url).encode()), SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json")

    def test_packet_tab_decoder_does_not_relax_landscape_or_other_controls(self):
        for control in ("\r", "\v", "\x1f"):
            with self.subTest(control=ord(control)):
                packet = self.packet()
                packet["sources"][0]["spans"][0]["excerpt"] = "first" + control + "second"
                with self.assertRaises(module.PacketError):
                    module._load_json(json.dumps(packet).encode())
        landscape = b'{"projects":[{"slug":"kyverno\\t","repositoryURL":"https://github.com/kyverno/kyverno"}]}'
        with self.assertRaises(module.PacketError):
            module._decode_json(landscape, module.MAX_LANDSCAPE_BYTES)

    def test_verify_sources_rejects_unsafe_object_shapes(self):
        data = b"first\nsecond"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data)
            object_root = self.object_root(root, data)
            leaf = object_root / "sha256" / hashlib.sha256(data).hexdigest()
            os.link(leaf, object_root / "sha256" / "hardlink")
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", object_root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data)
            object_root = self.object_root(root, data)
            leaf = object_root / "sha256" / hashlib.sha256(data).hexdigest()
            target = root / "outside"
            target.write_bytes(data)
            leaf.unlink()
            leaf.symlink_to(target)
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", object_root)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data)
            object_root = self.object_root(root, data)
            leaf = object_root / "sha256" / hashlib.sha256(data).hexdigest()
            leaf.unlink()
            try:
                os.mkfifo(leaf)
            except (AttributeError, NotImplementedError):
                self.skipTest("FIFO creation unavailable")
            with self.assertRaises(module.PacketError):
                module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", object_root)

    def test_verify_sources_counts_unique_bytes_and_rejects_small_aggregate_cap(self):
        first, second = b"first", b"second"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(first)
            source = copy.deepcopy(packet["sources"][0])
            source.update({"id": "repository-overview-second", "fileDigest": "sha256:" + hashlib.sha256(second).hexdigest(), "spans": [{"startLine": 1, "endLine": 1, "excerpt": "second"}]})
            packet["sources"].append(source)
            object_root = self.object_root(root, first)
            other = object_root / "sha256" / hashlib.sha256(second).hexdigest()
            other.write_bytes(second)
            other.chmod(0o600)
            prior = module.corpus.MAX_AGGREGATE_BYTES
            module.corpus.MAX_AGGREGATE_BYTES = len(first) + len(second) - 1
            try:
                with self.assertRaises(module.PacketError):
                    module.verify_packet_sources(packet, SCRIPT.parents[1] / "internal/cncfcheck/data/landscape-projects.json", object_root)
            finally:
                module.corpus.MAX_AGGREGATE_BYTES = prior

    def test_verify_sources_cli_is_redacted_and_validate_remains_source_root_free(self):
        data = b"PRIVATE_SOURCE_CANARY"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            packet = self.source_packet(data, excerpt="different")
            packet_path = root / "PRIVATE_PATH_CANARY.json"
            packet_path.write_text(json.dumps(packet))
            source_root = self.object_root(root, data)
            result = subprocess.run([sys.executable, str(SCRIPT), "verify-sources", "--packet", str(packet_path), "--source-root", str(source_root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "contribution-packet: packet rejected")
            self.assertNotIn("CANARY", result.stderr + result.stdout)
            validate = subprocess.run([sys.executable, str(SCRIPT), "validate", "--packet", str(packet_path), "--source-root", str(source_root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(validate.returncode, 2)
            self.assertEqual(validate.stderr.strip(), "contribution-packet: usage rejected")
            missing_root = subprocess.run([sys.executable, str(SCRIPT), "verify-sources", "--packet", str(packet_path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(missing_root.returncode, 2)
            self.assertEqual(missing_root.stderr.strip(), "contribution-packet: usage rejected")

    def test_ordinary_validate_output_remains_byte_compatible(self):
        packet = EXAMPLES / "karmada-1.18.3-to-1.19.0-candidate.json"
        result = subprocess.run([sys.executable, str(SCRIPT), "validate", "--packet", str(packet)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(hashlib.sha256(result.stdout).hexdigest(), "d7f89067dad70ab7a479d56f18f0cd2e380c20a7aefa387809e5017576506ad4")

    def test_scaffold_creates_private_incomplete_packet_and_validation_rejects_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            output = root / "candidate.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "scaffold", "--kind", "existing_project_transition",
                 "--project-slug", "karmada", "--display-name", "Karmada",
                 "--repository", "https://github.com/karmada-io/karmada",
                 "--current-version", "1.18.3", "--proposed-version", "1.19.0",
                 "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
            self.assertIn("incomplete packet skeleton", result.stdout)
            self.assertIn("contribution_packet.py validate --packet", result.stdout)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            packet = json.loads(output.read_text())
            self.assertEqual(set(packet), {"schema", "submission", "project", "transition", "tagBindings", "sources", "declaration", "limitations", "review", "attribution"})
            self.assertEqual(packet["tagBindings"], [])
            self.assertEqual(packet["sources"], [])
            self.assertIsNone(packet["declaration"]["statement"])
            rejected = subprocess.run(
                [sys.executable, str(SCRIPT), "validate", "--packet", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(rejected.returncode, 2)
            self.assertEqual(rejected.stdout, "")
            self.assertEqual(rejected.stderr.strip(), "contribution-packet: packet rejected")

    def test_scaffold_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(os.path.realpath(directory)) / "existing.json"
            original = b"private sentinel\n"
            output.write_bytes(original)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "scaffold", "--kind", "new_catalogue_identity_proposal",
                 "--project-slug", "synthetic-widget", "--display-name", "Synthetic Widget",
                 "--repository", "https://github.com/example/synthetic-widget", "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "contribution-packet: scaffold rejected")
            self.assertEqual(output.read_bytes(), original)

    def test_scaffold_rejects_symlink_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            target = root / "target.json"
            target.write_bytes(b"target\n")
            link = root / "link.json"
            link.symlink_to(target)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "scaffold", "--kind", "new_catalogue_identity_proposal",
                 "--project-slug", "synthetic-widget", "--display-name", "Synthetic Widget",
                 "--repository", "https://github.com/example/synthetic-widget", "--output", str(link)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "contribution-packet: scaffold rejected")
            self.assertEqual(target.read_bytes(), b"target\n")

    def test_scaffold_rejects_symlink_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(os.path.realpath(directory))
            target = root / "target"
            target.mkdir()
            link = root / "parent"
            link.symlink_to(target, target_is_directory=True)
            output = link / "candidate.json"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "scaffold", "--kind", "new_catalogue_identity_proposal",
                 "--project-slug", "synthetic-widget", "--display-name", "Synthetic Widget",
                 "--repository", "https://github.com/example/synthetic-widget", "--output", str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr.strip(), "contribution-packet: scaffold rejected; choose a real directory for the output parent")
            self.assertFalse((target / "candidate.json").exists())


if __name__ == "__main__":
    unittest.main()
