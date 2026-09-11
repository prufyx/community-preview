#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("source_corpus.py")
EXAMPLES = SCRIPT.parents[1] / "examples" / "corpus"
spec = importlib.util.spec_from_file_location("source_corpus", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SourceCorpusTests(unittest.TestCase):
    def manifest(self) -> dict:
        return json.loads((EXAMPLES / "synthetic-corpus.json").read_text())

    def objects(self, directory: Path) -> Path:
        root = directory / "objects"
        shutil.copytree(EXAMPLES / "objects", root)
        return root

    def verify(self, manifest: dict | None = None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            receipt = module.verify_corpus(manifest or self.manifest(), self.objects(root))
            return receipt

    def test_valid_synthetic_corpus_receipt_is_stable_and_non_authoritative(self):
        first = self.verify()
        second = self.verify()
        self.assertEqual(module._canonical(first), module._canonical(second))
        self.assertEqual(first["verification"], "VERIFIED_RETAINED_BYTES")
        self.assertEqual(first["recordCount"], 1)
        self.assertEqual(first["records"][0]["source"]["repositoryURL"], "https://github.com/example/synthetic-widget")
        self.assertIn("does not approve catalogue identity", " ".join(first["limitations"]))

    def test_allows_shared_blob_across_projects_and_counts_unique_bytes_once(self):
        manifest = self.manifest()
        other = copy.deepcopy(manifest["records"][0])
        other["id"] = "second-project-shared-source"
        other["project"] = {"slug": "second-project", "canonicalRepositoryURL": "https://github.com/example/second-project"}
        manifest["records"].append(other)
        receipt = self.verify(manifest)
        self.assertEqual(receipt["recordCount"], 2)
        self.assertEqual(receipt["aggregateByteLength"], manifest["records"][0]["source"]["byteLength"])
        self.assertNotEqual(receipt["records"][1]["project"]["canonicalRepositoryURL"], receipt["records"][1]["source"]["repositoryURL"])

    def test_reference_only_version_is_explicitly_accepted(self):
        manifest = self.manifest()
        manifest["records"][0]["source"]["version"] = "reference_only"
        receipt = self.verify(manifest)
        self.assertEqual(receipt["records"][0]["source"]["version"], "reference_only")

    def test_rejects_changed_bytes_missing_object_length_digest_and_span(self):
        manifest = self.manifest()
        digest = manifest["records"][0]["source"]["fileDigest"].removeprefix("sha256:")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = self.objects(root)
            (objects / "sha256" / digest).write_bytes(b"changed\n")
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, objects)
        for mutate in (
            lambda packet: packet["records"][0]["source"].__setitem__("byteLength", 1),
            lambda packet: packet["records"][0]["source"].__setitem__("fileDigest", "sha256:" + "0" * 64),
            lambda packet: packet["records"][0]["source"]["spans"][0].__setitem__("spanDigest", "sha256:" + "0" * 64),
        ):
            with self.subTest(mutate=mutate):
                packet = self.manifest()
                mutate(packet)
                with self.assertRaises(module.CorpusError):
                    self.verify(packet)

    def test_rejects_duplicate_record_or_exact_project_source_span_and_inconsistent_shared_metadata(self):
        duplicate = self.manifest()
        duplicate["records"].append(copy.deepcopy(duplicate["records"][0]))
        with self.assertRaises(module.CorpusError):
            self.verify(duplicate)
        exact = self.manifest()
        other = copy.deepcopy(exact["records"][0])
        other["id"] = "same-project-same-source"
        exact["records"].append(other)
        with self.assertRaises(module.CorpusError):
            self.verify(exact)
        inconsistent = self.manifest()
        other = copy.deepcopy(inconsistent["records"][0])
        other["id"] = "other-project-inconsistent-source"
        other["project"] = {"slug": "other-project", "canonicalRepositoryURL": "https://github.com/example/other-project"}
        other["source"]["version"] = "reference_only"
        inconsistent["records"].append(other)
        with self.assertRaises(module.CorpusError):
            self.verify(inconsistent)

    def test_rejects_unsafe_urls_authority_and_declared_fields(self):
        for mutate in (
            lambda packet: packet.__setitem__("authority", "APPROVED"),
            lambda packet: packet["records"][0]["source"].__setitem__("repositoryURL", "https://github.com/example/synthetic-widget.git"),
            lambda packet: packet["records"][0]["source"].__setitem__("immutableURL", packet["records"][0]["source"]["immutableURL"] + "?token=x"),
            lambda packet: packet["records"][0]["source"].__setitem__("immutableURL", packet["records"][0]["source"]["immutableURL"].replace("/CHANGELOG.md", "/../CHANGELOG.md")),
            lambda packet: packet["records"][0]["capture"].__setitem__("object", "../sha256/" + packet["records"][0]["source"]["fileDigest"].removeprefix("sha256:")),
            lambda packet: packet["records"][0]["declarations"].__setitem__("ruleIDs", ["rule", "rule"]),
        ):
            with self.subTest(mutate=mutate):
                packet = self.manifest()
                mutate(packet)
                with self.assertRaises(module.CorpusError):
                    self.verify(packet)

    def test_immutable_url_allows_leading_underscore_only_in_file_path_segment(self):
        commit = "6d7b233a54d59c8473803901768153f6e4353d02"
        repository = "https://github.com/karmada-io/karmada"
        url = f"{repository}/blob/{commit}/charts/karmada/_crds/bases/policy/policy.karmada.io_propagationpolicies.yaml"
        self.assertEqual(module._immutable_url(url, repository, commit), url)
        with self.assertRaises(module.CorpusError):
            module._canonical_repository("https://github.com/_karmada-io/karmada")

    def test_safe_read_rejects_symlink_and_fifo_without_reading(self):
        manifest = self.manifest()
        digest = manifest["records"][0]["source"]["fileDigest"].removeprefix("sha256:")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = self.objects(root)
            item = objects / "sha256" / digest
            target = root / "target"
            target.write_bytes(item.read_bytes())
            item.unlink()
            item.symlink_to(target)
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, objects)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = self.objects(root)
            item = objects / "sha256" / digest
            item.unlink()
            try:
                os.mkfifo(item)
            except (AttributeError, NotImplementedError):
                self.skipTest("FIFO creation unavailable")
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, objects)

    def test_manifest_reader_rejects_symlink_and_fifo_without_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target.json"
            target.write_bytes((EXAMPLES / "synthetic-corpus.json").read_bytes())
            link = root / "manifest.json"
            link.symlink_to(target)
            with self.assertRaises(module.CorpusError):
                module._read_manifest(link)
            fifo = root / "manifest.fifo"
            try:
                os.mkfifo(fifo)
            except (AttributeError, NotImplementedError):
                self.skipTest("FIFO creation unavailable")
            with self.assertRaises(module.CorpusError):
                module._read_manifest(fifo)

    def test_rejects_hardlinked_manifest_and_object(self):
        manifest = self.manifest()
        digest = manifest["records"][0]["source"]["fileDigest"].removeprefix("sha256:")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = self.objects(root)
            original = objects / "sha256" / digest
            hard = root / "hard-object"
            os.link(original, hard)
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, objects)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source.json"
            source.write_bytes((EXAMPLES / "synthetic-corpus.json").read_bytes())
            hard = root / "hard.json"
            os.link(source, hard)
            with self.assertRaises(module.CorpusError):
                module._read_manifest(hard)

    def test_accepts_64_distinct_records_and_rejects_65(self):
        accepted = self.manifest()
        seed = accepted["records"][0]
        records = []
        for number in range(64):
            record = copy.deepcopy(seed)
            record["id"] = f"shared-source-record-{number}"
            record["project"] = {"slug": f"project-{number}", "canonicalRepositoryURL": f"https://github.com/example/project-{number}"}
            records.append(record)
        accepted["records"] = records
        receipt = self.verify(accepted)
        self.assertEqual(receipt["recordCount"], 64)
        rejected = copy.deepcopy(accepted)
        record = copy.deepcopy(seed)
        record["id"] = "shared-source-record-64"
        record["project"] = {"slug": "project-64", "canonicalRepositoryURL": "https://github.com/example/project-64"}
        rejected["records"].append(record)
        with self.assertRaises(module.CorpusError):
            self.verify(rejected)

    def test_accepts_eight_ordered_spans_and_rejects_nine(self):
        data = b"\n".join(f"line-{number}".encode() for number in range(1, 10))
        digest = hashlib.sha256(data).hexdigest()
        manifest = self.manifest()
        source = manifest["records"][0]["source"]
        source["fileDigest"] = "sha256:" + digest
        source["byteLength"] = len(data)
        source["spans"] = [
            {"startLine": number, "endLine": number, "spanDigest": "sha256:" + hashlib.sha256(f"line-{number}".encode()).hexdigest()}
            for number in range(1, 9)
        ]
        manifest["records"][0]["capture"]["object"] = "sha256/" + digest
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = root / "objects" / "sha256"
            objects.mkdir(parents=True)
            (objects / digest).write_bytes(data)
            receipt = module.verify_corpus(manifest, root / "objects")
            self.assertEqual(receipt["recordCount"], 1)
            rejected = copy.deepcopy(manifest)
            rejected["records"][0]["source"]["spans"].append({"startLine": 9, "endLine": 9, "spanDigest": "sha256:" + hashlib.sha256(b"line-9").hexdigest()})
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(rejected, root / "objects")

    def test_rejects_boolean_length(self):
        boolean_length = self.manifest()
        boolean_length["records"][0]["source"]["byteLength"] = True
        with self.assertRaises(module.CorpusError):
            self.verify(boolean_length)

    def test_rejects_url_repository_and_commit_mismatches(self):
        repository = self.manifest()
        repository["records"][0]["source"]["immutableURL"] = repository["records"][0]["source"]["immutableURL"].replace("example/synthetic-widget", "attacker/synthetic-widget")
        with self.assertRaises(module.CorpusError):
            self.verify(repository)
        commit = self.manifest()
        commit["records"][0]["source"]["immutableURL"] = commit["records"][0]["source"]["immutableURL"].replace("0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef")
        with self.assertRaises(module.CorpusError):
            self.verify(commit)

    def test_raw_line_semantics_preserve_crlf_tabs_multibyte_and_final_component(self):
        data = b"first\r\n\tsecond\ncaf\xc3\xa9\n"
        selected = b"first\r\n\tsecond\ncaf\xc3\xa9"
        digest = "sha256:" + hashlib.sha256(selected).hexdigest()
        spans, _ = module._spans([{"startLine": 1, "endLine": 3, "spanDigest": digest}], data)
        self.assertEqual(spans[0]["spanDigest"], digest)
        final_digest = "sha256:" + hashlib.sha256(b"").hexdigest()
        final, _ = module._spans([{"startLine": 4, "endLine": 4, "spanDigest": final_digest}], data)
        self.assertEqual(final[0]["spanDigest"], final_digest)
        no_final = b"first\nlast"
        no_final_digest = "sha256:" + hashlib.sha256(no_final).hexdigest()
        module._spans([{"startLine": 1, "endLine": 2, "spanDigest": no_final_digest}], no_final)

    def test_rejects_excessive_source_line_count_and_invalid_manifest_text(self):
        excessive = b"\n" * module.MAX_SOURCE_LINES + b"x"
        with self.assertRaises(module.CorpusError):
            module._spans([{"startLine": 1, "endLine": 1, "spanDigest": "sha256:" + hashlib.sha256(b"").hexdigest()}], excessive)
        with self.assertRaises(module.CorpusError):
            module._decode_json(b'{"text":"\xff"}', module.MAX_MANIFEST_BYTES)
        with self.assertRaises(module.CorpusError):
            module._decode_json(b'{"text":"' + bytes([92]) + b'ud800"}', module.MAX_MANIFEST_BYTES)

    def test_json_bounds_and_cli_errors_are_redacted(self):
        with self.assertRaises(module.CorpusError):
            module._decode_json(b'{"a":1,"a":2}', module.MAX_MANIFEST_BYTES)
        with self.assertRaises(module.CorpusError):
            module._decode_json(("[" * 40 + "0" + "]" * 40).encode(), module.MAX_MANIFEST_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            manifest = root / "valid.json"
            manifest.write_bytes((EXAMPLES / "synthetic-corpus.json").read_bytes())
            result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--manifest", str(manifest), "--object-root", str(self.objects(root)), "--unknown", "/private/canary"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("usage rejected", result.stderr)
            self.assertNotIn("canary", result.stderr)
            manifest.write_text("{")
            result = subprocess.run([sys.executable, str(SCRIPT), "verify", "--manifest", str(manifest), "--object-root", str(root / "objects")], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, "source-corpus: corpus rejected\n")

    def test_raw_byte_span_preserves_carriage_returns_and_tabs(self):
        selected = b"first\r\n\tsecond"
        spans, _ = module._spans([{"startLine": 1, "endLine": 2, "spanDigest": "sha256:" + hashlib.sha256(selected).hexdigest()}], selected + b"\nthird")
        self.assertEqual(spans[0]["spanDigest"], "sha256:" + hashlib.sha256(selected).hexdigest())

    def test_cli_receipt_output_is_deterministic_and_stdout_only(self):
        command = [sys.executable, str(SCRIPT), "verify", "--manifest", str(EXAMPLES / "synthetic-corpus.json"), "--object-root", str(EXAMPLES / "objects")]
        first = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        second = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(first.stderr, b"")
        self.assertEqual(first.stdout, second.stdout)
        rejected = subprocess.run(command + ["--receipt-out", "/private/canary"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        self.assertEqual(rejected.returncode, 2)
        self.assertEqual(rejected.stdout, "")
        self.assertIn("usage rejected", rejected.stderr)
        self.assertNotIn("canary", rejected.stderr)

    def test_physical_walk_rejects_manifest_and_object_ancestor_symlink(self):
        manifest = self.manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real"
            real.mkdir()
            objects = self.objects(real)
            manifest_path = real / "manifest.json"
            manifest_path.write_bytes((EXAMPLES / "synthetic-corpus.json").read_bytes())
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(module.CorpusError):
                module._read_manifest(alias / "manifest.json")
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, alias / "objects")
            self.assertTrue(objects.is_dir())

    def test_safe_object_reader_rejects_root_and_intermediate_symlink(self):
        manifest = self.manifest()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = self.objects(root)
            root_link = root / "objects-link"
            root_link.symlink_to(objects, target_is_directory=True)
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, root_link)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            objects = self.objects(root)
            sha = objects / "sha256"
            moved = root / "moved-sha256"
            sha.rename(moved)
            sha.symlink_to(moved, target_is_directory=True)
            with self.assertRaises(module.CorpusError):
                module.verify_corpus(manifest, objects)



if __name__ == "__main__":
    unittest.main()
