#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import zipfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER = HERE / "community-staging-receipt.py"
ROOT = HERE.parents[1]
STAGING_WORKFLOW = ROOT / ".github/workflows/community-release.yml"
SPEC = importlib.util.spec_from_file_location("community_staging_receipt", HELPER)
assert SPEC is not None and SPEC.loader is not None
RECEIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECEIPT)


def staging_preconditions() -> str:
    lines = STAGING_WORKFLOW.read_text(encoding="utf-8").splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line == "  release-preconditions:\n")
    end = next((i for i, line in enumerate(lines[start + 1:], start + 1) if line.startswith("  ") and not line.startswith("    ") and line.strip().endswith(":")), len(lines))
    return "".join(lines[start:end])


def staging_precondition_script() -> str:
    lines = staging_preconditions().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line == "        run: |\n") + 1
    body = []
    for line in lines[start:]:
        if not line.startswith("          "):
            break
        body.append(line.removeprefix("          "))
    if not body:
        raise AssertionError("release precondition run body is absent")
    return "".join(body)


def run_staging_preconditions(visibility: str | None) -> subprocess.CompletedProcess[str]:
    env = os.environ | {
        "ACTUAL_REPOSITORY": "prufyx/prufyx-cli",
        "ACTUAL_REF_TYPE": "tag",
        "ACTUAL_REF": "refs/tags/v0.1.0-alpha.5",
        "ACTUAL_REF_PROTECTED": "true",
    }
    if visibility is not None:
        env["ACTUAL_REPOSITORY_VISIBILITY"] = visibility
    else:
        env.pop("ACTUAL_REPOSITORY_VISIBILITY", None)
    return subprocess.run(["bash", "-c", staging_precondition_script()], env=env, text=True, capture_output=True, check=False)


class CommunityStagingReceiptTest(unittest.TestCase):
    def test_staging_preconditions_require_public_visibility(self) -> None:
        block = staging_preconditions()
        self.assertIn("ACTUAL_REPOSITORY_VISIBILITY: ${{ github.event.repository.visibility }}", block)
        self.assertIn("set -euo pipefail", block)
        self.assertIn('test "$ACTUAL_REPOSITORY" = "prufyx/prufyx-cli"', block)
        self.assertIn('test "$ACTUAL_REPOSITORY_VISIBILITY" = "public"', block)
        self.assertIn('test "$ACTUAL_REF" = "refs/tags/v0.1.0-alpha.5"', block)
        self.assertIn('test "$ACTUAL_REF_PROTECTED" = "true"', block)
        for visibility, expected in (("public", 0), ("private", 1), (None, 1), ("internal", 1), ("unknown", 1)):
            with self.subTest(visibility=visibility):
                result = run_staging_preconditions(visibility)
                self.assertEqual(result.returncode, expected, result.stderr)

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="community-staging-receipt-test-")
        self.bundle = Path(self.temp.name) / "bundle"
        self.bundle.mkdir()
        self.source_sha = "a" * 40
        self.workflow_sha = "b" * 40
        for name in RECEIPT.required_assets():
            content = (self.source_sha + "\n").encode() if name == "SOURCE-REVISION" else (name + "\n").encode()
            (self.bundle / name).write_bytes(content)
        checksums = "".join(
            f"{hashlib.sha256((self.bundle / name).read_bytes()).hexdigest()}  {name}\n"
            for name in RECEIPT.required_assets()
        )
        (self.bundle / RECEIPT.CHECKSUMS_NAME).write_text(checksums, encoding="ascii")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def command(self, command: str, **overrides: str) -> subprocess.CompletedProcess[str]:
        values = {
            "bundle_dir": str(self.bundle), "repository": RECEIPT.REPOSITORY,
            "workflow_path": RECEIPT.WORKFLOW_PATH, "workflow_sha": self.workflow_sha,
            "event": RECEIPT.EVENT, "run_id": "1234", "run_attempt": "1",
            "ref": RECEIPT.REF, "source_sha": self.source_sha, "version": RECEIPT.VERSION,
        }
        values.update(overrides)
        argv = [sys.executable, str(HELPER), command]
        for key, value in values.items():
            argv.extend([f"--{key.replace('_', '-')}", value])
        return subprocess.run(argv, text=True, capture_output=True, check=False)

    def create(self) -> None:
        result = self.command("create")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_valid_bundle_creates_and_revalidates_canonical_in_bundle_receipt(self) -> None:
        self.create()
        receipt = self.bundle / RECEIPT.RECEIPT_NAME
        value = json.loads(receipt.read_text(encoding="ascii"))
        self.assertEqual(value["schemaVersion"], "prufyx.io/community-staging-receipt/v1")
        self.assertEqual(value["artifactName"], RECEIPT.ARTIFACT_NAME)
        self.assertEqual(value["attestationSubjects"], "assets_listed_in_SHA256SUMS")
        self.assertEqual([item["name"] for item in value["assets"]], RECEIPT.required_assets())
        self.assertEqual(value["checksumSetDigest"], "sha256:" + hashlib.sha256((self.bundle / "SHA256SUMS").read_bytes()).hexdigest())
        self.assertEqual(receipt.read_bytes(), RECEIPT.canonical_json(value))
        self.assertEqual(self.command("verify").returncode, 0)

    def test_extra_or_missing_bundle_entry_is_rejected_before_receipt_creation(self) -> None:
        (self.bundle / "UNLISTED.txt").write_text("no\n", encoding="ascii")
        result = self.command("create")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.bundle / RECEIPT.RECEIPT_NAME).exists())
        (self.bundle / "UNLISTED.txt").unlink()
        (self.bundle / "NOTICE").unlink()
        self.assertNotEqual(self.command("create").returncode, 0)

    def test_hard_linked_bundle_entries_are_rejected(self) -> None:
        copy = self.bundle / "NOTICE-copy"
        (self.bundle / "NOTICE").rename(copy)
        __import__("os").link(copy, self.bundle / "NOTICE")
        self.assertNotEqual(self.command("create").returncode, 0)

    def test_tampered_assets_and_checksum_entries_are_rejected(self) -> None:
        (self.bundle / "NOTICE").write_text("tampered\n", encoding="ascii")
        self.assertNotEqual(self.command("create").returncode, 0)
        (self.bundle / "NOTICE").write_text("NOTICE\n", encoding="ascii")
        with (self.bundle / "SHA256SUMS").open("a", encoding="ascii") as handle:
            handle.write("0" * 64 + "  unexpected\n")
        self.assertNotEqual(self.command("create").returncode, 0)

    def test_identity_and_attempt_contract_is_fail_closed(self) -> None:
        for overrides in (
            {"repository": "other/repo"}, {"workflow_sha": "B" * 40},
            {"event": "workflow_dispatch"}, {"run_attempt": "2"},
            {"source_sha": "c" * 40}, {"version": "v0.1.0-alpha.4"},
        ):
            self.assertNotEqual(self.command("create", **overrides).returncode, 0, overrides)
            self.assertFalse((self.bundle / RECEIPT.RECEIPT_NAME).exists(), overrides)

    def test_receipt_must_remain_in_bundle_and_create_only(self) -> None:
        self.assertNotEqual(
            subprocess.run([sys.executable, str(HELPER), "create", "--output", str(Path(self.temp.name) / "outside.json")], text=True, capture_output=True).returncode,
            0,
        )
        self.create()
        self.assertFalse((Path(self.temp.name) / "outside.json").exists())
        self.assertNotEqual(self.command("create").returncode, 0)

    def test_artifact_binding_requires_one_current_unexpired_fixed_container(self) -> None:
        metadata = Path(self.temp.name) / "artifacts.json"
        valid = {"total_count": 1, "artifacts": [{
            "id": 77, "name": RECEIPT.ARTIFACT_NAME, "digest": "sha256:" + "d" * 64,
            "expired": False, "workflow_run": {"id": 1234},
        }]}
        metadata.write_bytes(RECEIPT.canonical_json(valid))
        argv = [sys.executable, str(HELPER), "artifact-binding", "--metadata", str(metadata),
                "--repository", RECEIPT.REPOSITORY, "--run-id", "1234", "--artifact-name", RECEIPT.ARTIFACT_NAME]
        result = subprocess.run(argv, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"artifactDigest": "sha256:" + "d" * 64, "artifactId": 77, "artifactName": RECEIPT.ARTIFACT_NAME, "runId": 1234})
        for changed in (
            {"artifacts": []},
            {"artifacts": valid["artifacts"] * 2},
            {"artifacts": [{**valid["artifacts"][0], "expired": True}]},
            {"artifacts": [{**valid["artifacts"][0], "workflow_run": {"id": 9}}]},
            {"artifacts": [{**valid["artifacts"][0], "digest": "sha256:bad"}]},
        ):
            metadata.write_bytes(RECEIPT.canonical_json(changed))
            self.assertNotEqual(subprocess.run(argv, text=True, capture_output=True, check=False).returncode, 0, changed)

    def test_after_download_verify_rejects_tampered_receipt_and_exact_set_drift(self) -> None:
        self.create()
        receipt = self.bundle / RECEIPT.RECEIPT_NAME
        value = json.loads(receipt.read_text(encoding="ascii"))
        for field, changed in (
            ("workflowPath", "other.yml"),
            ("checksumSetDigest", "sha256:" + "0" * 64),
            ("assets", []),
        ):
            mutated = dict(value)
            mutated[field] = changed
            receipt.write_bytes(RECEIPT.canonical_json(mutated))
            self.assertNotEqual(self.command("verify").returncode, 0, field)
        receipt.write_bytes(b'{"schemaVersion":"one","schemaVersion":"two"}\n')
        self.assertNotEqual(self.command("verify").returncode, 0)
        receipt.write_bytes(RECEIPT.canonical_json(value) + b" ")
        self.assertNotEqual(self.command("verify").returncode, 0)
        receipt.write_bytes(RECEIPT.canonical_json(value))
        (self.bundle / "UNLISTED.txt").write_text("no\n", encoding="ascii")
        self.assertNotEqual(self.command("verify").returncode, 0)


    def test_publisher_zip_and_handoff_are_digest_bound_and_fail_closed(self) -> None:
        self.create()
        archive = Path(self.temp.name) / "bundle.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
            for item in sorted(self.bundle.iterdir()):
                output.write(item, item.name)
        extracted = Path(self.temp.name) / "extracted"
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, str(HELPER), "extract-publisher-zip", "--zip-path", str(archive), "--zip-sha256", "sha256:" + digest, "--bundle-dir", str(extracted)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        handoff = Path(self.temp.name) / "handoff.json"
        result = self.command("publisher-handoff", publisher_workflow_sha="c" * 40, publisher_run_id="55", publisher_run_attempt="1", artifact_id="77", artifact_digest="sha256:" + "d" * 64, artifact_size="17", output=str(handoff))
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(handoff.read_text())
        self.assertEqual(value["status"], "PUBLISHER_HANDOFF_VERIFIED")
        self.assertEqual(value["stagingArtifactId"], 77)
        self.assertEqual(value["publisherRunId"], 55)
        self.assertEqual(value["publisherWorkflowPath"], RECEIPT.PUBLISHER_WORKFLOW_PATH)
        self.assertEqual(value["publisherRunAttempt"], 1)
        self.assertEqual(len(value["attestations"]), len(RECEIPT.required_assets()))
        self.assertEqual(handoff.read_bytes(), RECEIPT.canonical_json(value))
        verify = [sys.executable, str(HELPER), "verify-publisher-handoff", "--bundle-dir", str(self.bundle), "--repository", RECEIPT.REPOSITORY, "--workflow-path", RECEIPT.WORKFLOW_PATH, "--workflow-sha", self.workflow_sha, "--event", "push", "--run-id", "1234", "--run-attempt", "1", "--ref", RECEIPT.REF, "--source-sha", self.source_sha, "--version", RECEIPT.VERSION, "--publisher-workflow-sha", "c" * 40, "--publisher-run-id", "55", "--publisher-run-attempt", "1", "--artifact-id", "77", "--artifact-digest", "sha256:" + "d" * 64, "--artifact-size", "17", "--handoff", str(handoff)]
        self.assertEqual(subprocess.run(verify, text=True, capture_output=True).returncode, 0)
        original = dict(value)
        value["publisherRunAttempt"] = True
        handoff.write_bytes(RECEIPT.canonical_json(value))
        self.assertNotEqual(subprocess.run(verify, text=True, capture_output=True).returncode, 0)
        value = original
        value["sourceSha"] = "e" * 40; handoff.write_bytes(RECEIPT.canonical_json(value))
        self.assertNotEqual(subprocess.run(verify, text=True, capture_output=True).returncode, 0)
        bad = Path(self.temp.name) / "bad.zip"
        with zipfile.ZipFile(bad, "w") as output:
            output.writestr("../escape", "x")
        self.assertNotEqual(subprocess.run([sys.executable, str(HELPER), "extract-publisher-zip", "--zip-path", str(bad), "--zip-sha256", "sha256:" + hashlib.sha256(bad.read_bytes()).hexdigest(), "--bundle-dir", str(Path(self.temp.name) / "bad")], text=True, capture_output=True).returncode, 0)
        self.assertNotEqual(self.command("publisher-handoff", publisher_workflow_sha="not-a-sha", publisher_run_id="55", publisher_run_attempt="1", artifact_id="77", artifact_digest="sha256:" + "d" * 64, artifact_size="17", output=str(Path(self.temp.name) / "bad-handoff")).returncode, 0)


    def test_staging_run_tag_and_artifact_identity_is_closed(self) -> None:
        def write(name, value):
            path = Path(self.temp.name) / name; path.write_bytes(RECEIPT.canonical_json(value)); return path
        run = {"id":1234,"repository":{"id":RECEIPT.REPOSITORY_ID,"full_name":RECEIPT.REPOSITORY},"head_repository":{"id":RECEIPT.REPOSITORY_ID,"full_name":RECEIPT.REPOSITORY},"path":RECEIPT.WORKFLOW_PATH,"event":"push","head_branch":"v0.1.0-alpha.5","head_sha":self.source_sha,"run_attempt":1,"status":"completed","conclusion":"success"}
        artifact={"id":77,"name":RECEIPT.ARTIFACT_NAME,"digest":"sha256:"+"d"*64,"size_in_bytes":17,"expired":False,"workflow_run":{"id":1234,"repository_id":RECEIPT.REPOSITORY_ID,"head_repository_id":RECEIPT.REPOSITORY_ID,"head_sha":self.source_sha}}
        paths={"run_metadata":write("run.json",run),"tag_metadata":write("tag.json",{"object":{"type":"commit","sha":self.source_sha}}),"artifact_list":write("list.json",[{"total_count":1,"artifacts":[{**artifact,"created_at":"allowed-extra"}]}]),"artifact_metadata":write("artifact.json",{**artifact,"updated_at":"allowed-extra"})}
        base={"bundle_dir":str(self.bundle),"repository":RECEIPT.REPOSITORY,"workflow_path":RECEIPT.WORKFLOW_PATH,"workflow_sha":self.workflow_sha,"event":"push","run_id":"1234","run_attempt":"1","ref":RECEIPT.REF,"source_sha":self.source_sha,"version":RECEIPT.VERSION,"artifact_id":"77","artifact_digest":"sha256:"+"d"*64,"artifact_size":"17","downloaded_size":"17",**{k:str(v) for k,v in paths.items()}}
        def invoke(changes={}):
            v={**base,**changes}; argv=[sys.executable,str(HELPER),"validate-staging-identity"]
            for k,x in v.items(): argv += ["--"+k.replace("_","-"),x]
            return subprocess.run(argv,text=True,capture_output=True)
        self.assertEqual(invoke().returncode,0)
        run["run_attempt"] = True; write("run.json", run)
        self.assertNotEqual(invoke().returncode, 0)
        run["run_attempt"] = 1; write("run.json", run)
        write("list.json", [{"total_count":True,"artifacts":[artifact]}])
        self.assertNotEqual(invoke().returncode, 0)
        write("list.json", [{"total_count":1,"artifacts":[artifact]}])
        wrong_typed_artifact = {**artifact, "expired": 0}; write("artifact.json", wrong_typed_artifact)
        self.assertNotEqual(invoke().returncode, 0)
        write("artifact.json", artifact)
        for key,value in (("event","pull_request"),("ref","refs/tags/wrong"),("source_sha","b"*40),("run_attempt","2"),("artifact_size","18"),("downloaded_size","18")):
            self.assertNotEqual(invoke({key:value}).returncode,0,key)
        run["path"]=".github/workflows/wrong.yml"; write("run.json",run)
        self.assertNotEqual(invoke().returncode,0)
        run["path"]=RECEIPT.WORKFLOW_PATH; write("run.json",run)
        artifact["expired"]=True; write("artifact.json",artifact)
        self.assertNotEqual(invoke().returncode,0)
        artifact["expired"]=False; write("artifact.json",artifact); write("list.json",[{"total_count":2,"artifacts":[artifact,artifact]}])
        self.assertNotEqual(invoke().returncode,0)

        annotated = {"object":{"type":"tag","sha":"e"*40}}
        write("tag.json", annotated); tag_object = write("tag-object.json", {"sha":"e"*40,"object":{"type":"commit","sha":self.source_sha}})
        write("list.json", [{"total_count":1,"artifacts":[artifact]}])
        self.assertEqual(invoke({"tag_object_metadata":str(tag_object)}).returncode, 0)
        tag_object.write_bytes(RECEIPT.canonical_json({"sha":"e"*40,"object":{"type":"tag","sha":"e"*40}}))
        self.assertNotEqual(invoke({"tag_object_metadata":str(tag_object)}).returncode, 0)


if __name__ == "__main__":
    unittest.main()
