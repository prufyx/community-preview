from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import tempfile
import textwrap
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
WF = ROOT / ".github/workflows/community-publish.yml"
HELPER = ROOT / "cli/release/community-staging-receipt.py"
EXPECTED_WORKFLOW_SHA256 = "7153f06835389c5e09b6f043d9f3e3b52519f925964db5db23213c414cc39180"
SPEC = importlib.util.spec_from_file_location("publisher_receipt", HELPER)
assert SPEC and SPEC.loader
R = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(R)


def workflow_text() -> str:
    """Parse only the reviewed workflow's indentation-bound structural grammar."""
    raw = WF.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_WORKFLOW_SHA256:
        raise AssertionError("workflow bytes differ from the reviewed contract")
    value = raw.decode("utf-8", errors="strict")
    if "\t" in value or not value.startswith("name: Community publish\n") or value.count("\njobs:\n") != 1:
        raise AssertionError("workflow must use the reviewed YAML layout")
    jobs = value.split("\njobs:\n", 1)[1]
    names = re.findall(r"^  ([a-z0-9-]+):$", jobs, flags=re.MULTILINE)
    if names != ["transition-gate", "verify-staging", "publish"] or any(jobs.count(f"  {name}:\n") != 1 for name in names):
        raise AssertionError("workflow must contain exactly the reviewed job graph")
    return value


def job_block(name: str) -> str:
    lines = workflow_text().splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line == f"  {name}:\n")
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("  ") and not lines[i].startswith("    ") and lines[i].strip().endswith(":")), len(lines))
    return "".join(lines[start:end])


def transition_gate_script(visibility: str) -> str:
    block = job_block("transition-gate")
    lines = block.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line == "        run: |\n") + 1
    body = []
    for line in lines[start:]:
        if not line.startswith("          "):
            break
        body.append(line.removeprefix("          "))
    if not body:
        raise AssertionError("transition gate run body is absent")
    values = {
        "${{ github.repository }}": "prufyx/prufyx-cli",
        "${{ github.repository_id }}": "1360163747",
        "${{ github.event.repository.visibility }}": visibility,
        "${{ github.ref }}": "refs/heads/main",
        "${{ github.ref_protected }}": "true",
        "${{ github.workflow_ref }}": "prufyx/prufyx-cli/.github/workflows/community-publish.yml@refs/heads/main",
        "${{ github.workflow_sha }}": "c" * 40,
    }
    script = "".join(body)
    for expression, value in values.items():
        script = script.replace(expression, value)
    if "${{" in script:
        raise AssertionError("unexpected unresolved transition context")
    return script


def run_transition_gate(visibility: str) -> subprocess.CompletedProcess[str]:
    env = os.environ | {
        "PUBLICATION_ENABLED": "true", "PUBLISHER_SHA": "c" * 40,
        "EXPECTED_REPOSITORY": "prufyx/prufyx-cli", "EXPECTED_REPOSITORY_ID": "1360163747",
        "PUBLISHER_WORKFLOW": ".github/workflows/community-publish.yml",
    }
    return subprocess.run(["bash", "-c", transition_gate_script(visibility)], env=env, text=True, capture_output=True, check=False)


def inline_source() -> str:
    run = job_block("publish")
    begin = "# BEGIN TRUSTED_COMMUNITY_PUBLISHER_PYTHON_V1"
    end = "# END TRUSTED_COMMUNITY_PUBLISHER_PYTHON_V1"
    if run.count(begin) != 1 or run.count(end) != 1:
        raise AssertionError("trusted inline validator marker must be unique")
    block = run.split(begin, 1)[1].split(end, 1)[0]
    prefix = "<<'PY'\n"
    terminator = "\n          PY\n"
    if block.count(prefix) != 1 or block.count(terminator) != 1:
        raise AssertionError("trusted inline validator heredoc must be unique")
    return textwrap.dedent(block.split(prefix, 1)[1].split(terminator, 1)[0]) + "\n"


class PublisherContract(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="publisher-contract-")
        self.root = Path(self.tmp.name)
        self.bundle = self.root / "bundle"; self.bundle.mkdir()
        self.source = "a" * 40; self.staging = "b" * 40; self.publisher = "c" * 40
        for name in R.required_assets():
            (self.bundle / name).write_bytes((self.source + "\n").encode() if name == "SOURCE-REVISION" else (name + "\n").encode())
        sums = "".join(f"{hashlib.sha256((self.bundle/name).read_bytes()).hexdigest()}  {name}\n" for name in R.required_assets())
        (self.bundle / "SHA256SUMS").write_text(sums, encoding="ascii")
        args = argparse.Namespace(bundle_dir=str(self.bundle), repository=R.REPOSITORY, workflow_path=R.WORKFLOW_PATH, workflow_sha=self.staging, event="push", run_id="1234", run_attempt="1", ref=R.REF, source_sha=self.source, version=R.VERSION)
        R.create_receipt(args)
        args.publisher_workflow_sha=self.publisher; args.publisher_run_id="55"; args.publisher_run_attempt="1"; args.artifact_id="77"; args.artifact_digest="sha256:"+"d"*64; args.artifact_size="17"; args.output=str(self.bundle/"STAGING-PUBLISH-HANDOFF.json")
        R.create_publisher_handoff(args)
        self.good_handoff = (self.bundle/"STAGING-PUBLISH-HANDOFF.json").read_bytes()
        self.validator = self.root / "validator.py"; self.validator.write_text(inline_source(), encoding="utf-8")
        self.env = os.environ | {"HANDOFF_ID":"88","SOURCE_SHA":self.source,"STAGING_SHA":self.staging,"PUBLISHER_SHA":self.publisher,"STAGING_RUN_ID":"1234","STAGING_ARTIFACT_ID":"77","STAGING_ARTIFACT_DIGEST":"sha256:"+"d"*64,"STAGING_ARTIFACT_SIZE":"17","GITHUB_RUN_ID":"55","GITHUB_RUN_ATTEMPT":"1"}

    def tearDown(self) -> None: self.tmp.cleanup()

    def write(self, name: str, value) -> None: (self.root/name).write_bytes(R.canonical_json(value))

    def build_zip(self, mutate=None) -> None:
        z = self.root/"handoff.zip"
        with zipfile.ZipFile(z,"w",zipfile.ZIP_DEFLATED) as out:
            for p in sorted(self.bundle.iterdir()):
                if p.name == "LICENSE" and mutate == "missing": continue
                if p.name == "LICENSE" and mutate in {"directory","symlink","extra-metadata"}:
                    info=zipfile.ZipInfo("LICENSE"); info.create_system=3
                    info.external_attr=((0o040755 if mutate=="directory" else 0o120777 if mutate=="symlink" else 0o100600)<<16)
                    if mutate=="extra-metadata": info.extra=b"\r\x00\x00\x00"
                    out.writestr(info,b"target"); continue
                out.write(p,p.name)
            if mutate == "duplicate":
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning); out.writestr("LICENSE",b"second")
            if mutate in {"extra","traversal","absolute"}: out.writestr({"extra":"EXTRA","traversal":"../escape","absolute":"/escape"}[mutate],b"x")
        if mutate in {"encrypted","unsupported","oversized"}:
            raw=bytearray(z.read_bytes()); local=raw.index(b"PK\x03\x04"); central=raw.index(b"PK\x01\x02")
            if mutate=="encrypted":
                struct.pack_into("<H",raw,local+6,struct.unpack_from("<H",raw,local+6)[0]|1); struct.pack_into("<H",raw,central+8,struct.unpack_from("<H",raw,central+8)[0]|1)
            elif mutate=="unsupported": struct.pack_into("<H",raw,local+8,99); struct.pack_into("<H",raw,central+10,99)
            else: struct.pack_into("<I",raw,local+22,536870913); struct.pack_into("<I",raw,central+24,536870913)
            z.write_bytes(raw)
        digest="sha256:"+hashlib.sha256(z.read_bytes()).hexdigest(); self.env["HANDOFF_DIGEST"]=digest
        artifact={"id":88,"name":R.HANDOFF_NAME if hasattr(R,"HANDOFF_NAME") else "community-publish-handoff","digest":digest,"size_in_bytes":z.stat().st_size,"expired":False,"workflow_run":{"id":55,"repository_id":R.REPOSITORY_ID,"head_repository_id":R.REPOSITORY_ID,"head_sha":self.publisher}}
        self.write("handoff-artifact.json",artifact); self.write("handoff-list.json",[{"total_count":1,"artifacts":[{**artifact,"extra":"allowed"}]}])
        original={"id":77,"name":R.ARTIFACT_NAME,"digest":"sha256:"+"d"*64,"size_in_bytes":17,"expired":False,"workflow_run":{"id":1234,"repository_id":R.REPOSITORY_ID,"head_repository_id":R.REPOSITORY_ID,"head_sha":self.source}}
        self.write("staging-artifact.json",original)
        self.write("main.json",{"object":{"type":"commit","sha":self.publisher}})
        self.write("publish-tag-chain.json",[{"object":{"type":"commit","sha":self.source}}])

    def invoke(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run([os.sys.executable,"-B",str(self.validator),str(self.root),*args],env=self.env,text=True,capture_output=True)

    def test_activation_gate_permissions_and_draft_transition_contract(self) -> None:
        text=workflow_text(); self.assertIn('PUBLICATION_ENABLED: "true"',text); self.assertEqual(text.count("PUBLICATION_ENABLED:"),1)
        inputs=text.split("permissions: {}",1)[0]; self.assertNotIn("publication_enabled",inputs)
        required_inputs=("staging_run_id","staging_artifact_id","staging_artifact_digest","staging_source_sha","staging_workflow_sha","publisher_workflow_sha")
        self.assertEqual(re.findall(r"^      ([a-z_]+): \{required: true, type: string\}$",inputs,flags=re.MULTILINE),list(required_inputs))
        gate=job_block("transition-gate"); verify=job_block("verify-staging"); publish=job_block("publish")
        self.assertIn("    permissions: {}",gate); self.assertIn("    permissions: {contents: read, actions: read, attestations: read}",verify); self.assertIn("    permissions: {contents: write, actions: read}",publish)
        self.assertNotIn("actions/checkout",publish); self.assertNotIn("download-artifact",publish); self.assertNotIn("gh attestation",publish.lower()); self.assertNotIn("go build",publish)
        for token in ("actions/artifacts/$HANDOFF_ID/zip","--paginate --slurp","--verify-tag","--draft","--prerelease","--latest=false","verify-release true","-F draft=false","verify-context","verify-release false"): self.assertIn(token,publish)
        self.assertNotIn("github.repository_visibility", text)
        self.assertEqual(text.count("github.event.repository.visibility"), 2)
        for token in (
            'test "${{ github.repository }}" = "$EXPECTED_REPOSITORY"',
            'test "${{ github.repository_id }}" = "$EXPECTED_REPOSITORY_ID"',
            'test "${{ github.event.repository.visibility }}" = "public"',
            'test "${{ github.ref }}" = "refs/heads/main"',
            'test "${{ github.ref_protected }}" = "true"',
            'test "${{ github.workflow_ref }}" = "$EXPECTED_REPOSITORY/$PUBLISHER_WORKFLOW@refs/heads/main"',
            'test "${{ github.workflow_sha }}" = "$PUBLISHER_SHA"',
        ):
            self.assertIn(token,gate)
        for visibility, expected in (("public", 0), ("private", 1), ("internal", 1), ("unknown", 1), ("", 1)):
            with self.subTest(visibility=visibility):
                result = run_transition_gate(visibility)
                self.assertEqual(result.returncode, expected, result.stderr)
        self.assertIn("github.workflow_sha",verify); self.assertIn("validate-staging-identity",verify); self.assertIn("--deny-self-hosted-runners",verify)

    def test_exact_workflow_binding_rejects_crlf_bytes(self) -> None:
        crlf = self.root / "community-publish-crlf.yml"
        crlf.write_bytes(WF.read_bytes().replace(b"\n", b"\r\n"))
        with mock.patch(f"{__name__}.WF", crlf):
            with self.assertRaisesRegex(AssertionError, "workflow bytes differ"):
                workflow_text()

    def test_actual_inline_validator_accepts_exact_handoff_and_release(self) -> None:
        self.build_zip(); result=self.invoke("verify-handoff"); self.assertEqual(result.returncode,0,result.stderr)
        release={"id":99,"url":f"https://api.github.com/repos/{R.REPOSITORY}/releases/99","tag_name":R.VERSION,"draft":True,"prerelease":True}
        handoff=json.loads((self.root/"handoff/STAGING-PUBLISH-HANDOFF.json").read_text()); assets=[{"id":i+1,"name":x["name"],"size":x["size"],"digest":x["sha256"],"state":"uploaded"} for i,x in enumerate(handoff["assets"])]
        self.write("release.json",release); self.write("release-assets.json",[assets]); self.env["RELEASE_ID"]="99"
        self.assertEqual(self.invoke("verify-release","true").returncode,0)
        release["draft"]=False; self.write("release.json",release); self.assertEqual(self.invoke("verify-release","false").returncode,0)

    def assert_inline_handoff_rejected(self, case: str) -> None:
        (self.bundle/"STAGING-PUBLISH-HANDOFF.json").write_bytes(self.good_handoff)
        if case in {"handoff","handoff-bool-attempt","handoff-assets-object"}:
            value=json.loads(self.good_handoff)
            if case=="handoff": value["sourceSha"]="e"*40
            if case=="handoff-bool-attempt": value["publisherRunAttempt"]=True
            if case=="handoff-assets-object": value["assets"]={}
            (self.bundle/"STAGING-PUBLISH-HANDOFF.json").write_bytes(R.canonical_json(value))
        self.build_zip(case if case in {"missing","duplicate","extra","traversal","absolute","directory","symlink","extra-metadata","encrypted","unsupported","oversized"} else None)
        if case=="main": self.write("main.json",{"object":{"type":"commit","sha":"e"*40}})
        if case=="main-sha-int": self.write("main.json",{"object":{"type":"commit","sha":1}})
        if case=="tag": self.write("publish-tag-chain.json",[{"object":{"type":"commit","sha":"e"*40}}])
        if case=="tag-chain-object": self.write("publish-tag-chain.json",{"object":{"type":"commit","sha":self.source}})
        if case=="expired":
            value=json.loads((self.root/"handoff-artifact.json").read_text()); value["expired"]=True; self.write("handoff-artifact.json",value)
        if case=="pagination": self.write("handoff-list.json",[{"total_count":2,"artifacts":[]}])
        if case=="pagination-bool-total":
            value=json.loads((self.root/"handoff-list.json").read_text()); value[0]["total_count"]=True; self.write("handoff-list.json",value)
        if case in {"artifact-bool-id","artifact-expired-int"}:
            value=json.loads((self.root/"handoff-artifact.json").read_text())
            if case=="artifact-bool-id": value["id"]=True
            else: value["expired"]=0
            self.write("handoff-artifact.json",value)
        if case=="original":
            value=json.loads((self.root/"staging-artifact.json").read_text()); value["workflow_run"]["id"]=999; self.write("staging-artifact.json",value)
        if case=="original-size-bool":
            value=json.loads((self.root/"staging-artifact.json").read_text()); value["size_in_bytes"]=True; self.write("staging-artifact.json",value)
        self.assertNotEqual(self.invoke("verify-handoff").returncode,0)

    def test_actual_release_validator_rejects_asset_and_release_mutations(self) -> None:
        self.build_zip(); self.assertEqual(self.invoke("verify-handoff").returncode,0)
        h=json.loads((self.root/"handoff/STAGING-PUBLISH-HANDOFF.json").read_text()); good=[{"id":i+1,"name":x["name"],"size":x["size"],"digest":x["sha256"],"state":"uploaded"} for i,x in enumerate(h["assets"])]
        base={"id":99,"url":f"https://api.github.com/repos/{R.REPOSITORY}/releases/99","tag_name":R.VERSION,"draft":True,"prerelease":True}; self.env["RELEASE_ID"]="99"
        for field,value in (("tag_name","wrong"),("draft",False),("id",100)):
            self.write("release.json",base|{field:value}); self.write("release-assets.json",[good]); self.assertNotEqual(self.invoke("verify-release","true").returncode,0,field)
        self.write("release.json",base)
        for assets in (good[:-1], good+[{**good[0],"id":999}], [{**x,"digest":"sha256:"+"0"*64} if i==0 else x for i,x in enumerate(good)]):
            self.write("release-assets.json",[assets]); self.assertNotEqual(self.invoke("verify-release","true").returncode,0)


def mutation_test(case: str):
    def test(self: PublisherContract) -> None: self.assert_inline_handoff_rejected(case)
    return test


for _case in ("main","main-sha-int","tag","tag-chain-object","handoff","handoff-bool-attempt","handoff-assets-object","expired","pagination","pagination-bool-total","artifact-bool-id","artifact-expired-int","original","original-size-bool","missing","duplicate","extra","traversal","absolute","directory","symlink","extra-metadata","encrypted","unsupported","oversized"):
    setattr(PublisherContract, f"test_actual_inline_rejects_{_case.replace('-', '_')}", mutation_test(_case))


if __name__=="__main__": unittest.main()
