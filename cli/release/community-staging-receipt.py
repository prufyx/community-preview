#!/usr/bin/env python3
"""Create and revalidate the fixed Community staging bundle receipt.

The receipt binds the bundle's named subjects, not the uploaded artifact
container. A future publisher must obtain that container identity from Actions
REST and run this same verifier again after download.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from typing import Any

REPOSITORY = "prufyx/prufyx-cli"
REPOSITORY_ID = 1360163747
WORKFLOW_PATH = ".github/workflows/community-release.yml"
PUBLISHER_WORKFLOW_PATH = ".github/workflows/community-publish.yml"
PUBLISHER_REF = "refs/heads/main"
EVENT = "push"
REF = "refs/tags/v0.1.0-alpha.5"
VERSION = "v0.1.0-alpha.5"
ARTIFACT_NAME = "community-staging-bundle"
RECEIPT_NAME = "STAGING-RECEIPT.json"
CHECKSUMS_NAME = "SHA256SUMS"
MAX_METADATA_BYTES = 64 * 1024
MAX_ASSET_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_BYTES = 640 * 1024 * 1024
MAX_TAG_DEREFERENCES = 8
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
CHECKSUM_LINE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9._-]+)\n\Z")


class ReceiptError(ValueError):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReceiptError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def exact_typed_equal(actual: Any, expected: Any) -> bool:
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(exact_typed_equal(actual[key], value) for key, value in expected.items())
    if isinstance(expected, (list, tuple)):
        return len(actual) == len(expected) and all(exact_typed_equal(left, right) for left, right in zip(actual, expected))
    return actual == expected


def regular_bytes(path: Path, label: str, maximum: int = MAX_METADATA_BYTES) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1 or before_path.st_size > maximum:
            raise ReceiptError(f"{label} must be a bounded regular single-link file")
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != before_path.st_size:
                raise ReceiptError(f"{label} changed before being read")
            chunks: list[bytes] = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns)
            if len(raw) != before.st_size or len(raw) > maximum or identity(before) != identity(after):
                raise ReceiptError(f"{label} changed while being read or exceeds its bound")
            return raw
        finally:
            os.close(fd)
    except OSError as exc:
        raise ReceiptError(f"cannot safely read {label}") from exc


def regular_sha256(path: Path, label: str) -> str:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before_path = path.lstat()
        if not stat.S_ISREG(before_path.st_mode) or before_path.st_nlink != 1 or before_path.st_size > MAX_ASSET_BYTES:
            raise ReceiptError(f"{label} must be a bounded regular single-link file")
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != before_path.st_size:
                raise ReceiptError(f"{label} changed before being read")
            digest = hashlib.sha256()
            length = 0
            while True:
                chunk = os.read(fd, 1024 * 1024)
                if not chunk:
                    break
                length += len(chunk)
                if length > MAX_ASSET_BYTES:
                    raise ReceiptError(f"{label} exceeds its bound")
                digest.update(chunk)
            after = os.fstat(fd)
            identity = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_size, item.st_mtime_ns)
            if length != before.st_size or identity(before) != identity(after):
                raise ReceiptError(f"{label} changed while being read")
            return digest.hexdigest()
        finally:
            os.close(fd)
    except OSError as exc:
        raise ReceiptError(f"cannot safely read {label}") from exc


def required_assets() -> list[str]:
    version_number = VERSION.removeprefix("v")
    return sorted([
        "LICENSE", "NOTICE", "THIRD-PARTY.md", "Go-BSD-3-Clause.txt", "SBOM.spdx.json",
        "SOURCE-MANIFEST.json", "SOURCE-REVISION", "SOURCE-TREE.sha256",
        f"prufyx-cli_{version_number}_linux_amd64.tar.gz",
        f"prufyx-cli_{version_number}_linux_arm64.tar.gz",
        f"prufyx-cli_{version_number}_source.tar.gz",
    ])


def exact_hex(value: str, pattern: re.Pattern[str], label: str) -> str:
    if pattern.fullmatch(value) is None:
        raise ReceiptError(f"{label} must be an exact lowercase hexadecimal value")
    return value


def require_identity(args: argparse.Namespace) -> None:
    if args.repository != REPOSITORY:
        raise ReceiptError("repository is not the expected Prufyx repository")
    if args.workflow_path != WORKFLOW_PATH:
        raise ReceiptError("workflow path is not the protected staging workflow")
    if args.event != EVENT or args.ref != REF or args.version != VERSION:
        raise ReceiptError("staging event, ref, or version is not the fixed alpha.5 contract")
    exact_hex(args.workflow_sha, HEX40, "workflow SHA")
    exact_hex(args.source_sha, HEX40, "source SHA")
    if not args.run_id.isdecimal() or int(args.run_id) <= 0 or args.run_attempt != "1":
        raise ReceiptError("staging run identity must be a positive first attempt")


def require_exact_directory(bundle: Path, include_receipt: bool) -> None:
    try:
        info = bundle.lstat()
        if not stat.S_ISDIR(info.st_mode) or bundle.is_symlink():
            raise ReceiptError("bundle directory must be a real directory")
        expected = set(required_assets()) | {CHECKSUMS_NAME}
        if include_receipt:
            expected.add(RECEIPT_NAME)
        actual = {entry.name for entry in os.scandir(bundle)}
    except OSError as exc:
        raise ReceiptError("cannot enumerate staging bundle") from exc
    if actual != expected:
        raise ReceiptError("staging bundle has missing or unexpected entries")
    for name in sorted(expected):
        regular_sha256(bundle / name, f"staging bundle entry {name}")


def parse_checksums(bundle: Path) -> tuple[list[dict[str, str]], str]:
    raw = regular_bytes(bundle / CHECKSUMS_NAME, CHECKSUMS_NAME)
    names: list[str] = []
    rows: list[tuple[str, str]] = []
    for line in raw.splitlines(keepends=True):
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ReceiptError("SHA256SUMS has a non-canonical line")
        digest, name = (part.decode("ascii") for part in match.groups())
        if name in names:
            raise ReceiptError("SHA256SUMS contains a duplicate asset")
        names.append(name)
        rows.append((digest, name))
    if names != required_assets():
        raise ReceiptError("SHA256SUMS asset set is not the fixed staging set")
    assets = []
    for digest, name in rows:
        if regular_sha256(bundle / name, f"staged asset {name}") != digest:
            raise ReceiptError(f"staged asset digest mismatch for {name}")
        assets.append({"name": name, "sha256": f"sha256:{digest}"})
    return assets, f"sha256:{hashlib.sha256(raw).hexdigest()}"


def expected_receipt(bundle: Path, args: argparse.Namespace) -> dict[str, Any]:
    require_identity(args)
    assets, checksum_set_digest = parse_checksums(bundle)
    if regular_bytes(bundle / "SOURCE-REVISION", "SOURCE-REVISION") != (args.source_sha + "\n").encode("ascii"):
        raise ReceiptError("SOURCE-REVISION does not match the staged source SHA")
    return {
        "schemaVersion": "prufyx.io/community-staging-receipt/v1",
        "status": "STAGED_BUILD_VERIFIED",
        "repository": args.repository,
        "workflowPath": args.workflow_path,
        "workflowSha": args.workflow_sha,
        "event": args.event,
        "runId": int(args.run_id),
        "runAttempt": 1,
        "ref": args.ref,
        "sourceSha": args.source_sha,
        "version": args.version,
        "artifactName": ARTIFACT_NAME,
        "assets": assets,
        "checksumSetDigest": checksum_set_digest,
        "receiptExcludedFromChecksumSet": True,
        "attestationSubjects": "assets_listed_in_SHA256SUMS",
    }


def create_receipt(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle_dir)
    require_exact_directory(bundle, include_receipt=False)
    value = expected_receipt(bundle, args)
    receipt = bundle / RECEIPT_NAME
    try:
        fd = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except OSError as exc:
        raise ReceiptError("cannot create in-bundle staging receipt") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(value))
    except Exception:
        try:
            receipt.unlink()
        except OSError:
            pass
        raise
    verify_receipt(args)


def verify_receipt(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle_dir)
    require_exact_directory(bundle, include_receipt=True)
    expected = expected_receipt(bundle, args)
    raw = regular_bytes(bundle / RECEIPT_NAME, RECEIPT_NAME)
    try:
        actual = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("staging receipt is not valid strict JSON") from exc
    if not isinstance(actual, dict) or raw != canonical_json(actual) or not exact_typed_equal(actual, expected):
        raise ReceiptError("staging receipt does not bind the exact verified bundle")


def artifact_binding(args: argparse.Namespace) -> None:
    if args.repository != REPOSITORY or args.artifact_name != ARTIFACT_NAME:
        raise ReceiptError("artifact binding has an unexpected repository or artifact name")
    if not args.run_id.isdecimal() or int(args.run_id) <= 0:
        raise ReceiptError("artifact binding has an invalid run ID")
    raw = regular_bytes(Path(args.metadata), "artifact metadata")
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("artifact metadata is not valid strict JSON") from exc
    if not isinstance(value, dict) or not isinstance(value.get("artifacts"), list):
        raise ReceiptError("artifact metadata has no artifact list")
    matches = [item for item in value["artifacts"] if isinstance(item, dict) and item.get("name") == ARTIFACT_NAME]
    if len(matches) != 1:
        raise ReceiptError("artifact metadata must contain exactly one fixed staging artifact")
    item = matches[0]
    artifact_id = item.get("id")
    digest = item.get("digest")
    workflow_run = item.get("workflow_run")
    if isinstance(artifact_id, bool) or not isinstance(artifact_id, int) or artifact_id <= 0:
        raise ReceiptError("artifact metadata has an invalid artifact ID")
    if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
        raise ReceiptError("artifact metadata has an invalid artifact digest")
    if item.get("expired") is not False or not isinstance(workflow_run, dict) or type(workflow_run.get("id")) is not int or workflow_run.get("id") != int(args.run_id):
        raise ReceiptError("artifact metadata does not bind the current unexpired run")
    print(canonical_json({
        "artifactDigest": digest,
        "artifactId": artifact_id,
        "artifactName": ARTIFACT_NAME,
        "runId": int(args.run_id),
    }).decode("ascii"), end="")


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-path", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--event", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--version", required=True)




def load_strict_json(path: Path, label: str) -> dict[str, Any]:
    raw = regular_bytes(path, label)
    try: value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ReceiptError(f"{label} is not strict JSON") from exc
    if not isinstance(value, dict): raise ReceiptError(f"{label} must be an object")
    return value


def resolve_tag(args: argparse.Namespace) -> None:
    ref = load_strict_json(Path(args.tag_metadata), "tag ref metadata")
    obj = ref.get("object")
    if not isinstance(obj, dict):
        raise ReceiptError("tag ref metadata has no object")
    tag_objects = list(args.tag_object_metadata or [])
    seen: set[str] = set()
    used = 0
    while obj.get("type") == "tag":
        sha = obj.get("sha")
        if not isinstance(sha, str) or HEX40.fullmatch(sha) is None or sha in seen:
            raise ReceiptError("annotated tag chain is invalid or cyclic")
        seen.add(sha)
        if used >= MAX_TAG_DEREFERENCES or used >= len(tag_objects):
            raise ReceiptError("annotated tag chain is incomplete or too deep")
        tag = load_strict_json(Path(tag_objects[used]), f"annotated tag metadata {used + 1}")
        used += 1
        if tag.get("sha") != sha or not isinstance(tag.get("object"), dict):
            raise ReceiptError("annotated tag metadata does not match its requested object")
        obj = tag["object"]
    if used != len(tag_objects) or obj.get("type") != "commit" or obj.get("sha") != args.source_sha:
        raise ReceiptError("tag does not resolve exactly to the staged source SHA")


def artifact_projection(item: Any) -> tuple[Any, ...]:
    if not isinstance(item, dict) or not isinstance(item.get("workflow_run"), dict):
        raise ReceiptError("artifact metadata is missing its workflow run projection")
    run = item["workflow_run"]
    if (type(item.get("id")) is not int or item["id"] <= 0 or type(item.get("name")) is not str or
            type(item.get("digest")) is not str or DIGEST.fullmatch(item["digest"]) is None or
            type(item.get("size_in_bytes")) is not int or item["size_in_bytes"] <= 0 or
            type(item.get("expired")) is not bool or type(run.get("id")) is not int or run["id"] <= 0 or
            type(run.get("repository_id")) is not int or type(run.get("head_repository_id")) is not int or
            type(run.get("head_sha")) is not str or HEX40.fullmatch(run["head_sha"]) is None):
        raise ReceiptError("artifact metadata has a wrong-typed security projection")
    return (
        item.get("id"), item.get("name"), item.get("digest"), item.get("size_in_bytes"), item.get("expired"),
        run.get("id"), run.get("repository_id"), run.get("head_repository_id"), run.get("head_sha"),
    )


def complete_artifact_list(path: Path) -> list[Any]:
    raw = regular_bytes(path, "artifact list")
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReceiptError("artifact list is not strict JSON") from exc
    pages = value if isinstance(value, list) else [value]
    if not pages or not all(isinstance(page, dict) and isinstance(page.get("artifacts"), list) for page in pages):
        raise ReceiptError("artifact list has no complete page set")
    artifacts = [item for page in pages for item in page["artifacts"]]
    totals = {page.get("total_count") for page in pages}
    if len(totals) != 1 or type(next(iter(totals))) is not int or next(iter(totals)) != len(artifacts):
        raise ReceiptError("artifact list pagination is incomplete")
    ids = [item.get("id") for item in artifacts if isinstance(item, dict)]
    if len(ids) != len(artifacts) or any(type(value) is not int or value <= 0 for value in ids) or len(ids) != len(set(ids)):
        raise ReceiptError("artifact list contains an invalid or duplicate identity")
    return artifacts


def validate_staging_identity(args: argparse.Namespace) -> None:
    require_identity(args)
    if not args.artifact_id.isdecimal() or int(args.artifact_id) <= 0 or not args.artifact_size.isdecimal() or int(args.artifact_size) <= 0 or not args.downloaded_size.isdecimal():
        raise ReceiptError("artifact identity has invalid numeric fields")
    digest = "sha256:" + exact_hex(args.artifact_digest.removeprefix("sha256:"), HEX64, "artifact digest")
    run = load_strict_json(Path(args.run_metadata), "run metadata")
    repo = run.get("repository"); head_repo = run.get("head_repository")
    if (not isinstance(repo, dict) or not isinstance(head_repo, dict) or type(repo.get("id")) is not int or
            type(head_repo.get("id")) is not int or type(repo.get("full_name")) is not str or
            type(head_repo.get("full_name")) is not str or repo.get("id") != REPOSITORY_ID or
            head_repo.get("id") != REPOSITORY_ID or repo.get("full_name") != args.repository or
            head_repo.get("full_name") != args.repository):
        raise ReceiptError("run metadata has an unexpected repository identity")
    run_projection = {key: run.get(key) for key in ("id", "path", "event", "head_branch", "head_sha", "run_attempt", "status", "conclusion")}
    expected_run_projection = {"id": int(args.run_id), "path": args.workflow_path, "event": args.event,
        "head_branch": args.ref.removeprefix("refs/tags/"), "head_sha": args.source_sha, "run_attempt": 1,
        "status": "completed", "conclusion": "success"}
    if not exact_typed_equal(run_projection, expected_run_projection):
        raise ReceiptError("run metadata does not bind the fixed staging identity")
    resolve_tag(args)
    listing = complete_artifact_list(Path(args.artifact_list))
    direct = load_strict_json(Path(args.artifact_metadata), "artifact metadata")
    matches = [x for x in listing if isinstance(x, dict) and x.get("name") == ARTIFACT_NAME]
    if len(matches) != 1 or not exact_typed_equal(artifact_projection(matches[0]), artifact_projection(direct)):
        raise ReceiptError("artifact list and direct security projections do not agree")
    expected = {"id":int(args.artifact_id),"name":ARTIFACT_NAME,"digest":digest,"size_in_bytes":int(args.artifact_size),"expired":False}
    wr = direct.get("workflow_run", {})
    if (not exact_typed_equal({key: direct.get(key) for key in expected}, expected) or
            not exact_typed_equal({"id": wr.get("id"), "repository_id": wr.get("repository_id"),
                "head_repository_id": wr.get("head_repository_id"), "head_sha": wr.get("head_sha")},
                {"id": int(args.run_id), "repository_id": REPOSITORY_ID,
                 "head_repository_id": REPOSITORY_ID, "head_sha": args.source_sha}) or
            int(args.downloaded_size) != int(args.artifact_size)):
        raise ReceiptError("artifact does not bind the fixed unexpired staging container")


def extract_publisher_zip(args: argparse.Namespace) -> None:
    archive = Path(args.zip_path)
    expected_digest = exact_hex(args.zip_sha256.removeprefix("sha256:"), HEX64, "publisher ZIP SHA-256")
    if archive.stat().st_size > MAX_ARCHIVE_BYTES or regular_sha256(archive, "publisher artifact ZIP") != expected_digest:
        raise ReceiptError("publisher artifact ZIP digest mismatch")
    target = Path(args.bundle_dir)
    if target.exists() or target.is_symlink() or not target.parent.is_dir():
        raise ReceiptError("publisher extraction target must be a new child of an existing directory")
    expected = set(required_assets()) | {CHECKSUMS_NAME, RECEIPT_NAME}
    created: list[Path] = []
    try:
        with zipfile.ZipFile(archive) as source:
            infos = source.infolist(); names = [item.filename for item in infos]
            total = sum(item.file_size for item in infos)
            compressed = sum(item.compress_size for item in infos)
            if len(names) != len(set(names)) or set(names) != expected or total > MAX_ASSET_BYTES or compressed > MAX_ARCHIVE_BYTES:
                raise ReceiptError("publisher artifact ZIP has an unexpected or oversized entry set")
            aggregate = 0
            for item in infos:
                mode = item.external_attr >> 16
                if item.is_dir() or item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or item.file_size > MAX_ASSET_BYTES:
                    raise ReceiptError("publisher artifact ZIP contains an unsafe entry")
            target.mkdir(mode=0o700); created.append(target)
            for item in infos:
                out = target / item.filename
                fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600); created.append(out)
                count = 0
                with source.open(item) as inp, os.fdopen(fd, "wb") as handle:
                    while chunk := inp.read(1024 * 1024):
                        count += len(chunk)
                        aggregate += len(chunk)
                        if count > item.file_size or count > MAX_ASSET_BYTES or aggregate > MAX_ASSET_BYTES: raise ReceiptError("publisher artifact ZIP entry exceeds its bound")
                        handle.write(chunk)
                if count != item.file_size: raise ReceiptError("publisher artifact ZIP entry changed while read")
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise ReceiptError("cannot safely extract publisher artifact ZIP") from exc
    except Exception:
        for item in reversed(created):
            try: item.unlink() if item != target else item.rmdir()
            except OSError: pass
        raise


def expected_publisher_handoff(bundle: Path, args: argparse.Namespace) -> dict[str, Any]:
    verify_receipt(args)
    exact_hex(args.publisher_workflow_sha, HEX40, "publisher workflow SHA")
    if not args.publisher_run_id.isdecimal() or int(args.publisher_run_id) <= 0 or args.publisher_run_attempt != "1":
        raise ReceiptError("publisher run identity must be a positive first attempt")
    if not args.artifact_id.isdecimal() or int(args.artifact_id) <= 0 or not args.artifact_size.isdecimal() or int(args.artifact_size) <= 0:
        raise ReceiptError("staging artifact identity must be positive")
    artifact_digest = "sha256:" + exact_hex(args.artifact_digest.removeprefix("sha256:"), HEX64, "staging artifact digest")
    assets, checksum_digest = parse_checksums(bundle)
    asset_evidence = [{**asset, "size": (bundle / asset["name"]).stat().st_size} for asset in assets]
    attestations = [{
        "name": asset["name"], "status": "VERIFIED", "repository": REPOSITORY,
        "signerWorkflow": f"{REPOSITORY}/{WORKFLOW_PATH}", "signerDigest": args.workflow_sha,
        "sourceRef": args.ref, "sourceDigest": args.source_sha, "denySelfHostedRunners": True,
    } for asset in assets]
    return {
        "schemaVersion": "prufyx.io/community-publisher-handoff/v1", "status": "PUBLISHER_HANDOFF_VERIFIED",
        "repository": REPOSITORY, "repositoryId": REPOSITORY_ID,
        "stagingWorkflowPath": WORKFLOW_PATH, "stagingWorkflowSha": args.workflow_sha,
        "stagingEvent": EVENT, "stagingRunId": int(args.run_id), "stagingRunAttempt": 1,
        "stagingRef": REF, "sourceSha": args.source_sha, "version": VERSION,
        "stagingArtifactName": ARTIFACT_NAME,
        "publisherWorkflowPath": PUBLISHER_WORKFLOW_PATH, "publisherWorkflowRef": PUBLISHER_REF,
        "publisherWorkflowSha": args.publisher_workflow_sha, "publisherRunId": int(args.publisher_run_id), "publisherRunAttempt": 1,
        "stagingArtifactId": int(args.artifact_id), "stagingArtifactDigest": artifact_digest,
        "stagingArtifactSize": int(args.artifact_size), "checksumSetDigest": checksum_digest,
        "stagingReceiptDigest": "sha256:" + regular_sha256(bundle / RECEIPT_NAME, RECEIPT_NAME),
        "assets": asset_evidence, "attestations": attestations,
    }


def create_publisher_handoff(args: argparse.Namespace) -> None:
    value = expected_publisher_handoff(Path(args.bundle_dir), args)
    output = Path(args.output)
    try:
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(value))
    except OSError as exc:
        raise ReceiptError("cannot create publisher handoff") from exc



def verify_publisher_handoff(args: argparse.Namespace) -> None:
    bundle = Path(args.bundle_dir)
    value = expected_publisher_handoff(bundle, args)
    raw = regular_bytes(Path(args.handoff), "publisher handoff")
    try: actual = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ReceiptError("publisher handoff is not strict JSON") from exc
    if not isinstance(actual, dict) or raw != canonical_json(actual) or not exact_typed_equal(actual, value):
        raise ReceiptError("publisher handoff does not bind the exact verified bundle")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    verify = commands.add_parser("verify")
    binding = commands.add_parser("artifact-binding")
    extract = commands.add_parser("extract-publisher-zip")
    handoff = commands.add_parser("publisher-handoff")
    verify_handoff = commands.add_parser("verify-publisher-handoff")
    identity = commands.add_parser("validate-staging-identity")
    add_identity_arguments(create)
    add_identity_arguments(verify)
    add_identity_arguments(handoff)
    add_identity_arguments(verify_handoff)
    add_identity_arguments(identity)
    for key in ("run_metadata", "tag_metadata", "artifact_list", "artifact_metadata", "artifact_id", "artifact_digest", "artifact_size", "downloaded_size"):
        identity.add_argument("--" + key.replace("_", "-"), required=True)
    identity.add_argument("--tag-object-metadata", action="append", default=[])
    extract.add_argument("--zip-path", required=True)
    extract.add_argument("--zip-sha256", required=True)
    extract.add_argument("--bundle-dir", required=True)
    for command in (handoff, verify_handoff):
        command.add_argument("--publisher-workflow-sha", required=True)
        command.add_argument("--publisher-run-id", required=True)
        command.add_argument("--publisher-run-attempt", required=True)
        command.add_argument("--artifact-id", required=True)
        command.add_argument("--artifact-digest", required=True)
        command.add_argument("--artifact-size", required=True)
    handoff.add_argument("--output", required=True)
    verify_handoff.add_argument("--handoff", required=True)
    binding.add_argument("--metadata", required=True)
    binding.add_argument("--repository", required=True)
    binding.add_argument("--run-id", required=True)
    binding.add_argument("--artifact-name", required=True)
    args = parser.parse_args()
    try:
        if args.command == "create":
            create_receipt(args)
        elif args.command == "verify":
            verify_receipt(args)
        elif args.command == "artifact-binding":
            artifact_binding(args)
        elif args.command == "validate-staging-identity":
            validate_staging_identity(args)
        elif args.command == "extract-publisher-zip":
            extract_publisher_zip(args)
        elif args.command == "publisher-handoff":
            create_publisher_handoff(args)
        else:
            verify_publisher_handoff(args)
    except ReceiptError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
