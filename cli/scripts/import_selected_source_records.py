#!/usr/bin/env python3
"""Normalize approved private-reference corpus metadata without copying source bytes."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

OUTPUT_SCHEMA = "prufyx.io/selected-source-records/v1"
INDEX_SCHEMA = "prufyx.io/private-source-corpus-proposed-aggregate-index/v1"
MANIFEST_SCHEMA = "prufyx.io/public-source-corpus/v1"
AUTHORITY = "LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF"
MANIFEST_AUTHORITY = "DECLARED_PUBLIC_SOURCE_BYTES_NOT_RULE_OR_RUNTIME_PROOF"
PROJECT_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_KINDS = {"changelog", "helm_chart", "migration_guide", "release_note", "repository_metadata", "source_code"}
R16_INDEX_DIGEST = "sha256:90046886ad4903d0e938d1d5c4cb42cca0d034153dc293682c1503cec79e3de9"
R16_RECORD_COUNT = 102
R16_PROJECT_COUNT = 58
MAX_URL = 2048
MAX_ID = 160


class Invalid(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def reject_duplicate_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise Invalid("duplicate JSON object field")
        result[key] = value
    return result


def load(path: Path) -> tuple[Any, bytes]:
    try:
        raw = path.read_bytes()
        return json.loads(raw, object_pairs_hook=reject_duplicate_object), raw
    except (OSError, json.JSONDecodeError, Invalid) as exc:
        raise Invalid("unable to read trusted corpus metadata") from exc


def canonical(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n").encode()


def within(root: Path, relative: str) -> Path:
    require(isinstance(relative, str) and relative and not Path(relative).is_absolute(), "invalid manifest path")
    path = (root / relative).resolve()
    require(path.is_relative_to(root.resolve()) and path.is_file() and not path.is_symlink(), "manifest is outside selected corpus root")
    return path


def text(value: Any, label: str, maximum: int = MAX_URL) -> str:
    require(isinstance(value, str) and 0 < len(value) <= maximum and not any(ord(character) < 32 or ord(character) == 127 for character in value), f"invalid {label}")
    return value


def https_url(value: Any, label: str) -> str:
    value = text(value, f"{label} URL")
    parsed = urlparse(value)
    require(parsed.scheme == "https" and parsed.netloc and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment, f"invalid {label} URL")
    return value


def github_repository_url(value: Any, label: str) -> str:
    value = https_url(value, label)
    parsed = urlparse(value)
    require(parsed.netloc == "github.com" and len([part for part in parsed.path.split("/") if part]) == 2, f"invalid {label} GitHub repository URL")
    return value


def immutable_github_url(value: Any, label: str) -> tuple[str, str]:
    value = https_url(value, label)
    parsed = urlparse(value)
    parts = [part for part in parsed.path.split("/") if part]
    require(parsed.netloc == "github.com" and len(parts) >= 5 and parts[2] == "blob" and COMMIT_RE.fullmatch(parts[3]) is not None, f"invalid {label} immutable GitHub URL")
    return value, parts[3]


def normalize_record(raw: Any) -> dict[str, Any]:
    require(isinstance(raw, dict) and set(raw) == {"id", "project", "source", "capture", "declarations"}, "unexpected corpus record field")
    project, source, capture, declarations = raw["project"], raw["source"], raw["capture"], raw["declarations"]
    require(isinstance(project, dict) and set(project) == {"slug", "canonicalRepositoryURL"}, "unexpected corpus project field")
    require(isinstance(source, dict) and set(source) == {"repositoryURL", "immutableURL", "commit", "version", "sourceKind", "fileDigest", "byteLength", "spans"}, "unexpected corpus source field")
    require(isinstance(capture, dict) and set(capture) == {"capturedAt", "object"}, "unexpected corpus capture field")
    require(isinstance(declarations, dict) and set(declarations) == {"packetDigest", "ruleIDs"}, "unexpected corpus declaration field")
    record_id, project_id = raw["id"], project["slug"]
    require(isinstance(record_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", record_id) is not None, "invalid corpus record id")
    require(isinstance(project_id, str) and PROJECT_RE.fullmatch(project_id) is not None and len(project_id) <= 80, "invalid corpus project id")
    commit, source_kind, content_digest, byte_length = source["commit"], source["sourceKind"], source["fileDigest"], source["byteLength"]
    require(isinstance(commit, str) and COMMIT_RE.fullmatch(commit) is not None, "invalid corpus source commit")
    text(source["version"], "corpus source version", 128)
    require(source_kind in SOURCE_KINDS, "invalid corpus source kind")
    require(isinstance(content_digest, str) and DIGEST_RE.fullmatch(content_digest) is not None, "invalid corpus source digest")
    require(isinstance(byte_length, int) and not isinstance(byte_length, bool) and 0 < byte_length <= 1024 * 1024, "invalid corpus source byte length")
    canonical_repository = github_repository_url(project["canonicalRepositoryURL"], "canonical repository")
    repository = github_repository_url(source["repositoryURL"], "source repository")
    immutable, immutable_commit = immutable_github_url(source["immutableURL"], "immutable source")
    require(commit == immutable_commit, "immutable source commit mismatch")
    spans = source["spans"]
    require(isinstance(spans, list) and spans, "corpus source spans required")
    normalized_spans: list[dict[str, Any]] = []
    for span in spans:
        require(isinstance(span, dict) and set(span) == {"startLine", "endLine", "spanDigest"}, "unexpected corpus span field")
        start, end, span_digest = span["startLine"], span["endLine"], span["spanDigest"]
        require(isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int) and not isinstance(end, bool) and 0 < start <= end <= 10_000_000 and isinstance(span_digest, str) and DIGEST_RE.fullmatch(span_digest) is not None, "invalid corpus span")
        normalized_spans.append({"startLine": start, "endLine": end, "spanDigest": span_digest})
    return {"id": record_id, "projectID": project_id, "canonicalRepositoryURL": canonical_repository, "repositoryURL": repository, "immutableURL": immutable, "commit": commit, "version": source["version"], "sourceKind": source_kind, "contentDigest": content_digest, "byteLength": byte_length, "spans": sorted(normalized_spans, key=lambda item: (item["startLine"], item["endLine"], item["spanDigest"]))}


def build(corpus_root: Path, index_path: Path, expected_index_digest: str) -> dict[str, Any]:
    index, index_raw = load(index_path)
    actual_index_digest = digest(index_raw)
    require(DIGEST_RE.fullmatch(expected_index_digest) is not None and actual_index_digest == expected_index_digest, "collection index digest mismatch")
    index_fields = {"schema", "authority", "candidateStatus", "aggregate", "shards", "limitations", "preservation", "baseAcceptedIndexPath", "baseAcceptedIndexSHA256", "baseRootAcceptancePath", "baseRootAcceptanceSHA256", "baseStrictCLIIndexPath", "baseStrictCLIIndexSHA256"}
    require(isinstance(index, dict) and set(index) == index_fields and index.get("schema") == INDEX_SCHEMA and index.get("authority") == AUTHORITY and index.get("candidateStatus") == "ROOT_ACCEPTED_PRIVATE_REFERENCE_ONLY", "unaccepted collection index")
    aggregate = index.get("aggregate")
    aggregate_fields = {"logicalRecordCount", "distinctProjectCount", "deduplicatedObjectCount", "deduplicatedByteLength", "objectLengthConflicts"}
    require(isinstance(aggregate, dict) and set(aggregate) == aggregate_fields and aggregate["objectLengthConflicts"] == [] and all(isinstance(aggregate[key], int) and not isinstance(aggregate[key], bool) and aggregate[key] > 0 for key in aggregate_fields - {"objectLengthConflicts"}), "invalid collection aggregate")
    shards = index.get("shards")
    require(isinstance(shards, list) and shards, "collection shards required")
    records: list[dict[str, Any]] = []
    seen_shards: set[str] = set()
    for shard in shards:
        required_shard = {"name", "manifestPath", "manifestFileSHA256", "canonicalManifestDigest", "recordCount", "projectCount", "uniqueObjectCount", "uniqueByteLength", "withinSingleShardVerifierCaps"}
        optional_shard = {"verificationReceiptPath", "verificationReceiptSHA256", "builderReceiptPath", "builderReceiptSHA256", "independentPostCaptureReviewPath", "independentPostCaptureReviewSHA256", "independentPreCaptureReviewPath", "independentPreCaptureReviewSHA256", "candidateStatus"}
        require(isinstance(shard, dict) and required_shard.issubset(shard) and set(shard).issubset(required_shard | optional_shard), "unexpected shard field")
        if "candidateStatus" in shard:
            require(shard["candidateStatus"] == "ROOT_ACCEPTED_PRIVATE_REFERENCE_ONLY", "unaccepted shard")
        name = shard["name"]
        require(isinstance(name, str) and name and name not in seen_shards, "duplicate shard")
        seen_shards.add(name)
        require(isinstance(shard["manifestFileSHA256"], str) and DIGEST_RE.fullmatch(shard["manifestFileSHA256"]) is not None and isinstance(shard["canonicalManifestDigest"], str) and DIGEST_RE.fullmatch(shard["canonicalManifestDigest"]) is not None, "invalid manifest digest")
        require(all(isinstance(shard[key], int) and not isinstance(shard[key], bool) and shard[key] > 0 for key in {"recordCount", "projectCount", "uniqueObjectCount", "uniqueByteLength"}) and isinstance(shard["withinSingleShardVerifierCaps"], bool), "invalid shard counts")
        manifest_path = within(corpus_root, shard["manifestPath"])
        manifest, manifest_raw = load(manifest_path)
        require(digest(manifest_raw) == shard["manifestFileSHA256"], "manifest digest mismatch")
        require(isinstance(manifest, dict) and set(manifest) == {"schema", "revision", "authority", "records"} and manifest.get("schema") == MANIFEST_SCHEMA and manifest.get("authority") == MANIFEST_AUTHORITY and isinstance(manifest.get("revision"), str) and manifest["revision"], "invalid corpus manifest")
        manifest_records = manifest["records"]
        require(isinstance(manifest_records, list) and len(manifest_records) == shard["recordCount"], "manifest record count mismatch")
        normalized_records = [normalize_record(item) for item in manifest_records]
        require(len({item["projectID"] for item in normalized_records}) == shard["projectCount"], "manifest project count mismatch")
        records.extend(normalized_records)
    records.sort(key=lambda item: item["id"])
    require(len({item["id"] for item in records}) == len(records), "duplicate corpus record identity")
    require(len(records) == aggregate["logicalRecordCount"] and len({item["projectID"] for item in records}) == aggregate["distinctProjectCount"], "aggregate counts mismatch")
    if expected_index_digest == R16_INDEX_DIGEST:
        require(len(records) == R16_RECORD_COUNT and len({item["projectID"] for item in records}) == R16_PROJECT_COUNT, "pinned R16 aggregate counts mismatch")
    return {"schema": OUTPUT_SCHEMA, "provenance": {"collectionIndexDigest": actual_index_digest, "referenceState": "reference_only", "licenseState": "license_unreviewed"}, "records": records}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--corpus-root", type=Path, required=True)
    parser.add_argument("--collection-index", type=Path, required=True)
    parser.add_argument("--expected-index-digest", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        result = build(args.corpus_root.resolve(), args.collection_index.resolve(), args.expected_index_digest)
        rendered = canonical(result)
        if args.check:
            require(args.output.is_file() and args.output.read_bytes() == rendered, "normalized selected-source metadata is stale")
        else:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(rendered)
    except (OSError, Invalid) as exc:
        print(f"selected-source import: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
