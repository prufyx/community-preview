#!/usr/bin/env python3
"""Validate closed, offline upstream-evidence contribution packets.

This tool validates packet consistency only. It never fetches sources, authenticates
contributors or reviewers, verifies a tag binding, proves a source hash, promotes a
rule, or publishes data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

# The entrypoint is invoked as a script, while focused tests load it by path.
# Keep its sibling-only helper import stable in both modes.
if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_corpus as corpus

SCHEMA = "prufyx.io/upstream-evidence-packet/v1"
SCHEMA_V2 = "prufyx.io/upstream-evidence-packet/v2"
RECEIPT_SCHEMA = "prufyx.io/upstream-evidence-receipt/v1"
SOURCE_RECEIPT_SCHEMA = "prufyx.io/upstream-evidence-source-receipt/v1"
MAX_PACKET_BYTES = 256 * 1024
MAX_LANDSCAPE_BYTES = 4 * 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_LIST = 512
MAX_JSON_KEYS = 16
MAX_SOURCES = 8
MAX_TAG_BINDINGS = 4
MAX_SPANS_PER_SOURCE = 8
MAX_TEXT = 1200
MAX_EXCERPT_CHARS = 1200
MAX_EXCERPT_LINE_CHARS = 1200
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER = re.compile(r"^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$")
TAG_COMPONENT = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:@/-]{0,127}$")
GITHUB_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,98}$")
GIT_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$")


class PacketError(ValueError):
    """An intentionally non-descriptive packet rejection."""


def _reject() -> None:
    raise PacketError("contribution packet rejected")


def _valid_string(value: str, maximum: int, *, allow_tab: bool = False) -> bool:
    permitted_controls = "\n\t" if allow_tab else "\n"
    return bool(value) and len(value) <= maximum and not any(
        ord(character) == 0x7F
        or 0xD800 <= ord(character) <= 0xDFFF
        or (ord(character) < 0x20 and character not in permitted_controls)
        for character in value
    )


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if not _valid_string(key, 64) or "\n" in key or key in value:
            _reject()
        value[key] = item
    return value


def _bounded_int(token: str) -> int:
    if len(token) > 12:
        _reject()
    try:
        return int(token)
    except ValueError:
        _reject()


def _reject_float(_: str) -> None:
    _reject()


def _json_bounds(value: Any, depth: int = 0, *, allow_tab: bool = False) -> None:
    if depth > MAX_JSON_DEPTH:
        _reject()
    if isinstance(value, str):
        if not _valid_string(value, MAX_TEXT, allow_tab=allow_tab):
            _reject()
    elif isinstance(value, list):
        if len(value) > MAX_JSON_LIST:
            _reject()
        for item in value:
            _json_bounds(item, depth + 1, allow_tab=allow_tab)
    elif isinstance(value, dict):
        if len(value) > MAX_JSON_KEYS:
            _reject()
        for item in value.values():
            _json_bounds(item, depth + 1, allow_tab=allow_tab)
    elif value is None or isinstance(value, (bool, int)):
        return
    else:
        _reject()


def _decode_json(raw: bytes, maximum: int, *, allow_tab: bool = False) -> Any:
    if not raw or len(raw) > maximum:
        _reject()
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=lambda _: _reject(),
            parse_int=_bounded_int,
            parse_float=_reject_float,
        )
        _json_bounds(value, allow_tab=allow_tab)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _reject()


def _safe_read(path: Path, maximum: int) -> bytes:
    """Read a bounded, stable, regular no-follow file without blocking on a FIFO."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not nofollow:
        _reject()
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow
    fd = -1
    try:
        fd = os.open(path, flags)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size < 1 or before.st_size > maximum:
            _reject()
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(fd, min(65_536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        stable = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
        now = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
        if len(data) > maximum or stable != now or len(data) != before.st_size:
            _reject()
        return bytes(data)
    except OSError:
        _reject()
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _load_json(raw: bytes) -> Any:
    # Only packet loading permits TAB to reach the excerpt-specific validator.
    # Shared decoding, including the pinned Landscape reader, stays strict.
    return _decode_json(raw, MAX_PACKET_BYTES, allow_tab=True)


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        _reject()


def _closed(value: Any, required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _reject()
    return value


def _text(value: Any, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str) or not _valid_string(value, maximum) or "\n" in value:
        _reject()
    return value


def _excerpt(value: Any, start: int, end: int) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_EXCERPT_CHARS or "\r" in value:
        _reject()
    lines = value.split("\n")
    if len(lines) != end - start + 1:
        _reject()
    for line in lines:
        if len(line) > MAX_EXCERPT_LINE_CHARS or any(ord(character) == 0x7F or 0xD800 <= ord(character) <= 0xDFFF or (ord(character) < 0x20 and character != "\t") for character in line):
            _reject()
    return value


def _token(value: Any, expression: re.Pattern[str]) -> str:
    value = _text(value, maximum=128)
    if not expression.fullmatch(value):
        _reject()
    return value


def _enum(value: Any, allowed: set[str]) -> str:
    value = _text(value, maximum=128)
    if value not in allowed:
        _reject()
    return value


def _sha(value: Any) -> str:
    value = _text(value, maximum=71)
    if not SHA256.fullmatch(value):
        _reject()
    return value


def _commit(value: Any) -> str:
    value = _text(value, maximum=40)
    if not COMMIT.fullmatch(value):
        _reject()
    return value


def _semver(value: Any) -> str:
    value = _text(value, maximum=24)
    if not SEMVER.fullmatch(value):
        _reject()
    return value


def _github_repository(value: Any) -> tuple[str, str]:
    url = _text(value, maximum=256)
    if not url.isascii() or any(marker in url for marker in ("?", "#", "%", "\\")):
        _reject()
    try:
        parsed = urlsplit(url)
    except ValueError:
        _reject()
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        _reject()
    parts = parsed.path.split("/")
    if len(parts) != 3 or parts[0] or not GITHUB_SEGMENT.fullmatch(parts[1]) or not GITHUB_SEGMENT.fullmatch(parts[2]) or parts[2].lower().endswith(".git"):
        _reject()
    canonical = f"https://github.com/{parts[1]}/{parts[2]}"
    if url != canonical:
        _reject()
    return canonical, canonical


def _immutable_source_url(value: Any, repository: str, commit: str) -> str:
    url = _text(value, maximum=512)
    if not url.isascii() or any(marker in url for marker in ("?", "#", "%", "\\")):
        _reject()
    try:
        parsed = urlsplit(url)
    except ValueError:
        _reject()
    if parsed.scheme != "https" or parsed.netloc != "github.com" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        _reject()
    owner, repo = repository.removeprefix("https://github.com/").split("/")
    parts = parsed.path.split("/")
    if len(parts) < 6 or parts[:5] != ["", owner, repo, "blob", commit] or not all(GIT_PATH_SEGMENT.fullmatch(part) for part in parts[5:]):
        _reject()
    canonical = f"https://github.com/{owner}/{repo}/blob/{commit}/{'/'.join(parts[5:])}"
    if url != canonical:
        _reject()
    return canonical


def _landscape(path: Path) -> tuple[dict[str, dict[str, str]], str]:
    # The pinned catalogue is local trusted project data, not contributor input.
    try:
        raw = _safe_read(path, MAX_LANDSCAPE_BYTES)
        parsed = _decode_json(raw, MAX_LANDSCAPE_BYTES)
        projects = parsed["projects"]
    except (KeyError, TypeError):
        _reject()
    if not isinstance(projects, list):
        _reject()
    result: dict[str, dict[str, str]] = {}
    seen_slugs: set[str] = set()
    for project in projects:
        if not isinstance(project, dict):
            _reject()
        slug = project.get("slug")
        repository = project.get("repositoryURL")
        if not isinstance(slug, str) or slug in seen_slugs:
            _reject()
        seen_slugs.add(slug)
        if isinstance(repository, str):
            result[slug] = {"repositoryURL": repository}
        elif repository is not None:
            _reject()
    return result, "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_source(value: Any, repository: str, versions: set[str], ids: set[str]) -> None:
    source = _closed(value, {"id", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "spans"})
    source_id = _token(source["id"], SLUG)
    if source_id in ids:
        _reject()
    ids.add(source_id)
    _enum(source["sourceKind"], {"changelog", "release_note", "migration_guide", "source_code", "helm_chart", "repository_metadata"})
    if source["version"] == "identity":
        if versions:
            _reject()
    elif _semver(source["version"]) not in versions:
        _reject()
    commit = _commit(source["commit"])
    _immutable_source_url(source["immutableURL"], repository, commit)
    _sha(source["fileDigest"])
    spans = source["spans"]
    if not isinstance(spans, list) or not spans or len(spans) > MAX_SPANS_PER_SOURCE:
        _reject()
    prior_end = 0
    for span in spans:
        span = _closed(span, {"startLine", "endLine", "excerpt"})
        start, end = span["startLine"], span["endLine"]
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool):
            _reject()
        if start < 1 or end < start or end > 1_000_000 or start <= prior_end:
            _reject()
        prior_end = end
        _excerpt(span["excerpt"], start, end)


def _tag(value: Any) -> str:
    tag = _text(value, maximum=128)
    if tag.startswith("/") or tag.endswith(("/", ".")) or ".." in tag:
        _reject()
    components = tag.split("/")
    if any(not TAG_COMPONENT.fullmatch(component) or component.endswith(".lock") for component in components):
        _reject()
    return tag


def _validate_tag_binding(value: Any, versions: set[str]) -> tuple[str, str, str]:
    binding = _closed(value, {"version", "tag", "commit", "assertion"})
    version = _semver(binding["version"])
    if version not in versions:
        _reject()
    tag = _tag(binding["tag"])
    commit = _commit(binding["commit"])
    _enum(binding["assertion"], {"DECLARED_UNVERIFIED"})
    return version, tag, commit


def _matches_established_source_repository(slug: str, declared: str, established: str) -> bool:
    if declared == established:
        return True
    if (
        slug == "buildpacks"
        and established == "https://github.com/buildpacks/pack"
        and declared == "https://github.com/buildpacks/lifecycle"
    ):
        return True
    return (
        slug == "kubeflow"
        and established == "https://github.com/kubeflow/kubeflow"
        and declared == "https://github.com/kubeflow/pipelines"
    )


def _is_kubeflow_kfp_migration_guide(slug: str, repository: str, source: dict[str, Any], proposed: str) -> bool:
    if slug != "kubeflow" or repository != "https://github.com/kubeflow/pipelines":
        return False
    return (
        source.get("sourceKind") == "migration_guide"
        and source.get("version") == proposed == "2.0.0"
        and source.get("commit") == "debcbb9035e75869e9dc2ed6b9354376ac1a26e7"
        and source.get("immutableURL")
        == "https://github.com/kubeflow/website/blob/debcbb9035e75869e9dc2ed6b9354376ac1a26e7/content/en/docs/components/pipelines/user-guides/migration.md"
    )


def _validate_v1_packet(packet: Any, landscape_path: Path) -> dict[str, Any]:
    """Retain the exact v1 validation path and receipt."""
    packet = _closed(packet, {"schema", "submission", "project", "transition", "tagBindings", "sources", "declaration", "limitations", "review", "attribution"})
    _enum(packet["schema"], {SCHEMA})
    submission = _closed(packet["submission"], {"kind"})
    kind = _enum(submission["kind"], {"new_catalogue_identity_proposal", "existing_project_transition"})
    project = _closed(packet["project"], {"slug", "displayName", "canonicalRepositoryURL"})
    slug = _token(project["slug"], SLUG)
    _text(project["displayName"], maximum=120)
    repository_url, repository = _github_repository(project["canonicalRepositoryURL"])
    transition = packet["transition"]
    versions: set[str]
    current = proposed = ""
    landscape_digest: str | None = None
    if kind == "new_catalogue_identity_proposal":
        if transition is not None:
            _reject()
        versions = set()
    else:
        transition = _closed(transition, {"currentVersion", "proposedVersion"})
        current = _semver(transition["currentVersion"])
        proposed = _semver(transition["proposedVersion"])
        if current == proposed:
            _reject()
        versions = {current, proposed}
        established, landscape_digest = _landscape(landscape_path)
        if slug not in established or not _matches_established_source_repository(slug, repository_url, established[slug]["repositoryURL"]):
            _reject()
    bindings = packet["tagBindings"]
    if not isinstance(bindings, list) or len(bindings) > MAX_TAG_BINDINGS or (kind == "existing_project_transition" and len(bindings) != 2) or (kind == "new_catalogue_identity_proposal" and bindings):
        _reject()
    binding_versions: set[str] = set()
    binding_tags: set[str] = set()
    tag_commits: dict[str, str] = {}
    for binding in bindings:
        version, tag, commit = _validate_tag_binding(binding, versions)
        if version in binding_versions or tag in binding_tags:
            _reject()
        binding_versions.add(version)
        binding_tags.add(tag)
        tag_commits[version] = commit
    if kind == "existing_project_transition" and binding_versions != versions:
        _reject()
    sources = packet["sources"]
    if not isinstance(sources, list) or not sources or len(sources) > MAX_SOURCES:
        _reject()
    ids: set[str] = set()
    ordinary_source_versions: set[str] = set()
    kubeflow_guide_count = 0
    for source in sources:
        source_value = _closed(source, {"id", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "spans"})
        is_kubeflow_guide = _is_kubeflow_kfp_migration_guide(slug, repository, source_value, proposed)
        source_repository = "https://github.com/kubeflow/website" if is_kubeflow_guide else repository
        _validate_source(source_value, source_repository, versions, ids)
        if is_kubeflow_guide:
            kubeflow_guide_count += 1
            if kubeflow_guide_count > 1:
                _reject()
        elif kind == "existing_project_transition":
            ordinary_source_versions.add(source_value["version"])
        if kind == "existing_project_transition" and not is_kubeflow_guide and source_value["commit"] != tag_commits[source_value["version"]]:
            _reject()
    if kubeflow_guide_count and ordinary_source_versions != versions:
        _reject()
    declaration = _closed(packet["declaration"], {"statement", "proofStatus"})
    _text(declaration["statement"])
    _enum(declaration["proofStatus"], {"DECLARED_NOT_VERIFIED"})
    limitations = packet["limitations"]
    if not isinstance(limitations, list) or not limitations or len(limitations) > 8:
        _reject()
    if len(set(_text(item, maximum=500) for item in limitations)) != len(limitations):
        _reject()
    review = _closed(packet["review"], {"state", "claimedReviewer"})
    _enum(review["state"], {"NOT_REVIEWED"})
    reviewer = _closed(review["claimedReviewer"], {"kind", "identity"})
    _enum(reviewer["kind"], {"agent", "human"})
    _token(reviewer["identity"], IDENTITY)
    attribution = _closed(packet["attribution"], {"licenseAssertion", "attribution"})
    _enum(attribution["licenseAssertion"], {"DECLARED_UNKNOWN", "DECLARED_PERMISSIVE", "DECLARED_RESTRICTED"})
    _text(attribution["attribution"], maximum=500)
    digest = "sha256:" + hashlib.sha256(_canonical(packet)).hexdigest()
    return {
        "schema": RECEIPT_SCHEMA,
        "packetDigest": digest,
        "landscapeDigest": landscape_digest,
        "submissionKind": kind,
        "consistency": "VALID",
        "workflowState": "CANDIDATE",
        "limitations": [
            "local consistency only; upstream identity, tag bindings, source bytes, hashes, and spans are unverified",
            "declared reviewer and attribution fields are not authentication, independent review, approval, publication, or evaluator authority",
        ],
    }


def _validate_v2_source(value: Any, role: str, repository: str, path: str, commit: str, ids: set[str]) -> None:
    source = _closed(value, {"id", "evidenceRole", "sourceKind", "targetVersion", "commit", "immutableURL", "fileDigest", "spans"})
    source_id = _token(source["id"], SLUG)
    if source_id in ids:
        _reject()
    ids.add(source_id)
    if source["evidenceRole"] != role or source["targetVersion"] != "8.5.8":
        _reject()
    expected_kind = "repository_metadata" if role == "operator_action_guidance" else "source_code"
    if source["sourceKind"] != expected_kind or source["commit"] != commit:
        _reject()
    _immutable_source_url(source["immutableURL"], repository, commit)
    if not source["immutableURL"].endswith("/" + path):
        _reject()
    _sha(source["fileDigest"])
    spans = source["spans"]
    if not isinstance(spans, list) or not spans or len(spans) > MAX_SPANS_PER_SOURCE:
        _reject()
    prior_end = 0
    for span in spans:
        span = _closed(span, {"startLine", "endLine", "excerpt"})
        start, end = span["startLine"], span["endLine"]
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool):
            _reject()
        if start < 1 or end < start or end > 1_000_000 or start <= prior_end:
            _reject()
        prior_end = end
        _excerpt(span["excerpt"], start, end)


def _validate_v2_packet(packet: Any, landscape_path: Path) -> dict[str, Any]:
    packet = _closed(packet, {"schema", "submission", "project", "target", "tagBindings", "sources", "declaration", "limitations", "review", "attribution"})
    _enum(packet["schema"], {SCHEMA_V2})
    if _closed(packet["submission"], {"kind"})["kind"] != "existing_project_target_preflight":
        _reject()
    project = _closed(packet["project"], {"slug", "displayName", "canonicalRepositoryURL"})
    if project != {"slug": "tikv", "displayName": "TiKV", "canonicalRepositoryURL": "https://github.com/tikv/tikv"}:
        _reject()
    repository, _ = _github_repository(project["canonicalRepositoryURL"])
    established, landscape_digest = _landscape(landscape_path)
    if established.get("tikv", {}).get("repositoryURL") != repository:
        _reject()
    target = _closed(packet["target"], {"targetVersion", "operation"})
    if target != {"targetVersion": "8.5.8", "operation": "gcs-full-backup-wif"}:
        _reject()
    bindings = packet["tagBindings"]
    if not isinstance(bindings, list) or len(bindings) != 1:
        _reject()
    version, tag, target_commit = _validate_tag_binding(bindings[0], {"8.5.8"})
    if (version, tag, target_commit) != ("8.5.8", "v8.5.8", "3f446cfa9eb1d5c653031d261e185911495d0359"):
        _reject()
    sources = packet["sources"]
    if not isinstance(sources, list) or len(sources) != 3:
        _reject()
    expected = {
        "target_setting_declaration": ("https://github.com/tikv/tikv", "src/config/mod.rs", target_commit),
        "target_full_backup_caller": ("https://github.com/tikv/tikv", "components/backup/src/endpoint.rs", target_commit),
        "operator_action_guidance": ("https://github.com/pingcap/docs", "tikv-configuration-file.md", None),
    }
    ids: set[str] = set()
    roles: set[str] = set()
    for source in sources:
        if not isinstance(source, dict):
            _reject()
        role = source.get("evidenceRole")
        if role not in expected or role in roles:
            _reject()
        roles.add(role)
        source_repository, source_path, fixed_commit = expected[role]
        source_commit = source.get("commit")
        if fixed_commit is None:
            source_commit = _commit(source_commit)
        _validate_v2_source(source, role, source_repository, source_path, fixed_commit or source_commit, ids)
    if roles != set(expected):
        _reject()
    declaration = _closed(packet["declaration"], {"statement", "proofStatus"})
    _text(declaration["statement"])
    _enum(declaration["proofStatus"], {"DECLARED_NOT_VERIFIED"})
    limitations = packet["limitations"]
    if not isinstance(limitations, list) or not limitations or len(limitations) > 8:
        _reject()
    if len(set(_text(item, maximum=500) for item in limitations)) != len(limitations):
        _reject()
    review = _closed(packet["review"], {"state", "claimedReviewer"})
    _enum(review["state"], {"NOT_REVIEWED"})
    reviewer = _closed(review["claimedReviewer"], {"kind", "identity"})
    _enum(reviewer["kind"], {"agent", "human"})
    _token(reviewer["identity"], IDENTITY)
    attribution = _closed(packet["attribution"], {"licenseAssertion", "attribution"})
    _enum(attribution["licenseAssertion"], {"DECLARED_UNKNOWN", "DECLARED_PERMISSIVE", "DECLARED_RESTRICTED"})
    _text(attribution["attribution"], maximum=500)
    return {
        "schema": RECEIPT_SCHEMA,
        "packetDigest": "sha256:" + hashlib.sha256(_canonical(packet)).hexdigest(),
        "landscapeDigest": landscape_digest,
        "submissionKind": "existing_project_target_preflight",
        "consistency": "VALID",
        "workflowState": "CANDIDATE",
        "limitations": [
            "local consistency only; upstream identity, tag bindings, source bytes, hashes, and spans are unverified",
            "declared reviewer and attribution fields are not authentication, independent review, approval, publication, or evaluator authority",
        ],
    }


def validate_packet(packet: Any, landscape_path: Path) -> dict[str, Any]:
    """Return a canonical, consistency-only candidate receipt or raise PacketError."""
    if not isinstance(packet, dict):
        _reject()
    if packet.get("schema") == SCHEMA:
        return _validate_v1_packet(packet, landscape_path)
    if packet.get("schema") == SCHEMA_V2:
        return _validate_v2_packet(packet, landscape_path)
    _reject()


def verify_packet_sources(packet: Any, landscape_path: Path, source_root: Path) -> dict[str, Any]:
    """Bind an already-valid candidate's declared sources to local public bytes."""
    candidate = validate_packet(packet, landscape_path)
    object_cache: dict[str, bytes] = {}
    source_count = 0
    span_count = 0
    for source in packet["sources"]:
        digest = source["fileDigest"]
        object_name = "sha256/" + digest.removeprefix("sha256:")
        data = object_cache.get(digest)
        if data is None:
            try:
                data = corpus._safe_read_object(source_root, object_name)
            except corpus.CorpusError:
                _reject()
            if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
                _reject()
            object_cache[digest] = data
        source_count += 1
        for span in source["spans"]:
            try:
                selected = corpus._select_raw_lf_span(data, span["startLine"], span["endLine"])
                excerpt = selected.decode("utf-8")
            except (UnicodeDecodeError, corpus.CorpusError):
                _reject()
            if excerpt != span["excerpt"]:
                _reject()
            span_count += 1
    aggregate = sum(len(data) for data in object_cache.values())
    if aggregate > corpus.MAX_AGGREGATE_BYTES:
        _reject()
    source_set = sorted(object_cache)
    return {
        "schema": SOURCE_RECEIPT_SCHEMA,
        "packetDigest": candidate["packetDigest"],
        "verification": "LOCAL_DECLARED_PUBLIC_SOURCE_BYTES_MATCHED",
        "workflowState": "CANDIDATE",
        "admissionState": "NOT_ADMITTED",
        "sourceCount": source_count,
        "uniqueObjectCount": len(object_cache),
        "spanCount": span_count,
        "aggregateVerifiedByteLength": aggregate,
        "sourceSetDigest": "sha256:" + hashlib.sha256(_canonical(source_set)).hexdigest(),
        "limitations": [
            "local supplied public bytes only; no upstream fetch, tag or ref authentication, contributor or reviewer authentication, or license determination",
            "matching bytes and excerpts do not approve semantic correctness, a rule, catalogue admission, signing, runtime behavior, or publication",
        ],
    }


def _read_packet(path: Path) -> Any:
    return _load_json(_safe_read(path, MAX_PACKET_BYTES))


def _open_scaffold_parent(path: Path) -> tuple[int, str]:
    """Open every parent directory without following symlinks."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if not nofollow or not directory or not path.name or any(part in {".", ".."} for part in path.parts):
        raise PacketError("scaffold parent rejected")
    flags = os.O_RDONLY | os.O_CLOEXEC | directory | nofollow
    fd = os.open("/" if path.is_absolute() else ".", flags)
    try:
        parents = path.parts[1:-1] if path.is_absolute() else path.parts[:-1]
        for component in parents:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd, path.name
    except OSError as exc:
        try:
            os.close(fd)
        except OSError:
            pass
        raise PacketError("scaffold parent rejected") from exc


def _write_scaffold(path: Path, packet: dict[str, Any]) -> None:
    """Create one private incomplete packet without following or replacing a path."""
    raw = _canonical(packet) + b"\n"
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not nofollow:
        raise PacketError("scaffold rejected")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | nofollow
    parent_fd, leaf = _open_scaffold_parent(path)
    fd = -1
    written = 0
    created = False
    try:
        fd = os.open(leaf, flags, 0o600, dir_fd=parent_fd)
        created = True
        while written < len(raw):
            written += os.write(fd, raw[written:])
        os.fchmod(fd, 0o600)
    except OSError as exc:
        raise PacketError("scaffold rejected") from exc
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if created and written < len(raw):
            try:
                os.unlink(leaf, dir_fd=parent_fd)
            except OSError:
                pass
        try:
            os.close(parent_fd)
        except OSError:
            pass


def _scaffold(arguments: argparse.Namespace) -> None:
    kind = arguments.kind
    slug = _token(arguments.project_slug, SLUG)
    display_name = _text(arguments.display_name, maximum=120)
    repository, _ = _github_repository(arguments.repository)
    if kind == "existing_project_target_preflight":
        if (slug, display_name, repository, arguments.target_version, arguments.operation) != (
            "tikv", "TiKV", "https://github.com/tikv/tikv", "8.5.8", "gcs-full-backup-wif"
        ) or arguments.current_version is not None or arguments.proposed_version is not None:
            raise PacketError("scaffold rejected")
        packet: dict[str, Any] = {
            "schema": SCHEMA_V2,
            "submission": {"kind": kind},
            "project": {"slug": slug, "displayName": display_name, "canonicalRepositoryURL": repository},
            "target": {"targetVersion": "8.5.8", "operation": "gcs-full-backup-wif"},
            "tagBindings": [],
            "sources": [],
            "declaration": {"statement": None, "proofStatus": None},
            "limitations": [],
            "review": {"state": "NOT_REVIEWED", "claimedReviewer": {"kind": None, "identity": None}},
            "attribution": {"licenseAssertion": None, "attribution": None},
        }
        _write_scaffold(arguments.output, packet)
        return
    if arguments.target_version is not None or arguments.operation is not None:
        raise PacketError("scaffold rejected")
    if kind == "existing_project_transition":
        if arguments.current_version is None or arguments.proposed_version is None:
            raise PacketError("scaffold rejected")
        current = _semver(arguments.current_version)
        proposed = _semver(arguments.proposed_version)
        if current == proposed:
            raise PacketError("scaffold rejected")
        transition: dict[str, Any] | None = {"currentVersion": current, "proposedVersion": proposed}
    else:
        if arguments.current_version is not None or arguments.proposed_version is not None:
            raise PacketError("scaffold rejected")
        transition = None
    packet: dict[str, Any] = {
        "schema": SCHEMA,
        "submission": {"kind": kind},
        "project": {"slug": slug, "displayName": display_name, "canonicalRepositoryURL": repository},
        "transition": transition,
        "tagBindings": [],
        "sources": [],
        "declaration": {"statement": None, "proofStatus": None},
        "limitations": [],
        "review": {"state": "NOT_REVIEWED", "claimedReviewer": {"kind": None, "identity": None}},
        "attribution": {"licenseAssertion": None, "attribution": None},
    }
    _write_scaffold(arguments.output, packet)


class _Parser(argparse.ArgumentParser):
    def error(self, _: str) -> None:
        self.exit(2, "contribution-packet: usage rejected\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="contribution-packet", add_help=True)
    parser.add_argument("command", nargs="?")
    parser.add_argument("--packet", type=Path)
    parser.add_argument("--landscape", type=Path, default=Path(__file__).resolve().parents[1] / "internal/cncfcheck/data/landscape-projects.json")
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--kind", choices=("new_catalogue_identity_proposal", "existing_project_transition", "existing_project_target_preflight"))
    parser.add_argument("--project-slug")
    parser.add_argument("--display-name")
    parser.add_argument("--repository")
    parser.add_argument("--current-version")
    parser.add_argument("--proposed-version")
    parser.add_argument("--target-version")
    parser.add_argument("--operation")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    if arguments.command not in {"validate", "verify-sources", "scaffold"}:
        parser.error("required command")
    scaffold_values = (
        arguments.kind,
        arguments.project_slug,
        arguments.display_name,
        arguments.repository,
        arguments.current_version,
        arguments.proposed_version,
        arguments.target_version,
        arguments.operation,
        arguments.output,
    )
    if arguments.command == "scaffold":
        if arguments.packet is not None or arguments.source_root is not None or arguments.kind is None or arguments.project_slug is None or arguments.display_name is None or arguments.repository is None or arguments.output is None:
            parser.error("scaffold requires identifiers, kind, and output")
    else:
        if arguments.packet is None or any(value is not None for value in scaffold_values):
            parser.error("packet command arguments rejected")
    if arguments.command == "validate" and arguments.source_root is not None:
        parser.error("source root is only supported by verify-sources")
    if arguments.command == "verify-sources" and arguments.source_root is None:
        parser.error("source root is required")
    if arguments.command == "scaffold":
        try:
            _scaffold(arguments)
        except PacketError as exc:
            if str(exc) == "scaffold parent rejected":
                print("contribution-packet: scaffold rejected; choose a real directory for the output parent", file=sys.stderr)
            else:
                print("contribution-packet: scaffold rejected", file=sys.stderr)
            return 2
        print(f"scaffold: wrote incomplete packet skeleton to {arguments.output}")
        print(f"Complete tagBindings, sources, declaration, limitations, attribution, and reviewer details, then run: python3 -B {Path(__file__)} validate --packet {arguments.output}")
        return 0
    try:
        packet = _read_packet(arguments.packet)
        receipt = validate_packet(packet, arguments.landscape) if arguments.command == "validate" else verify_packet_sources(packet, arguments.landscape, arguments.source_root)
    except PacketError:
        print("contribution-packet: packet rejected", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
