#!/usr/bin/env python3
"""Verify bounded retained public-source bytes without fetching or promotion."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

SCHEMA = "prufyx.io/public-source-corpus/v1"
RECEIPT_SCHEMA = "prufyx.io/public-source-corpus-receipt/v1"
DECLARED_AUTHORITY = "DECLARED_PUBLIC_SOURCE_BYTES_NOT_RULE_OR_RUNTIME_PROOF"
LOCAL_AUTHORITY = "LOCAL_RETAINED_BYTES_AND_DECLARED_METADATA_ONLY"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_AGGREGATE_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 64
MAX_SPANS = 8
MAX_RULE_IDS = 16
MAX_SOURCE_LINES = 1_000_000
MAX_JSON_DEPTH = 32
MAX_JSON_LIST = 512
MAX_JSON_KEYS = 16
MAX_TEXT = 1200
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SEMVER = re.compile(r"^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$")
SLUG = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
RULE_ID = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
GITHUB_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,98}$")
GIT_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$")


class CorpusError(ValueError):
    """Intentionally non-descriptive corpus rejection."""


def _reject() -> None:
    raise CorpusError("source corpus rejected")


def _valid_string(value: str, maximum: int, *, multiline: bool = False) -> bool:
    return bool(value) and len(value) <= maximum and not any(
        ord(character) == 0x7F
        or 0xD800 <= ord(character) <= 0xDFFF
        or (ord(character) < 0x20 and (not multiline or character not in "\n"))
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


def _json_bounds(value: Any, depth: int = 0) -> None:
    if depth > MAX_JSON_DEPTH:
        _reject()
    if isinstance(value, str):
        if not _valid_string(value, MAX_TEXT, multiline=True):
            _reject()
    elif isinstance(value, list):
        if len(value) > MAX_JSON_LIST:
            _reject()
        for item in value:
            _json_bounds(item, depth + 1)
    elif isinstance(value, dict):
        if len(value) > MAX_JSON_KEYS:
            _reject()
        for item in value.values():
            _json_bounds(item, depth + 1)
    elif value is None or isinstance(value, (bool, int)):
        return
    else:
        _reject()


def _decode_json(raw: bytes, maximum: int) -> Any:
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
        _json_bounds(value)
        return value
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
        _reject()


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        _reject()


def _closed(value: Any, required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _reject()
    return value


def _text(value: Any, *, maximum: int = MAX_TEXT, multiline: bool = False) -> str:
    if not isinstance(value, str) or not _valid_string(value, maximum, multiline=multiline) or (not multiline and "\n" in value):
        _reject()
    return value


def _token(value: Any, expression: re.Pattern[str], *, maximum: int = 128) -> str:
    value = _text(value, maximum=maximum)
    if not expression.fullmatch(value):
        _reject()
    return value


def _sha(value: Any) -> str:
    value = _text(value, maximum=71)
    if not SHA256.fullmatch(value):
        _reject()
    return value


def _commit(value: Any) -> str:
    return _token(value, COMMIT, maximum=40)


def _semver(value: Any) -> str:
    return _token(value, SEMVER, maximum=24)


def _enum(value: Any, allowed: set[str]) -> str:
    value = _text(value, maximum=128)
    if value not in allowed:
        _reject()
    return value


def _canonical_repository(value: Any) -> str:
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
    return canonical


def _immutable_url(value: Any, repository: str, commit: str) -> str:
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


def _timestamp(value: Any) -> str:
    value = _text(value, maximum=20)
    if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value):
        _reject()
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _reject()
    return value


def _physical_components(path: Path) -> list[str]:
    """Return an absolute path without resolving any caller-supplied component."""
    raw = os.fspath(path)
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        _reject()
    candidate = Path(raw)
    # A relative input is interpreted from the physical working directory only.
    absolute = candidate if candidate.is_absolute() else Path(os.path.realpath(os.getcwd())) / candidate
    parts = absolute.parts
    if not parts or parts[0] != os.sep:
        _reject()
    components = list(parts[1:])
    if not components or any(item in ("", ".", "..") for item in components):
        _reject()
    return components


def _open_physical(path: Path, final_flags: int) -> int:
    """Open every path component by descriptor, rejecting all symlink ancestors."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if not nofollow or not directory:
        _reject()
    fd = -1
    components = _physical_components(path)
    try:
        fd = os.open(os.sep, os.O_RDONLY | os.O_CLOEXEC | directory)
        for index, component in enumerate(components):
            final = index + 1 == len(components)
            flags = final_flags if final else (os.O_RDONLY | os.O_CLOEXEC | directory)
            next_fd = os.open(component, flags | nofollow, dir_fd=fd)
            try:
                if not final and not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    _reject()
            except Exception:
                os.close(next_fd)
                raise
            os.close(fd)
            fd = next_fd
        return fd
    except CorpusError:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    except OSError:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        _reject()


def _read_regular_fd(fd: int, maximum: int) -> bytes:
    try:
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
        before_state = (before.st_dev, before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns, before.st_ctime_ns, before.st_nlink)
        after_state = (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink)
        if len(data) > maximum or len(data) != before.st_size or before_state != after_state:
            _reject()
        return bytes(data)
    except OSError:
        _reject()


def _safe_read_file(path: Path, maximum: int) -> bytes:
    fd = -1
    try:
        fd = _open_physical(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        return _read_regular_fd(fd, maximum)
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _safe_read_object(root: Path, object_name: str) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if not nofollow or not directory:
        _reject()
    parts = object_name.split("/")
    if len(parts) != 2 or parts[0] != "sha256" or not re.fullmatch(r"[0-9a-f]{64}", parts[1]):
        _reject()
    root_fd = directory_fd = file_fd = -1
    try:
        root_fd = _open_physical(root, os.O_RDONLY | os.O_CLOEXEC | directory)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            _reject()
        directory_fd = os.open(parts[0], os.O_RDONLY | os.O_CLOEXEC | directory | nofollow, dir_fd=root_fd)
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            _reject()
        file_fd = os.open(parts[1], os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow, dir_fd=directory_fd)
        return _read_regular_fd(file_fd, MAX_OBJECT_BYTES)
    except OSError:
        _reject()
    finally:
        for fd in (file_fd, directory_fd, root_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _spans(value: Any, data: bytes) -> tuple[list[dict[str, Any]], str]:
    if not isinstance(value, list) or not value or len(value) > MAX_SPANS:
        _reject()
    prior_end = 0
    spans: list[dict[str, Any]] = []
    for item in value:
        span = _closed(item, {"startLine", "endLine", "spanDigest"})
        start, end = span["startLine"], span["endLine"]
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool):
            _reject()
        if start < 1 or end < start or start <= prior_end:
            _reject()
        span_digest = _sha(span["spanDigest"])
        selected = _select_raw_lf_span(data, start, end)
        if "sha256:" + hashlib.sha256(selected).hexdigest() != span_digest:
            _reject()
        prior_end = end
        spans.append({"startLine": start, "endLine": end, "spanDigest": span_digest})
    return spans, "sha256:" + hashlib.sha256(_canonical(spans)).hexdigest()


def _select_raw_lf_span(data: bytes, start: int, end: int) -> bytes:
    """Return inclusive raw-LF lines without decoding or normalization."""
    lines = data.split(b"\n")
    if len(lines) > MAX_SOURCE_LINES or start < 1 or end < start or end > len(lines):
        _reject()
    return b"\n".join(lines[start - 1:end])


def _declarations(value: Any) -> dict[str, Any]:
    declaration = _closed(value, {"packetDigest", "ruleIDs"})
    packet = declaration["packetDigest"]
    if packet is not None:
        _sha(packet)
    rules = declaration["ruleIDs"]
    if not isinstance(rules, list) or len(rules) > MAX_RULE_IDS:
        _reject()
    checked = [_token(item, RULE_ID) for item in rules]
    if len(set(checked)) != len(checked):
        _reject()
    return {"packetDigest": packet, "ruleIDs": checked}


def _validate_record(value: Any, root: Path, seen_ids: set[str], seen_record_keys: set[tuple[str, str, str]], projects: dict[str, str], source_metadata: dict[str, tuple[str, str, str, str, int]], object_cache: dict[str, bytes], *, object_reader: Callable[[str], bytes] | None = None) -> tuple[dict[str, Any], int]:
    record = _closed(value, {"id", "project", "source", "capture", "declarations"})
    record_id = _token(record["id"], SLUG)
    if record_id in seen_ids:
        _reject()
    seen_ids.add(record_id)
    project = _closed(record["project"], {"slug", "canonicalRepositoryURL"})
    project_slug = _token(project["slug"], SLUG)
    repository = _canonical_repository(project["canonicalRepositoryURL"])
    if project_slug in projects and projects[project_slug] != repository:
        _reject()
    projects[project_slug] = repository
    source = _closed(record["source"], {"repositoryURL", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "byteLength", "spans"})
    source_repository = _canonical_repository(source["repositoryURL"])
    source_kind = _enum(source["sourceKind"], {"changelog", "release_note", "migration_guide", "source_code", "helm_chart", "repository_metadata"})
    version = _text(source["version"], maximum=24)
    if version != "reference_only":
        version = _semver(version)
    commit = _commit(source["commit"])
    immutable_url = _immutable_url(source["immutableURL"], source_repository, commit)
    file_digest = _sha(source["fileDigest"])
    byte_length = source["byteLength"]
    if not isinstance(byte_length, int) or isinstance(byte_length, bool) or byte_length < 1 or byte_length > MAX_OBJECT_BYTES:
        _reject()
    capture = _closed(record["capture"], {"capturedAt", "object"})
    captured_at = _timestamp(capture["capturedAt"])
    object_name = _text(capture["object"], maximum=71)
    expected_leaf = file_digest.removeprefix("sha256:")
    if object_name != f"sha256/{expected_leaf}":
        _reject()
    data = object_cache.get(object_name)
    if data is None:
        data = object_reader(object_name) if object_reader is not None else _safe_read_object(root, object_name)
        object_cache[object_name] = data
    if len(data) != byte_length or "sha256:" + hashlib.sha256(data).hexdigest() != file_digest:
        _reject()
    spans, spans_digest = _spans(source["spans"], data)
    record_key = (project_slug, immutable_url, spans_digest)
    if record_key in seen_record_keys:
        _reject()
    seen_record_keys.add(record_key)
    metadata = (source_repository, source_kind, version, file_digest, byte_length)
    if immutable_url in source_metadata and source_metadata[immutable_url] != metadata:
        _reject()
    source_metadata[immutable_url] = metadata
    declarations = _declarations(record["declarations"])
    return {
        "id": record_id,
        "project": {"slug": project_slug, "canonicalRepositoryURL": repository},
        "source": {"repositoryURL": source_repository, "sourceKind": source_kind, "version": version, "commit": commit, "immutableURL": immutable_url, "fileDigest": file_digest, "byteLength": byte_length, "spansDigest": spans_digest},
        "capture": {"capturedAt": captured_at, "objectDigest": file_digest},
        "declarations": declarations,
    }, len(data)


def verify_corpus(manifest: Any, object_root: Path, *, object_reader: Callable[[str], bytes] | None = None) -> dict[str, Any]:
    """Verify local retained bytes and return a deterministic non-authoritative receipt."""
    manifest = _closed(manifest, {"schema", "revision", "authority", "records"})
    _enum(manifest["schema"], {SCHEMA})
    revision = _token(manifest["revision"], SLUG)
    _enum(manifest["authority"], {DECLARED_AUTHORITY})
    records = manifest["records"]
    if not isinstance(records, list) or not records or len(records) > MAX_RECORDS:
        _reject()
    seen_ids: set[str] = set()
    seen_record_keys: set[tuple[str, str, str]] = set()
    projects: dict[str, str] = {}
    source_metadata: dict[str, tuple[str, str, str, str, int]] = {}
    object_cache: dict[str, bytes] = {}
    verified: list[dict[str, Any]] = []
    for item in records:
        result, _ = _validate_record(item, object_root, seen_ids, seen_record_keys, projects, source_metadata, object_cache, object_reader=object_reader)
        aggregate = sum(len(data) for data in object_cache.values())
        if aggregate > MAX_AGGREGATE_BYTES:
            _reject()
        verified.append(result)
    manifest_digest = "sha256:" + hashlib.sha256(_canonical(manifest)).hexdigest()
    return {
        "schema": RECEIPT_SCHEMA,
        "manifestDigest": manifest_digest,
        "revision": revision,
        "verification": "VERIFIED_RETAINED_BYTES",
        "authority": LOCAL_AUTHORITY,
        "recordCount": len(verified),
        "aggregateByteLength": aggregate,
        "records": verified,
        "limitations": [
            "verification is local retained-byte consistency only; it does not fetch or authenticate upstream sources, commits, tags, or licenses",
            "project, packet, and rule references are declarations only; this receipt does not approve catalogue identity, coverage, rules, runtime behavior, signing, or publication",
            "retained source objects are private evidence inputs and are not a client package, TUF target, or training authorization",
        ],
    }


def _read_manifest(path: Path) -> Any:
    return _decode_json(_safe_read_file(path, MAX_MANIFEST_BYTES), MAX_MANIFEST_BYTES)



class _Parser(argparse.ArgumentParser):
    def error(self, _: str) -> None:
        self.exit(2, "source-corpus: usage rejected\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="source-corpus", add_help=True)
    parser.add_argument("verify", nargs="?")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--object-root", required=True, type=Path)
    arguments = parser.parse_args(argv)
    if arguments.verify != "verify":
        parser.error("required command")
    try:
        receipt = verify_corpus(_read_manifest(arguments.manifest), arguments.object_root)
        output = _canonical(receipt) + b"\n"
    except CorpusError:
        print("source-corpus: corpus rejected", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
