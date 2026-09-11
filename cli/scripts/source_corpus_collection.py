#!/usr/bin/env python3
"""Compose verified private source-corpus shards into a bounded receipt.

This is a maintainer-only offline collection check. It verifies selected local
shards and their retained bytes; it does not authenticate upstream sources,
approve rules, or publish a corpus.
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
from typing import Any, Callable

import source_corpus as corpus

SCHEMA = "prufyx.io/private-source-corpus-collection/v1"
RECEIPT_SCHEMA = "prufyx.io/private-source-corpus-collection-receipt/v1"
AUTHORITY = "LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF"
MAX_INDEX_BYTES = 256 * 1024
MAX_SHARDS = 64
MAX_RECORDS = 4096
MAX_OBJECTS = 4096
MAX_UNIQUE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 1 * 1024 * 1024
MAX_PATH_BYTES = 512
MAX_PATH_SEGMENTS = 16
HEX = re.compile(r"^[0-9a-f]{64}$")


class CollectionError(ValueError):
    """Intentionally non-descriptive collection rejection."""


def _reject() -> None:
    raise CollectionError("collection rejected")


def _private_mode(st: os.stat_result, mode: int, *, directory: bool) -> None:
    # Directory link counts include one link for each child directory on
    # POSIX; hard-link protection is therefore meaningful for regular files.
    if st.st_uid != os.geteuid() or (not directory and st.st_nlink != 1) or stat.S_IMODE(st.st_mode) != mode:
        _reject()
    if directory:
        if not stat.S_ISDIR(st.st_mode):
            _reject()
    elif not stat.S_ISREG(st.st_mode):
        _reject()


def _open_root(path: Path) -> int:
    fd = -1
    try:
        fd = corpus._open_physical(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        _private_mode(os.fstat(fd), 0o700, directory=True)
        return fd
    except (OSError, ValueError):
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        _reject()


def _parts(value: Any) -> list[str]:
    if not isinstance(value, str) or not value or not value.isascii() or "\x00" in value:
        _reject()
    raw = value.encode("ascii")
    if len(raw) > MAX_PATH_BYTES or value.startswith("/") or "\\" in value or "//" in value:
        _reject()
    parts = value.split("/")
    if not 1 <= len(parts) <= MAX_PATH_SEGMENTS:
        _reject()
    if any(part in ("", ".", "..") or not corpus.GIT_PATH_SEGMENT.fullmatch(part) for part in parts):
        _reject()
    return parts


def _open_dir_at(root_fd: int, relative: str) -> int:
    parts = _parts(relative)
    current = os.dup(root_fd)
    try:
        for part in parts:
            nxt = os.open(part, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            try:
                _private_mode(os.fstat(nxt), 0o700, directory=True)
            except Exception:
                os.close(nxt)
                raise
            os.close(current)
            current = nxt
        return current
    except (OSError, ValueError):
        try:
            os.close(current)
        except OSError:
            pass
        _reject()


def _read_file_at(root_fd: int, relative: str) -> bytes:
    parts = _parts(relative)
    parent = root_fd
    opened_parent = -1
    fd = -1
    try:
        if len(parts) > 1:
            opened_parent = _open_dir_at(root_fd, "/".join(parts[:-1]))
            parent = opened_parent
        fd = os.open(parts[-1], os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
        _private_mode(os.fstat(fd), 0o600, directory=False)
        return corpus._read_regular_fd(fd, corpus.MAX_MANIFEST_BYTES)
    except (OSError, ValueError):
        _reject()
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        if opened_parent >= 0:
            try:
                os.close(opened_parent)
            except OSError:
                pass


def _object_reader(root_fd: int, relative: str) -> tuple[Callable[[str], bytes], tuple[int, int]]:
    object_fd = _open_dir_at(root_fd, relative)
    sha_fd = -1
    try:
        sha_fd = os.open("sha256", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=object_fd)
        _private_mode(os.fstat(sha_fd), 0o700, directory=True)
    except (OSError, ValueError):
        for fd in (sha_fd, object_fd):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
        _reject()

    def read(name: str) -> bytes:
        parts = name.split("/")
        if len(parts) != 2 or parts[0] != "sha256" or not HEX.fullmatch(parts[1]):
            _reject()
        fd = -1
        try:
            fd = os.open(parts[1], os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=sha_fd)
            _private_mode(os.fstat(fd), 0o600, directory=False)
            return corpus._read_regular_fd(fd, corpus.MAX_OBJECT_BYTES)
        except (OSError, ValueError):
            _reject()
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass

    return read, (object_fd, sha_fd)


def _closed(value: Any, required: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != required:
        _reject()
    return value


def _parse_index(raw: bytes) -> dict[str, Any]:
    try:
        value = corpus._decode_json(raw, MAX_INDEX_BYTES)
    except (ValueError, TypeError, RecursionError):
        _reject()
    value = _closed(value, {"schema", "revision", "authority", "shards"})
    corpus._enum(value["schema"], {SCHEMA})
    corpus._token(value["revision"], corpus.SLUG)
    corpus._enum(value["authority"], {AUTHORITY})
    shards = value["shards"]
    if not isinstance(shards, list) or not 1 <= len(shards) <= MAX_SHARDS:
        _reject()
    checked = []
    for shard in shards:
        shard = _closed(shard, {"manifestPath", "objectRoot"})
        manifest_path = "/".join(_parts(shard["manifestPath"]))
        object_root = "/".join(_parts(shard["objectRoot"]))
        if manifest_path == object_root:
            _reject()
        checked.append({"manifestPath": manifest_path, "objectRoot": object_root})
    if checked != sorted(checked, key=lambda item: (item["manifestPath"], item["objectRoot"])):
        _reject()
    if len({item["manifestPath"] for item in checked}) != len(checked) or len({item["objectRoot"] for item in checked}) != len(checked):
        _reject()
    value["shards"] = checked
    return value


def _verify(index: dict[str, Any], root_fd: int) -> dict[str, Any]:
    seen_ids: set[str] = set()
    seen_logical: set[tuple[str, str, str]] = set()
    projects: dict[str, str] = {}
    source_metadata: dict[str, tuple[Any, ...]] = {}
    objects: dict[str, int] = {}
    shard_receipts = []
    record_count = 0
    for shard in index["shards"]:
        manifest_raw = _read_file_at(root_fd, shard["manifestPath"])
        manifest = corpus._decode_json(manifest_raw, corpus.MAX_MANIFEST_BYTES)
        reader, descriptors = _object_reader(root_fd, shard["objectRoot"])
        try:
            try:
                receipt = corpus.verify_corpus(manifest, Path("."), object_reader=reader)
            except corpus.CorpusError:
                _reject()
        finally:
            for fd in descriptors:
                try:
                    os.close(fd)
                except OSError:
                    pass
        record_count += receipt["recordCount"]
        if record_count > MAX_RECORDS:
            _reject()
        shard_objects: set[str] = set()
        shard_bytes = 0
        for record in receipt["records"]:
            record_id = record["id"]
            if record_id in seen_ids:
                _reject()
            seen_ids.add(record_id)
            logical = (record["project"]["slug"], record["source"]["immutableURL"], record["source"]["spansDigest"])
            if logical in seen_logical:
                _reject()
            seen_logical.add(logical)
            slug = record["project"]["slug"]
            repository = record["project"]["canonicalRepositoryURL"]
            if slug in projects and projects[slug] != repository:
                _reject()
            projects[slug] = repository
            source = record["source"]
            metadata = tuple(source[key] for key in ("repositoryURL", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "byteLength"))
            if source["immutableURL"] in source_metadata and source_metadata[source["immutableURL"]] != metadata:
                _reject()
            source_metadata[source["immutableURL"]] = metadata
            digest = record["capture"]["objectDigest"]
            length = source["byteLength"]
            shard_objects.add(digest)
            if digest in objects and objects[digest] != length:
                _reject()
            objects[digest] = length
        for digest in shard_objects:
            shard_bytes += objects[digest]
        if len(objects) > MAX_OBJECTS:
            _reject()
        if sum(objects.values()) > MAX_UNIQUE_BYTES:
            _reject()
        shard_receipts.append({
            "manifestDigest": receipt["manifestDigest"],
            "manifestPath": shard["manifestPath"],
            "objectRoot": shard["objectRoot"],
            "receiptDigest": "sha256:" + hashlib.sha256(corpus._canonical(receipt)).hexdigest(),
            "recordCount": receipt["recordCount"],
            "uniqueByteLength": shard_bytes,
            "uniqueObjectCount": len(shard_objects),
        })
    result = {
        "schema": RECEIPT_SCHEMA,
        "indexDigest": "sha256:" + hashlib.sha256(corpus._canonical(index)).hexdigest(),
        "revision": index["revision"],
        "verification": "VERIFIED_LOCAL_COLLECTION",
        "authority": AUTHORITY,
        "recordCount": record_count,
        "projectCount": len(projects),
        "uniqueObjectCount": len(objects),
        "aggregateByteLength": sum(objects.values()),
        "shardReceipts": shard_receipts,
        "objectDigests": sorted(objects),
        "limitations": [
            "verification is limited to selected private retained shards and their declared metadata; it does not fetch or authenticate upstream sources",
            "this receipt does not approve catalogue identity, source ownership, rule coverage, compatibility, runtime behavior, signing, publication, or training",
            "only explicitly listed manifests and content-addressed objects are read; unreferenced files are ignored",
        ],
    }
    output = corpus._canonical(result) + b"\n"
    if len(output) > MAX_OUTPUT_BYTES:
        _reject()
    return result


def verify_collection_paths(collection_root: Path, index_path: str) -> dict[str, Any]:
    root_fd = _open_root(collection_root)
    try:
        index_parts = _parts(index_path)
        index_rel = "/".join(index_parts)
        raw = _read_file_at(root_fd, index_rel)
        index = _parse_index(raw)
        return _verify(index, root_fd)
    finally:
        try:
            os.close(root_fd)
        except OSError:
            pass


class _Parser(argparse.ArgumentParser):
    def error(self, _: str) -> None:
        self.exit(2, "source-corpus-collection: usage rejected\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="source-corpus-collection", add_help=True)
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--root", required=True)
    verify.add_argument("--index", required=True)
    try:
        arguments = parser.parse_args(argv)
        if arguments.command != "verify":
            parser.error("required command")
        receipt = verify_collection_paths(Path(arguments.root), arguments.index)
        output = corpus._canonical(receipt) + b"\n"
        sys.stdout.buffer.write(output)
        return 0
    except (CollectionError, corpus.CorpusError, OSError, ValueError, TypeError, RecursionError):
        print("source-corpus-collection: collection rejected", file=sys.stderr)
        return 2
    except Exception:
        print("source-corpus-collection: collection rejected", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
