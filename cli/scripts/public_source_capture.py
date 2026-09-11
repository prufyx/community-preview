#!/usr/bin/env python3
"""Capture a closed set of declared public GitHub source bytes for private review.

This maintainer tool has no end-user CLI integration and does not approve a
source, rule, release, package, or training data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing
import os
import re
import socket
import ssl
import stat
import sys
import time
from datetime import datetime, timezone
from multiprocessing import shared_memory
from pathlib import Path
from typing import Any, Callable

import source_corpus as corpus

SCHEMA = "prufyx.io/private-public-source-capture-request/v1"
RECEIPT_SCHEMA = "prufyx.io/private-public-source-capture-receipt/v1"
AUTHORITY = "DECLARED_PUBLIC_SOURCE_REQUESTS_NOT_RULE_OR_RUNTIME_PROOF"
LOCAL_AUTHORITY = "LOCAL_CAPTURED_PUBLIC_BYTES_NOT_RULE_OR_RUNTIME_PROOF"
MAX_REQUEST_BYTES = 256 * 1024
MAX_LOGICAL_REQUESTS = 64
MAX_UNIQUE_BYTES = 16 * 1024 * 1024
MAX_OBJECT_BYTES = 4 * 1024 * 1024
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_LINE = 4096
MAX_HEADERS = 64
MAX_IPC_BYTES = 4096
MAX_RECEIPT_BYTES = 256 * 1024
# Reserve time inside every requested wall-clock budget to terminate, kill, and
# reap a worker before its shared memory may be unlinked.
CLEANUP_RESERVE_SECONDS = 0.20
PER_SOURCE_SECONDS = 30.0
ATTEMPT_SECONDS = 120.0
RAW_HOST = "raw.githubusercontent.com"
RAW_PORT = 443
USER_AGENT = "prufyx-private-source-capture/1"
RAW_PATH = re.compile(r"^/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/[0-9a-f]{40}/(?:[A-Za-z0-9._+.-]+/)*[A-Za-z0-9._+.-]+$")


class CaptureError(ValueError):
    """Intentionally non-descriptive capture rejection."""


class CaptureFailure(CaptureError):
    def __init__(self, receipt: dict[str, Any]):
        super().__init__("public source capture rejected")
        self.receipt = receipt


class CaptureWriteFailure(CaptureError):
    def __init__(self, cleanup: str):
        super().__init__("capture write rejected")
        self.cleanup = cleanup


def _reject() -> None:
    raise CaptureError("public source capture rejected")


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        _reject()


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _private_mode(info: os.stat_result, directory: bool = False) -> None:
    if (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and not stat.S_ISREG(info.st_mode)):
        _reject()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        _reject()


def _stable(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_nlink)


def _read_private_request(path: Path) -> bytes:
    fd = -1
    try:
        fd = corpus._open_physical(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        before = os.fstat(fd)
        _private_mode(before)
        if before.st_nlink != 1 or before.st_size < 1 or before.st_size > MAX_REQUEST_BYTES:
            _reject()
        data = corpus._read_regular_fd(fd, MAX_REQUEST_BYTES)
        if _stable(before) != _stable(os.fstat(fd)):
            _reject()
        return data
    except (corpus.CorpusError, OSError, ValueError):
        _reject()
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass


def _open_private_parent(path: Path) -> tuple[int, tuple[int, int, int, int, int, int, int]]:
    fd = -1
    try:
        fd = corpus._open_physical(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)
        info = os.fstat(fd)
        _private_mode(info, directory=True)
        return fd, _stable(info)
    except corpus.CorpusError:
        _reject()
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        _reject()


def _closed(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        _reject()
    return value


def _capture_request(value: Any) -> tuple[str, list[dict[str, Any]], dict[str, dict[str, Any]]]:
    document = _closed(value, {"schema", "revision", "authority", "requests"})
    if document["schema"] != SCHEMA or document["authority"] != AUTHORITY:
        _reject()
    revision = corpus._token(document["revision"], corpus.SLUG)
    requests = document["requests"]
    if not isinstance(requests, list) or not requests or len(requests) > MAX_LOGICAL_REQUESTS:
        _reject()
    seen_ids: set[str] = set()
    seen_logical: set[tuple[str, str, str]] = set()
    projects: dict[str, str] = {}
    sources: dict[str, dict[str, Any]] = {}
    logical: list[dict[str, Any]] = []
    for item in requests:
        record = _closed(item, {"id", "project", "source", "declarations"})
        ident = corpus._token(record["id"], corpus.SLUG)
        if ident in seen_ids:
            _reject()
        seen_ids.add(ident)
        project = _closed(record["project"], {"slug", "canonicalRepositoryURL"})
        project_slug = corpus._token(project["slug"], corpus.SLUG)
        project_repo = corpus._canonical_repository(project["canonicalRepositoryURL"])
        if project_slug in projects and projects[project_slug] != project_repo:
            _reject()
        projects[project_slug] = project_repo
        source = _closed(record["source"], {"repositoryURL", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "spans"})
        source_repo = corpus._canonical_repository(source["repositoryURL"])
        source_kind = corpus._enum(source["sourceKind"], {"changelog", "release_note", "migration_guide", "source_code", "helm_chart", "repository_metadata"})
        version = corpus._text(source["version"], maximum=24)
        if version != "reference_only":
            version = corpus._semver(version)
        commit = corpus._commit(source["commit"])
        immutable = corpus._immutable_url(source["immutableURL"], source_repo, commit)
        digest = corpus._sha(source["fileDigest"])
        # Validate span shape before egress. Digest matching requires the bytes later.
        spans_value = source["spans"]
        if not isinstance(spans_value, list) or not spans_value or len(spans_value) > corpus.MAX_SPANS:
            _reject()
        normalized_spans: list[dict[str, Any]] = []
        previous = 0
        for span in spans_value:
            checked = _closed(span, {"startLine", "endLine", "spanDigest"})
            start, end = checked["startLine"], checked["endLine"]
            if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool) or start < 1 or end < start or start <= previous or end > corpus.MAX_SOURCE_LINES:
                _reject()
            normalized_spans.append({"startLine": start, "endLine": end, "spanDigest": corpus._sha(checked["spanDigest"])})
            previous = end
        spans_digest = _sha(corpus._canonical(normalized_spans))
        logical_key = (project_slug, immutable, spans_digest)
        if logical_key in seen_logical:
            _reject()
        seen_logical.add(logical_key)
        declarations = corpus._declarations(record["declarations"])
        prefix = "https://github.com/"
        owner_repo = source_repo.removeprefix(prefix).split("/")
        if len(owner_repo) != 2:
            _reject()
        path = immutable.split(f"/blob/{commit}/", 1)[1]
        requested_path = f"/{owner_repo[0]}/{owner_repo[1]}/{commit}/{path}"
        if not RAW_PATH.fullmatch(requested_path):
            _reject()
        raw_url = f"https://{RAW_HOST}{requested_path}"
        source_data = {"repositoryURL": source_repo, "sourceKind": source_kind, "version": version, "commit": commit, "immutableURL": immutable, "fileDigest": digest, "spans": normalized_spans, "rawURL": raw_url, "requestPath": requested_path}
        metadata = (source_repo, source_kind, version, commit, digest)
        prior = sources.get(immutable)
        if prior is None:
            sources[immutable] = {"source": source_data, "metadata": metadata, "references": []}
        elif prior["metadata"] != metadata:
            _reject()
        reference = {"id": ident, "project": {"slug": project_slug, "canonicalRepositoryURL": project_repo}, "source": source_data, "declarations": declarations}
        sources[immutable]["references"].append(reference)
        logical.append(reference)
    return revision, logical, sources


class _TLSReader:
    def __init__(self, sock: ssl.SSLSocket, initial: bytes):
        self.sock, self.buffer = sock, bytearray(initial)

    def _more(self, maximum: int) -> None:
        if maximum < 1:
            raise ValueError
        value = self.sock.recv(maximum)
        if not value:
            raise EOFError
        self.buffer.extend(value)

    def exact(self, amount: int) -> bytes:
        while len(self.buffer) < amount:
            self._more(amount - len(self.buffer))
        result = bytes(self.buffer[:amount])
        del self.buffer[:amount]
        return result

    def line(self, maximum: int) -> bytes:
        while True:
            marker = self.buffer.find(b"\r\n")
            if marker >= 0:
                if marker > maximum:
                    raise ValueError
                result = bytes(self.buffer[:marker])
                del self.buffer[:marker + 2]
                return result
            if len(self.buffer) < maximum:
                self._more(maximum - len(self.buffer))
                continue
            # Do not request a second byte until the first byte after a maximum
            # length line is known to be CR. An overlong line is rejected after
            # exactly one framing byte, rather than buffering an arbitrary read.
            if len(self.buffer) == maximum:
                self._more(1)
                continue
            if self.buffer[maximum] != 0x0D:
                raise ValueError
            if len(self.buffer) == maximum + 1:
                self._more(1)
                continue
            if self.buffer[maximum:maximum + 2] != b"\r\n":
                raise ValueError
            result = bytes(self.buffer[:maximum])
            del self.buffer[:maximum + 2]
            return result


def _header_response(sock: ssl.SSLSocket) -> tuple[int, dict[str, str], bytes]:
    # Parse incrementally: neither a single long line nor too many headers is
    # retained before its dedicated cap is enforced.
    reader = _TLSReader(sock, b"")
    total = 0

    def line_within_total() -> bytes:
        nonlocal total
        # Read one byte at a time here. Header-field/count admission must occur
        # before a TLS recv can retain bytes belonging to later fields or body.
        remaining = MAX_HEADER_BYTES - total
        if remaining < 2:
            raise ValueError
        maximum = min(MAX_HEADER_LINE, remaining - 2)
        while True:
            marker = reader.buffer.find(b"\r\n")
            if marker >= 0:
                if marker > maximum:
                    raise ValueError
                line = bytes(reader.buffer[:marker])
                del reader.buffer[:marker + 2]
                total += len(line) + 2
                return line
            if len(reader.buffer) >= maximum:
                # A line at its content cap needs at most one more byte to
                # establish that it is overlong; do not consume a whole field.
                reader._more(1)
                if reader.buffer[maximum] != 0x0D:
                    raise ValueError
                reader._more(1)
                if reader.buffer[maximum:maximum + 2] != b"\r\n":
                    raise ValueError
                line = bytes(reader.buffer[:maximum])
                del reader.buffer[:maximum + 2]
                total += len(line) + 2
                return line
            reader._more(1)

    status_line = line_within_total()
    try:
        bits = status_line.decode("ascii").split(" ", 2)
        if len(bits) < 2 or bits[0] != "HTTP/1.1" or not re.fullmatch(r"[0-9]{3}", bits[1]):
            raise ValueError
        status = int(bits[1])
    except (UnicodeDecodeError, ValueError):
        raise ValueError
    headers: dict[str, str] = {}
    while len(headers) < MAX_HEADERS:
        line = line_within_total()
        if not line:
            return status, headers, bytes(reader.buffer)
        if b":" not in line:
            raise ValueError
        name, value = line.split(b":", 1)
        try:
            key = name.decode("ascii").lower()
            parsed = value.strip().decode("ascii")
        except UnicodeDecodeError:
            raise ValueError
        if not re.fullmatch(r"[a-z0-9-]{1,64}", key) or key in headers:
            raise ValueError
        headers[key] = parsed
    # At the field cap, do not parse or retain a possible 65th header. Two
    # bytes are enough to distinguish the required empty CRLF terminator.
    if MAX_HEADER_BYTES - total < 2 or reader.exact(2) != b"\r\n":
        raise ValueError
    return status, headers, bytes(reader.buffer)


def _write_chunk(shared: memoryview, offset: int, chunk: bytes, digest: Any) -> int:
    if not chunk or offset + len(chunk) > MAX_OBJECT_BYTES:
        raise ValueError
    shared[offset:offset + len(chunk)] = chunk
    digest.update(chunk)
    return offset + len(chunk)


def _read_body(reader: _TLSReader, headers: dict[str, str], shared: memoryview) -> tuple[int, str]:
    encoding = headers.get("content-encoding", "identity").lower()
    if encoding != "identity":
        raise ValueError
    transfer = headers.get("transfer-encoding", "").lower()
    content_length = headers.get("content-length")
    if transfer and content_length:
        raise ValueError
    digest = hashlib.sha256()
    written = 0
    if transfer == "chunked":
        while True:
            line = reader.line(128)
            token = line.split(b";", 1)[0]
            if not re.fullmatch(b"[0-9A-Fa-f]{1,8}", token):
                raise ValueError
            size = int(token, 16)
            if size == 0:
                trailer_bytes = 0
                while True:
                    trailer = reader.line(MAX_HEADER_LINE)
                    trailer_bytes += len(trailer) + 2
                    if trailer_bytes > MAX_HEADER_BYTES:
                        raise ValueError
                    if not trailer:
                        return written, "sha256:" + digest.hexdigest()
                    if b":" not in trailer:
                        raise ValueError
            if size > MAX_OBJECT_BYTES - written:
                raise ValueError
            chunk = reader.exact(size)
            if reader.exact(2) != b"\r\n":
                raise ValueError
            written = _write_chunk(shared, written, chunk, digest)
    if transfer:
        raise ValueError
    if content_length is None or not re.fullmatch(r"[0-9]{1,7}", content_length):
        raise ValueError
    length = int(content_length)
    if length < 1 or length > MAX_OBJECT_BYTES:
        raise ValueError
    remaining = length
    while remaining:
        amount = min(65_536, remaining)
        chunk = reader.exact(amount)
        written = _write_chunk(shared, written, chunk, digest)
        remaining -= amount
    return written, "sha256:" + digest.hexdigest()


def _system_tls_context() -> ssl.SSLContext:
    # OpenSSL recognizes these process variables. Clear them in the isolated
    # worker before asking it for its default system-trust context.
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
        os.environ.pop(name, None)
    return ssl.create_default_context()


def _worker(shared_name: str, request_path: str, send: Any) -> None:
    """Fixed-host worker. It sends only a small JSON result; bytes stay in shared memory."""
    shared = None
    raw_socket = tls_socket = None
    try:
        if not RAW_PATH.fullmatch(request_path):
            raise ValueError
        # Constructing this first makes the environment-clearing order both
        # explicit and independently testable before any network connection.
        context = _system_tls_context()
        shared = shared_memory.SharedMemory(name=shared_name)
        raw_socket = socket.create_connection((RAW_HOST, RAW_PORT), timeout=10)
        tls_socket = context.wrap_socket(raw_socket, server_hostname=RAW_HOST)
        raw_socket = None
        tls_socket.settimeout(10)
        request = (f"GET {request_path} HTTP/1.1\r\nHost: {RAW_HOST}\r\nUser-Agent: {USER_AGENT}\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").encode("ascii")
        tls_socket.sendall(request)
        status, headers, initial = _header_response(tls_socket)
        if status != 200:
            send.send_bytes(_canonical({"kind": "HTTP_STATUS", "status": status}))
            return
        length, digest = _read_body(_TLSReader(tls_socket, initial), headers, shared.buf)
        send.send_bytes(_canonical({"kind": "HTTP_200", "status": status, "byteLength": length, "contentDigest": digest}))
    except (socket.timeout, TimeoutError):
        send.send_bytes(_canonical({"kind": "TRANSPORT_TIMEOUT"}))
    except (OSError, ssl.SSLError):
        send.send_bytes(_canonical({"kind": "TRANSPORT_FAILURE"}))
    except Exception:
        send.send_bytes(_canonical({"kind": "RESPONSE_REJECTED"}))
    finally:
        try:
            if tls_socket is not None:
                tls_socket.close()
            elif raw_socket is not None:
                raw_socket.close()
        except OSError:
            pass
        if shared is not None:
            shared.close()
        try:
            send.close()
        except OSError:
            pass


def _stop_worker(process: Any, deadline: float) -> bool:
    """Terminate, kill, and reap a child using the budget reserved up front."""
    if process is None:
        return True
    try:
        if process.is_alive():
            process.terminate()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        process.join(min(0.10, remaining))
        if process.is_alive():
            process.kill()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            process.join(min(0.10, remaining))
        # A dead process must still have an exit code: that is the reap proof.
        return not process.is_alive() and process.exitcode is not None
    except Exception:
        return False


def _worker_message(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    kind = value.get("kind")
    if kind == "HTTP_200":
        if set(value) != {"kind", "status", "byteLength", "contentDigest"}:
            return None
        length, digest = value.get("byteLength"), value.get("contentDigest")
        if value.get("status") != 200 or not isinstance(length, int) or isinstance(length, bool) or length < 1 or length > MAX_OBJECT_BYTES or not isinstance(digest, str) or not corpus.SHA256.fullmatch(digest):
            return None
    elif kind == "HTTP_STATUS":
        if set(value) != {"kind", "status"} or not isinstance(value.get("status"), int) or isinstance(value.get("status"), bool) or value["status"] < 100 or value["status"] > 599:
            return None
    elif kind in {"TRANSPORT_TIMEOUT", "TRANSPORT_FAILURE", "RESPONSE_REJECTED"}:
        if set(value) != {"kind"}:
            return None
    else:
        return None
    return value


def _worker_result(job: dict[str, Any], timeout: float, worker: Callable[..., None] = _worker) -> tuple[dict[str, Any], bytes | None]:
    timeout = max(0.0, timeout)
    # Do not create a child when the requested budget cannot include a positive
    # termination/reap phase. This keeps the advertised bound inclusive.
    if timeout <= CLEANUP_RESERVE_SECONDS:
        return {"kind": "TRANSPORT_TIMEOUT"}, None
    deadline = time.monotonic() + timeout
    work_deadline = deadline - CLEANUP_RESERVE_SECONDS
    shared = receive = send = process = None
    started = reaped = False
    try:
        context = multiprocessing.get_context("spawn")
        if time.monotonic() >= work_deadline:
            return {"kind": "TRANSPORT_TIMEOUT"}, None
        shared = shared_memory.SharedMemory(create=True, size=MAX_OBJECT_BYTES)
        receive, send = context.Pipe(duplex=False)
        process = context.Process(target=worker, args=(shared.name, job["source"]["requestPath"], send))
        process.daemon = True
        process.start(); started = True
        send.close(); send = None
        remaining = work_deadline - time.monotonic()
        if remaining <= 0 or not receive.poll(remaining):
            reaped = _stop_worker(process, deadline)
            return {"kind": "TRANSPORT_TIMEOUT"}, None
        try:
            raw = receive.recv_bytes(MAX_IPC_BYTES)
            result = _worker_message(json.loads(raw.decode("ascii")))
        except (EOFError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            result = None
        if result is None:
            reaped = _stop_worker(process, deadline)
            return {"kind": "TRANSPORT_FAILURE"}, None
        # A result is not accepted until the worker exits cleanly within the
        # work phase; teardown remains reserved for a misbehaving child.
        remaining = work_deadline - time.monotonic()
        process.join(max(0.0, remaining))
        if process.is_alive() or process.exitcode != 0:
            reaped = _stop_worker(process, deadline)
            return {"kind": "TRANSPORT_FAILURE"}, None
        reaped = True
        if result.get("kind") != "HTTP_200":
            return result, None
        length, digest = result.get("byteLength"), result.get("contentDigest")
        if not isinstance(length, int) or isinstance(length, bool) or length < 1 or length > MAX_OBJECT_BYTES or not isinstance(digest, str) or not corpus.SHA256.fullmatch(digest):
            return {"kind": "TRANSPORT_FAILURE"}, None
        data = bytes(shared.buf[:length])
        if _sha(data) != digest:
            return {"kind": "TRANSPORT_FAILURE"}, None
        return result, data
    except Exception:
        return {"kind": "TRANSPORT_FAILURE"}, None
    finally:
        if started and not reaped:
            reaped = _stop_worker(process, deadline)
        for handle in (send, receive):
            if handle is not None:
                try: handle.close()
                except OSError: pass
        if shared is not None:
            try: shared.close()
            except OSError: pass
            # Never unlink a shared region while a worker might still address
            # it. A failed reap is a closed transport failure, not a cleanup.
            if not started or reaped:
                try: shared.unlink()
                except (FileNotFoundError, OSError): pass


def _receipt(value: dict[str, Any]) -> dict[str, Any]:
    # A defensive final cap for either the retained receipt or stdout result.
    if len(_canonical(value)) > MAX_RECEIPT_BYTES:
        _reject()
    return value


def _attempt_receipt(request_digest: str | None, status: str, captures: list[dict[str, Any]], unattempted: int, cleanup: str = "NOT_APPLICABLE") -> dict[str, Any]:
    value = {"schema": RECEIPT_SCHEMA, "requestDigest": request_digest, "result": status, "authority": LOCAL_AUTHORITY, "captures": captures, "unattemptedSourceCount": unattempted, "cleanup": cleanup, "limitations": ["attempt metadata is not source, tag, rule, runtime, signing, publication, or training authority", "response bodies, local paths, redirect targets, exception text, and invalid caller values are omitted"]}
    try:
        return _receipt(value)
    except CaptureError:
        # Preserve the no-leak failure channel even if a caller somehow reaches
        # the defensive receipt limit.
        return {"schema": RECEIPT_SCHEMA, "requestDigest": None, "result": "REJECTED", "authority": LOCAL_AUTHORITY, "captures": [], "unattemptedSourceCount": 0, "cleanup": "NOT_APPLICABLE", "limitations": ["attempt receipt exceeded its local bound"]}


def _capture_failure(request_digest: str, captures: list[dict[str, Any]], sources: dict[str, dict[str, Any]], status: str) -> CaptureFailure:
    return CaptureFailure(_attempt_receipt(request_digest, status, captures, len(sources) - len(captures)))


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError
        view = view[written:]
    os.fsync(fd)


def _file_private(info: os.stat_result) -> bool:
    return stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077 and info.st_nlink == 1


def _hash_fd(fd: int, length: int) -> str | None:
    try:
        if os.lseek(fd, 0, os.SEEK_SET) != 0:
            return None
        remain = length
        digest = hashlib.sha256()
        while remain:
            chunk = os.read(fd, min(65_536, remain))
            if not chunk:
                return None
            digest.update(chunk); remain -= len(chunk)
        if os.read(fd, 1):
            return None
        return "sha256:" + digest.hexdigest()
    except OSError:
        return None


def _same_created_file(item: dict[str, Any]) -> bool:
    try:
        named = os.stat(item["name"], dir_fd=item["directoryFD"], follow_symlinks=False)
        held = os.fstat(item["fd"])
    except OSError:
        return False
    if not _file_private(named) or not _file_private(held):
        return False
    expected = (item["device"], item["inode"], item["size"])
    if (named.st_dev, named.st_ino, named.st_size) != expected or (held.st_dev, held.st_ino, held.st_size) != expected:
        return False
    return _hash_fd(item["fd"], item["size"]) == item["digest"]


def _create_file(directory_fd: int, name: str, data: bytes, created: list[dict[str, Any]]) -> None:
    fd = -1
    try:
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        info = os.fstat(fd)
        # Track as soon as an inode can be identified, even when its mode,
        # owner, or link count is already unsafe. Failed cleanup stays explicit.
        item = {"directoryFD": directory_fd, "name": name, "device": info.st_dev, "inode": info.st_ino, "size": len(data), "digest": _sha(data), "fd": fd}
        created.append(item); fd = -1
        if not _file_private(info):
            _reject()
        # Keep the descriptor and exact expected bytes until completion. It
        # lets the caller rebind every marker/name to its original inode.
        _write_all(item["fd"], data)
        if not _same_created_file(item):
            _reject()
    finally:
        if fd >= 0:
            os.close(fd)


def _close_created(created: list[dict[str, Any]]) -> None:
    for item in created:
        try: os.close(item["fd"])
        except OSError: pass


def _remove_created(created: list[dict[str, Any]]) -> bool:
    clean = True
    for item in reversed(created):
        try:
            current = os.stat(item["name"], dir_fd=item["directoryFD"], follow_symlinks=False)
            held = os.fstat(item["fd"])
            # Failure cleanup may run after a short write, so it proves only
            # the private held inode still names this entry. Successful output
            # verification keeps the stricter expected size and digest check.
            expected = (item["device"], item["inode"])
            if not _file_private(current) or not _file_private(held) or (current.st_dev, current.st_ino) != expected or (held.st_dev, held.st_ino) != expected:
                clean = False
                continue
            os.unlink(item["name"], dir_fd=item["directoryFD"])
        except (FileNotFoundError, OSError):
            clean = False
    return clean


def _directory_identity(directory_fd: int) -> tuple[int, int]:
    info = os.fstat(directory_fd)
    _private_mode(info, directory=True)
    return info.st_dev, info.st_ino


def _same_directory_entry(parent_fd: int, name: str, held_fd: int, expected: tuple[int, int]) -> bool:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        held = os.fstat(held_fd)
    except OSError:
        return False
    return (
        stat.S_ISDIR(current.st_mode)
        and stat.S_ISDIR(held.st_mode)
        and current.st_uid == os.geteuid()
        and held.st_uid == os.geteuid()
        and not current.st_mode & 0o077
        and not held.st_mode & 0o077
        and (current.st_dev, current.st_ino) == expected == (held.st_dev, held.st_ino)
    )


def _write_success(parent_fd: int, parent_state: tuple[int, int, int, int, int, int, int], destination: str, manifest: dict[str, Any], receipt: dict[str, Any], objects: dict[str, bytes]) -> None:
    if _stable(os.fstat(parent_fd)) != parent_state:
        _reject()
    try:
        os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
        _reject()
    except FileNotFoundError:
        pass
    destination_fd = objects_fd = sha_fd = -1
    created: list[dict[str, Any]] = []
    made_dirs: list[tuple[int, str, int, int]] = []
    parent_identity = _directory_identity(parent_fd)
    destination_identity = objects_identity = sha_identity = None

    def intact() -> bool:
        return (
            _directory_identity(parent_fd) == parent_identity
            and destination_identity is not None and objects_identity is not None and sha_identity is not None
            and _same_directory_entry(parent_fd, destination, destination_fd, destination_identity)
            and _same_directory_entry(destination_fd, "objects", objects_fd, objects_identity)
            and _same_directory_entry(objects_fd, "sha256", sha_fd, sha_identity)
            and all(_same_created_file(item) for item in created)
        )

    try:
        os.mkdir(destination, 0o700, dir_fd=parent_fd)
        made_dirs.append((parent_fd, destination, -1, -1))
        initial = os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
        _private_mode(initial, directory=True)
        destination_identity = (initial.st_dev, initial.st_ino); made_dirs[-1] = (parent_fd, destination, *destination_identity)
        destination_fd = os.open(destination, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
        if _directory_identity(destination_fd) != destination_identity: _reject()
        os.mkdir("objects", 0o700, dir_fd=destination_fd)
        made_dirs.append((destination_fd, "objects", -1, -1))
        initial = os.stat("objects", dir_fd=destination_fd, follow_symlinks=False)
        _private_mode(initial, directory=True)
        objects_identity = (initial.st_dev, initial.st_ino); made_dirs[-1] = (destination_fd, "objects", *objects_identity)
        objects_fd = os.open("objects", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=destination_fd)
        if _directory_identity(objects_fd) != objects_identity: _reject()
        os.mkdir("sha256", 0o700, dir_fd=objects_fd)
        made_dirs.append((objects_fd, "sha256", -1, -1))
        initial = os.stat("sha256", dir_fd=objects_fd, follow_symlinks=False)
        _private_mode(initial, directory=True)
        sha_identity = (initial.st_dev, initial.st_ino); made_dirs[-1] = (objects_fd, "sha256", *sha_identity)
        sha_fd = os.open("sha256", os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=objects_fd)
        if _directory_identity(sha_fd) != sha_identity: _reject()
        for digest, data in sorted(objects.items()):
            if not intact():
                raise CaptureError("capture directory replaced")
            _create_file(sha_fd, digest.removeprefix("sha256:"), data, created)
        if not intact():
            raise CaptureError("capture directory replaced")
        _create_file(destination_fd, "CANDIDATE-CORPUS-MANIFEST.json", _canonical(manifest) + b"\n", created)
        # Receipt is the completion marker and is intentionally created last.
        if not intact():
            raise CaptureError("capture directory replaced")
        _create_file(destination_fd, "CAPTURE-RECEIPT.json", _canonical(receipt) + b"\n", created)
        os.fsync(sha_fd); os.fsync(objects_fd); os.fsync(destination_fd); os.fsync(parent_fd)
        if not intact():
            raise CaptureError("capture directory replaced")
    except Exception:
        cleaned = _remove_created(created)
        for directory_fd, name, device, inode in reversed(made_dirs):
            try:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if current.st_dev != device or current.st_ino != inode or not stat.S_ISDIR(current.st_mode):
                    cleaned = False
                    continue
                os.rmdir(name, dir_fd=directory_fd)
            except (FileNotFoundError, OSError):
                cleaned = False
        _close_created(created)
        if not cleaned:
            raise CaptureWriteFailure("INCOMPLETE")
        raise CaptureWriteFailure("COMPLETE")
    finally:
        _close_created(created)
        for fd in (sha_fd, objects_fd, destination_fd):
            if fd >= 0:
                try: os.close(fd)
                except OSError: pass


def _candidate_manifest(logical: list[dict[str, Any]], lengths: dict[str, int], revision: str, captured_at: str) -> dict[str, Any]:
    records = []
    for reference in sorted(logical, key=lambda x: x["id"]):
        source = reference["source"]
        records.append({"id": reference["id"], "project": reference["project"], "source": {key: source[key] for key in ("repositoryURL", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "spans")} | {"byteLength": lengths[source["fileDigest"]]}, "capture": {"capturedAt": captured_at, "object": "sha256/" + source["fileDigest"].removeprefix("sha256:")}, "declarations": reference["declarations"]})
    return {"schema": corpus.SCHEMA, "revision": revision, "authority": corpus.DECLARED_AUTHORITY, "records": records}


def _preflight_manifest_bound(logical: list[dict[str, Any]], revision: str) -> None:
    # `capturedAt` is always a 20-byte UTC value and each observed length has
    # no more decimal digits than MAX_OBJECT_BYTES. This is a byte upper bound
    # for the final canonical JSON plus the LF written to disk.
    prospective = _candidate_manifest(logical, {item["source"]["fileDigest"]: MAX_OBJECT_BYTES for item in logical}, revision, "2000-01-01T00:00:00Z")
    if len(_canonical(prospective)) + 1 > corpus.MAX_MANIFEST_BYTES:
        _reject()


def capture_requests(document: Any, output_parent: Path, *, worker: Callable[..., None] = _worker) -> dict[str, Any]:
    """Capture one closed request document. `worker` is test-only injection."""
    raw_document = _canonical(document)
    if len(raw_document) > MAX_REQUEST_BYTES:
        _reject()
    request_digest = _sha(raw_document)
    try:
        revision, logical, sources = _capture_request(document)
    except corpus.CorpusError:
        _reject()
    _preflight_manifest_bound(logical, revision)
    parent_fd, parent_state = _open_private_parent(output_parent)
    destination = "capture-" + request_digest.removeprefix("sha256:")
    previous_umask = os.umask(0o077)
    try:
        try:
            os.stat(destination, dir_fd=parent_fd, follow_symlinks=False)
            _reject()
        except FileNotFoundError:
            pass
        deadline = time.monotonic() + ATTEMPT_SECONDS
        objects: dict[str, bytes] = {}
        captures: list[dict[str, Any]] = []
        captured_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        for immutable in sorted(sources):
            remain = min(PER_SOURCE_SECONDS, deadline - time.monotonic())
            job = sources[immutable]
            source = job["source"]
            public = {"immutableURL": immutable, "requestedURL": source["rawURL"], "observedURL": source["rawURL"], "references": [{"id": x["id"], "project": x["project"]} for x in sorted(job["references"], key=lambda x: x["id"])]}
            if remain <= 0:
                public["status"] = "ATTEMPT_TIMEOUT"
                captures.append(public)
                raise _capture_failure(request_digest, captures, sources, "REJECTED")
            result, data = _worker_result(job, remain, worker)
            if result.get("kind") != "HTTP_200" or data is None:
                public["status"] = result.get("kind") if result.get("kind") in {"HTTP_STATUS", "TRANSPORT_TIMEOUT", "TRANSPORT_FAILURE", "RESPONSE_REJECTED"} else "TRANSPORT_FAILURE"
                if isinstance(result.get("status"), int): public["httpStatus"] = result["status"]
                captures.append(public)
                raise _capture_failure(request_digest, captures, sources, "REJECTED")
            if _sha(data) != source["fileDigest"]:
                public.update({"status": "DIGEST_MISMATCH", "httpStatus": 200, "observedDigest": _sha(data), "byteLength": len(data)})
                captures.append(public)
                raise _capture_failure(request_digest, captures, sources, "REJECTED")
            try:
                for reference in job["references"]:
                    corpus._spans(reference["source"]["spans"], data)
            except corpus.CorpusError:
                public.update({"status": "SPAN_MISMATCH", "httpStatus": 200, "observedDigest": _sha(data), "byteLength": len(data)})
                captures.append(public)
                raise _capture_failure(request_digest, captures, sources, "REJECTED")
            objects.setdefault(source["fileDigest"], data)
            if sum(len(item) for item in objects.values()) > MAX_UNIQUE_BYTES:
                public.update({"status": "AGGREGATE_LIMIT", "httpStatus": 200, "observedDigest": _sha(data), "byteLength": len(data)})
                captures.append(public)
                raise _capture_failure(request_digest, captures, sources, "REJECTED")
            public.update({"status": "MATCHED_DECLARED_BYTES", "httpStatus": 200, "observedDigest": _sha(data), "byteLength": len(data), "object": "sha256/" + source["fileDigest"].removeprefix("sha256:")})
            captures.append(public)
        manifest = _candidate_manifest(logical, {digest: len(data) for digest, data in objects.items()}, revision, captured_at)
        receipt = _receipt({"schema": RECEIPT_SCHEMA, "requestDigest": request_digest, "result": "MATCHED_DECLARED_BYTES", "authority": LOCAL_AUTHORITY, "revision": revision, "logicalRequestCount": len(logical), "uniqueSourceCount": len(sources), "aggregateByteLength": sum(len(item) for item in objects.values()), "captures": captures, "candidateManifestDigest": _sha(_canonical(manifest)), "cleanup": "NOT_APPLICABLE", "limitations": ["capture verifies only declared byte and span consistency; it does not authenticate source ownership, tags, releases, licences, rules, runtime behavior, signing, publication, or training", "project, packet, rule, version, and capture-time fields remain declarations; the candidate manifest needs separate offline verification and independent source review"]})
        try:
            _write_success(parent_fd, parent_state, destination, manifest, receipt, objects)
        except CaptureWriteFailure as failure:
            raise CaptureFailure(_attempt_receipt(request_digest, "REJECTED", captures, 0, failure.cleanup))
        return receipt | {"outputName": destination}
    finally:
        os.umask(previous_umask)
        try: os.close(parent_fd)
        except OSError: pass


class _Parser(argparse.ArgumentParser):
    def error(self, _: str) -> None:
        self.exit(2, "public-source-capture: usage rejected\n")


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="public-source-capture")
    parser.add_argument("command", nargs="?")
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--output-parent", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command != "capture":
        parser.error("required command")
    try:
        document = corpus._decode_json(_read_private_request(args.request), MAX_REQUEST_BYTES)
        receipt = capture_requests(document, args.output_parent)
    except CaptureFailure as failure:
        sys.stdout.buffer.write(_canonical(failure.receipt) + b"\n")
        print("public-source-capture: capture rejected", file=sys.stderr)
        return 2
    except Exception:
        # The CLI is the redaction boundary for filesystem/runtime failures as
        # well as malformed input. Never stringify an exception or its path.
        sys.stdout.buffer.write(_canonical(_attempt_receipt(None, "REJECTED", [], 0)) + b"\n")
        print("public-source-capture: capture rejected", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(_canonical(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
