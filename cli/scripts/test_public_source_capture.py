#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import io
import importlib.util
import json
import multiprocessing.shared_memory
import os
import stat
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

SCRIPT = Path(__file__).with_name("public_source_capture.py")
spec = importlib.util.spec_from_file_location("public_source_capture", SCRIPT)
assert spec and spec.loader
capture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)

BODY = b"removed option\nreplacement option\n"
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def fixture_worker(shared_name: str, request_path: str, send) -> None:
    shared = multiprocessing.shared_memory.SharedMemory(name=shared_name)
    try:
        if request_path.endswith("/slow.md"):
            time.sleep(60)
            return
        if request_path.endswith("/404.md"):
            send.send_bytes(capture._canonical({"kind": "HTTP_STATUS", "status": 404}))
            return
        body = BODY if not request_path.endswith("/mismatch.md") else b"different\n"
        shared.buf[:len(body)] = body
        send.send_bytes(capture._canonical({"kind": "HTTP_200", "status": 200, "byteLength": len(body), "contentDigest": capture._sha(body)}))
    finally:
        shared.close()
        send.close()




def malformed_worker(shared_name: str, request_path: str, send) -> None:
    shared = multiprocessing.shared_memory.SharedMemory(name=shared_name)
    try:
        send.send_bytes(b"[]")
    finally:
        shared.close()
        send.close()


def delayed_success_worker(shared_name: str, request_path: str, send) -> None:
    shared = multiprocessing.shared_memory.SharedMemory(name=shared_name)
    try:
        shared.buf[:1] = b"x"
        send.send_bytes(capture._canonical({"kind": "HTTP_200", "status": 200, "byteLength": 1, "contentDigest": digest(b"x")}))
        time.sleep(60)
    finally:
        shared.close()
        send.close()


def nonzero_worker(shared_name: str, request_path: str, send) -> None:
    # Do not send a result: the parent must reap this non-successful child.
    os._exit(3)


class _RecordingSocket:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        self.requests: list[int] = []

    def recv(self, amount: int) -> bytes:
        self.requests.append(amount)
        result = bytes(self.data[:amount])
        del self.data[:amount]
        return result


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def span(start: int, end: int) -> dict:
    return {"startLine": start, "endLine": end, "spanDigest": digest(b"\n".join(BODY.split(b"\n")[start - 1:end]))}


def document(*, path: str = "CHANGELOG.md", digest_value: str | None = None, requests: int = 1) -> dict:
    source = {
        "repositoryURL": "https://github.com/example/source-repository",
        "sourceKind": "release_note",
        "version": "1.2.3",
        "commit": COMMIT,
        "immutableURL": f"https://github.com/example/source-repository/blob/{COMMIT}/{path}",
        "fileDigest": digest_value or digest(BODY),
        "spans": [span(1, 2)],
    }
    result = {"schema": capture.SCHEMA, "revision": "synthetic-capture-v1", "authority": capture.AUTHORITY, "requests": [{"id": "first-source", "project": {"slug": "synthetic-project", "canonicalRepositoryURL": "https://github.com/example/project"}, "source": source, "declarations": {"packetDigest": None, "ruleIDs": []}}]}
    for index in range(1, requests):
        other = copy.deepcopy(result["requests"][0])
        other["id"] = f"shared-source-{index}"
        other["project"] = {"slug": f"synthetic-project-{index}", "canonicalRepositoryURL": f"https://github.com/example/project-{index}"}
        result["requests"].append(other)
    return result


class PublicSourceCaptureTests(unittest.TestCase):
    def parent(self, root: Path) -> Path:
        parent = root / "private-output"
        parent.mkdir(mode=0o700)
        parent.chmod(0o700)
        return parent

    def test_matching_capture_is_private_deduplicated_and_hands_to_unchanged_corpus_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            result = capture.capture_requests(document(requests=2), parent, worker=fixture_worker)
            output = parent / result["outputName"]
            manifest = json.loads((output / "CANDIDATE-CORPUS-MANIFEST.json").read_text())
            self.assertEqual(result["result"], "MATCHED_DECLARED_BYTES")
            self.assertLessEqual(len(capture._canonical(result)), capture.MAX_RECEIPT_BYTES)
            self.assertEqual(result["logicalRequestCount"], 2)
            self.assertEqual(result["uniqueSourceCount"], 1)
            self.assertEqual(len(result["captures"]), 1)
            self.assertEqual(len(list((output / "objects" / "sha256").iterdir())), 1)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "CAPTURE-RECEIPT.json").stat().st_mode), 0o600)
            receipt = capture.corpus.verify_corpus(manifest, output / "objects")
            self.assertEqual(receipt["verification"], "VERIFIED_RETAINED_BYTES")
            self.assertEqual(receipt["recordCount"], 2)

    def test_leading_underscore_path_segment_capture_round_trips_through_corpus_verifier(self):
        """Keep accepted public paths such as charts/project/_crds/schema.yaml covered."""
        request = document(path="charts/project/_crds/schema.yaml")
        expected_raw = f"https://raw.githubusercontent.com/example/source-repository/{COMMIT}/charts/project/_crds/schema.yaml"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            result = capture.capture_requests(request, parent, worker=fixture_worker)
            output = parent / result["outputName"]
            manifest = json.loads((output / "CANDIDATE-CORPUS-MANIFEST.json").read_text())
            self.assertEqual(result["result"], "MATCHED_DECLARED_BYTES")
            self.assertEqual(result["captures"][0]["status"], "MATCHED_DECLARED_BYTES")
            self.assertEqual(result["captures"][0]["requestedURL"], expected_raw)
            self.assertEqual(manifest["records"][0]["source"]["immutableURL"], request["requests"][0]["source"]["immutableURL"])
            receipt = capture.corpus.verify_corpus(manifest, output / "objects")
            self.assertEqual(receipt["verification"], "VERIFIED_RETAINED_BYTES")
            self.assertEqual(receipt["recordCount"], 1)
            self.assertEqual(receipt["aggregateByteLength"], len(BODY))

    def test_same_digest_different_urls_are_independently_requested(self):
        request = document()
        other = copy.deepcopy(request["requests"][0])
        other["id"] = "second-url"
        other["project"] = {"slug": "second", "canonicalRepositoryURL": "https://github.com/example/second"}
        other["source"]["immutableURL"] = other["source"]["immutableURL"].replace("CHANGELOG.md", "OTHER.md")
        request["requests"].append(other)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            result = capture.capture_requests(request, parent, worker=fixture_worker)
            output = parent / result["outputName"]
            self.assertEqual(result["uniqueSourceCount"], 2)
            self.assertEqual(len(result["captures"]), 2)
            self.assertEqual(len(list((output / "objects" / "sha256").iterdir())), 1)

    def test_digest_mismatch_retains_no_output_and_emits_only_attempt_metadata(self):
        request = document(path="mismatch.md")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            with self.assertRaises(capture.CaptureFailure) as raised:
                capture.capture_requests(request, parent, worker=fixture_worker)
            receipt = raised.exception.receipt
            self.assertEqual(receipt["captures"][0]["status"], "DIGEST_MISMATCH")
            self.assertNotIn("different", json.dumps(receipt))
            self.assertEqual(list(parent.iterdir()), [])

    def test_http_error_and_timeout_are_bounded_without_output(self):
        for path, expected, timeout in [("404.md", "HTTP_STATUS", None), ("slow.md", "TRANSPORT_TIMEOUT", 0.05)]:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve(); parent = self.parent(root)
                request = document(path=path)
                if timeout is None:
                    runner = capture.capture_requests
                    with self.assertRaises(capture.CaptureFailure) as raised:
                        runner(request, parent, worker=fixture_worker)
                else:
                    original = capture.PER_SOURCE_SECONDS
                    capture.PER_SOURCE_SECONDS = timeout
                    try:
                        with self.assertRaises(capture.CaptureFailure) as raised:
                            capture.capture_requests(request, parent, worker=fixture_worker)
                    finally:
                        capture.PER_SOURCE_SECONDS = original
                self.assertEqual(raised.exception.receipt["captures"][0]["status"], expected)
                self.assertEqual(list(parent.iterdir()), [])

    def test_invalid_contract_is_rejected_before_worker_or_output(self):
        request = document()
        request["requests"][0]["source"]["immutableURL"] += "?token=secret"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            with self.assertRaises(capture.CaptureError):
                capture.capture_requests(request, parent, worker=fixture_worker)
            self.assertEqual(list(parent.iterdir()), [])

    def test_existing_destination_rejected_before_worker(self):
        request = document()
        request_digest = capture._sha(capture._canonical(request)).removeprefix("sha256:")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            (parent / f"capture-{request_digest}").mkdir()
            with self.assertRaises(capture.CaptureError):
                capture.capture_requests(request, parent, worker=fixture_worker)

    def test_private_input_and_parent_reject_links_special_files_hardlinks_and_permissive_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            raw = capture._canonical(document())
            request = root / "request.json"; request.write_bytes(raw); request.chmod(0o644)
            with self.assertRaises(capture.CaptureError): capture._read_private_request(request)
            request.chmod(0o600)
            link = root / "request-link"; link.symlink_to(request)
            with self.assertRaises(capture.CaptureError): capture._read_private_request(link)
            hard = root / "request-hard"; os.link(request, hard)
            with self.assertRaises(capture.CaptureError): capture._read_private_request(hard)
            parent.chmod(0o755)
            with self.assertRaises(capture.CaptureError): capture.capture_requests(document(), parent, worker=fixture_worker)

    def test_ancestor_link_and_output_parent_fifo_are_rejected_before_egress(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); target = root / "target"; target.mkdir()
            ancestor = root / "linked"; ancestor.symlink_to(target, target_is_directory=True)
            with self.assertRaises(capture.CaptureError): capture.capture_requests(document(), ancestor, worker=fixture_worker)
            fifo = root / "fifo"
            try:
                os.mkfifo(fifo)
            except (AttributeError, NotImplementedError): self.skipTest("FIFO unavailable")
            with self.assertRaises(capture.CaptureError): capture.capture_requests(document(), fifo, worker=fixture_worker)

    def test_span_mismatch_and_limits_reject_without_persisting_bytes(self):
        request = document(); request["requests"][0]["source"]["spans"][0]["spanDigest"] = "sha256:" + "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            with self.assertRaises(capture.CaptureFailure) as raised:
                capture.capture_requests(request, parent, worker=fixture_worker)
            self.assertEqual(raised.exception.receipt["captures"][0]["status"], "SPAN_MISMATCH")
            self.assertEqual(list(parent.iterdir()), [])
        too_many = document(requests=capture.MAX_LOGICAL_REQUESTS + 1)
        with self.assertRaises(capture.CaptureError): capture.capture_requests(too_many, Path("."), worker=fixture_worker)


    def test_umask_cannot_weaken_private_output_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            prior = os.umask(0o777)
            try:
                result = capture.capture_requests(document(), parent, worker=fixture_worker)
            finally:
                os.umask(prior)
            output = parent / result["outputName"]
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "objects" / "sha256").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "CAPTURE-RECEIPT.json").stat().st_mode), 0o600)

    def test_write_and_cleanup_failure_leave_no_completion_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); parent = self.parent(root)
            request = document(); destination = parent / ("capture-" + capture._sha(capture._canonical(request)).removeprefix("sha256:"))
            original_create = capture._create_file
            def fail_before_receipt(directory_fd, name, data, created):
                if name == "CAPTURE-RECEIPT.json":
                    raise OSError("fixture write failure")
                return original_create(directory_fd, name, data, created)
            original_unlink = capture.os.unlink
            def cleanup_failure(name, *args, **kwargs):
                if name == "CANDIDATE-CORPUS-MANIFEST.json":
                    raise OSError("fixture cleanup failure")
                return original_unlink(name, *args, **kwargs)
            with mock.patch.object(capture, "_create_file", side_effect=fail_before_receipt), mock.patch.object(capture.os, "unlink", side_effect=cleanup_failure):
                with self.assertRaises(capture.CaptureError):
                    capture.capture_requests(request, parent, worker=fixture_worker)
            self.assertFalse((destination / "CAPTURE-RECEIPT.json").exists())

    def test_nine_spans_and_wrong_url_same_hash_reject_before_worker(self):
        nine = document()
        nine["requests"][0]["source"]["spans"] *= 9
        with self.assertRaises(capture.CaptureError):
            capture.capture_requests(nine, Path("."), worker=fixture_worker)
        wrong = document()
        wrong["requests"][0]["source"]["immutableURL"] = wrong["requests"][0]["source"]["immutableURL"].replace("source-repository", "other-repository")
        with self.assertRaises(capture.CaptureError):
            capture.capture_requests(wrong, Path("."), worker=fixture_worker)

    def test_preflight_project_conflict_and_oversized_candidate_never_start_worker(self):
        conflict = document()
        other = copy.deepcopy(conflict["requests"][0])
        other["id"] = "conflicting-project"
        other["project"] = {"slug": "synthetic-project", "canonicalRepositoryURL": "https://github.com/example/other-project"}
        other["source"]["immutableURL"] = other["source"]["immutableURL"].replace("CHANGELOG.md", "SECOND.md")
        conflict["requests"].append(other)
        def must_not_run(*_):
            raise AssertionError("worker started after preflight rejection")
        with tempfile.TemporaryDirectory() as directory:
            parent = self.parent(Path(directory).resolve())
            with self.assertRaises(capture.CaptureError):
                capture.capture_requests(conflict, parent, worker=must_not_run)
            self.assertEqual(list(parent.iterdir()), [])

        def large(rule_padding: int) -> dict:
            request = document()
            base = request["requests"][0]
            owner, repo = "o" * 99, "r" * 99
            path = "d" * 127 + "/" + "e" * 119
            immutable = f"https://github.com/{owner}/{repo}/blob/{COMMIT}/{path}"
            items = []
            for index in range(capture.MAX_LOGICAL_REQUESTS):
                item = copy.deepcopy(base)
                item["id"] = "a" + str(index).zfill(2) + "-" + "a" * 124
                item["project"] = {"slug": "p" + str(index).zfill(2) + "-" + "b" * 124, "canonicalRepositoryURL": "https://github.com/" + "q" * 99 + "/" + str(index).zfill(2) + "x" * 97}
                item["source"]["repositoryURL"] = f"https://github.com/{owner}/{repo}"
                item["source"]["immutableURL"] = immutable
                item["source"]["spans"] = [{"startLine": part * 2 + 1, "endLine": part * 2 + 1, "spanDigest": "sha256:" + "0" * 64} for part in range(4)]
                item["declarations"]["ruleIDs"] = [f"r{rule:02d}" + "z" * rule_padding for rule in range(16)]
                items.append(item)
            request["requests"] = items
            return request

        accepted = large(114)
        revision, logical, _ = capture._capture_request(accepted)
        capture._preflight_manifest_bound(logical, revision)
        rejected = large(115)
        self.assertLess(len(capture._canonical(rejected)), capture.MAX_REQUEST_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            parent = self.parent(Path(directory).resolve())
            with self.assertRaises(capture.CaptureError):
                capture.capture_requests(rejected, parent, worker=must_not_run)
            self.assertEqual(list(parent.iterdir()), [])

    def test_tls_reader_never_overreads_declared_body_or_chunk_line(self):
        socket = _RecordingSocket(b"x" + b"Z" * 4096)
        reader = capture._TLSReader(socket, b"")
        target = memoryview(bytearray(capture.MAX_OBJECT_BYTES))
        length, _ = capture._read_body(reader, {"content-length": "1"}, target)
        self.assertEqual(length, 1)
        self.assertEqual(socket.requests, [1])
        self.assertEqual(bytes(reader.buffer), b"")
        socket = _RecordingSocket(b"A" * 1024)
        with self.assertRaises(ValueError):
            capture._TLSReader(socket, b"").line(128)
        self.assertEqual(socket.requests, [128, 1])

    def test_worker_messages_environment_and_lifecycle_fail_closed(self):
        job = {"source": {"requestPath": f"/example/repo/{COMMIT}/file.md"}}
        result, data = capture._worker_result(job, 1.0, malformed_worker)
        self.assertEqual(result, {"kind": "TRANSPORT_FAILURE"})
        self.assertIsNone(data)
        started = time.monotonic()
        result, _ = capture._worker_result(job, 1.0, delayed_success_worker)
        self.assertEqual(result, {"kind": "TRANSPORT_FAILURE"})
        self.assertLess(time.monotonic() - started, 1.0)
        result, _ = capture._worker_result(job, 0.1, nonzero_worker)
        self.assertEqual(result, {"kind": "TRANSPORT_TIMEOUT"})
        self.assertIsNone(data)
        self.assertIsNone(capture._worker_message({"kind": "TRANSPORT_TIMEOUT", "status": 200}))

        observed: dict[str, str | None] = {}
        class Send:
            def send_bytes(self, _: bytes) -> None: pass
            def close(self) -> None: pass
        def tls_context():
            for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"):
                observed[name] = os.environ.get(name)
            raise OSError("fixture")
        with mock.patch.dict(os.environ, {"SSL_CERT_FILE": "CA-CANARY", "SSL_CERT_DIR": "DIR-CANARY", "SSLKEYLOGFILE": "KEYLOG-CANARY"}, clear=False), mock.patch.object(capture.ssl, "create_default_context", side_effect=tls_context):
            capture._worker("unreachable", job["source"]["requestPath"], Send())
        self.assertEqual(observed, {"SSL_CERT_FILE": None, "SSL_CERT_DIR": None, "SSLKEYLOGFILE": None})

        real_context = capture.multiprocessing.get_context
        real_shared = capture.shared_memory.SharedMemory
        made = []
        class StartFailureProcess:
            daemon = False
            def start(self): raise RuntimeError("fixture")
        class StartFailureContext:
            def __init__(self): self.context = real_context("spawn")
            def Pipe(self, *args, **kwargs): return self.context.Pipe(*args, **kwargs)
            def Process(self, *args, **kwargs): return StartFailureProcess()
        def recording_shared(*args, **kwargs):
            value = real_shared(*args, **kwargs)
            if kwargs.get("create"): made.append(value)
            return value
        with mock.patch.object(capture.multiprocessing, "get_context", return_value=StartFailureContext()), mock.patch.object(capture.shared_memory, "SharedMemory", side_effect=recording_shared):
            result, _ = capture._worker_result(job, 1.0, fixture_worker)
        self.assertEqual(result, {"kind": "TRANSPORT_FAILURE"})
        self.assertEqual(len(made), 1)
        with self.assertRaises(FileNotFoundError):
            real_shared(name=made[0].name)

    def test_write_failures_and_directory_replacement_never_complete_output(self):
        for phase in ("partial_write", "post_fsync"):
            for call in (1, 2, 3):
                with self.subTest(phase=phase, file_call=call), tempfile.TemporaryDirectory() as directory:
                    parent = self.parent(Path(directory).resolve())
                    request = document()
                    destination = parent / ("capture-" + capture._sha(capture._canonical(request)).removeprefix("sha256:"))
                    original = capture._write_all
                    calls = [0]
                    def fail_after_fsync(fd, data):
                        calls[0] += 1
                        if calls[0] == call:
                            if phase == "partial_write":
                                os.write(fd, data[:max(1, len(data) // 2)])
                            else:
                                original(fd, data)
                            raise OSError("fixture")
                        original(fd, data)
                    with mock.patch.object(capture, "_write_all", side_effect=fail_after_fsync):
                        with self.assertRaises(capture.CaptureFailure) as raised:
                            capture.capture_requests(request, parent, worker=fixture_worker)
                    self.assertEqual(raised.exception.receipt["cleanup"], "COMPLETE")
                    self.assertFalse((destination / "CAPTURE-RECEIPT.json").exists())
                    self.assertFalse(destination.exists())
        with tempfile.TemporaryDirectory() as directory:
            parent = self.parent(Path(directory).resolve())
            request = document()
            destination = parent / ("capture-" + capture._sha(capture._canonical(request)).removeprefix("sha256:"))
            moved = parent / "moved-original"
            original = capture._create_file
            swapped = [False]
            def replace_destination(directory_fd, name, data, created):
                if not swapped[0]:
                    swapped[0] = True
                    destination.rename(moved)
                    destination.mkdir(mode=0o700)
                return original(directory_fd, name, data, created)
            with mock.patch.object(capture, "_create_file", side_effect=replace_destination):
                with self.assertRaises(capture.CaptureFailure) as raised:
                    capture.capture_requests(request, parent, worker=fixture_worker)
            self.assertEqual(raised.exception.receipt["cleanup"], "INCOMPLETE")
            self.assertFalse((destination / "CAPTURE-RECEIPT.json").exists())
            self.assertFalse((moved / "CAPTURE-RECEIPT.json").exists())

    def test_timeout_reserves_reap_budget_and_header_limits_are_incremental(self):
        job = {"source": {"requestPath": f"/example/repo/{COMMIT}/file.md"}}
        before = {child.pid for child in capture.multiprocessing.active_children()}
        def sleeper(shared_name, path, send): time.sleep(60)
        started = time.monotonic()
        result, _ = capture._worker_result(job, 0.05, sleeper)
        self.assertEqual(result, {"kind": "TRANSPORT_TIMEOUT"})
        self.assertLess(time.monotonic() - started, 0.05)
        self.assertEqual([child for child in capture.multiprocessing.active_children() if child.pid not in before], [])
        long = _RecordingSocket(b"HTTP/1.1 200 " + b"X" * 5000)
        with self.assertRaises(ValueError): capture._header_response(long)
        self.assertEqual(long.requests[:2], [1, 1])
        self.assertEqual(sum(long.requests), capture.MAX_HEADER_LINE + 1)
        fields64 = b"".join(f"x-{index}: v\r\n".encode() for index in range(capture.MAX_HEADERS))
        exact = _RecordingSocket(b"HTTP/1.1 200 OK\r\n" + fields64 + b"\r\n")
        status, headers, remainder = capture._header_response(exact)
        self.assertEqual((status, len(headers), remainder), (200, capture.MAX_HEADERS, b""))
        self.assertEqual(sum(exact.requests), len(b"HTTP/1.1 200 OK\r\n" + fields64 + b"\r\n"))
        forbidden = _RecordingSocket(b"HTTP/1.1 200 OK\r\n" + fields64 + b"x-65: " + b"A" * capture.MAX_HEADER_LINE)
        with self.assertRaises(ValueError): capture._header_response(forbidden)
        self.assertEqual(forbidden.requests[-1], 2)
        self.assertEqual(sum(forbidden.requests), len(b"HTTP/1.1 200 OK\r\n" + fields64) + 2)
        status = b"HTTP/1.1 200 OK\r\n"
        full = status + b"x1:" + b"a" * 4093 + b"\r\n" + b"x2:" + b"a" * 4093 + b"\r\n" + b"x3:" + b"a" * 4093 + b"\r\n" + b"x4:" + b"a" * 4066 + b"\r\n\r\n"
        self.assertEqual(len(full), capture.MAX_HEADER_BYTES)
        self.assertEqual(capture._header_response(_RecordingSocket(full))[0], 200)
        over = status + b"x1:" + b"a" * 4093 + b"\r\n" + b"x2:" + b"a" * 4093 + b"\r\n" + b"x3:" + b"a" * 4093 + b"\r\n" + b"x4:" + b"a" * 4068 + b"\r\n"
        self.assertEqual(len(over), capture.MAX_HEADER_BYTES)
        socket = _RecordingSocket(over)
        with self.assertRaises(ValueError): capture._header_response(socket)
        self.assertEqual(sum(socket.requests), capture.MAX_HEADER_BYTES)

    def test_directory_and_file_races_are_never_accepted(self):
        for doomed in ("destination", "objects", "sha256"):
            with self.subTest(directory_mode=doomed), tempfile.TemporaryDirectory() as directory:
                parent = self.parent(Path(directory).resolve()); request = document()
                destination = parent / ("capture-" + capture._sha(capture._canonical(request)).removeprefix("sha256:"))
                original = capture._create_file; changed = [False]
                def make_permissive(directory_fd, name, data, created):
                    if not changed[0]:
                        changed[0] = True
                        target = {"destination": destination, "objects": destination / "objects", "sha256": destination / "objects" / "sha256"}[doomed]
                        target.chmod(0o755)
                    return original(directory_fd, name, data, created)
                with mock.patch.object(capture, "_create_file", side_effect=make_permissive):
                    with self.assertRaises(capture.CaptureFailure) as raised:
                        capture.capture_requests(request, parent, worker=fixture_worker)
                self.assertEqual(raised.exception.receipt["cleanup"], "COMPLETE")
                self.assertFalse(destination.exists())
        for doomed in ("destination", "objects", "sha256"):
            with self.subTest(directory_open=doomed), tempfile.TemporaryDirectory() as directory:
                parent = self.parent(Path(directory).resolve()); request = document()
                original = capture.os.open
                destination = "capture-" + capture._sha(capture._canonical(request)).removeprefix("sha256:")
                names = {"destination": destination, "objects": "objects", "sha256": "sha256"}
                def fail_open(name, flags, *args, **kwargs):
                    if name == names[doomed] and flags & os.O_DIRECTORY: raise OSError("SECRET-CANARY-open")
                    return original(name, flags, *args, **kwargs)
                with mock.patch.object(capture.os, "open", side_effect=fail_open):
                    with self.assertRaises(capture.CaptureFailure) as raised: capture.capture_requests(request, parent, worker=fixture_worker)
                self.assertIn(raised.exception.receipt["cleanup"], {"COMPLETE", "INCOMPLETE"})
                self.assertFalse(any(path.name == "CAPTURE-RECEIPT.json" for path in parent.rglob("*")))
        for private_mode_call in (3, 5, 7):
            with self.subTest(directory_private_mode=private_mode_call), tempfile.TemporaryDirectory() as directory:
                parent = self.parent(Path(directory).resolve()); original = capture._private_mode; count = [0]
                def fail_after_mkdir(info, directory=False):
                    count[0] += 1
                    if count[0] == private_mode_call: raise OSError("SECRET-CANARY-mode")
                    return original(info, directory)
                with mock.patch.object(capture, "_private_mode", side_effect=fail_after_mkdir):
                    with self.assertRaises(capture.CaptureFailure) as raised: capture.capture_requests(document(), parent, worker=fixture_worker)
                self.assertIn(raised.exception.receipt["cleanup"], {"COMPLETE", "INCOMPLETE"})
                self.assertFalse(any(path.name == "CAPTURE-RECEIPT.json" for path in parent.rglob("*")))
        with tempfile.TemporaryDirectory() as directory:
            parent = self.parent(Path(directory).resolve()); request = document(); destination = parent / ("capture-" + capture._sha(capture._canonical(request)).removeprefix("sha256:")); moved = parent / "moved"
            original = capture._create_file; changed = [False]
            def replace_after_create(directory_fd, name, data, created):
                original(directory_fd, name, data, created)
                if not changed[0]:
                    changed[0] = True
                    capture.os.rename(name, name + ".moved", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                    fd = capture.os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory_fd)
                    capture.os.write(fd, b"bad"); capture.os.close(fd)
            with mock.patch.object(capture, "_create_file", side_effect=replace_after_create):
                with self.assertRaises(capture.CaptureFailure) as raised: capture.capture_requests(request, parent, worker=fixture_worker)
            self.assertEqual(raised.exception.receipt["cleanup"], "INCOMPLETE")
            self.assertFalse((destination / "CAPTURE-RECEIPT.json").exists())
        with tempfile.TemporaryDirectory() as directory:
            parent = self.parent(Path(directory).resolve()); outside = parent / "outside"; request = document(); original = capture._create_file; linked = [False]
            def create_hardlink(directory_fd, name, data, created):
                old_open = capture.os.open
                def hooked(path, flags, *args, **kwargs):
                    fd = old_open(path, flags, *args, **kwargs)
                    if not linked[0] and len(str(path)) == 64:
                        linked[0] = True; capture.os.link(path, outside, src_dir_fd=directory_fd)
                    return fd
                with mock.patch.object(capture.os, "open", side_effect=hooked): return original(directory_fd, name, data, created)
            with mock.patch.object(capture, "_create_file", side_effect=create_hardlink):
                with self.assertRaises(capture.CaptureFailure) as raised: capture.capture_requests(request, parent, worker=fixture_worker)
            self.assertEqual(raised.exception.receipt["cleanup"], "INCOMPLETE")
            self.assertTrue(outside.exists())

    def test_runtime_os_errors_are_redacted_at_cli_and_capture_boundaries(self):
        class Output:
            def __init__(self): self.buffer = io.BytesIO()
        stdout, stderr = Output(), io.StringIO()
        with mock.patch.object(capture, "_read_private_request", side_effect=OSError("SECRET-CANARY-read")), mock.patch.object(capture.sys, "stdout", stdout), mock.patch.object(capture.sys, "stderr", stderr):
            self.assertEqual(capture.main(["capture", "--request", "ignored", "--output-parent", "ignored"]), 2)
        self.assertNotIn("SECRET-CANARY", stdout.buffer.getvalue().decode() + stderr.getvalue())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "request"; path.write_bytes(capture._canonical(document())); path.chmod(0o600)
            with mock.patch.object(capture.corpus, "_read_regular_fd", side_effect=OSError("SECRET-CANARY-read")):
                with self.assertRaises(capture.CaptureError): capture._read_private_request(path)
            with mock.patch.object(capture.os, "fstat", side_effect=OSError("SECRET-CANARY-fstat")):
                with self.assertRaises(capture.CaptureError): capture._read_private_request(path)
            with mock.patch.object(capture.os, "close", side_effect=OSError("SECRET-CANARY-close")):
                with self.assertRaises(capture.CaptureError): capture._read_private_request(path)
        job = {"source": {"requestPath": f"/example/repo/{COMMIT}/file.md"}}
        with mock.patch.object(capture.shared_memory, "SharedMemory", side_effect=OSError("SECRET-CANARY-shm")):
            result, _ = capture._worker_result(job, 1.0, fixture_worker)
        self.assertEqual(result, {"kind": "TRANSPORT_FAILURE"})
        with tempfile.TemporaryDirectory() as directory:
            parent = self.parent(Path(directory).resolve())
            with mock.patch.object(capture, "_write_all", side_effect=OSError("SECRET-CANARY-write")):
                with self.assertRaises(capture.CaptureFailure) as raised: capture.capture_requests(document(), parent, worker=fixture_worker)
            self.assertNotIn("SECRET-CANARY", json.dumps(raised.exception.receipt))

    def test_cli_never_echoes_invalid_path_or_value(self):
        class Output:
            def __init__(self): self.buffer = io.BytesIO()
        stdout, stderr = Output(), io.StringIO()
        with mock.patch.object(capture.sys, "stdout", stdout), mock.patch.object(capture.sys, "stderr", stderr):
            result = capture.main(["capture", "--request", "/private/SECRET-CANARY-path", "--output-parent", "/private/output"])
        self.assertEqual(result, 2)
        self.assertNotIn("SECRET-CANARY", stdout.buffer.getvalue().decode() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
