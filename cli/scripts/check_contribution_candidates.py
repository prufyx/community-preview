#!/usr/bin/env python3
"""Validate every positive upstream contribution candidate in the staged tree.

This is a source-gate helper, not a contribution admission mechanism.  It only
enumerates the documented positive JSON files, invokes the existing offline
packet validator, and emits a path-free summary.  It never fetches sources or
executes anything declared by a packet.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import stat
import subprocess
import sys

MAX_CANDIDATE_FILES = 64
MAX_PACKET_BYTES = 256 * 1024
POSITIVE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*\.json$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RECEIPT_FIELDS = {
    "schema", "packetDigest", "landscapeDigest", "submissionKind",
    "consistency", "workflowState", "limitations",
}
RECEIPT_SCHEMA = "prufyx.io/upstream-evidence-receipt/v1"
SUMMARY_SCHEMA = "prufyx.io/upstream-evidence-candidate-summary/v1"


class CandidateError(ValueError):
    pass


def _reject() -> None:
    raise CandidateError("candidate rejected")


def _decode_receipt(raw: bytes) -> dict[str, object]:
    try:
        receipt = json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _reject()
    if not isinstance(receipt, dict) or set(receipt) != RECEIPT_FIELDS:
        _reject()
    if receipt.get("schema") != RECEIPT_SCHEMA:
        _reject()
    if receipt.get("consistency") != "VALID" or receipt.get("workflowState") != "CANDIDATE":
        _reject()
    digest = receipt.get("packetDigest")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        _reject()
    limitations = receipt.get("limitations")
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        _reject()
    return receipt


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            _reject()
        value[key] = item
    return value


def _candidate_files(directory: Path) -> list[Path]:
    try:
        directory_stat = directory.lstat()
    except OSError:
        _reject()
    if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
        _reject()
    candidates: list[Path] = []
    try:
        entries = sorted(directory.iterdir(), key=lambda item: item.name)
    except OSError:
        _reject()
    for entry in entries:
        try:
            item_stat = entry.lstat()
        except OSError:
            _reject()
        if entry.name == "negative":
            if stat.S_ISLNK(item_stat.st_mode) or not stat.S_ISDIR(item_stat.st_mode):
                _reject()
            continue
        if stat.S_ISLNK(item_stat.st_mode) or not stat.S_ISREG(item_stat.st_mode):
            _reject()
        if not POSITIVE_NAME.fullmatch(entry.name):
            _reject()
        if item_stat.st_nlink != 1 or item_stat.st_size > MAX_PACKET_BYTES:
            _reject()
        candidates.append(entry)
    if len(candidates) > MAX_CANDIDATE_FILES:
        _reject()
    return candidates


def _validate(path: Path, validator: Path, landscape: Path) -> dict[str, object]:
    try:
        completed = subprocess.run(
            [sys.executable, "-B", str(validator), "validate", "--packet", str(path), "--landscape", str(landscape)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        _reject()
    if completed.returncode != 0:
        _reject()
    return _decode_receipt(completed.stdout)


def validate_candidates(directory: Path, validator: Path, landscape: Path) -> dict[str, object]:
    files = _candidate_files(directory)
    receipts = [_validate(path, validator, landscape) for path in files]
    return {
        "schema": SUMMARY_SCHEMA,
        "status": "PASS",
        "candidateCount": len(receipts),
        "candidateDigests": [receipt["packetDigest"] for receipt in receipts],
        "workflowState": "CANDIDATE",
        "supportAdmission": "NOT_ADMITTED",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="check-contribution-candidates")
    parser.add_argument("--directory", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--landscape", type=Path, help=argparse.SUPPRESS)
    arguments = parser.parse_args(argv)
    cli_root = Path(__file__).resolve().parents[1]
    directory = arguments.directory or cli_root / "examples/contributions"
    validator = cli_root / "scripts/contribution_packet.py"
    landscape = arguments.landscape or cli_root / "internal/cncfcheck/data/landscape-projects.json"
    try:
        summary = validate_candidates(directory, validator, landscape)
    except CandidateError:
        print("contribution-candidates: rejected", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
