#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
CLI = HERE.parent
RUNNER = HERE / "check_contribution_candidates.py"
EXAMPLES = CLI / "examples/contributions"


class ContributionCandidateDiscoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="contribution-candidates."))

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def run_runner(self, directory: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(RUNNER), "--directory", str(directory)],
            cwd=CLI,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=30,
        )

    def copy_candidate(self, source: str, name: str) -> Path:
        target = self.work / name
        shutil.copyfile(EXAMPLES / source, target)
        return target

    def test_fresh_candidate_is_discovered_without_a_hardcoded_entry(self) -> None:
        candidate = self.copy_candidate("synthetic-new-identity-packet.json", "fresh.json")
        result = self.run_runner(self.work)
        self.assertEqual(0, result.returncode, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual({
            "schema", "status", "candidateCount", "candidateDigests",
            "workflowState", "supportAdmission",
        }, set(summary))
        self.assertEqual("prufyx.io/upstream-evidence-candidate-summary/v1", summary["schema"])
        self.assertEqual("PASS", summary["status"])
        self.assertEqual(1, summary["candidateCount"])
        self.assertEqual("CANDIDATE", summary["workflowState"])
        self.assertEqual("NOT_ADMITTED", summary["supportAdmission"])
        expected_digest = "sha256:" + hashlib.sha256(
            json.dumps(json.loads(candidate.read_text()), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual([expected_digest], summary["candidateDigests"])
        self.assertNotIn("fresh.json", result.stdout)
        self.assertNotIn(str(self.work), result.stdout)

    def test_fresh_invalid_candidate_fails_without_payload_output(self) -> None:
        candidate = self.copy_candidate("synthetic-new-identity-packet.json", "invalid.json")
        packet = json.loads(candidate.read_text())
        packet["unexpected"] = "must be rejected"
        candidate.write_text(json.dumps(packet), encoding="utf-8")
        result = self.run_runner(self.work)
        self.assertEqual(1, result.returncode)
        self.assertEqual("", result.stdout)
        self.assertEqual("contribution-candidates: rejected\n", result.stderr)

    def test_unsafe_entries_and_file_count_are_rejected(self) -> None:
        self.copy_candidate("synthetic-new-identity-packet.json", "valid.json")
        (self.work / "notes.txt").write_text("positive candidates are JSON only", encoding="utf-8")
        result = self.run_runner(self.work)
        self.assertEqual(1, result.returncode)
        self.assertEqual("contribution-candidates: rejected\n", result.stderr)

        (self.work / "notes.txt").unlink()
        for index in range(64):
            self.copy_candidate("synthetic-new-identity-packet.json", f"candidate-{index:02d}.json")
        (self.work / "candidate-64.json").write_text("{}", encoding="utf-8")
        result = self.run_runner(self.work)
        self.assertEqual(1, result.returncode)
        self.assertEqual("contribution-candidates: rejected\n", result.stderr)

        (self.work / "candidate-64.json").unlink()
        (self.work / "unsafe.json").symlink_to(EXAMPLES / "synthetic-new-identity-packet.json")
        result = self.run_runner(self.work)
        self.assertEqual(1, result.returncode)
        self.assertEqual("contribution-candidates: rejected\n", result.stderr)

    def test_negative_directory_is_separate_from_positive_discovery(self) -> None:
        candidate = self.copy_candidate("synthetic-new-identity-packet.json", "valid.json")
        negative = self.work / "negative"
        negative.mkdir()
        shutil.copyfile(EXAMPLES / "negative/source-commit-mismatch.json", negative / "rejected.json")
        result = self.run_runner(self.work)
        self.assertEqual(0, result.returncode, result.stderr)
        summary = json.loads(result.stdout)
        self.assertEqual(1, summary["candidateCount"])
        self.assertEqual(1, len(summary["candidateDigests"]))
        self.assertTrue(candidate.exists())


if __name__ == "__main__":
    unittest.main()
