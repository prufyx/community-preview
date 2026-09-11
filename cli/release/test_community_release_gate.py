#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
GATE = HERE / "community-release-gate.py"
# Full gate commands derive the Go graph before source-file checks, including FIFO
# paths. The direct FIFO boundary probes below retain the short nonblocking bound.
SOURCE_GRAPH_TIMEOUT_SECONDS = 120
PROMPT_REJECTION_TIMEOUT_SECONDS = 10


class CommunityReleaseGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.caller_umask = os.umask(0o022)
        try:
            self.create_fixture()
        except BaseException:
            if hasattr(self, "work"):
                shutil.rmtree(self.work, ignore_errors=True)
            os.umask(self.caller_umask)
            raise

    def create_fixture(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="community-release-gate-test."))
        self.root = self.work / "source"
        (self.root / "cli/cmd/tool").mkdir(parents=True)
        (self.root / "cli/internal/value/testdata").mkdir(parents=True)
        (self.root / "cli/release").mkdir(parents=True)
        (self.root / "LICENSES").mkdir()
        (self.root / "cli/go.mod").write_text("module example.test/community\n\ngo 1.26\n", encoding="utf-8")
        (self.root / "cli/cmd/tool/main.go").write_text(
            'package main\nimport ("fmt"; "example.test/community/internal/value")\nfunc main(){fmt.Print(value.Text())}\n', encoding="utf-8"
        )
        (self.root / "cli/cmd/tool/main_test.go").write_text(
            'package main\nimport "testing"\nfunc TestMainPackage(t *testing.T){}\n', encoding="utf-8"
        )
        (self.root / "cli/internal/value/value.go").write_text(
            'package value\nimport _ "embed"\n//go:embed data.txt\nvar text string\nfunc Text() string { return text + ArchValue() }\n', encoding="utf-8"
        )
        (self.root / "cli/internal/value/value_amd64.go").write_text('package value\nfunc ArchValue() string { return "amd64" }\n', encoding="utf-8")
        (self.root / "cli/internal/value/value_arm64.go").write_text('package value\nfunc ArchValue() string { return "arm64" }\n', encoding="utf-8")
        (self.root / "cli/internal/testhelper").mkdir()
        (self.root / "cli/internal/testhelper/helper.go").write_text('package testhelper\nfunc Expected() string { return "public fixture\\n" }\n', encoding="utf-8")
        (self.root / "cli/internal/value/data.txt").write_text("public fixture\n", encoding="utf-8")
        (self.root / "cli/internal/value/value_test.go").write_text(
            'package value\nimport ("strings"; "testing"; "example.test/community/internal/testhelper")\nfunc TestText(t *testing.T){if !strings.HasPrefix(Text(),testhelper.Expected()){t.Fatal(Text())}}\n', encoding="utf-8"
        )
        (self.root / "cli/internal/value/parity_test.go").write_text(
            '//go:build parityreview\n\npackage value\nimport "testing"\nfunc TestParity(t *testing.T){if Text()==""{t.Fatal("empty")}}\n', encoding="utf-8"
        )
        (self.root / "cli/internal/value/testdata/vector.json").write_text('{"expected":"public fixture"}\n', encoding="utf-8")
        (self.root / "LICENSE").write_text("test license\n", encoding="utf-8")
        (self.root / "LICENSES/runtime.txt").write_text("runtime license\n", encoding="utf-8")
        version = subprocess.check_output(["go", "env", "GOVERSION"], text=True).strip()
        self.policy = self.root / "cli/release/policy.json"
        self.policy.write_text(json.dumps({
            "allowExternalModules": False, "binaryName": "tool",
            "buildTargets": ["linux/amd64", "linux/arm64"],
            "entrypoints": ["./cmd/tool"], "moduleRoot": "cli",
            "requiredGoVersion": version,
            "requiredPaths": [
                {"path": "LICENSE", "role": "license"},
                {"path": "LICENSES", "recursive": True, "role": "license"},
            ],
            "schemaVersion": "prufyx.io/community-shipping-policy/v1",
            "sourceBuildTargets": ["linux/amd64", "linux/arm64", "darwin/arm64"],
            "testPolicy": {"requireDirectTestsForProductionPackages": True, "testTags": ["parityreview"]},
            "toolchainArchives": {
                "linux/amd64": "0" * 64, "linux/arm64": "1" * 64,
                "darwin/arm64": "2" * 64,
            },
        }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def tearDown(self) -> None:
        try:
            shutil.rmtree(self.work)
        finally:
            os.umask(self.caller_umask)

    def command(self, *args: str, ok: bool = True, timeout_seconds: int = SOURCE_GRAPH_TIMEOUT_SECONDS) -> subprocess.CompletedProcess[str]:
        result = subprocess.run([
            sys.executable, str(GATE), "--source-root", str(self.root),
            "--policy", str(self.policy), *args,
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_seconds)
        if ok and result.returncode:
            self.fail(result.stderr)
        return result

    def assert_manifest_fifo_boundary(self, manifest: Path) -> None:
        code = """
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("fixture_gate", sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
try:
    gate.load_external_json(Path(sys.argv[2]))
except gate.GateError as exc:
    print(exc)
    raise SystemExit(0)
raise SystemExit(1)
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(GATE), str(manifest)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=PROMPT_REJECTION_TIMEOUT_SECONDS,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("bounded regular file", result.stdout)

    def assert_source_fifo_boundary(self) -> None:
        code = """
import importlib.util
import sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("fixture_gate", sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
try:
    gate.stable_read(Path(sys.argv[2]), "extra.pipe")
except gate.GateError as exc:
    print(exc)
    raise SystemExit(0)
raise SystemExit(1)
"""
        result = subprocess.run(
            [sys.executable, "-B", "-c", code, str(GATE), str(self.root)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=PROMPT_REJECTION_TIMEOUT_SECONDS,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("not a single-link regular file", result.stdout)

    def enable_v2_fixture(self) -> None:
        module = "example.test/dependency"
        version = "v1.0.0"
        vendor = self.root / "cli/vendor/example.test/dependency"
        vendor.mkdir(parents=True)
        (vendor / "value.go").write_text(
            'package dependency\nimport _ "embed"\n//go:embed data.bin\nvar Data string\nfunc Text() string { return Data }\n', encoding="utf-8"
        )
        (vendor / "unused_plan9.go").write_text("//go:build plan9\n\npackage dependency\n", encoding="utf-8")
        (vendor / "data.bin").write_bytes(b"public\x00binary fixture\n")
        license_bytes = b"Synthetic dependency license\n"
        (vendor / "LICENSE").write_bytes(license_bytes)
        (self.root / "LICENSES/dependency.txt").write_bytes(license_bytes)
        (self.root / "cli/vendor/modules.txt").write_text(
            f"# {module} {version}\n## explicit; go 1.26\n{module}\n", encoding="utf-8"
        )
        (self.root / "cli/go.mod").write_text(
            f"module example.test/community\n\ngo 1.26\n\nrequire {module} {version}\n", encoding="utf-8"
        )
        module_sum = "h1:" + "A" * 43 + "="
        go_mod_sum = "h1:" + "B" * 43 + "="
        (self.root / "cli/go.sum").write_text(
            f"{module} {version} {module_sum}\n{module} {version}/go.mod {go_mod_sum}\n", encoding="utf-8"
        )
        (self.root / "cli/cmd/tool/main.go").write_text(
            'package main\nimport ("fmt"; "example.test/community/internal/value"; "example.test/dependency")\nfunc main(){fmt.Print(value.Text(), dependency.Text())}\n', encoding="utf-8"
        )
        policy = json.loads(self.policy.read_text())
        policy.update({
            "schemaVersion": "prufyx.io/community-shipping-policy/v2",
            "allowExternalModules": True,
            "vendorRoot": "cli/vendor",
            "externalModules": [{
                "path": module, "version": version, "moduleSum": module_sum, "goModSum": go_mod_sum, "licenseDeclared": "MIT",
                "notices": [{
                    "sourcePath": "cli/vendor/example.test/dependency/LICENSE",
                    "distributionPath": "LICENSES/dependency.txt",
                    "sha256": hashlib.sha256(license_bytes).hexdigest(),
                }],
            }],
            "binaryResources": [{
                "path": "cli/vendor/example.test/dependency/data.bin",
                "sha256": hashlib.sha256((vendor / "data.bin").read_bytes()).hexdigest(),
            }],
            "vendorTreeDigest": self.vendor_tree_digest(),
        })
        policy["requiredPaths"].append({"path": "cli/vendor", "recursive": True, "role": "vendor"})
        policy["requiredPaths"].append({"path": "cli/release/policy.json", "role": "release-policy"})
        self.policy.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def vendor_tree_digest(self) -> str:
        vendor = self.root / "cli/vendor"
        entries = []
        for path in sorted(vendor.rglob("*")):
            if path.is_file() and not path.is_symlink():
                raw = path.read_bytes()
                entries.append({
                    "mode": f"{path.stat().st_mode & 0o7777:04o}",
                    "path": path.relative_to(self.root).as_posix(),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                })
        raw = (json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    def refresh_vendor_tree_digest(self) -> None:
        policy = json.loads(self.policy.read_text())
        policy["vendorTreeDigest"] = self.vendor_tree_digest()
        self.policy.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")

    def test_manifest_is_deterministic_complete_and_stageable(self) -> None:
        first = self.work / "first.json"
        second = self.work / "second.json"
        self.command("generate", "--output", str(first))
        self.command("generate", "--output", str(second))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        manifest = json.loads(first.read_text())
        paths = {item["path"]: item for item in manifest["files"]}
        expected = {
            "cli/cmd/tool/main.go", "cli/cmd/tool/main_test.go", "cli/internal/value/value.go",
            "cli/internal/value/value_amd64.go", "cli/internal/value/value_arm64.go",
            "cli/internal/value/value_test.go", "cli/internal/value/parity_test.go", "cli/internal/value/data.txt",
            "cli/internal/value/testdata/vector.json", "cli/go.mod", "LICENSE",
            "LICENSES/runtime.txt", "cli/internal/testhelper/helper.go",
        }
        self.assertEqual(expected, set(paths))
        self.assertEqual(hashlib.sha256((self.root / "cli/internal/value/data.txt").read_bytes()).hexdigest(), paths["cli/internal/value/data.txt"]["sha256"])
        self.assertEqual("test-support-go", paths["cli/internal/testhelper/helper.go"]["role"])
        self.command("verify", "--manifest", str(first))
        stage = self.work / "stage"
        self.command("stage", "--manifest", str(first), "--output", str(stage))
        self.assertEqual((self.root / "cli/internal/value/data.txt").read_bytes(), (stage / "cli/internal/value/data.txt").read_bytes())
        env = os.environ.copy()
        env.update({"CGO_ENABLED": "0", "GOFLAGS": "-buildvcs=false", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOWORK": "off"})
        subprocess.run(["go", "test", "./...", "-count=1"], cwd=stage / "cli", env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.run(["go", "test", "-tags", "parityreview", "./...", "-count=1"], cwd=stage / "cli", env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for goarch in ("amd64", "arm64"):
            target_env = env.copy()
            target_env.update({"GOOS": "linux", "GOARCH": goarch, "GOAMD64": "v1", "GOARM64": "v8.0"})
            subprocess.run(["go", "build", "-o", str(self.work / f"tool-linux-{goarch}"), "./cmd/tool"], cwd=stage / "cli", env=target_env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_source_change_invalidates_manifest(self) -> None:
        manifest = self.work / "manifest.json"
        self.command("generate", "--output", str(manifest))
        (self.root / "cli/internal/value/data.txt").write_text("changed\n", encoding="utf-8")
        result = self.command("verify", "--manifest", str(manifest), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("manifest differs", result.stderr)

    def test_untested_production_package_is_rejected(self) -> None:
        (self.root / "cli/internal/value/value_test.go").unlink()
        (self.root / "cli/internal/value/parity_test.go").unlink()
        result = self.command("generate", "--output", str(self.work / "manifest.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("without direct tests", result.stderr)

    def test_symlink_and_private_key_material_are_rejected(self) -> None:
        (self.root / "LICENSE").unlink()
        (self.root / "LICENSE").symlink_to("LICENSES/runtime.txt")
        result = self.command("generate", "--output", str(self.work / "link.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("safely read", result.stderr)
        (self.root / "LICENSE").unlink()
        (self.root / "LICENSE").write_text("-----BEGIN " + "PRIVATE KEY-----\n", encoding="utf-8")
        result = self.command("generate", "--output", str(self.work / "key.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("private-key material", result.stderr)
        (self.root / "LICENSE").write_text("-----BEGIN ENCRYPTED " + "PRIVATE KEY-----\n", encoding="utf-8")
        result = self.command("generate", "--output", str(self.work / "encrypted-key.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("private-key material", result.stderr)

    def test_policy_symlink_is_rejected(self) -> None:
        policy_target = self.policy.with_name("policy-target.json")
        self.policy.rename(policy_target)
        self.policy.symlink_to(policy_target.name)
        result = self.command("generate", "--output", str(self.work / "manifest.json"), ok=False, timeout_seconds=PROMPT_REJECTION_TIMEOUT_SECONDS)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("policy must not be a symlink", result.stderr)

    def test_manifest_fifo_is_rejected_without_blocking(self) -> None:
        manifest = self.work / "manifest.pipe"
        os.mkfifo(manifest)
        self.assert_manifest_fifo_boundary(manifest)
        result = self.command("verify", "--manifest", str(manifest), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("bounded regular file", result.stderr)

    def test_manifest_cannot_be_written_inside_source(self) -> None:
        result = self.command("generate", "--output", str(self.root / "manifest.json"), ok=False, timeout_seconds=PROMPT_REJECTION_TIMEOUT_SECONDS)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("outside the source root", result.stderr)

    def test_fifo_is_rejected_without_blocking(self) -> None:
        fifo = self.root / "extra.pipe"
        os.mkfifo(fifo)
        policy = json.loads(self.policy.read_text())
        policy["requiredPaths"].append({"path": "extra.pipe", "role": "operator-data"})
        self.policy.write_text(json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        self.assert_source_fifo_boundary()
        result = self.command("generate", "--output", str(self.work / "fifo.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("not a single-link regular file", result.stderr)

    def test_noncanonical_source_mode_is_rejected(self) -> None:
        os.chmod(self.root / "LICENSE", 0o600)
        result = self.command("generate", "--output", str(self.work / "mode.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("0644 or 0755", result.stderr)

    def test_failed_command_reports_bounded_stdout_and_stderr(self) -> None:
        fake_go = self.work / "fake-go"
        fake_go.write_text("#!/bin/sh\nprintf 'fixture stdout\\n'\nprintf 'fixture stderr\\n' >&2\nexit 9\n", encoding="utf-8")
        fake_go.chmod(0o755)
        result = subprocess.run([
            sys.executable, str(GATE), "--source-root", str(self.root),
            "--policy", str(self.policy), "--go", str(fake_go),
            "generate", "--output", str(self.work / "manifest.json"),
        ], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=PROMPT_REJECTION_TIMEOUT_SECONDS)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("stdout tail:\nfixture stdout", result.stderr)
        self.assertIn("stderr tail:\nfixture stderr", result.stderr)

    def test_v2_vendored_module_is_exact_offline_and_tamper_evident(self) -> None:
        self.enable_v2_fixture()
        manifest = self.work / "v2.json"
        self.command("generate", "--output", str(manifest))
        value = json.loads(manifest.read_text())
        self.assertEqual("vendor", value["moduleMode"])
        self.assertEqual(["example.test/dependency"], [item["path"] for item in value["externalModules"]])
        self.assertEqual("sha256:" + hashlib.sha256(self.policy.read_bytes()).hexdigest(), value["policyDigest"])
        stage = self.work / "v2-stage"
        self.command("stage", "--manifest", str(manifest), "--output", str(stage))
        empty_cache = self.work / "empty-module-cache"
        empty_cache.mkdir()
        env = os.environ.copy()
        env.update({"GOMODCACHE": str(empty_cache), "GOPROXY": "off", "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "-mod=vendor -buildvcs=false"})
        subprocess.run(["go", "test", "./...", "-count=1"], cwd=stage / "cli", env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (self.root / "cli/vendor/example.test/dependency/value.go").write_text("package dependency\nfunc Text() string { return \"tampered\" }\n", encoding="utf-8")
        result = self.command("generate", "--output", str(self.work / "changed-vendor.json"), ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("vendor tree differs", result.stderr)

    def test_v2_rechecks_captured_vendor_and_policy_bytes(self) -> None:
        self.enable_v2_fixture()
        spec = importlib.util.spec_from_file_location("community_release_gate_under_test", GATE)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        original = gate.stable_read

        vendor_path = "cli/vendor/example.test/dependency/value.go"
        vendor_reads = 0

        def changed_vendor(root, relative, binary_allowed=False):
            nonlocal vendor_reads
            raw, mode = original(root, relative, binary_allowed)
            if relative == vendor_path:
                vendor_reads += 1
                if vendor_reads == 2:
                    return raw + b"// changed after validation\n", mode
            return raw, mode

        with mock.patch.object(gate, "stable_read", side_effect=changed_vendor):
            with self.assertRaisesRegex(gate.GateError, "captured vendor tree differs"):
                gate.derive(self.root.resolve(), self.policy.resolve(), "go")

        policy_reads = 0

        def changed_policy(root, relative, binary_allowed=False):
            nonlocal policy_reads
            raw, mode = original(root, relative, binary_allowed)
            if relative == "cli/release/policy.json":
                policy_reads += 1
                if policy_reads == 2:
                    return raw + b" ", mode
            return raw, mode

        with mock.patch.object(gate, "stable_read", side_effect=changed_policy):
            with self.assertRaisesRegex(gate.GateError, "captured shipping policy differs"):
                gate.derive(self.root.resolve(), self.policy.resolve(), "go")

    def test_capture_native_test_is_mandatory_for_a_complete_shipped_suite(self) -> None:
        spec = importlib.util.spec_from_file_location("community_release_gate_under_test", GATE)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        paths = sorted(
            gate.CAPTURE_NATIVE_TEST_PATHS
            | {gate.CAPTURE_EXAMPLE_PREFIX + "synthetic.json"}
            | {gate.CANDIDATE_RUNNER_PATH, gate.CANDIDATE_TEST_PATH}
        )
        manifest = {"files": [{"path": path} for path in paths]}
        self.assertIn(
            ["python3", "-B", "scripts/test_public_source_capture.py"],
            gate.native_script_commands(manifest),
        )
        with self.assertRaisesRegex(gate.GateError, "capture shipping requires"):
            gate.native_script_commands({"files": [
                {"path": gate.CANDIDATE_RUNNER_PATH},
                {"path": gate.CANDIDATE_TEST_PATH},
                {"path": gate.CAPTURE_NATIVE_TEST_PATHS.__iter__().__next__()},
            ]})

        with self.assertRaisesRegex(gate.GateError, "candidate runner and test"):
            gate.native_script_commands({"files": [{"path": paths[0]}]})

    def test_support_inventory_native_test_is_mandatory_for_complete_shipped_suite(self) -> None:
        spec = importlib.util.spec_from_file_location("community_release_gate_under_test", GATE)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        paths = sorted(
            gate.SUPPORT_INVENTORY_NATIVE_PATHS
            | {gate.CANDIDATE_RUNNER_PATH, gate.CANDIDATE_TEST_PATH}
        )
        manifest = {"files": [{"path": path} for path in paths]}
        self.assertIn(
            ["python3", "-B", "scripts/test_support_inventory.py"],
            gate.native_script_commands(manifest),
        )
        with self.assertRaisesRegex(gate.GateError, "support inventory shipping requires"):
            gate.native_script_commands({"files": [
                {"path": gate.CANDIDATE_RUNNER_PATH},
                {"path": gate.CANDIDATE_TEST_PATH},
                {"path": paths[0]},
            ]})

    def test_staging_receipt_helper_and_test_are_shipped_and_run_as_a_pair(self) -> None:
        spec = importlib.util.spec_from_file_location("community_release_gate_staging_receipt", GATE)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        paths = sorted(
            gate.STAGING_RECEIPT_NATIVE_PATHS
            | {gate.CANDIDATE_RUNNER_PATH, gate.CANDIDATE_TEST_PATH}
        )
        commands = gate.native_script_commands({"files": [{"path": path} for path in paths]})
        self.assertIn(
            ["python3", "-B", "-m", "unittest", "release/test_community_staging_receipt.py"],
            commands,
        )
        self.assertIn(
            ["python3", "-B", "-m", "unittest", "release/test_community_publisher_contract.py"],
            commands,
        )
        for missing in gate.STAGING_RECEIPT_NATIVE_PATHS:
            remaining = [path for path in paths if path != missing]
            with self.assertRaisesRegex(gate.GateError, "publisher shipping requires"):
                gate.native_script_commands({"files": [{"path": path} for path in remaining]})

    def test_offline_boundary_receipt_requires_observed_matrix(self) -> None:
        spec = importlib.util.spec_from_file_location("community_release_gate_receipt", GATE)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        receipt = {
            "apiVersion": "prufyx.io/offline-cli-boundary-receipt/v1",
            "status": "PASS",
            "platform": "linux",
            "observer": "strace -f trace=%network",
            "isolation": "fresh sudo -n unshare --net per command then setpriv to original fixture owner",
            "sudoUsedForNamespaceOnly": True,
            "namespaceUIDNonRoot": True,
            "namespaceUID": "1001",
            "namespaceGID": "1001",
            "fixtureMode": "0600",
            "socketPositiveControl": True,
            "positiveControlPerNamespace": True,
            "commands": ["help", "version", "check", "prepare", "cilium-prepare", "cilium-check", "db verify", "db import", "check --knowledge-db", "db status", "historical replay"],
            "networkSyscallsObserved": False,
            "explicitUpdateExcluded": True,
            "binaryDigest": "sha256:" + "a" * 64,
        }
        raw = gate.canonical_json(receipt)
        self.assertEqual(receipt, gate.validate_offline_boundary_receipt(raw))
        receipt_without_verify = dict(receipt)
        receipt_without_verify["commands"] = [command for command in receipt["commands"] if command != "db verify"]
        with self.assertRaisesRegex(gate.GateError, "required matrix"):
            gate.validate_offline_boundary_receipt(gate.canonical_json(receipt_without_verify))
        receipt["positiveControlPerNamespace"] = False
        with self.assertRaisesRegex(gate.GateError, "positiveControlPerNamespace"):
            gate.validate_offline_boundary_receipt(gate.canonical_json(receipt))
        receipt["unexpected"] = "must not be emitted"
        receipt["positiveControlPerNamespace"] = True
        with self.assertRaisesRegex(gate.GateError, "unexpected fields"):
            gate.validate_offline_boundary_receipt(gate.canonical_json(receipt))

    def test_v2_rejects_unknown_module_missing_notice_and_binary_drift(self) -> None:
        for case in ("unknown-module", "module-replacement", "missing-notice", "binary-drift", "extra-file", "removed-unused-source"):
            with self.subTest(case=case):
                self.tearDown()
                self.setUp()
                self.enable_v2_fixture()
                if case == "unknown-module":
                    path = self.root / "cli/vendor/modules.txt"
                    path.write_text(path.read_text() + "# example.test/unknown v1.0.0\n## explicit; go 1.26\n", encoding="utf-8")
                elif case == "module-replacement":
                    path = self.root / "cli/vendor/modules.txt"
                    path.write_text(path.read_text().replace("# example.test/dependency v1.0.0", "# example.test/dependency v1.0.0 => ./local"), encoding="utf-8")
                    self.refresh_vendor_tree_digest()
                elif case == "missing-notice":
                    (self.root / "LICENSES/dependency.txt").unlink()
                elif case == "binary-drift":
                    (self.root / "cli/vendor/example.test/dependency/data.bin").write_bytes(b"changed\x00binary\n")
                elif case == "extra-file":
                    (self.root / "cli/vendor/example.test/dependency/extra.go").write_text("package dependency\n", encoding="utf-8")
                else:
                    (self.root / "cli/vendor/example.test/dependency/unused_plan9.go").unlink()
                result = self.command("generate", "--output", str(self.work / f"{case}.json"), ok=False)
                self.assertNotEqual(0, result.returncode)
                self.assertTrue(any(text in result.stderr for text in ("vendor tree differs", "malformed module header", "inconsistent vendoring", "notice binding differs", "cannot safely read", "binary vendor resource differs")), result.stderr)


if __name__ == "__main__":
    unittest.main()
