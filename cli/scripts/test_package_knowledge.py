#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("package-knowledge.py")
spec = importlib.util.spec_from_file_location("package_knowledge", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class PackageKnowledgeTests(unittest.TestCase):
    def source(self, root: Path, profile: str = "cncf", target_data: bytes = b"signed-target") -> Path:
        (root / "metadata").mkdir(parents=True)
        (root / "targets" / "knowledge").mkdir(parents=True)
        for name, data in {
            "metadata/1.root.json": b"signed-root",
            "metadata/1.snapshot.json": b"signed-snapshot",
            "metadata/1.targets.json": b"signed-targets",
            "metadata/timestamp.json": b"signed-timestamp",
        }.items():
            path = root / name
            path.write_bytes(data)
            path.chmod(0o644)
        digest = hashlib.sha256(target_data).hexdigest()
        target = root / "targets" / "knowledge" / f"{digest}.{module.TARGET_SUFFIX[profile]}"
        target.write_bytes(target_data)
        target.chmod(0o644)
        return root

    def test_canonical_ustar_and_profile_suffixes(self):
        with tempfile.TemporaryDirectory() as temp:
            for profile in module.TARGET_SUFFIX:
                source = self.source(Path(temp) / profile, profile)
                raw = module.package_directory(source, profile)
                self.assertEqual(raw, module.package_directory(source, profile))
                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
                    members = archive.getmembers()
                    self.assertEqual([m.name for m in members], sorted(m.name for m in members))
                    self.assertEqual(len(members), 5)
                    for member in members:
                        self.assertEqual(member.mode, 0o644)
                        self.assertEqual(member.uid, 0)
                        self.assertEqual(member.gid, 0)
                        self.assertEqual(member.uname, "")
                        self.assertEqual(member.gname, "")
                        self.assertEqual(member.mtime, 0)
                        self.assertTrue(member.isreg())

    def test_rejects_profile_mismatch_hash_and_unknown_tree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "source", "cncf")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cert-manager")
            target = next((source / "targets" / "knowledge").iterdir())
            target.rename(target.with_name("0" * 64 + ".constraints.v1.json"))
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")
            source = self.source(root / "unknown", "cncf")
            (source / "metadata" / "nested").mkdir()
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")
            (source / "metadata" / "nested").rmdir()
            (source / "unexpected.txt").write_bytes(b"x")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

    def test_rejects_links_and_boundary_sizes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "symlink", "cncf")
            source_file = source / "metadata" / "1.root.json"
            source_file.unlink()
            source_file.symlink_to("1.snapshot.json")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

            source = self.source(root / "hardlink", "cncf")
            os.link(source / "metadata/1.root.json", source / "metadata/2.root.json")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

            source = self.source(root / "entry", "cncf")
            (source / "metadata/1.root.json").write_bytes(b"x" * (module.MAX_PACKAGE_ENTRY + 1))
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

            source = self.source(root / "total", "cncf")
            for name in ["metadata/1.root.json", "metadata/1.snapshot.json", "metadata/1.targets.json"]:
                (source / name).write_bytes(b"x" * 700_000)
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

            source = self.source(root / "count", "cncf")
            for version in range(2, 14):
                (source / f"metadata/{version}.root.json").write_bytes(b"x")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

    def test_rejects_incomplete_and_target_mismatch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "missing", "cncf")
            (source / "metadata/timestamp.json").unlink()
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")
            source = self.source(root / "target", "cncf")
            target = next((source / "targets/knowledge").iterdir())
            target.write_bytes(b"changed")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

    def test_rejects_fifo_and_replaced_input_members(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "fifo", "cncf")
            fifo = source / "metadata/1.root.json"
            fifo.unlink()
            try:
                os.mkfifo(fifo)
            except (AttributeError, NotImplementedError):
                self.skipTest("FIFO creation unavailable")
            with self.assertRaises(module.PackageError):
                module.package_directory(source, "cncf")

            source = self.source(root / "replaced", "cncf")
            member = source / "metadata/1.root.json"
            original = member.read_bytes()
            info = member.lstat()
            replacement = member.with_name("replacement")
            replacement.write_bytes(original)
            replacement.replace(member)
            with self.assertRaises(module.PackageError):
                module._safe_read(member, len(original), info)

    def test_rejects_same_size_in_place_mutation_during_read(self):
        if not hasattr(os, "pwrite"):
            self.skipTest("pwrite unavailable")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "mutated", "cncf")
            original_read = module.os.read
            original_walk = module.os.walk
            writer_fd = os.open(source / "metadata/1.root.json", os.O_WRONLY)
            changed = False

            def mutating_read(fd, size):
                nonlocal changed
                data = original_read(fd, size)
                if data and not changed:
                    changed = True
                    os.pwrite(writer_fd, b"M" * len(data), 0)
                return data

            module.os.read = mutating_read

            def ordered_walk(*args, **kwargs):
                for current, directories, files in original_walk(*args, **kwargs):
                    yield current, directories, sorted(files)

            module.os.walk = ordered_walk
            try:
                with self.assertRaises(module.PackageError):
                    module.package_directory(source, "cncf")
            finally:
                module.os.read = original_read
                module.os.walk = original_walk
                os.close(writer_fd)
            self.assertTrue(changed)

    def test_enumeration_errors_are_sanitized(self):
        with tempfile.TemporaryDirectory() as temp:
            source = self.source(Path(temp) / "source", "cncf")
            original_walk = module.os.walk

            def failing_walk(*args, **kwargs):
                kwargs["onerror"](OSError("permission denied"))
                return iter(())

            module.os.walk = failing_walk
            try:
                with self.assertRaises(module.PackageError):
                    module.package_directory(source, "cncf")
            finally:
                module.os.walk = original_walk

    def test_requires_private_output_parent_and_rejects_output_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "source", "cncf")
            public_parent = root / "public"
            public_parent.mkdir(mode=0o755)
            public_parent.chmod(0o755)
            with self.assertRaises(module.PackageError):
                module.write_package(source, public_parent / "out.tar", "cncf")
            self.assertFalse((public_parent / "out.tar").exists())

            destination = root / "out-link.tar"
            sentinel = root / "sentinel"
            sentinel.write_bytes(b"keep")
            destination.symlink_to(sentinel)
            with self.assertRaises(module.PackageError):
                module.write_package(source, destination, "cncf")
            self.assertEqual(sentinel.read_bytes(), b"keep")

    def test_cli_sanitizes_os_errors(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            missing = root / "PACKAGE_PATH_CANARY"
            destination = root / "out.tar"
            result = subprocess.run(
                [sys.executable, str(SCRIPT), "--profile", "cncf", "--input", str(missing), "--output", str(destination)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr.strip(), "package-knowledge: packaging rejected")
            self.assertNotIn("PACKAGE_PATH_CANARY", result.stderr)
            self.assertNotIn("Traceback", result.stderr)

    def test_writes_new_output_private(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "source", "cncf")
            destination = root / "out.tar"
            module.write_package(source, destination, "cncf")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)
            self.assertEqual(destination.read_bytes(), module.package_directory(source, "cncf"))

    def test_refuses_overwrite_and_keeps_existing_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.source(root / "source", "cncf")
            destination = root / "out.tar"
            destination.write_bytes(b"keep")
            destination.chmod(0o600)
            with self.assertRaises(module.PackageError):
                module.write_package(source, destination, "cncf")
            self.assertEqual(destination.read_bytes(), b"keep")
            self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o600)

    def test_go_fixture_byte_parity_and_import_when_available(self):
        go = os.environ.get("PRUFYX_GO") or shutil.which("go")
        if not go:
            self.skipTest("Go toolchain unavailable")
        cli = Path(__file__).parents[1]
        env = os.environ.copy()
        env.update({"GOTOOLCHAIN": "local", "GOWORK": "off", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "-mod=vendor -buildvcs=false"})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for profile in ("cert-manager", "cncf", "spiffe-x509-svid", "cloudevents-structured-json", "tikv-gcp-v2-wif-backup"):
                fixture = root / f"fixture-{profile}"
                subprocess.run([go, "run", "./examples/community/knowledge/generate-synthetic-packages.go", "--output", str(fixture), "--profile", profile], cwd=cli, env=env, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
                package_path = fixture / "synthetic-revision-2.tar"
                unpacked = root / f"unpacked-{profile}"
                unpacked.mkdir()
                with tarfile.open(package_path, "r:") as archive:
                    for member in archive.getmembers():
                        self.assertTrue(member.isfile())
                        destination = unpacked / member.name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(archive.extractfile(member).read())
                assembled = root / f"assembled-{profile}.tar"
                module.write_package(unpacked, assembled, profile)
                self.assertEqual(module.package_directory(unpacked, profile), package_path.read_bytes())
                self.assertEqual(assembled.read_bytes(), package_path.read_bytes())
                manifest = json.loads((fixture / "synthetic-manifest.json").read_bytes())
                output = root / f"imported-{profile}"
                command = [go, "run", "./cmd/prufyx-community", "db", "import", str(assembled), "--profile", profile, "--db-root", str(output), "--bootstrap-root", str(fixture / "synthetic-root.json"), "--bootstrap-root-digest", manifest["bootstrapRoot"]["digest"], "--format", "json"]
                result = subprocess.run(command, cwd=cli, env=env, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
                self.assertEqual(result.returncode, 0, result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
