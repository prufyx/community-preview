#!/usr/bin/env python3
"""Derive, verify, and stage the exact Prufyx Community source boundary.

The policy is the sole human-maintained shipping authority. The manifest is a
content-addressed receipt derived from Go package metadata and explicit public
non-Go inputs; it is never a second allowlist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable

SCHEMA_V1 = "prufyx.io/community-shipping-policy/v1"
SCHEMA_V2 = "prufyx.io/community-shipping-policy/v2"
MANIFEST_SCHEMA = "prufyx.io/community-source-manifest/v1"
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 16 * 1024
GO_SOURCE_FIELDS = (
    "GoFiles", "CgoFiles", "CFiles", "CXXFiles", "MFiles", "HFiles",
    "FFiles", "SFiles", "SwigFiles", "SwigCXXFiles", "SysoFiles",
)
TEST_SOURCE_FIELDS = ("TestGoFiles", "XTestGoFiles")
PRIVATE_KEY_RE = re.compile(br"-----BEGIN (?:[A-Z0-9][A-Z0-9 -]{0,64} )?PRIVATE KEY(?: BLOCK)?-----")
CAPTURE_NATIVE_TEST_PATHS = frozenset({
    "cli/scripts/public_source_capture.py",
    "cli/scripts/test_public_source_capture.py",
    "cli/docs/public-source-capture.md",
})
CAPTURE_EXAMPLE_PREFIX = "cli/examples/capture/"
SUPPORT_INVENTORY_NATIVE_PATHS = frozenset({
    "cli/docs/community-support-inventory.md",
    "cli/docs/data/selected-source-records-v1.json",
    "cli/docs/generated/community-support-inventory.json",
    "cli/docs/generated/community-support-inventory.md",
    "cli/scripts/generate_support_inventory.py",
    "cli/scripts/import_selected_source_records.py",
    "cli/scripts/test_support_inventory.py",
})
CANDIDATE_RUNNER_PATH = "cli/scripts/check_contribution_candidates.py"
CANDIDATE_TEST_PATH = "cli/scripts/test_contribution_candidates.py"
STAGING_RECEIPT_NATIVE_PATHS = frozenset({
    ".github/workflows/community-publish.yml",
    "cli/release/community-staging-receipt.py",
    "cli/release/test_community_staging_receipt.py",
    "cli/release/test_community_publisher_contract.py",
})


class GateError(Exception):
    pass


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GateError(f"cannot parse JSON {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"JSON object required: {label}")
    return value


def load_external_json(path: Path) -> tuple[dict[str, Any], bytes]:
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE_BYTES:
                raise GateError(f"manifest must be a bounded regular file: {path}")
            raw = b""
            while len(raw) <= MAX_FILE_BYTES:
                chunk = os.read(fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            after = os.fstat(fd)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
            if len(raw) != before.st_size or len(raw) > MAX_FILE_BYTES or identity(before) != identity(after):
                raise GateError(f"manifest changed while being read or exceeds its bound: {path}")
        finally:
            os.close(fd)
    except OSError as exc:
        raise GateError(f"cannot safely read manifest {path}: {exc}") from exc
    return parse_json(raw, str(path)), raw


def safe_relative(raw: str, label: str) -> str:
    if not isinstance(raw, str) or not raw or "\\" in raw or not raw.isascii():
        raise GateError(f"{label} must be a non-empty ASCII POSIX path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise GateError(f"unsafe {label}: {raw}")
    return path.as_posix()


def validate_policy(value: dict[str, Any]) -> dict[str, Any]:
    base = {
        "schemaVersion", "moduleRoot", "entrypoints", "binaryName",
        "buildTargets", "requiredGoVersion", "allowExternalModules",
        "requiredPaths", "sourceBuildTargets", "testPolicy",
        "toolchainArchives",
    }
    schema = value.get("schemaVersion")
    required = base if schema == SCHEMA_V1 else base | {"vendorRoot", "vendorTreeDigest", "externalModules", "binaryResources"}
    if schema not in (SCHEMA_V1, SCHEMA_V2) or set(value) != required:
        raise GateError("shipping policy has an unknown field, missing field, or schema")
    value["moduleRoot"] = safe_relative(value["moduleRoot"], "moduleRoot")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value.get("binaryName", "")):
        raise GateError("invalid binaryName")
    if not re.fullmatch(r"go[0-9]+\.[0-9]+\.[0-9]+", value.get("requiredGoVersion", "")):
        raise GateError("requiredGoVersion must pin a patch release")
    if schema == SCHEMA_V1 and value.get("allowExternalModules") is not False:
        raise GateError("Community v1 must reject external Go modules")
    if schema == SCHEMA_V2 and value.get("allowExternalModules") is not True:
        raise GateError("Community v2 requires its exact external module profile")
    entries = value.get("entrypoints")
    if not isinstance(entries, list) or not entries:
        raise GateError("entrypoints must be a non-empty list")
    for entry in entries:
        if not isinstance(entry, str) or not re.fullmatch(r"\./(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+", entry):
            raise GateError(f"invalid entrypoint: {entry!r}")
    if value.get("buildTargets") != ["linux/amd64", "linux/arm64"]:
        raise GateError("Community v1 buildTargets must be exactly linux/amd64 and linux/arm64")
    if value.get("sourceBuildTargets") != ["linux/amd64", "linux/arm64", "darwin/arm64"]:
        raise GateError("Community v1 sourceBuildTargets must be Linux release tuples plus darwin/arm64")
    archives = value.get("toolchainArchives")
    if not isinstance(archives, dict) or set(archives) != set(value["sourceBuildTargets"]):
        raise GateError("toolchainArchives must cover every source-build tuple exactly")
    if any(not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) for digest in archives.values()):
        raise GateError("toolchainArchives values must be lowercase SHA-256 digests")
    required_paths = value.get("requiredPaths")
    if not isinstance(required_paths, list) or not required_paths:
        raise GateError("requiredPaths must be a non-empty list")
    seen: set[str] = set()
    for item in required_paths:
        if not isinstance(item, dict) or set(item) - {"path", "role", "recursive"}:
            raise GateError("requiredPaths entries have a closed schema")
        path = safe_relative(item.get("path"), "required path")
        if path in seen:
            raise GateError(f"duplicate required path: {path}")
        seen.add(path)
        if not re.fullmatch(r"[a-z][a-z0-9-]*", item.get("role", "")):
            raise GateError(f"invalid role for {path}")
        if "recursive" in item and item["recursive"] is not True:
            raise GateError(f"recursive must be true when present: {path}")
    if value.get("testPolicy") != {"requireDirectTestsForProductionPackages": True, "testTags": ["parityreview"]}:
        raise GateError("Community policy requires direct tests and the parityreview test tag")
    if schema == SCHEMA_V2:
        value["vendorRoot"] = safe_relative(value.get("vendorRoot"), "vendorRoot")
        if value["vendorRoot"] != f'{value["moduleRoot"]}/vendor':
            raise GateError("Community v2 vendorRoot must be the module vendor directory")
        if not isinstance(value.get("vendorTreeDigest"), str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["vendorTreeDigest"]):
            raise GateError("Community v2 vendorTreeDigest must bind the exact vendor tree")
        modules = value.get("externalModules")
        if not isinstance(modules, list) or not modules:
            raise GateError("Community v2 externalModules must be a non-empty exact profile")
        module_paths: list[str] = []
        notice_destinations: set[str] = set()
        for module in modules:
            if not isinstance(module, dict) or set(module) != {"path", "version", "moduleSum", "goModSum", "licenseDeclared", "notices"}:
                raise GateError("external module entries have a closed schema")
            path = module.get("path")
            version = module.get("version")
            if not isinstance(path, str) or not re.fullmatch(r"[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~+-]+)+", path):
                raise GateError("invalid external module path")
            if not isinstance(version, str) or not re.fullmatch(r"v[0-9][0-9A-Za-z.+-]*", version):
                raise GateError(f"invalid external module version: {path}")
            for field in ("moduleSum", "goModSum"):
                if not isinstance(module.get(field), str) or not re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", module[field]):
                    raise GateError(f"invalid {field}: {path}")
            if not isinstance(module.get("licenseDeclared"), str) or not re.fullmatch(r"[A-Za-z0-9.-]+", module["licenseDeclared"]):
                raise GateError(f"invalid declared license: {path}")
            notices = module.get("notices")
            if not isinstance(notices, list) or not notices:
                raise GateError(f"external module has no distribution notice: {path}")
            for notice in notices:
                if not isinstance(notice, dict) or set(notice) != {"sourcePath", "distributionPath", "sha256"}:
                    raise GateError("external module notice entries have a closed schema")
                source = safe_relative(notice.get("sourcePath"), "vendor notice source")
                destination = safe_relative(notice.get("distributionPath"), "distribution notice")
                if not source.startswith(value["vendorRoot"] + "/") or not destination.startswith("LICENSES/"):
                    raise GateError("external module notices must bind vendor bytes to LICENSES")
                if not re.fullmatch(r"[0-9a-f]{64}", notice.get("sha256", "")):
                    raise GateError("external module notice digest must be SHA-256")
                if destination in notice_destinations:
                    raise GateError(f"duplicate distribution notice: {destination}")
                notice_destinations.add(destination)
                notice["sourcePath"] = source
                notice["distributionPath"] = destination
            module_paths.append(path)
        if module_paths != sorted(set(module_paths)):
            raise GateError("external modules must be unique and sorted by path")
        resources = value.get("binaryResources")
        if not isinstance(resources, list) or not resources:
            raise GateError("Community v2 binaryResources must explicitly identify each binary vendor input")
        resource_paths: list[str] = []
        for resource in resources:
            if not isinstance(resource, dict) or set(resource) != {"path", "sha256"}:
                raise GateError("binary resource entries have a closed schema")
            path = safe_relative(resource.get("path"), "binary resource")
            if not path.startswith(value["vendorRoot"] + "/") or not re.fullmatch(r"[0-9a-f]{64}", resource.get("sha256", "")):
                raise GateError("binary resource must be an exact vendored SHA-256 binding")
            resource["path"] = path
            resource_paths.append(path)
        if resource_paths != sorted(set(resource_paths)):
            raise GateError("binary resources must be unique and sorted")
    return value


def go_env(extra: dict[str, str] | None = None, vendor: bool = False) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("GOOS", None)
    env.pop("GOARCH", None)
    env.update({
        "CGO_ENABLED": "0", "GOFLAGS": ("-mod=vendor " if vendor else "") + "-buildvcs=false", "GOEXPERIMENT": "",
        "GOAMD64": "v1", "GOARM64": "v8.0", "GOPROXY": "off",
        "GOSUMDB": "off", "GOTOOLCHAIN": "local", "GOWORK": "off",
    })
    if extra:
        env.update(extra)
    return env


def command_detail(stdout: bytes, stderr: bytes) -> str:
    parts = []
    for label, raw in (("stdout", stdout), ("stderr", stderr)):
        if raw:
            parts.append(f"{label} tail:\n" + raw[-MAX_DIAGNOSTIC_BYTES:].decode("utf-8", "replace").strip())
    return "\n".join(parts) if parts else "no command output"


def run(go: str, args: list[str], cwd: Path, env: dict[str, str]) -> bytes:
    try:
        completed = subprocess.run([go, *args], cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as exc:
        raise GateError(f"cannot execute Go toolchain: {exc}") from exc
    if completed.returncode:
        raise GateError(f"{' '.join([go, *args])} failed:\n{command_detail(completed.stdout, completed.stderr)}")
    return completed.stdout


def decode_stream(raw: bytes) -> list[dict[str, Any]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateError("go list returned non-UTF-8 output") from exc
    decoder = json.JSONDecoder(object_pairs_hook=reject_duplicates)
    values: list[dict[str, Any]] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, dict):
            raise GateError("go list stream contains a non-object")
        values.append(value)
    return values


def package_in_module(pkg: dict[str, Any], module_path: str) -> bool:
    module = pkg.get("Module")
    return isinstance(module, dict) and module.get("Path") == module_path


def package_files(pkg: dict[str, Any], fields: Iterable[str]) -> list[str]:
    names: list[str] = []
    for field in fields:
        values = pkg.get(field, [])
        if not isinstance(values, list) or any(not isinstance(v, str) for v in values):
            raise GateError(f"go list returned invalid {field} for {pkg.get('ImportPath')}")
        names.extend(values)
    return names


def relative_to_root(source_root: Path, path: Path, label: str) -> str:
    try:
        return path.relative_to(source_root).as_posix()
    except ValueError as exc:
        raise GateError(f"{label} is outside source root: {path}") from exc


def add_file(files: dict[str, str], path: str, role: str) -> None:
    prior = files.get(path)
    priorities = {"production-go": 100, "production-embed": 95, "test-go": 90, "test-support-go": 85, "test-support-embed": 84, "testdata": 80, "module": 75}
    if prior is None or priorities.get(role, 10) > priorities.get(prior, 10):
        files[path] = role


def merge_package(target: dict[str, dict[str, Any]], pkg: dict[str, Any], fields: Iterable[str]) -> None:
    import_path = pkg["ImportPath"]
    current = target.setdefault(import_path, pkg.copy())
    for field in fields:
        current[field] = sorted(set(current.get(field, [])) | set(pkg.get(field, [])))


def validate_module_sums_bytes(raw: bytes, policy: dict[str, Any]) -> None:
    sums: dict[tuple[str, str], str] = {}
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError("go.sum must be UTF-8") from exc
    for line in lines:
        fields = line.split(" ")
        if len(fields) != 3 or not all(fields):
            raise GateError("go.sum contains a non-canonical line")
        key = (fields[0], fields[1])
        if key in sums:
            raise GateError("go.sum contains a duplicate module identity")
        sums[key] = fields[2]
    for module in policy["externalModules"]:
        version = module["version"]
        if sums.get((module["path"], version)) != module["moduleSum"] or sums.get((module["path"], version + "/go.mod")) != module["goModSum"]:
            raise GateError(f'external module checksums differ from policy: {module["path"]}')


def validate_module_sums(source_root: Path, policy: dict[str, Any]) -> None:
    raw, _ = stable_read(source_root, f'{policy["moduleRoot"]}/go.sum')
    validate_module_sums_bytes(raw, policy)


def vendored_modules_bytes(raw: bytes) -> list[str]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise GateError("vendor/modules.txt must be UTF-8") from exc
    result: list[str] = []
    for line in lines:
        if not line.startswith("# "):
            continue
        match = re.fullmatch(r"# ([^ ]+) (v[^ ]+)", line)
        if match is None:
            raise GateError("vendor/modules.txt contains a replacement or malformed module header")
        result.append(f"{match.group(1)} {match.group(2)}")
    if not result:
        raise GateError("vendor/modules.txt contains no module profile")
    return result


def vendored_modules(source_root: Path, policy: dict[str, Any]) -> list[str]:
    raw, _ = stable_read(source_root, f'{policy["vendorRoot"]}/modules.txt')
    return vendored_modules_bytes(raw)


def vendor_tree_digest(entries: list[dict[str, Any]], blobs: dict[str, bytes], vendor_root: str) -> str:
    prefix = vendor_root + "/"
    captured = []
    for entry in entries:
        path = entry["path"]
        if path.startswith(prefix):
            raw = blobs[path]
            captured.append({
                "mode": entry["mode"], "path": path,
                "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
            })
    captured.sort(key=lambda item: PurePosixPath(item["path"]).parts)
    return "sha256:" + hashlib.sha256(canonical_json(captured)).hexdigest()


def validate_vendor_tree(source_root: Path, policy: dict[str, Any]) -> None:
    vendor = source_root / policy["vendorRoot"]
    if not vendor.is_dir() or vendor.is_symlink():
        raise GateError("Community v2 vendor root is missing or unsafe")
    binary_resources = {item["path"]: item["sha256"] for item in policy["binaryResources"]}
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for candidate in sorted(vendor.rglob("*")):
        if candidate.is_symlink() or (candidate.exists() and not candidate.is_dir() and not candidate.is_file()):
            raise GateError(f"vendor tree contains a non-regular entry: {candidate}")
        if candidate.is_dir():
            continue
        relative = relative_to_root(source_root, candidate, "vendor file")
        raw, mode = stable_read(source_root, relative, binary_allowed=True)
        if b"\x00" in raw and relative not in binary_resources:
            raise GateError(f"unreviewed binary content in vendor tree: {relative}")
        digest = hashlib.sha256(raw).hexdigest()
        if relative in binary_resources and digest != binary_resources[relative]:
            raise GateError(f"binary vendor resource differs from policy: {relative}")
        seen.add(relative)
        entries.append({"mode": f"{mode:04o}", "path": relative, "sha256": digest, "size": len(raw)})
    if not set(binary_resources).issubset(seen):
        raise GateError("binary vendor resource is absent from the exact vendor tree")
    actual = "sha256:" + hashlib.sha256(canonical_json(entries)).hexdigest()
    if actual != policy["vendorTreeDigest"]:
        raise GateError("vendor tree differs from the exact Community v2 policy")


def collect(source_root: Path, policy: dict[str, Any], go: str) -> tuple[dict[str, str], list[dict[str, Any]]]:
    module_root = source_root / policy["moduleRoot"]
    if not module_root.is_dir() or module_root.is_symlink():
        raise GateError(f"module root is missing or unsafe: {module_root}")
    vendor_mode = policy["schemaVersion"] == SCHEMA_V2
    env = go_env(vendor=vendor_mode)
    version = run(go, ["env", "GOVERSION"], module_root, env).decode().strip()
    if version != policy["requiredGoVersion"]:
        raise GateError(f"Go toolchain must be {policy['requiredGoVersion']}, found {version}")
    module_flag = "-mod=vendor" if vendor_mode else "-mod=readonly"
    if vendor_mode:
        module_line = run(go, ["list", module_flag, "-m"], module_root, env).decode().strip()
        modules = [module_line, *vendored_modules(source_root, policy)]
    else:
        modules = run(go, ["list", module_flag, "-m", "all"], module_root, env).decode().splitlines()
    if len(modules) != 1 and not policy["allowExternalModules"]:
        raise GateError("Community source closure contains an external Go module")
    module_path = modules[0].split()[0]
    if vendor_mode:
        expected_modules = [f'{item["path"]} {item["version"]}' for item in policy["externalModules"]]
        if modules[1:] != expected_modules:
            raise GateError("vendored Go module closure differs from the exact Community v2 profile")
        validate_module_sums(source_root, policy)
    production: dict[str, dict[str, Any]] = {}
    for target in policy["sourceBuildTargets"]:
        goos, goarch = target.split("/", 1)
        stream = decode_stream(run(go, ["list", "-json", "-deps", *policy["entrypoints"]], module_root, go_env({"GOOS": goos, "GOARCH": goarch}, vendor=vendor_mode)))
        for pkg in stream:
            if package_in_module(pkg, module_path):
                merge_package(production, pkg, GO_SOURCE_FIELDS + ("EmbedFiles",))
    if not production:
        raise GateError("entrypoint produced no in-module Go package closure")

    test_packages: dict[str, dict[str, Any]] = {}
    test_support: dict[str, dict[str, Any]] = {}
    imports = sorted(production)
    test_variants: list[list[str]] = [[]]
    test_variants.extend([["-tags", tag] for tag in policy["testPolicy"]["testTags"]])
    for target in policy["sourceBuildTargets"]:
        goos, goarch = target.split("/", 1)
        for variant in test_variants:
            stream = decode_stream(run(go, ["list", "-json", "-deps", "-test", *variant, *imports], module_root, go_env({"GOOS": goos, "GOARCH": goarch}, vendor=vendor_mode)))
            for pkg in stream:
                import_path = pkg.get("ImportPath", "")
                if not package_in_module(pkg, module_path) or " [" in import_path or import_path.endswith(".test"):
                    continue
                if import_path in production:
                    merge_package(test_packages, pkg, TEST_SOURCE_FIELDS + ("TestEmbedFiles", "XTestEmbedFiles"))
                elif not pkg.get("ForTest"):
                    merge_package(test_support, pkg, GO_SOURCE_FIELDS + ("EmbedFiles",))

    files: dict[str, str] = {}
    package_receipts: list[dict[str, Any]] = []
    missing_tests: list[str] = []
    for import_path, pkg in sorted(production.items()):
        directory = Path(pkg["Dir"])
        rel_dir = relative_to_root(source_root, directory, f"package {import_path}")
        for name in package_files(pkg, GO_SOURCE_FIELDS):
            add_file(files, f"{rel_dir}/{name}", "production-go")
        for name in package_files(pkg, ("EmbedFiles",)):
            add_file(files, relative_to_root(source_root, directory / name, "embedded production input"), "production-embed")
        test_pkg = test_packages.get(import_path, {})
        tests = sorted(set(package_files(test_pkg, TEST_SOURCE_FIELDS)))
        for name in tests:
            add_file(files, f"{rel_dir}/{name}", "test-go")
        for name in package_files(test_pkg, ("TestEmbedFiles", "XTestEmbedFiles")):
            add_file(files, relative_to_root(source_root, directory / name, "embedded test input"), "testdata")
        testdata = directory / "testdata"
        if testdata.exists():
            if not testdata.is_dir() or testdata.is_symlink():
                raise GateError(f"unsafe testdata directory: {testdata}")
            for candidate in sorted(testdata.rglob("*")):
                if candidate.is_file() and not candidate.is_symlink():
                    add_file(files, relative_to_root(source_root, candidate, "testdata"), "testdata")
                elif candidate.is_symlink() or (candidate.exists() and not candidate.is_dir()):
                    raise GateError(f"testdata contains a non-regular entry: {candidate}")
        if not tests:
            missing_tests.append(import_path)
        package_receipts.append({"importPath": import_path, "name": pkg.get("Name"), "path": rel_dir, "directTests": tests})
    if missing_tests:
        raise GateError("production packages without direct tests: " + ", ".join(missing_tests))

    for import_path, pkg in sorted(test_support.items()):
        directory = Path(pkg["Dir"])
        rel_dir = relative_to_root(source_root, directory, f"test dependency {import_path}")
        for name in package_files(pkg, GO_SOURCE_FIELDS):
            add_file(files, f"{rel_dir}/{name}", "test-support-go")
        for name in package_files(pkg, ("EmbedFiles",)):
            add_file(files, relative_to_root(source_root, directory / name, "embedded test dependency input"), "test-support-embed")

    for module_file in (module_root / "go.mod", module_root / "go.sum"):
        if module_file.exists():
            add_file(files, relative_to_root(source_root, module_file, "module file"), "module")
    for item in policy["requiredPaths"]:
        candidate = source_root / item["path"]
        if item.get("recursive"):
            if not candidate.is_dir() or candidate.is_symlink():
                raise GateError(f"required directory is missing or unsafe: {item['path']}")
            for child in sorted(candidate.rglob("*")):
                if child.is_file() and not child.is_symlink():
                    add_file(files, relative_to_root(source_root, child, "required file"), item["role"])
                elif child.is_symlink() or (child.exists() and not child.is_dir()):
                    raise GateError(f"required directory contains a non-regular entry: {child}")
        else:
            add_file(files, item["path"], item["role"])
    return files, package_receipts


def stable_read(root: Path, relative: str, binary_allowed: bool = False) -> tuple[bytes, int]:
    parts = PurePosixPath(safe_relative(relative, "manifest path")).parts
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise GateError("O_NOFOLLOW is required")
    root_fd = os.open(root, flags | os.O_DIRECTORY)
    parent_fd = root_fd
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags | os.O_DIRECTORY | nofollow, dir_fd=parent_fd)
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(parts[-1], flags | nofollow, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise GateError(f"selected source is not a single-link regular file: {relative}")
            mode = stat.S_IMODE(before.st_mode)
            if mode not in (0o644, 0o755):
                raise GateError(f"selected source mode must be 0644 or 0755: {relative}")
            if before.st_size > MAX_FILE_BYTES:
                raise GateError(f"selected source exceeds size bound: {relative}")
            raw = b""
            while len(raw) <= MAX_FILE_BYTES:
                chunk = os.read(fd, min(1024 * 1024, MAX_FILE_BYTES + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            after = os.fstat(fd)
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns)
            if len(raw) > MAX_FILE_BYTES or identity(before) != identity(after):
                raise GateError(f"selected source changed while being read: {relative}")
            if b"\x00" in raw and not binary_allowed:
                raise GateError(f"binary content is outside the Community source policy: {relative}")
            if PRIVATE_KEY_RE.search(raw):
                raise GateError(f"private-key material is forbidden in Community source: {relative}")
            return raw, mode
        finally:
            os.close(fd)
    except OSError as exc:
        raise GateError(f"cannot safely read selected source {relative}: {exc}") from exc
    finally:
        if parent_fd != root_fd:
            os.close(parent_fd)
        os.close(root_fd)


def derive(source_root: Path, policy_path: Path, go: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        policy_relative = policy_path.relative_to(source_root).as_posix()
    except ValueError as exc:
        raise GateError("shipping policy must be inside the source root") from exc
    policy_raw, _ = stable_read(source_root, policy_relative)
    policy_value = parse_json(policy_raw, policy_relative)
    policy = validate_policy(policy_value)
    if policy["schemaVersion"] == SCHEMA_V2:
        validate_vendor_tree(source_root, policy)
    files, packages = collect(source_root, policy, go)
    binary_resources = {item["path"]: item["sha256"] for item in policy.get("binaryResources", [])}
    blobs: dict[str, bytes] = {}
    entries = []
    total = 0
    for path, role in sorted(files.items()):
        raw, mode = stable_read(source_root, path, path in binary_resources)
        if path in binary_resources and hashlib.sha256(raw).hexdigest() != binary_resources[path]:
            raise GateError(f"binary vendor resource differs from policy: {path}")
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise GateError("selected Community source exceeds total size bound")
        blobs[path] = raw
        entries.append({"mode": f"{mode:04o}", "path": path, "role": role, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)})
    if policy["schemaVersion"] == SCHEMA_V2:
        if blobs.get(policy_relative) != policy_raw:
            raise GateError("captured shipping policy differs from the policy used for derivation")
        if vendor_tree_digest(entries, blobs, policy["vendorRoot"]) != policy["vendorTreeDigest"]:
            raise GateError("captured vendor tree differs from the exact Community v2 policy")
        expected_modules = [f'{item["path"]} {item["version"]}' for item in policy["externalModules"]]
        captured_modules = vendored_modules_bytes(blobs[f'{policy["vendorRoot"]}/modules.txt'])
        if captured_modules != expected_modules:
            raise GateError("captured vendored Go module closure differs from the exact Community v2 profile")
        validate_module_sums_bytes(blobs[f'{policy["moduleRoot"]}/go.sum'], policy)
    manifest: dict[str, Any] = {
        "schemaVersion": MANIFEST_SCHEMA, "binaryName": policy["binaryName"],
        "buildTargets": policy["buildTargets"], "sourceBuildTargets": policy["sourceBuildTargets"],
        "entrypoints": policy["entrypoints"], "testTags": policy["testPolicy"]["testTags"],
        "files": entries, "packages": packages,
        "policyDigest": "sha256:" + hashlib.sha256(
            policy_raw if policy["schemaVersion"] == SCHEMA_V2 else canonical_json(policy_value)
        ).hexdigest(),
        "requiredGoVersion": policy["requiredGoVersion"],
        "toolchainArchives": policy["toolchainArchives"],
    }
    if policy["schemaVersion"] == SCHEMA_V2:
        for module in policy["externalModules"]:
            for notice in module["notices"]:
                source = blobs.get(notice["sourcePath"])
                destination = blobs.get(notice["distributionPath"])
                digest = notice["sha256"]
                if source is None or destination is None or source != destination or hashlib.sha256(source).hexdigest() != digest:
                    raise GateError(f'external module notice binding differs: {module["path"]}')
        manifest["moduleMode"] = "vendor"
        manifest["vendorTreeDigest"] = policy["vendorTreeDigest"]
        manifest["externalModules"] = [
            {"path": module["path"], "version": module["version"], "moduleSum": module["moduleSum"], "goModSum": module["goModSum"], "licenseDeclared": module["licenseDeclared"]}
            for module in policy["externalModules"]
        ]
        manifest["binaryResources"] = policy["binaryResources"]
    manifest["manifestDigest"] = "sha256:" + hashlib.sha256(canonical_json(manifest)).hexdigest()
    return manifest, blobs


def write_new(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        raise GateError(f"refusing to overwrite output {path}: {exc}") from exc
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)


def verify_manifest(source_root: Path, policy_path: Path, manifest_path: Path, go: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    expected, blobs = derive(source_root, policy_path, go)
    actual, raw = load_external_json(manifest_path)
    if raw != canonical_json(actual):
        raise GateError("manifest is not canonical JSON")
    if actual != expected:
        raise GateError("manifest differs from the exact current policy and source bytes")
    return expected, blobs


def stage_tree(destination: Path, manifest: dict[str, Any], blobs: dict[str, bytes]) -> None:
    if destination.exists() or destination.is_symlink():
        raise GateError(f"refusing to overwrite stage: {destination}")
    destination.mkdir(parents=True, mode=0o700)
    try:
        for entry in manifest["files"]:
            target = destination / entry["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, int(entry["mode"], 8))
            with os.fdopen(fd, "wb") as handle:
                handle.write(blobs[entry["path"]])
            os.chmod(target, int(entry["mode"], 8))
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def native_script_commands(manifest: dict[str, Any]) -> list[list[str]]:
    paths = {entry["path"] for entry in manifest["files"]}
    if not {CANDIDATE_RUNNER_PATH, CANDIDATE_TEST_PATH}.issubset(paths):
        raise GateError("contribution candidate runner and test must be staged")
    commands = [
        ["python3", "-B", "-m", "unittest", "release/test_community_release_gate.py"],
        ["bash", "scripts/test-component-configuration-adapter.sh"],
        ["bash", "scripts/test-kubeconfig-api-snapshot-offline.sh"],
        ["python3", "-B", "scripts/check_contribution_candidates.py"],
    ]
    if "cli/scripts/test-offline-cli-boundary.sh" in paths:
        commands.append(["bash", "scripts/test-offline-cli-boundary.sh"])
    if "cli/scripts/test_package_knowledge.py" in paths:
        commands.append(["python3", "-B", "-m", "unittest", "scripts/test_package_knowledge.py"])
    if "cli/scripts/test_contribution_packet.py" in paths:
        commands.append(["python3", "-B", "-m", "unittest", "scripts/test_contribution_packet.py"])
    if "cli/scripts/test_source_corpus.py" in paths:
        commands.append(["python3", "-B", "-m", "unittest", "scripts/test_source_corpus.py"])
    if "cli/scripts/test_source_corpus_collection.py" in paths:
        commands.append(["python3", "-B", "-m", "unittest", "scripts/test_source_corpus_collection.py"])
    capture_example_paths = {path for path in paths if path.startswith(CAPTURE_EXAMPLE_PREFIX)}
    present_capture_paths = paths & CAPTURE_NATIVE_TEST_PATHS
    if present_capture_paths or capture_example_paths:
        if present_capture_paths != CAPTURE_NATIVE_TEST_PATHS or not capture_example_paths:
            raise GateError("capture shipping requires its complete tool, test, documentation, and example suite")
        commands.append(["python3", "-B", "scripts/test_public_source_capture.py"])
    present_inventory_paths = paths & SUPPORT_INVENTORY_NATIVE_PATHS
    if present_inventory_paths:
        if present_inventory_paths != SUPPORT_INVENTORY_NATIVE_PATHS:
            raise GateError("support inventory shipping requires its complete generator, normalized metadata, generated output, documentation, and test suite")
        commands.append(["python3", "-B", "scripts/test_support_inventory.py"])
    present_staging_receipt_paths = paths & STAGING_RECEIPT_NATIVE_PATHS
    if present_staging_receipt_paths:
        if present_staging_receipt_paths != STAGING_RECEIPT_NATIVE_PATHS:
            raise GateError("publisher shipping requires its workflow, helper, and complete test suite")
        commands.append(["python3", "-B", "-m", "unittest", "release/test_community_staging_receipt.py"])
        commands.append(["python3", "-B", "-m", "unittest", "release/test_community_publisher_contract.py"])
    return commands


def validate_offline_boundary_receipt(raw: bytes) -> dict[str, Any]:
    receipt = parse_json(raw, "offline CLI boundary receipt")
    expected_commands = [
        "help", "version", "check", "prepare", "cilium-prepare", "cilium-check",
        "db verify", "db import", "check --knowledge-db", "db status", "historical replay",
    ]
    required = {
        "apiVersion", "status", "platform", "observer", "isolation",
        "sudoUsedForNamespaceOnly", "namespaceUIDNonRoot", "namespaceUID",
        "namespaceGID", "fixtureMode", "socketPositiveControl",
        "positiveControlPerNamespace", "commands", "networkSyscallsObserved",
        "explicitUpdateExcluded", "binaryDigest",
    }
    missing = sorted(required - set(receipt))
    if missing:
        raise GateError(f"offline CLI boundary receipt is missing fields: {', '.join(missing)}")
    extra = sorted(set(receipt) - required)
    if extra:
        raise GateError(f"offline CLI boundary receipt has unexpected fields: {', '.join(extra)}")
    if receipt["apiVersion"] != "prufyx.io/offline-cli-boundary-receipt/v1":
        raise GateError("offline CLI boundary receipt has an unexpected schema")
    if receipt["status"] != "PASS" or receipt["platform"] != "linux":
        raise GateError("offline CLI boundary receipt is not a passing Linux result")
    if receipt["observer"] != "strace -f trace=%network":
        raise GateError("offline CLI boundary receipt has an unexpected observer")
    if receipt["isolation"] != "fresh sudo -n unshare --net per command then setpriv to original fixture owner":
        raise GateError("offline CLI boundary receipt has an unexpected isolation")
    for field in ("sudoUsedForNamespaceOnly", "namespaceUIDNonRoot", "socketPositiveControl", "positiveControlPerNamespace"):
        if receipt[field] is not True:
            raise GateError(f"offline CLI boundary receipt must set {field}=true")
    if receipt["networkSyscallsObserved"] is not False:
        raise GateError("offline CLI boundary receipt must set networkSyscallsObserved=false")
    if receipt["explicitUpdateExcluded"] is not True:
        raise GateError("offline CLI boundary receipt must exclude explicit update")
    if receipt["fixtureMode"] != "0600" or receipt["commands"] != expected_commands:
        raise GateError("offline CLI boundary receipt does not describe the required matrix")
    for field in ("namespaceUID", "namespaceGID"):
        value = receipt[field]
        if not isinstance(value, str) or not value.isdecimal() or int(value) == 0:
            raise GateError(f"offline CLI boundary receipt has an invalid non-root {field}")
    if not isinstance(receipt["binaryDigest"], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", receipt["binaryDigest"]):
        raise GateError("offline CLI boundary receipt has an invalid binary digest")
    return receipt


def run_native_checks(stage: Path, manifest: dict[str, Any], go: str) -> None:
    module_root = stage / "cli"
    vendor_mode = manifest.get("moduleMode") == "vendor"
    env = go_env(vendor=vendor_mode)
    env["PRUFYX_GO"] = go
    host_os = run(go, ["env", "GOHOSTOS"], module_root, env).decode().strip()
    host_arch = run(go, ["env", "GOHOSTARCH"], module_root, env).decode().strip()
    if f"{host_os}/{host_arch}" not in manifest["sourceBuildTargets"]:
        raise GateError(f"native tests require a declared source-build runner, found {host_os}/{host_arch}")
    run(go, ["vet", "./..."], module_root, env)
    run(go, ["test", "./...", "-count=1"], module_root, env)
    for tag in manifest["testTags"]:
        run(go, ["test", "-tags", tag, "./...", "-count=1"], module_root, env)
    offline_receipt: dict[str, Any] | None = None
    for command in native_script_commands(manifest):
        completed = subprocess.run(command, cwd=module_root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if completed.returncode:
            raise GateError(f"{' '.join(command)} failed:\n{command_detail(completed.stdout, completed.stderr)}")
        if command == ["bash", "scripts/test-offline-cli-boundary.sh"]:
            offline_receipt = validate_offline_boundary_receipt(completed.stdout)
    with tempfile.TemporaryDirectory(prefix="community-cross-build.") as output:
        for target in manifest["buildTargets"]:
            goos, goarch = target.split("/", 1)
            binary = str(Path(output) / f"{manifest['binaryName']}-{goos}-{goarch}")
            run(go, ["build", "-trimpath", "-buildvcs=false", "-o", binary, *manifest["entrypoints"]], module_root, go_env({"GOOS": goos, "GOARCH": goarch}, vendor=vendor_mode))
    if offline_receipt is not None:
        sys.stdout.buffer.write(canonical_json(offline_receipt))
        sys.stdout.flush()


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--source-root", type=Path, required=True)
    value.add_argument("--policy", type=Path, required=True)
    value.add_argument("--go", default="go", help="exact Go executable")
    sub = value.add_subparsers(dest="command", required=True)
    generate = sub.add_parser("generate")
    generate.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    stage = sub.add_parser("stage")
    stage.add_argument("--manifest", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.add_argument("--run-native-checks", action="store_true")
    return value


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    source_argument = args.source_root.absolute()
    if source_argument.is_symlink():
        raise GateError("source root must not be a symlink")
    source_root = source_argument.resolve()
    policy_argument = args.policy.absolute()
    if policy_argument.is_symlink():
        raise GateError("shipping policy must not be a symlink")
    policy_path = policy_argument.resolve()
    if not source_root.is_dir() or source_root.is_symlink():
        raise GateError("source root must be a real directory")
    if args.command == "generate":
        try:
            args.output.resolve().relative_to(source_root)
        except ValueError:
            pass
        else:
            raise GateError("generated manifest output must be outside the source root")
        manifest, _ = derive(source_root, policy_path, args.go)
        write_new(args.output, canonical_json(manifest))
        print(manifest["manifestDigest"])
        return 0
    manifest, blobs = verify_manifest(source_root, policy_path, args.manifest, args.go)
    if args.command == "verify":
        print(manifest["manifestDigest"])
        return 0
    stage_tree(args.output, manifest, blobs)
    if args.run_native_checks:
        run_native_checks(args.output, manifest, args.go)
    print(manifest["manifestDigest"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GateError as exc:
        print(f"community release gate: {exc}", file=sys.stderr)
        raise SystemExit(1)
