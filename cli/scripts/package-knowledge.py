#!/usr/bin/env python3
"""Assemble an already-signed offline knowledge package.

This helper only performs bounded local directory validation and deterministic
USTAR assembly, with the standard GNU long-name record needed by one closed
target basename. It does not verify TUF signatures, trust roots, source evidence,
or maintainer review. ``prufyx db import`` performs trust/signature and structural
admission checks; neither utility verifies source correctness or that review occurred.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
from pathlib import Path, PurePosixPath

MAX_PACKAGE_BYTES = 4 << 20
MAX_PACKAGE_FILES = 16
MAX_PACKAGE_ENTRY = 1 << 20
MAX_PACKAGE_TOTAL = 2 << 20

METADATA_NAMES = {
    "metadata/timestamp.json",
}
TARGET_SUFFIX = {
    "cert-manager": "cert-manager.v1.json",
    "cncf": "constraints.v1.json",
    "spiffe-x509-svid": "spiffe-x509-svid-profile.v1.json",
    "cloudevents-structured-json": "cloudevents-structured-json-profile.v1.json",
    "tikv-gcp-v2-wif-backup": "tikv-gcp-v2-wif-backup-profile.v1.json",
}


class PackageError(ValueError):
    """A caller-correctable packaging input or output error."""


def _matches_expected(info: os.stat_result, expected: os.stat_result, expected_size: int) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_nlink == 1
        and info.st_dev == expected.st_dev
        and info.st_ino == expected.st_ino
        and info.st_size == expected_size
        and info.st_mtime_ns == expected.st_mtime_ns
        and info.st_ctime_ns == expected.st_ctime_ns
    )


def _metadata_name(name: str) -> bool:
    if name in METADATA_NAMES:
        return True
    if not name.startswith("metadata/") or not name.endswith(".json"):
        return False
    stem = name[len("metadata/") : -len(".json")]
    if "." not in stem:
        return False
    version, role = stem.split(".", 1)
    return version.isascii() and version.isdecimal() and 1 <= len(version) <= 10 and version[0] != "0" and role in {"root", "snapshot", "targets"}


def _target_name(name: str, suffix: str) -> bool:
    prefix = "targets/knowledge/"
    ending = "." + suffix
    if not name.startswith(prefix) or not name.endswith(ending):
        return False
    digest = name[len(prefix) : -len(ending)]
    return len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)


def _allowed_name(name: str, suffix: str) -> bool:
    return _metadata_name(name) or _target_name(name, suffix)


def _safe_read(path: Path, expected_size: int, expected_info: os.stat_result) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise PackageError(f"cannot read {path}: {exc}") from exc
    try:
        info = os.fstat(fd)
        if not _matches_expected(info, expected_info, expected_size):
            raise PackageError(f"input member changed before reading: {path}")
        data = bytearray()
        while len(data) <= expected_size:
            chunk = os.read(fd, expected_size + 1 - len(data))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) != expected_size or not _matches_expected(after, expected_info, expected_size):
            raise PackageError(f"input member changed while reading: {path}")
        try:
            current = path.lstat()
        except OSError as exc:
            raise PackageError("input member disappeared while reading") from exc
        if not _matches_expected(current, expected_info, expected_size):
            raise PackageError(f"input member changed after reading: {path}")
        return bytes(data)
    finally:
        os.close(fd)


def collect_members(input_dir: Path, profile: str) -> dict[str, bytes]:
    try:
        root_info = input_dir.lstat()
    except OSError as exc:
        raise PackageError(f"input directory unavailable: {exc}") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise PackageError("--input must be a directory")

    suffix = TARGET_SUFFIX[profile]
    members: dict[str, bytes] = {}
    inodes: set[tuple[int, int]] = set()
    total = 0
    allowed_dirs = {"metadata", "targets", "targets/knowledge"}

    def walk_error(exc: OSError) -> None:
        raise PackageError("cannot enumerate input directory") from exc

    for current, dirnames, filenames in os.walk(input_dir, topdown=True, onerror=walk_error, followlinks=False):
        current_path = Path(current)
        rel_current = current_path.relative_to(input_dir).as_posix()
        if rel_current == ".":
            rel_current = ""
        # The only directories permitted in the source tree are the two
        # package namespaces and their required parent.
        for dirname in list(dirnames):
            directory = current_path / dirname
            info = directory.lstat()
            rel = directory.relative_to(input_dir).as_posix()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or rel not in allowed_dirs:
                raise PackageError(f"unknown or linked input directory: {rel}")
        dirnames[:] = sorted(dirnames)
        for filename in filenames:
            path = current_path / filename
            info = path.lstat()
            rel = path.relative_to(input_dir).as_posix()
            # The names are ASCII by construction of the accepted grammar;
            # reject aliases, separators and all unrecognized members.
            if not rel.isascii() or PurePosixPath(rel).as_posix() != rel or not _allowed_name(rel, suffix):
                raise PackageError(f"unknown input member: {rel}")
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise PackageError(f"input member is not a regular file: {rel}")
            if info.st_nlink != 1:
                raise PackageError(f"hard-linked input member: {rel}")
            inode = (info.st_dev, info.st_ino)
            if inode in inodes:
                raise PackageError(f"duplicate hard-linked input member: {rel}")
            inodes.add(inode)
            if info.st_size < 1 or info.st_size > MAX_PACKAGE_ENTRY:
                raise PackageError(f"input member size out of bounds: {rel}")
            if len(members) >= MAX_PACKAGE_FILES:
                raise PackageError("too many package members")
            total += info.st_size
            if total > MAX_PACKAGE_TOTAL:
                raise PackageError("package total size exceeds 2 MiB")
            members[rel] = _safe_read(path, info.st_size, info)

    if len(members) < 4:
        raise PackageError("package requires at least four members")
    if "metadata/timestamp.json" not in members:
        raise PackageError("metadata/timestamp.json is required")
    targets = [name for name in members if _target_name(name, suffix)]
    if len(targets) != 1:
        raise PackageError("package requires exactly one content-addressed target")
    target_name = targets[0]
    target_digest = target_name[len("targets/knowledge/") : -len("." + suffix)]
    if hashlib.sha256(members[target_name]).hexdigest() != target_digest:
        raise PackageError("target filename digest does not match target bytes")
    return dict(sorted(members.items()))


def _octal(value: int, width: int) -> bytes:
    encoded = format(value, "o").encode("ascii")
    if len(encoded) > width - 1:
        raise PackageError("USTAR numeric field overflow")
    return b"0" * (width - 1 - len(encoded)) + encoded + b"\0"


def _ustar_header(name: str, size: int, typeflag: str = "0", mode: int = 0o644) -> bytes:
    encoded = name.encode("ascii")
    prefix = b""
    suffix = encoded
    if len(encoded) > 100:
        # Match Go archive/tar's splitUSTARPath: search the last slash in
        # name[:156], leaving a suffix no longer than the 100-byte name field.
        split_limit = min(len(encoded), 155 + 1)
        index = encoded[:split_limit].rfind(b"/")
        if index <= 0 or len(encoded) - index - 1 > 100 or index > 155:
            raise PackageError("member name cannot be represented in USTAR")
        prefix, suffix = encoded[:index], encoded[index + 1 :]
    if len(suffix) > 100 or len(prefix) > 155:
        raise PackageError("member name cannot be represented in USTAR")
    header = bytearray(512)
    header[0 : len(suffix)] = suffix
    header[100:108] = _octal(mode, 8)
    header[108:116] = _octal(0, 8)
    header[116:124] = _octal(0, 8)
    header[124:136] = _octal(size, 12)
    header[136:148] = _octal(0, 12)
    header[148:156] = b"        "
    header[156] = ord(typeflag)
    header[257:263] = b"ustar\0"
    header[263:265] = b"00"
    header[329:337] = _octal(0, 8)
    header[337:345] = _octal(0, 8)
    header[345 : 345 + len(prefix)] = prefix
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _gnu_header(name: str, size: int, typeflag: str, mode: int) -> bytes:
    header = bytearray(_ustar_header(name, size, typeflag, mode))
    header[257:265] = b"ustar  \0"
    if typeflag == "L":
        header[329:345] = b"\0" * 16
    header[148:156] = b"        "
    checksum = sum(header)
    header[148:156] = f"{checksum:06o}\0 ".encode("ascii")
    return bytes(header)


def _archive_member(name: str, data: bytes) -> bytes:
    try:
        header = _ustar_header(name, len(data))
        return header + data + b"\0" * ((-len(data)) % 512)
    except PackageError:
        encoded = name.encode("ascii")
        if len(encoded) <= 100:
            raise
        long_name = encoded + b"\0"
        long_header = _gnu_header("././@LongLink", len(long_name), "L", 0)
        long_padding = b"\0" * ((-len(long_name)) % 512)
        # Match Go archive/tar's GNU writer: the LongLink payload supplies the
        # exact name and the following header retains its leading 100 bytes.
        placeholder = encoded[:100].decode("ascii")
        file_header = _gnu_header(placeholder, len(data), "0", 0o644)
        file_padding = b"\0" * ((-len(data)) % 512)
        return long_header + long_name + long_padding + file_header + data + file_padding


def canonical_archive(members: dict[str, bytes]) -> bytes:
    output = bytearray()
    for name, data in members.items():
        output.extend(_archive_member(name, data))
    output.extend(b"\0" * 1024)
    raw = bytes(output)
    if len(raw) > MAX_PACKAGE_BYTES:
        raise PackageError("canonical archive exceeds 4 MiB")
    return raw


def package_directory(input_dir: os.PathLike[str] | str, profile: str) -> bytes:
    if profile not in TARGET_SUFFIX:
        raise PackageError("unsupported profile")
    return canonical_archive(collect_members(Path(input_dir), profile))


def write_package(input_dir: os.PathLike[str] | str, output: os.PathLike[str] | str, profile: str) -> None:
    raw = package_directory(input_dir, profile)
    destination = Path(output)
    if destination.name in {"", ".", ".."} or destination.name != os.path.basename(destination):
        raise PackageError("output must name a regular file")
    parent = destination.parent
    parent_fd = None
    fd = None
    created = False
    success = False
    try:
        parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            parent_flags |= os.O_NOFOLLOW
        parent_fd = os.open(parent, parent_flags)
        parent_info = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) != 0o700 or parent_info.st_uid != os.getuid():
            raise PackageError("output parent must be a private 0700 directory owned by the current user")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(destination.name, flags, 0o600, dir_fd=parent_fd)
        created = True
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(parent_fd)
        success = True
    except FileExistsError as exc:
        raise PackageError("refusing to overwrite existing output") from exc
    except OSError as exc:
        raise PackageError("cannot create private output") from exc
    finally:
        if fd is not None:
            os.close(fd)
        if created and not success and parent_fd is not None:
            try:
                os.unlink(destination.name, dir_fd=parent_fd)
            except OSError:
                pass
        if parent_fd is not None:
            os.close(parent_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Assemble a bounded canonical knowledge package from already-signed local metadata and content-addressed targets.",
        epilog="This assembles bytes only; it does not verify TUF signatures, trust roots, source evidence, or maintainer review. Run prufyx db import for admission.",
    )
    parser.add_argument("--profile", choices=sorted(TARGET_SUFFIX), required=True, help="fixed target profile")
    parser.add_argument("--input", required=True, metavar="DIR", help="operator-prepared metadata/ and targets/ directory")
    parser.add_argument("--output", required=True, metavar="FILE", help="new canonical archive in a private 0700 parent; existing files are never overwritten")
    args = parser.parse_args(argv)
    try:
        write_package(args.input, args.output, args.profile)
    except (PackageError, OSError):
        print("package-knowledge: packaging rejected", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
