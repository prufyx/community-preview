#!/usr/bin/env python3
"""Classify bounded kubectl diagnostics without retaining or printing them."""

import sys
from typing import Tuple


MAX_STDERR_BYTES = 64 * 1024
CHUNK_BYTES = 4096

# These are deliberately plain bounded substring checks rather than user-sized
# regular expressions.  The helper's stdout is the complete allow-list.
ENUMS = (
    "authentication_exec_plugin_failure",
    "unauthorized",
    "authorization_rbac_forbidden",
    "invalid_kubeconfig_context",
    "tls_certificate",
    "dns",
    "transport_timeout_unreachable",
    "unsupported_not_found_api",
    "generic_api_read_failure",
)


def read_bounded() -> bytes:
    retained = bytearray()
    while True:
        chunk = sys.stdin.buffer.read(CHUNK_BYTES)
        if not chunk:
            return bytes(retained)
        if len(retained) < MAX_STDERR_BYTES:
            retained.extend(chunk[: MAX_STDERR_BYTES - len(retained)])


def normalized_lines(raw: bytes) -> Tuple[str, ...]:
    text = raw.decode("utf-8", errors="replace")
    # Drop terminal control sequences and other controls without interpreting
    # them as message syntax.  In particular, NUL/ANSI input cannot turn an
    # arbitrary line into a canonical kubectl diagnostic.
    clean = "".join(char if char in "\n\r\t" or ord(char) >= 0x20 else " " for char in text)
    lines = []
    for line in clean.splitlines():
        if "\x1b" in line:
            continue
        lines.append(line.strip().lower())
    return tuple(lines)


def has_prefix(lines: Tuple[str, ...], prefixes: Tuple[str, ...]) -> bool:
    return any(line.startswith(prefix) for line in lines for prefix in prefixes)


def has_shape(lines: Tuple[str, ...], prefix: str, fragments: Tuple[str, ...]) -> bool:
    return any(
        line.startswith(prefix) and any(fragment in line for fragment in fragments)
        for line in lines
    )


def classify(raw: bytes) -> str:
    try:
        lines = normalized_lines(raw)
    except Exception:
        return "generic_api_read_failure"

    # Precedence is intentional: an explicit auth plugin failure is more
    # actionable than the enclosing transport/authentication wording.
    if has_shape(
        lines,
        "error: exec plugin:",
        ("executable", "failed", "invalid", "returned"),
    ) or has_shape(
        lines,
        "unable to connect to the server: getting credentials: exec:",
        ("executable", "failed"),
    ):
        return "authentication_exec_plugin_failure"
    if has_prefix(
        lines,
        (
            "error from server (unauthorized):",
            "you must be logged in to the server (unauthorized)",
            "you must be logged in to the server (the server has asked for the client to provide credentials)",
            "the server has asked for the client to provide credentials",
        ),
    ):
        return "unauthorized"
    if has_prefix(lines, ("error from server (forbidden):",)):
        return "authorization_rbac_forbidden"
    if has_prefix(
        lines,
        (
            "error: invalid configuration:",
            "error: context ",
            "error: no context exists with the name",
            "error: current-context is not set",
        ),
    ) and any(
        (
            "does not exist" in line
            or "no context exists" in line
            or "invalid configuration:" in line
            or "not set" in line
        )
        for line in lines
    ):
        return "invalid_kubeconfig_context"
    if has_prefix(
        lines,
        (
            "unable to connect to the server: x509:",
            "unable to connect to the server: tls:",
            "unable to connect to the server: certificate",
        ),
    ):
        return "tls_certificate"
    if has_shape(
        lines,
        "unable to connect to the server: dial tcp:",
        ("lookup ", "no such host", "name or service not known"),
    ):
        return "dns"
    if has_shape(
        lines,
        "unable to connect to the server:",
        (
            "i/o timeout",
            "context deadline exceeded",
            "connection refused",
            "connection reset",
            "network is unreachable",
            "host is unreachable",
        ),
    ):
        return "transport_timeout_unreachable"
    if has_prefix(
        lines,
        (
            "error from server (notfound):",
            "error from server (unsupportedmediatype):",
            "error from server (methodnotallowed):",
            "error: the server doesn't have a resource type",
            "error: no matches for kind ",
        ),
    ) or has_prefix(
        lines,
        ("the server could not find the requested resource",),
    ):
        return "unsupported_not_found_api"
    return "generic_api_read_failure"


def main() -> int:
    result = "generic_api_read_failure"
    try:
        result = classify(read_bounded())
    except Exception:
        result = "generic_api_read_failure"
    if result not in ENUMS:
        result = "generic_api_read_failure"
    try:
        sys.stdout.write(result + "\n")
        sys.stdout.flush()
    except Exception:
        # The caller may have been interrupted after closing its sanitized
        # result pipe.  Never emit input or an exception diagnostic.
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
