#!/usr/bin/env python3
"""Fail-closed JSON pass-through with duplicate-key rejection and a size bound."""

import json
import sys

# Kubernetes list responses can legitimately exceed 4 MiB when a context has
# many workloads. Keep a bounded single-response ceiling while allowing the
# collector's chunk-size=200 requests to pass through in normal clusters.
MAX_JSON_BYTES = 16 * 1024 * 1024


def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate object key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-standard JSON constant")


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_JSON_BYTES + 1)
        if len(raw) > MAX_JSON_BYTES:
            raise ValueError("JSON input exceeds local bound")
        json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=reject_duplicate,
            parse_constant=reject_constant,
        )
    except Exception:
        return 1
    sys.stdout.buffer.write(raw)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
