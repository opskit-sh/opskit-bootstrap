#!/usr/bin/env python3
"""Canonical JSON serialization helper for OpsKit Bootstrap (RFC 8785 profile)."""
import json
import sys


def _reject_duplicate_keys(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"Duplicate JSON object key: {k!r}")
        obj[k] = v
    return obj


def _reject_nonfinite(constant):
    raise ValueError(f"Non-finite JSON constant is not permitted: {constant!r}")


def loads_strict(raw):
    """Parse JSON strictly, rejecting duplicate keys and non-finite constants."""
    return json.loads(
        raw,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite,
    )


def canonical_json(obj, strip_keys=()):
    """
    Serialize obj to canonical JSON string with sorted keys,
    compact separators, and UTF-8 characters preserved.
    If obj is a dict and strip_keys is specified, those top-level keys are omitted.
    """
    if isinstance(obj, dict) and strip_keys:
        obj = {k: v for k, v in obj.items() if k not in strip_keys}
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_bytes(obj, strip_keys=()):
    """Return canonical UTF-8 bytes for obj."""
    return canonical_json(obj, strip_keys).encode('utf-8')


if __name__ == '__main__':
    strip = set()
    args = sys.argv[1:]
    while args and args[0] == '--strip':
        args.pop(0)
        if args:
            strip.add(args.pop(0))
    file_arg = args[0] if args else '-'
    if file_arg == '-':
        data = loads_strict(sys.stdin.read())
    else:
        with open(file_arg, 'r', encoding='utf-8') as f:
            data = loads_strict(f.read())
    sys.stdout.buffer.write(canonical_bytes(data, strip))
