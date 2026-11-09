#!/usr/bin/env python3
"""Canonical JSON serialization helper for OpsKit Bootstrap."""
import json
import sys


def canonical_json(obj, strip_keys=()):
    """
    Serialize obj to canonical JSON string with sorted keys,
    compact separators, and UTF-8 characters preserved.
    If obj is a dict and strip_keys is specified, those top-level keys are omitted.
    """
    if isinstance(obj, dict) and strip_keys:
        obj = {k: v for k, v in obj.items() if k not in strip_keys}
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


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
        data = json.load(sys.stdin)
    else:
        with open(file_arg, 'r', encoding='utf-8') as f:
            data = json.load(f)
    sys.stdout.buffer.write(canonical_bytes(data, strip))
