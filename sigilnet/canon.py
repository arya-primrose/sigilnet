"""Canonical JSON for signed events (spec section 4).

Only strings, integers, booleans, null, arrays and objects. NO floats, NaN or Infinity. Object keys sorted by UTF-16 code
units (RFC 8785 order), no whitespace, ASCII output (`ensure_ascii`). `loads` accepts ONLY canonical bytes, so one event has
exactly one byte representation on the wire and in the id: no parser differentials, no re-encoding tricks.
"""
from __future__ import annotations

import json

MAX_DEPTH = 16
MAX_INT = 2 ** 53 - 1          # integers stay exactly representable everywhere
MAX_BYTES = 256 * 1024         # hard ceiling for any single parse; events have a much smaller rule cap


class CanonError(ValueError):
    """Not representable as (or not equal to) canonical JSON."""


def _check(obj, depth=0):
    """Return a copy of obj with dict keys in canonical order; raise CanonError on anything not allowed."""
    if depth > MAX_DEPTH:
        raise CanonError("nesting too deep")
    if obj is None or isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        if abs(obj) > MAX_INT:
            raise CanonError("integer out of range")
        return obj
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")                     # rejects lone surrogates
        except UnicodeEncodeError as e:
            raise CanonError("string is not valid unicode") from e
        return obj
    if isinstance(obj, (list, tuple)):
        return [_check(x, depth + 1) for x in obj]
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise CanonError("object keys must be strings")
        out = {}
        for k in sorted(obj, key=lambda k: k.encode("utf-16-be", "surrogatepass")):
            out[_check(k)] = _check(obj[k], depth + 1)
        return out
    raise CanonError(f"type {type(obj).__name__} is not allowed (no floats, bytes, sets, ...)")


def dumps(obj) -> bytes:
    """Canonical bytes of obj."""
    return json.dumps(_check(obj), sort_keys=False, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _no_dupes(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise CanonError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _no_float(s):
    raise CanonError("floats are not allowed")


def _no_const(s):
    raise CanonError(f"{s} is not allowed")


def loads(data: bytes | str):
    """Parse and require that `data` is EXACTLY the canonical form of what it contains."""
    raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
    if len(raw) > MAX_BYTES:
        raise CanonError("input too large")
    try:
        text = raw.decode("utf-8")
        obj = json.loads(text, object_pairs_hook=_no_dupes, parse_float=_no_float, parse_constant=_no_const)
    except CanonError:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError) as e:
        raise CanonError(f"not valid JSON: {e}") from e
    if dumps(obj) != raw:
        raise CanonError("not in canonical form")
    return obj
