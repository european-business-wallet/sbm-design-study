#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""RFC 8785 JSON Canonicalization Scheme (JCS) — the single shared implementation
of canonical bytes for this profile (Internet-Draft draft-sbm-mls-erd,
Canonicalisation and Payload Hashing; umbrella the I-D (Evidence Objects and COSE Packaging) -> I-D).

Every canonical byte-string in the repo — payload hashing, the evidence seal
signed payload, the recipient wallet signature, discovery-document seals — MUST
go through this module, so that `json.dumps(sort_keys=True, separators=...)`
approximations cannot drift from RFC 8785 (object-key ordering by UTF-16 code
units, string escaping, number serialisation).

Scope: the profile's data is objects with string keys and string / integer /
boolean / null / nested values (no floating-point). This implementation is
correct and complete for that data; it additionally serialises floats per the
ECMAScript Number→String rules for the common range (enough to pass the RFC 8785
§3 examples), and rejects NaN / Infinity. It is self-contained (no external
dependency), matching the repository's no-third-party-runtime-dependency
discipline.
"""
import re

_ESC = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f',
        '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _string(s):
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append('\\u%04x' % ord(ch))
        else:
            out.append(ch)  # incl. non-ASCII, emitted as literal UTF-8
    out.append('"')
    return ''.join(out)


def _number(n):
    """ECMAScript Number→String (RFC 8785 §3.2.2.3), sufficient for the profile
    (no floats) and the RFC 8785 §3 test vector."""
    if n != n or n in (float('inf'), float('-inf')):
        raise ValueError("NaN and Infinity are not permitted in JCS")
    if n == 0:
        return "0"  # normalises -0.0 as well
    # Integer-valued within the ES non-exponential range: emit as an integer.
    if n == int(n) and abs(n) < 1e21:
        return str(int(n))
    # Otherwise the shortest round-tripping representation. Python's float repr
    # is shortest since 3.1 and already uses the ES 'e+NN' / 'e-NN' exponent
    # form; strip a redundant leading zero in the exponent (repr never adds one,
    # but be defensive).
    s = repr(n)
    return re.sub(r'e([+-])0*(\d)', r'e\1\2', s)


def _serialize(obj, out):
    if obj is True:
        out.append("true")
    elif obj is False:
        out.append("false")
    elif obj is None:
        out.append("null")
    elif isinstance(obj, str):
        out.append(_string(obj))
    elif isinstance(obj, bool):  # unreachable (True/False handled above), for clarity
        out.append("true" if obj else "false")
    elif isinstance(obj, int):
        out.append(str(obj))
    elif isinstance(obj, float):
        out.append(_number(obj))
    elif isinstance(obj, (list, tuple)):
        out.append("[")
        for i, v in enumerate(obj):
            if i:
                out.append(",")
            _serialize(v, out)
        out.append("]")
    elif isinstance(obj, dict):
        # RFC 8785: sort keys by their UTF-16 code units. Comparing the
        # big-endian UTF-16 byte sequence yields exactly that order.
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        out.append("{")
        for i, (k, v) in enumerate(items):
            if not isinstance(k, str):
                raise TypeError(f"JCS object keys must be strings, got {type(k).__name__}")
            if i:
                out.append(",")
            out.append(_string(k))
            out.append(":")
            _serialize(v, out)
        out.append("}")
    else:
        raise TypeError(f"cannot canonicalise value of type {type(obj).__name__}")


def canonicalize(obj) -> str:
    """Return the RFC 8785 canonical JSON string for a JSON-compatible object."""
    out = []
    _serialize(obj, out)
    return ''.join(out)


def canonicalize_bytes(obj) -> bytes:
    """Return the RFC 8785 canonical JSON as UTF-8 bytes (the hashing/signing input)."""
    return canonicalize(obj).encode("utf-8")
