#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""X-02 — the single canonical identifier grammar and check-character algorithm.

This module is the ONE source of truth for the UID/MID syntax and their
Reed-Solomon check symbols over GF(2^5). The toolkit and the linters import it, so
there is no second implementation to drift.

Check characters (redesign, X-02).  The old Luhn-32 (C1) + decimal-projection
Verhoeff (C2) are replaced by Reed-Solomon check symbols computed DIRECTLY on the
Crockford Base32 alphabet (no lossy decimal projection):

  * Field: GF(2^5) with primitive polynomial p(x) = x^5 + x^2 + 1 (0x25); the
    primitive element is alpha = x (the field element 2). Each Base32 symbol maps
    to a field element by its Crockford index 0..31.
  * UID: the two check symbols C1 C2 are the Reed-Solomon parity of the 13 data
    symbols (scheme_code, payload[0..11]) with generator g(x) = (x+alpha)(x+alpha^2)
    (systematic encoding). The code is a distance-3 MDS [15,13] code, so ANY error
    confined to at most two symbols is detected (every single error, every double
    error, hence all transpositions and twin errors).
  * MID: the 9th character is one Reed-Solomon parity symbol of the 8 payload
    symbols (generator x + alpha), a distance-2 code: all single errors and all
    transpositions of distinct symbols are detected.
  * CC (the country code) uses ISO-3166 alpha-2 (26 letters); together with the
    digit-bearing payload alphabet that exceeds 32 symbols, so CC cannot be a
    GF(2^5) symbol and is deliberately NOT covered by the check (it is validated as
    a registered country code and by directory resolution).
"""
import re

# Crockford Base32 alphabet (excludes I, L, O, U). Index == GF(2^5) element.
B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
IDX = {c: i for i, c in enumerate(B32)}

# --- GF(2^5), p(x) = x^5 + x^2 + 1 = 0x25 ; alpha = x = 2 ---------------------
_PRIM = 0x25
ALPHA = 2
_EXP = [0] * 31
_LOG = [0] * 32
_x = 1
for _i in range(31):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x20:
        _x ^= _PRIM


def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return _EXP[(_LOG[a] + _LOG[b]) % 31]


def _rs_parity(data, gen):
    """Systematic Reed-Solomon parity of `data` (symbols, high-order first) for
    generator whose non-leading coefficients are `gen` (len == number of parity
    symbols). Returns the parity symbols, high-order first."""
    parity = [0] * len(gen)
    for d in data:
        fb = d ^ parity[0]
        for i in range(len(gen) - 1):
            parity[i] = parity[i + 1] ^ gf_mul(fb, gen[i])
        parity[-1] = gf_mul(fb, gen[-1])
    return parity


# UID generator g(x) = (x+a)(x+a^2) = x^2 + (a+a^2) x + a^3
_UID_GEN = [_EXP[1] ^ _EXP[2], _EXP[3]]
# MID generator g(x) = (x + a)
_MID_GEN = [_EXP[1]]

SCHEME_CODE = {"EOID": "E", "PSBID": "P"}

UID_REGEX = re.compile(r"^EU-[A-Z]{2}-(EOID|PSBID)-[0-9A-HJ-NP-TV-Z]{14}$")
MID_REGEX = re.compile(r"^[0-9A-HJ-NP-TV-Z]{9}$")
ROLE_REGEX = re.compile(r"^[a-z0-9._-]{1,32}$")


def uid_check_chars(scheme, payload12):
    """The two Base32 check characters C1 C2 for a UID (scheme in EOID/PSBID,
    payload12 = 12 Crockford Base32 chars)."""
    data = [IDX[SCHEME_CODE[scheme]]] + [IDX[c] for c in payload12]
    p = _rs_parity(data, _UID_GEN)
    return B32[p[0]] + B32[p[1]]


def mid_check_char(payload8):
    """The single Base32 check character for a MID (payload8 = 8 Crockford
    Base32 chars)."""
    data = [IDX[c] for c in payload8]
    p = _rs_parity(data, _MID_GEN)
    return B32[p[0]]


def uid_valid_checksum(uid):
    """True iff `uid` is syntactically well-formed AND its C1 C2 are correct."""
    if not UID_REGEX.match(uid):
        return False
    _, cc, scheme, tail = uid.split("-", 3)
    payload, c1c2 = tail[:12], tail[12:]
    return uid_check_chars(scheme, payload) == c1c2


def mid_valid_checksum(mid):
    if not MID_REGEX.match(mid):
        return False
    return mid_check_char(mid[:8]) == mid[8]


def make_uid(cc, scheme, payload12):
    """Build a checksum-valid UID from parts."""
    return f"EU-{cc}-{scheme}-{payload12}{uid_check_chars(scheme, payload12)}"


def make_mid(payload8):
    return payload8 + mid_check_char(payload8)


if __name__ == "__main__":  # tiny self-check
    u = make_uid("DE", "EOID", "7K3D9W0Q2M5F")
    m = make_mid("A1B2C3D4")
    print("UID", u, uid_valid_checksum(u))
    print("MID", m, mid_valid_checksum(m))
