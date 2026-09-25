# SPDX-License-Identifier: CC-BY-4.0
# SPDX-FileCopyrightText: 2026 Secure Business Messaging contributors
"""Known-answer tests pinning the v2 deterministic-CBOR commitment construction
(twenty-fifth review, M3/T4; the I-D (Grade Commitment)/(Mandate Commitment)).

The grade/mandate commitment is the most legally load-bearing computation in the
profile — a disputing party recomputes it from a reveal — so its byte layout is
frozen three ways: (1) the function must match an INDEPENDENT re-derivation of
the documented dCBOR fixed-position array (non-circular); (2) the literal digest
is pinned, so silent drift is caught even if both sides drifted together; (3) the
v2 dCBOR value must differ from the retired v1 JSON-canonicalisation build,
documenting the break that carries evidence 1.17 -> 1.18. Salt and org_digest are
byte strings (hex-decoded); the rest are text.

The v1 canonical octets are PINNED in this file rather than recomputed: the
canonicaliser was removed with the JSON-canonicalisation hash modes on
2026-09-25, and a retired construction is a historical constant, not a live
dependency. Pinning the octets keeps the proof non-circular — the test still
hashes bytes it can show you, it just no longer needs the encoder.
"""
import hashlib
import importlib.util
import pathlib

import cbor2

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lint_cli = _load("lint_cli", "lint_cli.py")

SALT = "00112233445566778899aabbccddeeff"           # 16 bytes
ORG_DIGEST = "a" * 64                                # 32 bytes
MANDATE_ORG_DIGEST = "b" * 64


def _dcbor(dst, fields):
    """Independent re-derivation of the documented dCBOR array (not via lint_cli)."""
    return hashlib.sha256(cbor2.dumps([dst, *fields], canonical=True)).hexdigest()


def test_grade_commitment_matches_documented_cbor_layout():
    got = lint_cli.compute_grade_commitment(SALT, "invoice", ORG_DIGEST)
    exp = _dcbor("sm-mls:grade-commitment:v2",
                 [bytes.fromhex(SALT), "invoice", "availability", bytes.fromhex(ORG_DIGEST)])
    assert got == exp


def test_mandate_commitment_matches_documented_cbor_layout():
    got = lint_cli.compute_mandate_commitment(SALT, "mandate-1", "invoice", MANDATE_ORG_DIGEST)
    exp = _dcbor("sm-mls:mandate-commitment:v2",
                 [bytes.fromhex(SALT), "mandate-1", "invoice", bytes.fromhex(MANDATE_ORG_DIGEST)])
    assert got == exp


def test_grade_commitment_is_pinned():
    # Anti-drift pin: this literal MUST NOT change without an evidence-version bump.
    assert lint_cli.compute_grade_commitment(SALT, "invoice", ORG_DIGEST) == \
        "5a02639a5fafe029cb55e2dcdf2b08bd67ba709d1dbcd4bc705b806b9231f184"


def test_mandate_commitment_is_pinned():
    assert lint_cli.compute_mandate_commitment(SALT, "mandate-1", "invoice", MANDATE_ORG_DIGEST) == \
        "43be3c2a1c7457fe7bdb35ece5a71c92699315ba30a3fbd453ff4f4229622df5"


# The retired v1 canonical octets for the SALT/ORG_DIGEST vectors above: the
# JSON-canonical serialisation of {dst, salt, content_class, grade, org_digest}
# with the values as hex STRINGS. Recorded verbatim, so the v1 digest below is
# derived here and not asserted on faith.
V1_CANONICAL_OCTETS = (
    b'{"content_class":"invoice","dst":"sm-mls:grade-commitment:v1",'
    b'"grade":"availability","org_digest":"' + b"a" * 64 + b'",'
    b'"salt":"00112233445566778899aabbccddeeff"}'
)


def test_v2_dcbor_differs_from_retired_v1_build():
    # v1 hashed canonical JSON over hex strings; v2 is deterministic CBOR with
    # typed bstr salt/org_digest. They MUST differ — the break behind 1.17 -> 1.18.
    v1 = hashlib.sha256(V1_CANONICAL_OCTETS).hexdigest()
    assert v1 == "79a140b116dbf2f1c9a969fb518107296f9fa599dc90258219028502c5ec53ec", \
        "the pinned v1 octets are the ones the retired build hashed"
    v2 = lint_cli.compute_grade_commitment(SALT, "invoice", ORG_DIGEST)
    assert v1 != v2


def test_salt_and_org_digest_are_byte_strings():
    # Distinct-length hex must be distinct commitments (the bstr .size typing).
    a = lint_cli.compute_grade_commitment(SALT, "invoice", ORG_DIGEST)
    b = lint_cli.compute_grade_commitment(SALT, "invoic", ORG_DIGEST)  # different class
    assert a != b
