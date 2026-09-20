# SPDX-License-Identifier: MIT
"""Round 10 / B7 — R10-11: the post-quantum suite, pinned and honestly numbered.

The profile named the hybrid `X25519MLKEM768` and the reference mapped it to
`0x004D`. The source it cites — draft-ietf-mls-pq-ciphersuites-06 — names it
`MLKEM768X25519` and leaves its code point TBD, and the IANA MLS registry has
allocated `0x004D` to nothing. Both were checked at source, not taken from the
review.

The vector checks obey this repository's KAT rule (tests/test_mls_wire_kat.py):
"a test that calls the same helper as the producer is not independent
evidence". Every value is re-derived here from RFC 9420 without importing
`scripts/mls_wire.py`; only then is the reference compared with them.
"""
import base64
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "samples" / "cipher-suite-vectors.json").read_text())
REGISTRY = json.loads((ROOT / "registries" / "cipher-suites.json").read_text())
PQ = "MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519"
RETIRED_NAME = "MLS_128_X25519MLKEM768_AES128GCM_SHA256_Ed25519"


# --- an independent RFC 9420 RefHash ----------------------------------------

def _varint(n):
    """RFC 9000 §16 variable-length integer, as RFC 9420 §2.1.2 uses it."""
    if n < 0x40:
        return bytes([n])
    if n < 0x4000:
        return (0x4000 | n).to_bytes(2, "big")
    return (0x80000000 | n).to_bytes(4, "big")


def _refhash_input(label, value):
    lab = label.encode("ascii")
    return _varint(len(lab)) + lab + _varint(len(value)) + value


def _b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ---------------------------------------------------------------------------

def test_the_vectors_are_what_rfc_9420_says_they_are():
    for case in VECTORS["refhash"]:
        inp = _refhash_input(case["label"], bytes.fromhex(case["value_hex"]))
        assert inp.hex() == case["refhash_input_hex"], case["label"]
        assert _b64u(hashlib.sha256(inp).digest()) == case["sha256_b64url"], case["label"]


def test_the_vectors_exercise_the_two_byte_length_form():
    """A 79-byte value takes the two-byte varint. One-byte-only vectors would
    pass an encoder that never implemented the longer form."""
    kp = next(c for c in VECTORS["refhash"] if "KeyPackage" in c["label"])
    assert len(bytes.fromhex(kp["value_hex"])) >= 0x40
    lab = kp["label"].encode()
    assert kp["refhash_input_hex"][2 + 2 * len(lab):][:4] == \
        (0x4000 | len(bytes.fromhex(kp["value_hex"]))).to_bytes(2, "big").hex()


def test_the_reference_agrees_with_the_independent_vectors():
    """Only now is the producer consulted."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import mls_wire as w
    kp, gi = VECTORS["refhash"]
    assert w.suite_hash_name(PQ) == "sha256"
    assert w.keypackage_ref(bytes.fromhex(kp["value_hex"]), cipher_suite=PQ) == kp["sha256_b64url"]
    assert w.group_info_commitment(bytes.fromhex(gi["value_hex"]), cipher_suite=PQ) \
        == gi["sha256_b64url"]


def test_the_code_point_is_private_use_and_says_so():
    cp = REGISTRY["code_points"][PQ]
    value = int(cp["value"], 16)
    assert 0xF000 <= value <= 0xFFFF, "outside the RFC 9420 private-use range"
    assert cp["status"] == "private-use"
    assert VECTORS["code_point"]["wire_hex"] == value.to_bytes(2, "big").hex()


def test_no_value_implies_an_allocation_that_has_not_happened():
    """0x004D was never allocated to this suite; nothing may map it now, and
    only the suites IANA has actually allocated are marked `iana`."""
    sys.path.insert(0, str(ROOT / "scripts"))
    import mls_wire as w
    assert 0x004D not in w.CIPHER_SUITE_NAMES
    assert w.CIPHER_SUITE_NAMES[0xF5C1] == PQ
    iana = {n for n, v in REGISTRY["code_points"].items()
            if not n.startswith("$") and v["status"] == "iana"}
    assert all(int(REGISTRY["code_points"][n]["value"], 16) <= 0x0007 for n in iana)
    assert PQ not in iana


def test_the_name_is_the_one_the_source_defines_and_the_order_is_unchanged():
    """v2 renamed one member of v1 and moved nothing."""
    order = REGISTRY["preference_vector"]["order"]
    assert REGISTRY["preference_vector"]["id"] == "mls-suite-preference/v2"
    assert order[0] == PQ and RETIRED_NAME not in order


def test_the_retained_history_is_not_rewritten():
    """The demo group was formed under registry revision 1; the retained copy
    of that revision keeps the name it had then. Rewriting it would make the
    bundle's record of "the registry as it stood when the group was formed"
    say something that was never true."""
    retained = json.loads((ROOT / "samples" / "suite-registry.demo.json").read_text())
    assert retained["registry_version"] == "1"
    assert retained["preference_vector"]["id"] == "mls-suite-preference/v1"
    assert RETIRED_NAME in retained["preference_vector"]["order"]
