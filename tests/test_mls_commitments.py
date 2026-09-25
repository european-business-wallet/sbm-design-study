# SPDX-License-Identifier: MIT
"""R-02 / D3 — the MLS commitments are byte-exact over real wire structs.

Former defect: `envelope_hash` $ref'd the generic `Hash` (a signed SE carrying
a SHA-512 mode selector was schema-valid), `mls_state` enumerated two hashes with no
cipher suite/version/extensions, and the mock hashed a SYNTHETIC string, not MLS
octets. Evidence 2.2 introduces the dedicated fixed types EnvelopeHash
(SHA-256 over TLS-serialize(MLSMessage)) and MlsStateHash (SHA-256 over
TLS-serialize(GroupContext)) with scripts/mls_wire.py as the reference
serializer.

Known-answer test: the serialized bytes and their hash are pinned, so an
independent implementation reproduces them from RFC 9420 + the I-D alone.
One-byte mutation: any change to the transmitted octets changes the commitment
and fails the SE<->confirmation cross-check (LINT-DE-16).
"""
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import mls_wire as w  # noqa: E402
import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- Known-answer: the TLS serialization itself is pinned -------------------

def test_kat_mls_message_serialization():
    """A fully pinned MLSMessage: fixed inputs -> fixed bytes -> fixed hash."""
    pm = w.serialize_private_message(
        group_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        epoch=7, authenticated_data=b"", encrypted_sender_data=b"\x01\x02",
        ciphertext=b"\xaa" * 4)
    msg = w.serialize_mls_message(pm)
    # header: mls10 (0001) + wire_format private_message (0002)
    assert msg[:4] == bytes.fromhex("00010002")
    # group_id<V>: varint len 16 (0x10) + 16 bytes
    assert msg[4:5] == b"\x10" and msg[5:21] == bytes.fromhex(
        "00112233445566778899aabbccddeeff")
    # epoch uint64
    assert msg[21:29] == (7).to_bytes(8, "big")
    # content_type application (01), then AD<V>=00, ESD<V>=02 0102, CT<V>=04 aaaaaaaa
    assert msg[29:] == bytes.fromhex("01" "00" "02" "0102" "04" "aaaaaaaa")
    assert hashlib.sha256(msg).hexdigest() == (
        "15d50c0e127e636735c57f620406a56e24927575eae0998d456dca9256ca100e")


def test_kat_group_context_serialization():
    gc = w.serialize_group_context(
        cipher_suite=0x0001,
        group_id=bytes.fromhex("00112233445566778899aabbccddeeff"),
        epoch=7, tree_hash=b"\x11" * 32, confirmed_transcript_hash=b"\x22" * 32,
        extensions=b"")
    assert gc[:4] == bytes.fromhex("00010001")  # mls10 + baseline suite
    assert gc[4:5] == b"\x10"                    # group_id length varint
    assert gc[21:29] == (7).to_bytes(8, "big")
    assert gc[29:30] == b"\x20" and gc[30:62] == b"\x11" * 32   # tree_hash<V>
    assert gc[62:63] == b"\x20" and gc[63:95] == b"\x22" * 32   # transcript<V>
    assert gc[95:] == b"\x00"                    # empty extensions<V>
    assert hashlib.sha256(gc).hexdigest() == (
        "380c2fecc4a628dc47bed6ddf90e6d2ea02f9ba1d9468222d87e70ed682f2076")


def test_varint_boundaries():
    assert w.varint(0) == b"\x00" and w.varint(0x3F) == b"\x3f"
    assert w.varint(0x40) == b"\x40\x40"
    assert w.varint(0x3FFF) == b"\x7f\xff"
    assert w.varint(0x4000) == bytes.fromhex("80004000")


# --- The evidence commitments are these bytes' hashes -----------------------

SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]


def test_sample_envelope_hash_is_the_mls_message_hash():
    msg = w.demo_mls_message(SE["message_id"], SE["mls_group_id"], SE["mls_epoch"])
    assert SE["envelope_hash"] == {"format": "mls10-message",
                                   "hex": hashlib.sha256(msg).hexdigest()}


def test_sample_mls_state_is_the_group_context_hash():
    gc = w.demo_group_context(SE["mls_group_id"], SE["mls_epoch"])
    assert SE["mls_state"] == {"format": "mls10-group-context",
                               "hex": hashlib.sha256(gc).hexdigest()}


def test_one_byte_mutation_changes_the_commitment_and_fails_the_cross_check():
    """The acceptance criterion: mutate ONE byte of the transmitted MLSMessage ->
    the commitment differs -> a confirmation echoing the true value no longer
    matches an SE sealed over the mutated one (LINT-DE-16)."""
    el = _load("evidence_lint", "evidence_lint.py")
    msg = bytearray(w.demo_mls_message(SE["message_id"], SE["mls_group_id"],
                                       SE["mls_epoch"]))
    msg[-1] ^= 0x01  # one flipped bit in the ciphertext
    mutated = w.envelope_hash(bytes(msg))
    assert mutated != SE["envelope_hash"]
    # DE cross-check: the confirmation echoes the TRUE value; an SE claiming the
    # mutated one diverges -> LINT-DE-16.
    de = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]
    se_bad = copy.deepcopy(SE)
    se_bad["envelope_hash"] = mutated
    v = el.Violations()
    el.lint_de(v, copy.deepcopy(de), se=se_bad)
    assert any(r == "LINT-DE-16" for r, _ in v.items), v.items


def test_generic_hash_shape_is_unrepresentable():
    """R-02's first acceptance criterion: SHA-512 and the manifest modes are
    schema-REJECTED for envelope_hash (the dedicated type has no selectors) —
    including a mode the profile does define, because the selector itself is
    what the dedicated type removes."""
    bad = copy.deepcopy(SE)
    bad["envelope_hash"] = {"alg": "SHA-512", "hex": "a" * 128,
                            "hash_mode": "raw-sha512"}
    assert lc.validate_body(bad), "the generic-Hash shape must be schema-invalid"
    bad2 = copy.deepcopy(SE)
    bad2["mls_state"] = {"tree_hash": "x", "confirmed_transcript_hash": "y"}
    assert lc.validate_body(bad2), "the 2.1 enumerated pair must be schema-invalid"
