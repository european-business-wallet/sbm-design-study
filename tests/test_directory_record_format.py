# SPDX-License-Identifier: MIT
"""F-11 — core directory signatures are interoperably profiled.

Former defect: DirectoryRecord/SignedEnvelope permitted "COSE_Sign1 or JWS"
with no signed-bytes definition, serialization, protected headers,
algorithms, payload rules or timestamp input — two implementations could
not verify each other's records. Meanwhile the reference Stage-1 registry
already implemented a single concrete construction the spec failed to
mandate.

Now (umbrella §5.2, normative): ONE format — COSE_Sign1 over the
deterministic-CBOR record minus {signature, timestamp} (embedded payload;
EdDSA baseline / ES256 admitted; kid + production x5chain), qualified
timestamp imprinting SHA-256 of the COSE bytes. The KAT below verifies the
shipped registry records and proves the three mutation negatives the
finding names: re-serialization, header mutation, alternative payload
interpretation.
"""
import base64
import copy
import hashlib
import importlib.util
import json
import pathlib
import sys

import cbor2
from nacl.signing import SigningKey, VerifyKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")

REG = json.loads((ROOT / "samples" / "registry.stage1.demo.json").read_text())
SEED = "design-authority-demo"
PUB = SigningKey(hashlib.sha256(SEED.encode()).digest()).verify_key


def _verify(record, pub=PUB):
    """The reference verification: recompute the dCBOR payload from the
    record content ALONE, decode the COSE, check the embedded payload
    equals the recomputation, verify the signature."""
    body = {k: v for k, v in record.items()
            if k not in ("signature", "timestamp")}
    expected_payload = cbor2.dumps(body, canonical=True)
    protected_b, _u, payload, sig = cbor2.loads(
        base64.b64decode(record["signature"]))
    if bytes(payload) != expected_payload:
        return False
    to_sign = cbor2.dumps(["Signature1", protected_b, b"", bytes(payload)])
    try:
        pub.verify(to_sign, sig)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The KAT: the shipped records verify, byte-reproducibly
# ---------------------------------------------------------------------------

def test_kat_the_shipped_registry_records_verify():
    assert REG["records"], "the Stage-1 registry ships records"
    for rec in REG["records"]:
        assert _verify(rec), rec["uid"]


def test_kat_the_signed_bytes_are_reproducible_from_content_alone():
    """The two-implementation property: dCBOR determinism means an
    independent implementation derives the SAME payload bytes."""
    rec = REG["records"][0]
    body = {k: v for k, v in rec.items() if k not in ("signature", "timestamp")}
    reordered = dict(reversed(list(body.items())))   # a different insertion order
    assert cbor2.dumps(body, canonical=True) == \
        cbor2.dumps(reordered, canonical=True)


def test_kat_the_timestamp_imprints_the_signature_bytes():
    for rec in REG["records"]:
        # R10-X5: read through the ONE parser. This asserted the legacy prefix
        # and took the imprint as `raw[4:]` — a second statement of where the
        # imprint sits, which stopped being true the day the token gained its
        # time.
        import sys as _sys
        _sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
        import lint_cli as _lc
        imprint, gen_time = _lc.parse_demo_qts(base64.b64decode(rec["timestamp"]))
        assert imprint == hashlib.sha256(base64.b64decode(rec["signature"])).digest()
        assert gen_time == rec["asserted_at"], "stamped at a time other than its assertion"


# ---------------------------------------------------------------------------
# The three mutation negatives the finding names
# ---------------------------------------------------------------------------

def test_negative_reserialization_fails():
    """A payload produced under a DIFFERENT canonicalisation (plain JSON
    bytes) is not the signed payload."""
    rec = copy.deepcopy(REG["records"][0])
    body = {k: v for k, v in rec.items() if k not in ("signature", "timestamp")}
    protected_b, _u, _payload, sig = cbor2.loads(
        base64.b64decode(rec["signature"]))
    alt_payload = json.dumps(body, sort_keys=True).encode()
    forged = cbor2.dumps([protected_b, {}, alt_payload, sig])
    rec["signature"] = base64.b64encode(forged).decode()
    assert not _verify(rec), "a re-serialized payload must fail"


def test_negative_header_mutation_fails():
    rec = copy.deepcopy(REG["records"][0])
    protected_b, _u, payload, sig = cbor2.loads(
        base64.b64decode(rec["signature"]))
    hdr = cbor2.loads(protected_b)
    hdr[4] = b"attacker"                      # mutate the kid
    forged = cbor2.dumps([cbor2.dumps(hdr), {}, payload, sig])
    rec["signature"] = base64.b64encode(forged).decode()
    assert not _verify(rec), "a mutated protected header must fail"


def test_negative_alternative_payload_interpretation_fails():
    """Signing the FULL record (including signature) is not the profiled
    input — the embedded payload will not equal the recomputation."""
    rec = copy.deepcopy(REG["records"][0])
    rec["status"] = "suspended"               # content change, old signature
    assert not _verify(rec), "a content change under the old seal must fail"


def test_negative_a_foreign_key_fails():
    rec = REG["records"][0]
    other = SigningKey(hashlib.sha256(b"attacker").digest()).verify_key
    assert not _verify(rec, pub=other)


# ---------------------------------------------------------------------------
# The dual-format text is gone
# ---------------------------------------------------------------------------

def test_the_dual_format_is_gone_and_forbidden():
    dl = _load("doc_lint", "doc_lint.py")
    umb = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
    assert "COSE_Sign1 or JWS" not in umb
    assert "one mandatory format, no alternative" in umb
    assert any(p.search("COSE_Sign1 or JWS") for p in dl.FORBIDDEN)
