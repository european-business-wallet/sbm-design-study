# SPDX-License-Identifier: MIT
"""F10 (PoC feedback, twelfth review): the Stage-1 registry file convention
(umbrella Annex P.1.1) — samples/registry.stage1.demo.json.

- every record validates against the DirectoryRecord component of the EDD
  resolver OpenAPI (the record shape is SHARED with a Stage-2 resolver, so a
  pilot graduates from file to resolver with no record migration);
- every record's signature is a COSE_Sign1 by the design-authority demo key
  (published in samples/trust-store.demo.json) over the deterministic-CBOR record
  minus {signature, timestamp};
- the timestamp token carries the SHA-256 imprint of the signature bytes —
  the seal-then-timestamp sequencing of the I-D (Evidence Objects and COSE
  Packaging);
- a tampered record fails seal verification (fail-closed demo material).

The demo registry is emitted by scripts/regen_samples.py — never hand-edit.
"""
import base64
import copy
import hashlib
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402  — R10-X5: one reader for the demo token
import cbor2  # noqa: E402


def _need(mod):
    try:
        __import__(mod)
    except Exception:
        pytest.skip(f"{mod} not installed; skipping Stage-1 registry tests",
                    allow_module_level=True)


_need("cbor2")
_need("nacl")

REGISTRY = json.loads(
    (ROOT / "samples" / "registry.stage1.demo.json").read_text(encoding="utf-8"))
STORE = json.loads(
    (ROOT / "samples" / "trust-store.demo.json").read_text(encoding="utf-8"))
DA_PUB = STORE["entries"]["design-authority"]["pubkey_b64"]


def _verify_record(rec, pub_b64=DA_PUB):
    """Seal + timestamp verification per Annex P.1.1 (demo scope)."""
    import cbor2
    from nacl.signing import VerifyKey
    cose = cbor2.loads(base64.b64decode(rec["signature"]))
    protected, _unprotected, payload, sig = cose
    expected = cbor2.dumps(
        {k: v for k, v in rec.items() if k not in ("signature", "timestamp")}, canonical=True)
    assert bytes(payload) == expected, \
        "seal payload != dCBOR record minus {signature, timestamp}"
    to_sign = cbor2.dumps(["Signature1", protected, b"", bytes(payload)])
    VerifyKey(base64.b64decode(pub_b64)).verify(to_sign, sig)
    # demo QTS: DER SEQUENCE{ OCTET STRING(32) }, imprint = SHA-256(signature)
    der = base64.b64decode(rec["timestamp"])
    imprint = hashlib.sha256(base64.b64decode(rec["signature"])).digest()
    assert lc.parse_demo_qts(der)[0] == imprint, \
        "timestamp imprint != SHA-256(signature bytes)"


def test_records_validate_against_the_edd_openapi_component():
    yaml = pytest.importorskip("yaml")
    jsonschema = pytest.importorskip("jsonschema")
    spec = yaml.safe_load(
        (ROOT / "edd-resolver-openapi.yaml").read_text(encoding="utf-8"))
    schema = spec["components"]["schemas"]["DirectoryRecord"]
    assert REGISTRY["records"], "demo registry must not be empty"
    for rec in REGISTRY["records"]:
        jsonschema.validate(instance=rec, schema=schema)


def test_every_record_seal_verifies_with_the_design_authority_key():
    for rec in REGISTRY["records"]:
        _verify_record(rec)


def test_tampered_record_fails_seal_verification():
    rec = copy.deepcopy(REGISTRY["records"][0])
    rec["status"] = "suspended"
    with pytest.raises(AssertionError):
        _verify_record(rec)


def test_wrong_key_fails_seal_verification():
    from nacl.exceptions import BadSignatureError
    rec = REGISTRY["records"][0]
    with pytest.raises(BadSignatureError):
        _verify_record(rec, pub_b64=STORE["entries"]["entity-admin"]["pubkey_b64"])
