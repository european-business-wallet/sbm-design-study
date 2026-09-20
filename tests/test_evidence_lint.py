# SPDX-License-Identifier: MIT
"""Semantic-conformance (evidence_lint) tests — spec §9.4.

`test_schemas.py` / `test_schema_negative.py` cover JSON-Schema validity.
This module covers *protocol conformance*: the cross-field invariants that
Schema cannot express, checked by `scripts/evidence_lint.py`.

- Every evidence sample MUST be lint-clean (schema-valid AND conformant).
- LINT-PKG-04: the V1 sign-then-timestamp sequencing is verified on mock
  output — strip {seal, qualified_timestamp}, reseal, and confirm the seal
  reproduces and the timestamp imprint == SHA-256(seal).

The negative fixtures (mutations that MUST fail lint) live in
`test_evidence_lint_negative.py`.
"""
import base64
import hashlib
import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


lint_mod = _load("evidence_lint", "evidence_lint.py")
reconstruct = lint_mod.reconstruct  # M4: decode artefacts

EVIDENCE_SAMPLES = [
    "sample-SE.json",
    "sample-SE-multipart.json",
    "sample-SE-scoped.json",
    "sample-DE.json",
    "sample-DE-walletsig.json",
    "sample-DE-scoped.json",
    "sample-NDE.json",
    "sample-NDE-mismatch.json",
    "sample-RE.json",
    "sample-CE.json",
    "sample-EP.json",
    "sample-EP-scoped.json",
]


@pytest.mark.parametrize("sample", EVIDENCE_SAMPLES)
def test_sample_is_lint_clean(sample):
    """Schema-valid is necessary; lint-clean is the conformance bar (§9.4)."""
    doc = reconstruct(json.loads((ROOT / "samples" / sample).read_text(encoding="utf-8")))
    issues = lint_mod.lint(doc)
    assert issues == [], f"{sample} lint violations: {issues}"


def test_lint_hard_fails_without_cbor(monkeypatch):
    """W3: without cbor2 the conformance lint exits non-zero; --dev-mode runs the
    degraded lint (exit follows violations) and prints a NOT-a-conformance notice."""
    monkeypatch.setattr(lint_mod, "_HAVE_CBOR", False)
    sample = str(ROOT / "samples" / "sample-SE.json")
    assert lint_mod.main(["evidence_lint.py", sample]) == 2  # hard fail
    assert lint_mod.main(["evidence_lint.py", "--dev-mode", sample]) == 0  # degraded, clean
    assert lint_mod.main(["evidence_lint.py", "--no-cbor-check", sample]) == 0  # alias


@pytest.mark.parametrize("sample", EVIDENCE_SAMPLES)
def test_verify_demo_signatures(sample):
    """N6/LINT-VERIFY-01: --verify-demo verifies every seal against the demo keys,
    so the reference samples (real demo signatures) are clean in that mode."""
    doc = reconstruct(json.loads((ROOT / "samples" / sample).read_text(encoding="utf-8")))
    rules = [r for r, _ in lint_mod.lint(doc, verify_demo=True)]
    assert "LINT-VERIFY-01" not in rules, (sample, rules)


def test_verify_demo_catches_tampered_signature():
    """A tampered COSE signature fails --verify-demo (LINT-VERIFY-01)."""
    try:
        import cbor2
    except Exception:  # pragma: no cover
        pytest.skip("cbor2 required")
    d = reconstruct(json.loads((ROOT / "samples" / "sample-SE.json").read_text(encoding="utf-8")))
    cose = cbor2.loads(base64.b64decode(d["seal"]["cose_b64"]))
    cose[3] = b"\x00" * 64  # replace the signature
    d["seal"]["cose_b64"] = base64.b64encode(cbor2.dumps(cose)).decode("ascii")
    rules = [r for r, _ in lint_mod.lint(d, verify_demo=True)]
    assert "LINT-VERIFY-01" in rules, rules


def test_scope_ref_mismatch_flags_lint_de_07():
    """LINT-DE-07 (S3/D6): within an EP, a DE whose scope_ref differs from the
    SE's for the same message is flagged."""
    ep = reconstruct(json.loads((ROOT / "samples" / "sample-EP.json").read_text(encoding="utf-8")))
    ep["outcomes"][0]["scope_ref"] = {"scope_id": "other", "version": "9"}
    rules = [r for r, _ in lint_mod.lint(ep)]
    assert "LINT-DE-07" in rules, rules


def test_ep_scope_incoherence_flags_lint_ep_05():
    """LINT-EP-05 (N9): a package cannot span two confidentiality scopes — an
    outcome whose scope_ref differs from the enclosed SE's is flagged."""
    ep = reconstruct(json.loads((ROOT / "samples" / "sample-EP-scoped.json").read_text(encoding="utf-8")))
    # the scoped chain lives in the finance scope (F-08) — diverge to legal
    ep["outcomes"][0]["scope_ref"] = {"scope_id": "legal", "version": "1"}
    rules = [r for r, _ in lint_mod.lint(ep)]
    assert "LINT-EP-05" in rules, rules


def test_ep_hop_evidence_mismatch_flags_lint_ep_06():
    """LINT-EP-06 (finding 2, twentieth review): an OPTIONAL per-hop relay-evidence
    reference (profile-2 four-corner, FC-2) must bind THIS package — its message_id
    equals the EP message_id. A hop reference for a different message is flagged;
    a well-formed one is not."""
    ep = reconstruct(json.loads((ROOT / "samples" / "sample-EP.json").read_text(encoding="utf-8")))
    good = {
        "event": "B.1-RelayAcceptance",
        "message_id": ep["message_id"],
        "seal_digest": {"alg": "SHA-256", "hex": "a" * 64},
    }
    ep["rdp_chain"][0]["evidence"] = good
    assert "LINT-EP-06" not in [r for r, _ in lint_mod.lint(ep)]
    # now break the binding: the hop references a different message
    ep["rdp_chain"][0]["evidence"] = {**good, "message_id": "01HZ3NOTTHISMESSAGE00000000"}
    rules = [r for r, _ in lint_mod.lint(ep)]
    assert "LINT-EP-06" in rules, rules


def test_federated_ep_seal_digest_pins_the_decoded_cose_bytes():
    """CF-5 (twenty-first review): the published profile-2 EP's per-hop reference
    digests the DECODED COSE_Sign1 bytes of the referenced B.1's seal — NOT the
    base64 text. Both are readings of "the SHA-256 of its seal" and they yield
    different digests; this test pins the INPUT in bytes, so an implementer can
    self-check against the sample rather than against prose. The decoded bytes are
    the profile's one convention (the LINT-PKG-08 timestamp imprint uses the same
    input, so a seal has exactly one digest)."""
    import base64
    import hashlib
    ep = reconstruct(json.loads((ROOT / "samples" / "sample-EP-federated.json").read_text(encoding="utf-8")))
    b1 = reconstruct(json.loads((ROOT / "samples" / "sample-RELAY-b1.json").read_text(encoding="utf-8")))
    ref = next(h["evidence"] for h in ep["rdp_chain"] if "evidence" in h)
    # the reference binds THIS package and THAT object
    assert ref["message_id"] == ep["message_id"] == b1["message_id"]
    assert ref["event"] == b1["event"]
    # ...and its digest is over the decoded seal bytes
    decoded = hashlib.sha256(base64.b64decode(b1["seal"]["cose_b64"])).hexdigest()
    base64_text = hashlib.sha256(b1["seal"]["cose_b64"].encode()).hexdigest()
    assert ref["seal_digest"]["hex"] == decoded
    assert ref["seal_digest"]["hex"] != base64_text  # the reading NOT taken
    # the hop carrying the reference is the B.1's ISSUER (its receiving RDP)
    hop = next(h for h in ep["rdp_chain"] if "evidence" in h)
    assert hop["rdp_id"] == b1["receiving_rdp_id"]


def test_ep_outcome_finality_lint_ep_07():
    """Finding R4 (twenty-fourth review): an EP carries at most ONE terminal
    outcome (DE / NDE / RE) for its message. A DE together with a terminal NDE is
    contradictory finality and is rejected; supplementary evidence belongs in
    changes/states, not as a second terminal outcome."""
    ep = reconstruct(json.loads((ROOT / "samples" / "sample-EP.json").read_text(encoding="utf-8")))
    assert "LINT-EP-07" not in [r for r, _ in lint_mod.lint(ep)]  # one DE, clean
    nde = reconstruct(json.loads((ROOT / "samples" / "sample-NDE.json").read_text(encoding="utf-8")))
    nde["message_id"] = ep["message_id"]
    ep["outcomes"].append(nde)  # a DE *and* a terminal NDE for the same message
    assert "LINT-EP-07" in [r for r, _ in lint_mod.lint(ep)]


def test_relay_evidence_semantic_rules_lint_rly():
    """LINT-RLY-01/02 (finding 1, twentieth review): a B.2 rejection needs a typed
    reason; a relay hop is between two DISTINCT providers. The clean samples pass;
    the mutations fire."""
    b2 = reconstruct(json.loads((ROOT / "samples" / "sample-RELAY-b2.json").read_text(encoding="utf-8")))
    assert not [r for r, _ in lint_mod.lint(b2) if r.startswith("LINT-RLY")]
    bad_reason = {**b2, "reason": "recipient-unreachable"}
    assert "LINT-RLY-01" in [r for r, _ in lint_mod.lint(bad_reason)]
    b1 = reconstruct(json.loads((ROOT / "samples" / "sample-RELAY-b1.json").read_text(encoding="utf-8")))
    assert not [r for r, _ in lint_mod.lint(b1) if r.startswith("LINT-RLY")]
    same_rdp = {**b1, "receiving_rdp_id": b1["sending_rdp_id"]}
    assert "LINT-RLY-02" in [r for r, _ in lint_mod.lint(same_rdp)]


def test_mock_v1_sequencing():
    """LINT-PKG-04: on mock output, the signed payload (object minus seal +
    qualified_timestamp) re-seals to the stored seal, and the timestamp imprint
    equals SHA-256 of the seal bytes — i.e. seal-then-timestamp, not circular."""
    import os
    os.environ["KEY_SEED"] = "demo"
    try:
        mock = _load("mock_rdp", "mock_rdp.py")
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"mock_rdp not importable ({exc})")
    ep = mock.make_evidence({
        "from_uid": "EU-DE-EOID-7K3D9W0Q2M5FW0",
        "to_uid": "EU-FR-PSBID-ZYWVTSRQPNM8M4",
        "payload_hash": {
            "alg": "SHA-256",
            "hex": "d8bae9a71f8d30c5cf47817ac8299037541d1a46aa1ee2edd476e3b1119ec77e",
            "hash_mode": "jcs-sha256"},
    })
    # M4: `ep` is the authoritative artefact {sm_artifact_b64, projection}.
    import cbor2
    # reconstructing + linting verifies every seal's dCBOR payload binding
    # (LINT-PKG-06) and its imprint (LINT-PKG-08), incl. the nested sub-artefacts.
    assert lint_mod.lint(reconstruct(ep)) == []
    # and the top-level EP timestamp imprints its own inner COSE bytes.
    cose, qts = cbor2.loads(base64.b64decode(ep["sm_artifact_b64"]))
    tok = base64.b64decode(qts["token_b64"])
    assert tok[0] == 0x30, "timestamp token must be a DER SEQUENCE"
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "scripts"))
    import lint_cli as _lc
    assert _lc.parse_demo_qts(tok)[0] == hashlib.sha256(bytes(cose)).digest(), \
        "qualified timestamp must imprint SHA-256 of the inner COSE bytes"


def _collect_sigs(doc):
    """Yield (b64_signature, demo_seed) for every COSE signature in a doc."""
    if isinstance(doc.get("seal"), dict) and "cose_b64" in doc["seal"]:
        yield (doc["seal"]["cose_b64"], "demo")
    for key in ("s3_attestation", "recipient_confirmation",
                "sender_confirmation", "refusal_confirmation"):
        conf = doc.get(key)
        if isinstance(conf, dict) and "wallet_signature_b64" in conf:
            # X-32: per-device wallet keys
            yield (conf["wallet_signature_b64"],
                   f"wallet:{conf.get('mid', '')}:{conf.get('device_id', '')}")
    for q in doc.get("quorum") or []:
        if isinstance(q, dict) and "wallet_signature_b64" in q:
            yield (q["wallet_signature_b64"],
                   f"wallet:{q.get('mid', '')}:{q.get('device_id', '')}")
    if doc.get("type") == "EP-v1":
        if "se" in doc:
            yield from _collect_sigs(doc["se"])
        for o in doc.get("outcomes", []):
            yield from _collect_sigs(o)
        for c in doc.get("changes") or []:
            yield from _collect_sigs(c)


@pytest.mark.parametrize("sample", EVIDENCE_SAMPLES)
def test_sample_signatures_verify_against_demo_key(sample):
    """LINT-PKG-07 (test form, X2): every sample COSE_Sign1 is a REAL Ed25519
    signature verifiable against the published deterministic demo public key —
    not an HMAC placeholder."""
    try:
        import cbor2
        from nacl.signing import VerifyKey
    except Exception:  # pragma: no cover
        pytest.skip("pynacl/cbor2 required for signature verification")
    mock = _load("mock_rdp", "mock_rdp.py")
    vks = {}

    def _vk(seed):
        if seed not in vks:
            vks[seed] = VerifyKey(base64.b64decode(mock.demo_public_key_b64(seed)))
        return vks[seed]
    doc = reconstruct(json.loads((ROOT / "samples" / sample).read_text(encoding="utf-8")))
    sigs = list(_collect_sigs(doc))
    assert sigs, f"{sample}: no signatures found"
    for b64, seed in sigs:
        cose = cbor2.loads(base64.b64decode(b64))
        protected, _unprotected, payload, sig = cose
        to_sign = mock._cbor_any(["Signature1", protected, b"", payload])
        _vk(seed).verify(to_sign, sig)  # raises nacl.exceptions.BadSignatureError if invalid
