# SPDX-License-Identifier: MIT
"""Production-profile lint tests (X7).

`evidence_lint --profile production` adds LINT-PROD-01..03: the seal must embed
a verifier-resolvable QSealC identity (COSE x5chain/x5t), a TSA identifier must
be present, and no demo identifiers may appear. The pilot demo samples MUST fail
production mode; a purpose-built production fixture MUST pass.
"""
import base64
import copy
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


def _production_se():
    """A purpose-built production SE: non-demo identifiers, a TSA id, and an
    x5chain in the COSE protected header. Not one of the pilot demo samples."""
    mock = _load("mock_rdp", "mock_rdp.py")
    se = copy.deepcopy(reconstruct(json.loads((ROOT / "samples" / "sample-SE.json").read_text())))
    se.pop("seal", None)
    se["profile"] = "production"
    se["rdp_id"] = "urn:sbm:rdp:eu-qtsp-001"
    se["policy_id"] = "https://rdp.qtsp.eu/policy/qerds/1"
    payload = mock._dcbor(se)
    cose = mock.cose_sign(payload, kid="EU-QTSP-001", seed="demo",
                          extra_ph={33: b"DUMMY_DER_QSEALC_CHAIN"})  # 33 = COSE x5chain
    cose_b64 = base64.b64encode(cose).decode()
    imprint = hashlib.sha256(base64.b64decode(cose_b64)).digest()
    der = b"\x30\x22\x04\x20" + imprint
    se["seal"] = {
        "cose_b64": cose_b64,
        "qualified_timestamp": {
            "format": "rfc3161",
            "token_b64": base64.b64encode(der).decode(),
            "tsa_id": "QTSA:EU:QTSP-TS-01",
        },
    }
    return se


def test_production_fixture_is_clean():
    assert lint_mod.lint(_production_se(), profile="production") == []


def test_pilot_demo_sample_fails_production_mode():
    se = reconstruct(json.loads((ROOT / "samples" / "sample-SE.json").read_text()))
    rules = [r for r, _ in lint_mod.lint(se, profile="production")]
    assert "LINT-PROD-01" in rules   # no x5chain / x5t in the demo seal
    assert "LINT-PROD-03" in rules   # demo kid / MockEU / example.eu / pilot profile
    # ...but the same sample is clean in the default pilot mode.
    assert lint_mod.lint(se, profile="pilot") == []


def _production_de(wallet_x5chain):
    """A DE with a clean PRODUCTION rdp seal, whose recipient confirmation is
    wallet-signed with OR without an x5chain — so a LINT-PROD-01 is attributable
    to the WALLET signature, not the RDP seal (finding D)."""
    mock = _load("mock_rdp", "mock_rdp.py")
    de = copy.deepcopy(reconstruct(json.loads((ROOT / "samples" / "sample-DE-walletsig.json").read_text())))
    de["profile"] = "production"
    de["rdp_id"] = "urn:sbm:rdp:eu-qtsp-001"
    de["policy_id"] = "https://rdp.qtsp.eu/policy/qerds/1"
    # (1) re-sign the wallet confirmation, with or without an x5chain in its header
    conf = de["s3_attestation"]
    conf.pop("wallet_signature_b64", None)
    wpayload = mock._dcbor(conf)
    extra = {33: b"DUMMY_DER_QSEALC_CHAIN"} if wallet_x5chain else {}
    conf["wallet_signature_b64"] = base64.b64encode(mock.cose_sign(
        wpayload, kid=("EU-WALLET-001" if wallet_x5chain else "wallet"),
        seed="demo", extra_ph=extra)).decode()
    # (2) give the DE itself a clean production seal (x5chain, non-demo identity)
    de.pop("seal", None)
    de_cose_b64 = base64.b64encode(mock.cose_sign(
        mock._dcbor(de), kid="EU-QTSP-001", seed="demo",
        extra_ph={33: b"DUMMY_DER_QSEALC_CHAIN"})).decode()
    imprint = hashlib.sha256(base64.b64decode(de_cose_b64)).digest()
    de["seal"] = {
        "cose_b64": de_cose_b64,
        "qualified_timestamp": {
            "format": "rfc3161",
            "token_b64": base64.b64encode(b"\x30\x22\x04\x20" + imprint).decode(),
            "tsa_id": "QTSA:EU:QTSP-TS-01",
        },
    }
    return de


def test_production_applies_the_identity_rule_to_the_wallet_signature():
    """Finding D: at the production profile the wallet advanced electronic
    signature must carry a verifier-resolvable x5chain, the SAME rule as the RDP
    seal. The DE seal is clean-production in both cases, so LINT-PROD-01 here is
    the WALLET signature — which was never checked before this cycle."""
    # a demo-kid wallet signature with no x5chain fails
    rules = [r for r, _ in lint_mod.lint(_production_de(False), profile="production")]
    assert "LINT-PROD-01" in rules
    # ...and one carrying an x5chain passes (no LINT-PROD-01 anywhere — DE seal is clean too)
    ok = [r for r, _ in lint_mod.lint(_production_de(True), profile="production")]
    assert "LINT-PROD-01" not in ok
