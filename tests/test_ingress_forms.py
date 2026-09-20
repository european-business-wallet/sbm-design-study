# SPDX-License-Identifier: MIT
"""Round 11 / B7 — R11-09 and R11-10: what enters a verifier is checked the
same way whatever form it arrives in, and malformed input is a finding.

R11-09. Both linters accept an artefact as the wire wrapper
`{sm_artifact_b64, projection}` or in the FLAT form (body beside its
`doc_cose_b64` / `seal`), and only the wrapper had its body validated against
the authoritative Schema. A provider descriptor without `endpoints`, genuinely
re-sealed, passed the discovery CLI with `--verify-demo`, the trust store and
an authenticated register — exit 0 — while the identical signed body in the
wrapper got LINT-PKG-12. Phase 1 found it is the whole class: a BW-MEMBER
without `status`, an SE without `sent_at`.

R11-10. Register ingress read the protected `kid`, ignored the declared
algorithm and verified as Ed25519 whatever it said — Ed25519 bytes under `alg`
ES256, 0 or 42 authenticated — and crashed on a null payload (TypeError) and on
a history entry without `status` (KeyError).
"""
import base64
import copy
import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import cbor2  # noqa: E402
import lint_cli as lc  # noqa: E402
import mock_rdp as mock  # noqa: E402
import test_federation_gate as fg  # noqa: E402

SAMPLES = sorted(p for p in (ROOT / "samples").glob("sample-*.json")
                 if "sm_artifact_b64" in json.loads(p.read_text()))
STORE = lc.load_trust_store(str(ROOT / "samples" / "trust-store.demo.json"))


def _ev():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ev_b7", ROOT / "scripts" / "evidence_lint.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _rules(found):
    return {r for r, _ in found}


# ---------------------------------------------------------------------------
# R11-09 — one body, one verdict, whatever the wrapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("drop", ["endpoints", "roles", "version"])
def test_a_descriptor_missing_a_mandatory_field_fails_in_every_form(drop):
    body = copy.deepcopy(fg.DESCRIPTOR["projection"]); body.pop(drop)
    art = mock.discovery_artifact(body, kid=body["kid"], seed=f"{body['kid']}-demo")
    dl = fg._discovery_lint()
    for form in (art, lc.reconstruct(art)):
        found = dl.lint(form, verify_demo=True, trust_store=STORE,
                        federation_register=fg.REGISTER)
        assert "LINT-PKG-12" in _rules(found), (drop, "flat" if form is not art else "wrapper")


def test_the_consuming_cli_refuses_the_flat_form(tmp_path):
    """The review's reproduction, through the actual CLI and its flags."""
    body = copy.deepcopy(fg.DESCRIPTOR["projection"]); body.pop("endpoints")
    art = mock.discovery_artifact(body, kid=body["kid"], seed=f"{body['kid']}-demo")
    flat = tmp_path / "descriptor-flat.json"
    flat.write_text(json.dumps(lc.reconstruct(art)))
    r = subprocess.run([sys.executable, str(ROOT / "scripts" / "discovery_lint.py"),
                        "--verify-demo",
                        "--trust-store", str(ROOT / "samples" / "trust-store.demo.json"),
                        "--federation-register",
                        str(ROOT / "samples" / "federation.stage1.demo.json"), str(flat)],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "LINT-PKG-12" in r.stdout + r.stderr


def test_other_discovery_types_and_evidence_too():
    member = copy.deepcopy(json.loads((ROOT / "samples" / "sample-BW-MEMBER-fr.json")
                                      .read_text())["projection"]); member.pop("status")
    art = mock.discovery_artifact(member, kid="entity-admin")
    assert "LINT-PKG-12" in _rules(fg._discovery_lint().lint(lc.reconstruct(art)))
    se = copy.deepcopy(json.loads((ROOT / "samples" / "sample-SE.json").read_text())
                       ["projection"]); se.pop("sent_at")
    art = mock.evidence_artifact(se, kid="rdp")
    assert "LINT-PKG-12" in _rules(_ev().lint(lc.reconstruct(art)))


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_the_flat_form_normalises_to_exactly_the_projection(path):
    sample = json.loads(path.read_text())
    assert lc.flat_projection(lc.reconstruct(sample)) == sample["projection"]


@pytest.mark.parametrize("path", SAMPLES, ids=lambda p: p.name)
def test_a_valid_artefact_gets_the_same_verdict_in_both_forms(path):
    sample = json.loads(path.read_text())
    is_discovery = str(sample["projection"].get("type", "")).startswith("BW-") or \
        sample["projection"].get("type") in ("STATUS-v1", "ROSTER-v1")
    lint = fg._discovery_lint().lint if is_discovery else _ev().lint
    wrapped = _rules(lint(sample)) - {"LINT-PKG-11"}      # PKG-11 is wrapper-only by definition
    assert _rules(lint(lc.reconstruct(sample))) == wrapped


# ---------------------------------------------------------------------------
# R11-10 — register ingress: a finding, never an exception, never a substitution
# ---------------------------------------------------------------------------

def _resealed(alg):
    """The genuine register, every record re-signed by the demo FA key with
    Ed25519 bytes under a DIFFERENT declared algorithm — the trusted signer,
    not an attacker, which is what makes a silent substitution the defect."""
    reg = copy.deepcopy(fg.REGISTER)
    for i, rec in enumerate(reg["records"]):
        body = {k: v for k, v in rec.items() if k not in ("signature", "timestamp")}
        sig = base64.b64encode(mock.cose_sign(mock._dcbor(body), kid="federation-authority",
                                              seed="federation-authority-demo",
                                              extra_ph={1: alg})).decode()
        reg["records"][i] = dict(body, signature=sig, timestamp=mock._qts_over_cose(
            base64.b64decode(sig), body["asserted_at"])["token_b64"])
    return reg


def _auth(reg):
    return lc.authenticate_register(reg, fg._anchor())


def test_the_genuine_register_still_authenticates():
    got, problems = _auth(fg.REGISTER)
    assert got is not None and problems == []


@pytest.mark.parametrize("alg,says", [
    (-7, "production form (ES256)"), (-35, "production form (ES384)"),
    (0, "not an algorithm this profile permits"),
    (42, "not an algorithm this profile permits"),
])
def test_a_declared_algorithm_is_never_substituted(alg, says):
    got, problems = _auth(_resealed(alg))
    assert got is None, "Ed25519 bytes authenticated under another declared algorithm"
    assert problems and all(says in m for _, m in problems), problems[:1]


def _mutated(fn):
    reg = copy.deepcopy(fg.REGISTER); fn(reg["records"][0]); return reg


def _cose_with(rec, **parts):
    arr = cbor2.loads(base64.b64decode(rec["signature"]))
    items = list(arr.value if hasattr(arr, "value") else arr)
    for idx, val in parts.items():
        items[int(idx[1:])] = val
    rec["signature"] = base64.b64encode(cbor2.dumps(items)).decode()


@pytest.mark.parametrize("name,mutate", [
    ("history entry without status", lambda r: r["status_history"][0].pop("status")),
    ("history entry without from", lambda r: r["status_history"][0].pop("from")),
    ("status_history not a list", lambda r: r.__setitem__("status_history", "admitted")),
    ("null payload", lambda r: _cose_with(r, i2=None)),
    ("text payload", lambda r: _cose_with(r, i2="not bytes")),
    ("protected header not bytes", lambda r: _cose_with(r, i0={1: -8})),
    ("protected header not a map", lambda r: _cose_with(r, i0=cbor2.dumps([1, 2]))),
    ("seal is three elements", lambda r: r.__setitem__(
        "signature", base64.b64encode(cbor2.dumps([b"", {}, b""])).decode())),
    ("record is a string", None),
])
def test_malformed_input_is_a_finding_not_a_crash(name, mutate):
    if mutate is None:
        reg = copy.deepcopy(fg.REGISTER); reg["records"][0] = "not a record"
    else:
        reg = _mutated(mutate)
    got, problems = _auth(reg)                      # must not raise
    assert got is None and problems, name
    assert all(r == "LINT-TRUST-08" for r, _ in problems)
