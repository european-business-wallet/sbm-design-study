# SPDX-License-Identifier: MIT
"""X-04 / D5 — availability finality, rebuttable by a proven mismatch.

The availability DE stays FINAL at authenticated S2 (settled D5); the GCM-v1
dispute object lets the recipient PROVE a grade-commitment mismatch by revealing
the envelope's true (salt, content_class). Valid iff the recomputation differs
from the sealed commitment OR it matches but the class is not
availability-declared; a matching+availability-declared reveal is VOID.

The fixtures encode the finding's acceptance: an invoice committed under
availability treatment cannot silently keep it (the GCM rebuts), and a forged
GCM against an honest availability delivery is rejected.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")
bl = _load("bundle_lint", "bundle_lint.py")
GCM = json.load(open(ROOT / "samples" / "sample-GCM.json"))["projection"]


def _default_bundle(extra_evidence):
    m = bl.reconstruct(json.loads(
        (ROOT / "samples" / "bundle.default.manifest.json").read_text()))
    base = ROOT / "samples"

    def _rc(x):
        return bl.reconstruct(json.loads((base / x).read_text()))
    ev = [_rc(x) for x in m["evidence"]] + extra_evidence
    return [m["entity_uid"], _rc(m["med"]), _rc(m["org"]),
            [_rc(x) for x in m["members"]], ev]


def test_shipped_gcm_is_schema_and_lint_clean():
    assert lc.validate_body(GCM) == []
    v = el.Violations()
    el.lint_gcm(v, bl.reconstruct(json.load(
        open(ROOT / "samples" / "sample-GCM.json"))))
    assert v.items == [], v.items


def test_valid_mismatch_rebuttal_passes_the_bundle_check():
    """Mode (b): the reveal recomputes to the sealed commitment AND 'invoice' is
    NOT availability-declared (the FR ORG declares only regulatory-filing) —
    a truthfully-committed non-availability class got availability treatment:
    the GCM is a VALID rebuttal (no LINT-BND-26 violation)."""
    gcm = bl.reconstruct(json.load(open(ROOT / "samples" / "sample-GCM.json")))
    issues = bl.check_bundle(*_default_bundle([gcm]))
    assert not [m for r, m in issues if r == "LINT-BND-26"], issues


def test_forged_gcm_against_an_honest_availability_delivery_is_void():
    """The positive-delivery protection: a 'dispute' whose reveal matches the
    sealed commitment AND whose class IS availability-declared proves nothing —
    rejected, the availability DE stands."""
    reveals = json.load(open(ROOT / "samples" / "grade-reveal.demo.json"))["reveals"][0]
    org = bl.reconstruct(json.load(open(ROOT / "samples" / "sample-BW-ORG.json")))
    org_payload = {k: v for k, v in org.items() if k != "doc_cose_b64"}
    org_digest = bl.hashlib.sha256(bl.dcbor(org_payload)).hexdigest()
    forged = copy.deepcopy(GCM)
    forged["message_id"] = reveals["message_id"]  # the honest availability message
    forged["reveal"] = {"salt": reveals["salt"],
                        "content_class": reveals["content_class"]}
    forged["grade_commitment"] = lc.compute_grade_commitment(
        reveals["salt"], reveals["content_class"], org_digest)
    # DR-03 (2.7): the dispute must first be ATTRIBUTABLE — re-sign the
    # recipient confirmation over the forged tuple so the check reaches the
    # VOID arm. (A forged dispute WITHOUT a valid confirmation is rejected
    # earlier and for a different reason; test_gcm_proof_model covers that.)
    mock = _load("mock_rdp", "mock_rdp.py")
    conf = {k: v for k, v in forged["reveal_confirmation"].items()
            if k != "wallet_signature_b64"}
    conf.update({"message_id": forged["message_id"],
                 "envelope_hash": forged["envelope_hash"],
                 "grade_commitment": forged["grade_commitment"],
                 "salt": forged["reveal"]["salt"],
                 "content_class": forged["reveal"]["content_class"]})
    conf["wallet_signature_b64"] = mock._wallet_sign(conf)
    forged["reveal_confirmation"] = conf
    issues = bl.check_bundle(*_default_bundle([forged]))
    assert any(r == "LINT-BND-26" and "VOID" in m for r, m in issues), issues


def test_gcm_never_retracts_the_de_ep_finality_untouched():
    """A GCM is not a terminal outcome: LINT-EP-07 counts DE/NDE/RE only, and
    the EP carries GCMs in disputes[], not outcomes[]."""
    ep_schema = json.loads(
        (ROOT / "schemas" / "evidence-ep.schema.json").read_text())
    assert "disputes" in ep_schema["properties"]
    src = (ROOT / "scripts" / "evidence_lint.py").read_text()
    assert 'in ("DE-v1", "NDE-v1", "RE-v1")' in src or \
           '{"DE-v1", "NDE-v1", "RE-v1"}' in src, "EP-07 terminal set changed"


def test_gcm_in_ep_must_echo_the_disputed_commitment():
    """LINT-GCM-01: within an EP the GCM must reference the SE's sealed value."""
    v = el.Violations()
    se = {"message_id": GCM["message_id"], "grade_commitment": "f" * 64}
    el.lint_gcm(v, copy.deepcopy(GCM), se=se)
    assert any(r == "LINT-GCM-01" and "echo" in m for r, m in v.items), v.items


def test_legal_clause_is_a_marked_todo():
    idtxt = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "TODO(legal)" in idtxt and "D5 LEGAL-CONFIRM" in idtxt
