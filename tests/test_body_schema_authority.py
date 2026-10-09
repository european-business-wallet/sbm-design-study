# SPDX-License-Identifier: MIT
"""N-02 — one verifier entry point enforces all three properties.

The former defect: the I-D verification algorithm ended with CDDL validation, the
linters never invoked jsonschema, and schema-smoke only checks the shipped
samples — so NO entry point rejected a hostile minimal `{type, version}`
discovery artefact that is CDDL-valid with projection≡payload. Now the decoded
body MUST validate against its authoritative JSON Schema (LINT-PKG-12), enforced
at the linters' ingest path and inside the cddl-check gate.

The negative fixture is the finding's acceptance criterion end-to-end: a REAL
artefact whose body is `{type: BW-ORG-v1, version: "2.1"}` (CDDL-valid,
projection≡payload) is rejected by the discovery linter.
"""
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402
import discovery_lint as dl  # noqa: E402
import evidence_lint as el  # noqa: E402
from cddl_tool import requires_cddl  # noqa: E402



def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mock = _load("mock_rdp", "mock_rdp.py")


@requires_cddl
def test_negative_minimal_discovery_body_is_rejected_at_the_entry_point():
    """The acceptance criterion: CDDL-valid + projection≡payload, Schema-invalid
    → rejected by ONE entry point (the discovery linter), fail-closed."""
    # The version is DERIVED: the CDDL pins the current one, so a literal here
    # makes the vector CDDL-invalid the next time the dimension moves — which
    # is what it was, at "2.1", so the Schema was not the only authority
    # refusing it and this criterion was never exercised.
    _ver = json.loads((ROOT / "versions.json").read_text(encoding="utf-8"))[
        "dimensions"]["discovery_bw_org"]["value"]
    art = mock.discovery_artifact({"type": "BW-ORG-v1", "version": _ver})
    # sanity: the projection equals the decoded payload (N1 holds)
    assert lc.projection_equals_decode(art) == []
    # ...and the premise this criterion rests on — that the body IS CDDL-valid,
    # so the Schema is what refuses it — is checked rather than asserted in the
    # docstring. Without this the test passes on a body the CDDL also refuses,
    # which proves something narrower than it claims.
    import cddl_check
    assert cddl_check._check_body(art["projection"], "minimal BW-ORG"), \
        "the vector must be CDDL-valid, or the Schema is not what rejects it"
    issues = dl.lint(art)
    rules = [r for r, _ in issues]
    assert "LINT-PKG-12" in rules, (
        "a minimal {type, version} BW-ORG body must fail the authoritative "
        f"Schema at the linter entry point; got {issues}")


def test_negative_schema_invalid_evidence_body_is_rejected():
    """Evidence side: a well-typed SE body with a wrong-typed field passes no
    schema. Build a real SE artefact from a shipped sample's body, then break a
    field type the lint rules do not cover."""
    se = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
    bad = dict(se)
    bad["sender_uid"] = 12345  # wrong type — schema says Uid string
    art = mock.evidence_artifact(bad)
    issues = el.lint(art)
    rules = [r for r, _ in issues]
    assert "LINT-PKG-12" in rules, issues


def test_positive_shipped_samples_pass_the_body_schema():
    """Every shipped wrapped sample is Schema-valid at the entry point."""
    for p in sorted((ROOT / "samples").glob("sample-*.json")):
        d = json.loads(p.read_text())
        if not (isinstance(d, dict) and "sm_artifact_b64" in d):
            continue
        assert lc.validate_body(d["projection"]) == [], p.name


def test_cddl_check_gate_reports_all_three_properties():
    """The gate's output names the three properties (one gate = all three)."""
    src = (ROOT / "scripts" / "cddl_check.py").read_text()
    assert "validate_body" in src, "cddl_check no longer runs the Schema step"
    assert "body Schema-valid" in src


def test_id_verification_algorithm_requires_the_schema_step():
    idtxt = (ROOT / "ietf" / "draft-sbm-mls-erd-00.md").read_text()
    assert "authoritative JSON Schema" in idtxt
    assert "CDDL-valid but Schema-invalid" in idtxt
