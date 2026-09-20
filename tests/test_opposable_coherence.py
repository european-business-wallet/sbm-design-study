# SPDX-License-Identifier: MIT
"""X-15 — `opposable` is defined once and every layer agrees.

Former defect: Annex R.2 called the mandate commitment OPTIONAL while the
TS and the lint (LINT-DE-15) REQUIRE it when `mandate_ref.opposable` is
true — the default — and Annex R never defined `opposable`: an implementer
following the agent profile alone produced an SE that normative intake
rejects. The schema did not enforce the rule structurally either, so
schema and lint disagreed with each other too.

Now: Annex R.2 DEFINES `opposable` (protocol effect: the commitment,
owned by the I-D Mandate Commitment rule; legal weight: the agreement
layer, per the three-layer rule), states the default (true), and the
MandateRef schema enforces the same rule structurally — the same agent
submission is accepted or rejected identically by Annex R, TS, schema and
reference lint.
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

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
FLAT = " ".join(UMB.split()).replace("*", "").replace("`", "")
SEA = json.load(open(ROOT / "samples" / "sample-SE-agent.json"))["projection"]


def _de15(body):
    v = el.Violations()
    el.lint_se(v, body)
    return [m for r, m in v.items if r == "LINT-DE-15"]


def test_annex_r_defines_opposable_with_the_default():
    assert "opposable (defined here):" in FLAT
    assert "assertable against the principal" in FLAT
    assert "default is true" in FLAT
    assert "an absent opposable field means opposable" in FLAT


def test_the_optional_contradiction_is_gone():
    assert "The OPTIONAL salted `SE.mandate_ref.mandate_commitment`" not in UMB


def test_one_owner_and_the_legal_layer_stays_put():
    assert "owned by the I-D (Mandate Commitment)" in FLAT
    assert "never automatically binding" in FLAT


def test_the_shipped_opposable_agent_se_passes_everywhere():
    assert not lc.validate_body(copy.deepcopy(SEA))
    assert not _de15(copy.deepcopy(SEA))


def test_negative_opposable_without_commitment_rejected_identically():
    """The finding's acceptance: schema and lint agree on the SAME object."""
    bad = copy.deepcopy(SEA)
    bad["mandate_ref"].pop("mandate_commitment")
    assert lc.validate_body(bad), "the schema must reject it"
    assert _de15(bad), "and LINT-DE-15 must reject it"


def test_positive_non_opposable_without_commitment_accepted_identically():
    ok = copy.deepcopy(SEA)
    ok["mandate_ref"].pop("mandate_commitment")
    ok["mandate_ref"]["opposable"] = False
    assert not lc.validate_body(ok), "the schema must accept it"
    assert not _de15(ok), "and the lint must accept it"


def test_negative_non_opposable_with_commitment_is_incoherent():
    bad = copy.deepcopy(SEA)
    bad["mandate_ref"]["opposable"] = False   # keeps the commitment
    assert lc.validate_body(bad), \
        "a non-opposable act carrying a commitment must fail the schema"
