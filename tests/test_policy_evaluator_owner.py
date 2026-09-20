# SPDX-License-Identifier: MIT
"""X-10 — acceptance-policy evaluation has ONE owner: RDP(in).

Former defect: the umbrella said the MSP "collects per-leaf-node delivery
confirmations within the MLS group and evaluates the policy" while the TS
assigned the legally decisive evaluation to RDP(in) — two owners for one
decision, and per-leaf wording contradicting the distinct-member counting
unit.

Now: the TS clause 6 states the rule once (RDP(in) = the sole
evidence-authoritative evaluator over validated member-level confirmations;
the MSP collects and forwards only); the umbrella roles clause carries the
responsibility table (informative, deferring to the TS); the rule-ownership
family `acceptance-policy-evaluator` and a doc_lint FORBIDDEN pattern keep
the two-owner phrasing from returning.
"""
import importlib.util
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dl = _load("doc_lint", "doc_lint.py")

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
TS = (ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text()
FORMER_DEFECT = ("The MSP collects per-leaf-node delivery confirmations "
                 "within the MLS group and evaluates the policy.")


def _forbidden_hits(text):
    return [p.pattern for p in dl.FORBIDDEN if p.search(text)]


def test_the_ts_owns_the_sole_evaluator_rule():
    assert re.search(r"RDP\(in\) shall be the \*\*sole evidence-authoritative "
                     r"evaluator\*\*", TS), \
        "the TS clause 6 must state the evaluator-of-record rule"


def test_the_umbrella_names_exactly_one_decision_maker():
    assert "RDP(in) — the sole decision-maker" in UMB, \
        "the responsibility table must name exactly one DE decision-maker"
    assert FORMER_DEFECT not in UMB, "the two-owner sentence must be gone"


def test_negative_the_former_two_owner_sentence_is_forbidden():
    """The former defect verbatim trips the doc_lint guard."""
    assert _forbidden_hits(FORMER_DEFECT), \
        "doc_lint must forbid the MSP-evaluates phrasing"
    assert _forbidden_hits("the MSP evaluates the acceptance policy")


def test_the_current_prose_does_not_trip_the_guard():
    for text in (UMB, TS):
        hits = [p.pattern for p in dl.FORBIDDEN
                if "MSP" in p.pattern and p.search(text)]
        assert not hits, hits


def test_the_schema_description_defers_to_the_single_owner():
    d = json.loads((ROOT / "schemas" / "bw-org.schema.json").read_text())
    desc = d["properties"]["acceptance_policy"]["additionalProperties"]["description"]
    assert "RDP(in) alone" in desc and "MSP/RDP" not in desc


def test_no_per_leaf_policy_evaluation_wording_remains():
    """The counting unit is the distinct active member, never the leaf."""
    assert not re.search(r"per-leaf(-node)? [a-z ]*(polic|evaluat)", UMB, re.I)
    assert not re.search(r"per-leaf(-node)? [a-z ]*(polic|evaluat)", TS, re.I)
