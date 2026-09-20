# SPDX-License-Identifier: MIT
"""X-28 — a relay rejection is a relay-stage event, never pre-submission.

Former defect: after sender-side acceptance (A.1/SE), a recipient-side B.2
RelayRejection was exported as an NDE with event `A.2-SubmissionRejection` —
an event history saying the same submission was both accepted and rejected
BEFORE submission, chronologically invalid when read from the EP alone.

Now: the TS clause 4.1 mapping exports every B.2 translation with event
`B.3-RelayFailure` (the relay stage; the X-30 registry rows admit it), and
LINT-BND-31 enforces it where a bundle carries the B.2 and the sender NDE
for the same message. The selected mapping is documented as a translation
pending standards-owner (ETSI TC ESI) review — the finding's open residual.
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

ENTITY = "EU-DE-EOID-7K3D9W0Q2M5FW0"
RELAY = bl.reconstruct(json.loads(
    (ROOT / "samples" / "sample-RELAY-b2.json").read_text()))   # B.2, policy-violation
NDE = bl.reconstruct(json.loads((ROOT / "samples" / "sample-NDE.json").read_text()))


def _pair(event):
    nde = copy.deepcopy(NDE)
    nde["message_id"] = RELAY["message_id"]
    nde["reason"] = "policy-block"     # the correct BND-19 reason mapping
    nde["event"] = event
    return [copy.deepcopy(RELAY), nde]


def _bnd31(evidence):
    issues = bl.check_bundle(ENTITY, {}, {}, [], evidence)
    return [m for r, m in issues if r == "LINT-BND-31"]


def test_positive_the_b3_translation_is_clean():
    assert not _bnd31(_pair("B.3-RelayFailure"))


def test_negative_the_former_a2_mislabel_fails():
    """The former defect verbatim: accepted at A.1, then 'rejected before
    submission'."""
    msgs = _bnd31(_pair("A.2-SubmissionRejection"))
    assert msgs and "B.3-RelayFailure" in msgs[0]


def test_the_registry_admits_the_relay_stage_for_every_b2_translation():
    """X-30 rows back the mapping: each B.2-translated NDE reason has the
    relay stage bound to B.3-RelayFailure."""
    for b2, entry in lc._REASONS["relay_b2_reasons"].items():
        nde_reason = entry["nde_reason"]
        stages = lc._REASONS["nde_reasons"][nde_reason]["stages"]
        assert stages.get("relay") == "B.3-RelayFailure", (b2, nde_reason)


def test_the_b3_nde_is_event_valid_standalone():
    """LINT-NDE-07 (the registry table) accepts the relay-stage event."""
    nde = _pair("B.3-RelayFailure")[1]
    v = el.Violations()
    el.lint_nde(v, nde)
    assert not [m for r, m in v.items if r == "LINT-NDE-07"]


def test_the_ts_documents_the_pending_standards_review():
    ts = (ROOT / "etsi" / "TS-SBM-QERDS-Binding-v0.1.md").read_text()
    assert "pending standards-owner review (ETSI TC ESI)" in ts
    assert "| `policy-violation` | `policy-block` | `B.3-RelayFailure` |" in ts
