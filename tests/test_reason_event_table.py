# SPDX-License-Identifier: MIT
"""X-30 — the exhaustive reason × stage × event × external-mapping table.

Former defect: `uid-suspended`, `uid-retired`, `uid-merged` and
`keypackage-replay` carried `allowed_events: null` — unbound to any permitted
event or EN 319 522-2 meaning, so conforming providers could emit
semantically incompatible NDEs for the same condition at different stages.

Now: every ACTIVE nde_reason carries `stages` (stage → EN 319 522-1 clause 6
event), coherent `allowed_events`, and `en_319_522` (the external mapping or
an explicit no-equivalent with the exported translation). A COMPLETE row is
a PREREQUISITE for registration: `lint_cli` refuses to load an incomplete
entry (fail-closed at import), and LINT-NDE-07 enforces the bindings on
evidence.
"""
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import lint_cli as lc  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


el = _load("evidence_lint", "evidence_lint.py")

REG = json.loads((ROOT / "registries" / "reason-codes.json").read_text())
NDE = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]

STAGES = {"intake", "relay", "consignment", "expiry", "handover"}


# ---------------------------------------------------------------------------
# Completeness: every registered reason has its full row
# ---------------------------------------------------------------------------

def test_every_active_reason_has_a_complete_row():
    for code, entry in REG["nde_reasons"].items():
        if entry.get("status") != "active":
            continue
        assert isinstance(entry.get("stages"), dict) and entry["stages"], code
        assert set(entry["stages"]) <= STAGES, (code, entry["stages"])
        assert sorted(set(entry["stages"].values())) == \
            sorted(set(entry["allowed_events"])), code
        assert isinstance(entry.get("en_319_522"), str) and entry["en_319_522"], code


def test_the_formerly_null_reasons_are_bound():
    """The former defect verbatim: the four null bindings."""
    for code in ("uid-suspended", "uid-retired", "uid-merged",
                 "keypackage-replay"):
        entry = REG["nde_reasons"][code]
        assert entry["allowed_events"], f"{code} must no longer be unbound"
        assert code in lc.NDE_REASON_EVENT


def test_mls_specific_reasons_declare_no_equivalent_explicitly():
    for code in ("keypackage-replay", "no-matching-scope", "scope-violation",
                 "mls-group-invalid", "expiry-mismatch",
                 "keypackage-pool-exhausted"):
        assert "no-equivalent" in REG["nde_reasons"][code]["en_319_522"], code


# ---------------------------------------------------------------------------
# The registration prerequisite: an incomplete entry cannot load
# ---------------------------------------------------------------------------

def test_negative_an_incomplete_registration_cannot_load():
    bad = copy.deepcopy(REG["nde_reasons"])
    bad["x-new-reason"] = {"status": "active"}   # no stages/events/mapping
    with pytest.raises(ValueError, match="registration prerequisites"):
        lc._validate_nde_registry(bad)


def test_negative_events_disagreeing_with_stages_cannot_load():
    bad = copy.deepcopy(REG["nde_reasons"])
    bad["uid-suspended"]["allowed_events"] = ["A.2-SubmissionRejection"]
    with pytest.raises(ValueError, match="disagree"):
        lc._validate_nde_registry(bad)


def test_a_retired_entry_is_exempt_from_the_prerequisite():
    ok = copy.deepcopy(REG["nde_reasons"])
    ok["x-old-reason"] = {"status": "retired"}
    lc._validate_nde_registry(ok)   # must not raise


# ---------------------------------------------------------------------------
# LINT-NDE-07 enforces the new bindings on evidence
# ---------------------------------------------------------------------------

def _nde07(body):
    v = el.Violations()
    el.lint_nde(v, body)
    return [m for r, m in v.items if r == "LINT-NDE-07"]


def test_newly_bound_reasons_enforce_their_events():
    for code, good_event in (("uid-suspended", "A.2-SubmissionRejection"),
                             ("uid-retired", "D.2-ContentConsignmentFailure"),
                             ("keypackage-replay", "A.2-SubmissionRejection")):
        ok = copy.deepcopy(NDE)
        ok["reason"] = code
        ok["event"] = good_event
        if code == "uid-merged":
            ok["redirect_uid"] = "EU-DE-EOID-7K3D9W0Q2M5FW0"
        assert not _nde07(ok), (code, _nde07(ok))
        bad = copy.deepcopy(ok)
        bad["event"] = "E.2-ContentHandoverFailure"   # in no stage row of these
        assert _nde07(bad), f"{code} at a stage outside its table must fail"


def test_uid_suspended_admits_the_relay_stage_event():
    ok = copy.deepcopy(NDE)
    ok["reason"] = "uid-suspended"
    ok["event"] = "B.3-RelayFailure"
    assert not _nde07(ok)
