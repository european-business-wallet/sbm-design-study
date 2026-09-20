# SPDX-License-Identifier: MIT
"""X-11 — suspension holds an in-flight message; it never silently terminates.

Former defect: §4.4 made suspension immediately terminal for every queued,
not-yet-delivered message (NDE `uid-suspended`); with EP finality (one
terminal outcome) a ten-minute suspension killed a three-day-TTL message,
and nothing distinguished suspension-at-event from suspension-at-expiry.

Chosen model (approved): HOLD-until-reactivation-or-expiry. Suspension
pauses delivery (no legal-effect event during it — the §5.7 gate);
reactivation before `expires_at` resumes delivery; expiry during the
suspension yields NDE `expired` (the authenticated deadline is the only
clock that terminates a held message — LINT-BND-22 enforces it);
suspension-to-retirement yields NDE `uid-retired`. `uid-suspended` remains
an INTAKE reason only.

The timelines below are exercised against the real machinery: the resumed
DE and each terminal NDE are validated by schema + the X-30 event table +
the LINT-BND-22 temporal-coherence rule against the message's SE.
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

UMB = (ROOT / "Secure-Business-Messaging-Profile.md").read_text()
SE = json.load(open(ROOT / "samples" / "sample-SE.json"))["projection"]
DE = json.load(open(ROOT / "samples" / "sample-DE.json"))["projection"]
NDE = json.load(open(ROOT / "samples" / "sample-NDE.json"))["projection"]

# The acceptance timeline: sent_at + a 3-day TTL; a 10-minute suspension.
SENT = SE["sent_at"]                       # 2026-04-04T10:15:xxZ family
EXPIRES = SE["expires_at"]


def _bnd22(evidence):
    issues = bl.check_bundle(SE["recipient_uid"], {}, {}, [], evidence)
    return [m for r, m in issues if r == "LINT-BND-22"]


# ---------------------------------------------------------------------------
# The model is stated
# ---------------------------------------------------------------------------

def test_the_hold_model_is_normative_and_the_terminal_rule_is_gone():
    assert "HELD, not terminated" in UMB
    assert "no legal-effect event may occur while it lasts" in UMB
    former = ("when suspension takes effect **MUST** also result in "
              "**NDE-v1** `uid-suspended`")
    assert former not in UMB, "the terminal-at-suspension sentence must be gone"
    assert "`uid-suspended` is an **intake** reason" in UMB


# ---------------------------------------------------------------------------
# Timeline 1 — the acceptance case: 10-minute suspension, 3-day TTL
# ---------------------------------------------------------------------------

def test_a_ten_minute_suspension_on_a_three_day_ttl_delivers():
    """ONE outcome: the resumed DE, delivered after reactivation and within
    the authenticated deadline — temporally coherent with the SE."""
    de = copy.deepcopy(DE)
    de["delivered_at"] = "2026-04-04T10:30:00Z"   # after the 10-min hold
    assert de["delivered_at"] < EXPIRES
    assert not _bnd22([copy.deepcopy(SE), de]), \
        "the resumed delivery must be LINT-BND-22-clean"


# ---------------------------------------------------------------------------
# Timeline 2 — expiry during the suspension: NDE expired, never premature
# ---------------------------------------------------------------------------

def test_expiry_during_suspension_yields_nde_expired():
    nde = copy.deepcopy(NDE)
    nde["message_id"] = SE["message_id"]
    nde["reason"] = "expired"
    nde["event"] = "C.5-AcceptanceRejectionExpiry"
    nde["observed_at"] = "2026-05-09T00:00:00Z"   # past expires_at
    assert nde["observed_at"] > EXPIRES
    assert not lc.validate_body(nde)
    assert not _bnd22([copy.deepcopy(SE), nde])


def test_negative_a_held_message_cannot_be_expired_early():
    """The deadline is the ONLY clock that terminates a held message: an
    `expired` NDE observed during the suspension but before expires_at is
    premature and fails LINT-BND-22 — suspension itself terminates nothing."""
    nde = copy.deepcopy(NDE)
    nde["message_id"] = SE["message_id"]
    nde["reason"] = "expired"
    nde["event"] = "C.5-AcceptanceRejectionExpiry"
    nde["observed_at"] = "2026-04-04T10:25:00Z"   # inside the 10-min hold
    assert nde["observed_at"] < EXPIRES
    assert _bnd22([copy.deepcopy(SE), nde]), \
        "a premature expired NDE during a hold must fail LINT-BND-22"


# ---------------------------------------------------------------------------
# Timeline 3 — the suspension resolves to retirement
# ---------------------------------------------------------------------------

def test_suspension_to_retirement_yields_uid_retired():
    nde = copy.deepcopy(NDE)
    nde["message_id"] = SE["message_id"]
    nde["reason"] = "uid-retired"
    nde["event"] = "D.2-ContentConsignmentFailure"
    assert not lc.validate_body(nde)
    v = el.Violations()
    el.lint_nde(v, nde)
    assert not [m for r, m in v.items if r == "LINT-NDE-07"]


# ---------------------------------------------------------------------------
# The delivered-before-suspension message retains its DE
# ---------------------------------------------------------------------------

def test_a_message_past_its_delivery_point_retains_its_de():
    assert "retains its DE-v1" in UMB
    assert "tie = delivered" in UMB
