# SPDX-License-Identifier: MIT
"""DR-11 — historical member/key resolution, actually integrated.

Former defect (round-2 review, High): INTF-2 has required since X-17 that the
confirmation key and the member's status be resolved AS THEY STOOD AT THE ACT,
and `as_of_resolve()` implemented exactly that — but nothing in `bundle_lint`
ever called it. The linter built `by_mid` from members whose CURRENT status is
`active` and verified signatures against their CURRENT device keys. It consumed
no history, no ROSTER snapshot, and never looked at `device.added_at`.
`as_of_resolve` was tested only as an isolated helper, which is why the gap
survived: the helper passed its own tests while no production path used it.

Two opposite errors followed, and the second is the dangerous one:

  * a confirmation that was valid when it was made was REJECTED once the member
    retired — evidence decaying with the roster;
  * a signature under a key ADDED AFTER the claimed act was ACCEPTED — a key
    minted today could validate a confirmation dated yesterday.

`LINT-BND-34` closes both. This file drives `check_bundle` end to end rather
than the resolver in isolation, because "specified but not integrated" is the
finding: a test that exercises only the helper would have passed before the fix.
"""
import copy
import importlib.util
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")
mock = _load("mock_rdp", "mock_rdp.py")


MANIFEST = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
SAMPLES = ROOT / "samples"


def _doc(filename):
    """Load a sample the way bundle_lint's own loader does — the M4 artefact
    reconstructed from its authoritative payload."""
    return bl._load(str(SAMPLES / filename))


ENTITY = MANIFEST["entity_uid"]
MED = _doc(MANIFEST["med"])
ORG = _doc(MANIFEST["org"])
MEMBERS = [_doc(m) for m in MANIFEST["members"]]
EVIDENCE = [_doc(e) for e in MANIFEST["evidence"]]
REVEALS = {r["message_id"]: r for r in json.loads(
    (SAMPLES / MANIFEST["grade_reveals"]).read_text())["reveals"]}

DE = next(e for e in EVIDENCE if e.get("type") == "DE-v1"
          and e.get("s3_attestation"))
ACT = DE["s3_attestation"]["verified_at"]
MID = DE["s3_attestation"]["mid"]
DEVICE_ID = (DE.get("recipient_confirmation") or {}).get("device_id")


def _members():
    return copy.deepcopy(MEMBERS)


def _run(members, **kw):
    return bl.check_bundle(ENTITY, MED, ORG, members, copy.deepcopy(EVIDENCE),
                           reveals=REVEALS, **kw)


def _bnd(issues, rule):
    return [m for r, m in issues if r == rule]


def _target(members):
    """The member whose device anchors the shipped s3 confirmation."""
    return next(m for m in members if m.get("mid") == MID)


def _confirming_device(member):
    devs = member.get("devices") or []
    return next((d for d in devs if d.get("device_id") == DEVICE_ID), devs[0])


# ---------------------------------------------------------------------------
# The shipped bundle still passes — the migration is back-compatible
# ---------------------------------------------------------------------------

def test_the_shipped_bundle_is_clean_without_any_history():
    """A bundle with one current version per mid behaves as before."""
    assert not _bnd(_run(_members()), "LINT-BND-34")
    assert not _bnd(_run(_members()), "LINT-BND-21")


# ---------------------------------------------------------------------------
# The dangerous direction: a key that did not exist at the act
# ---------------------------------------------------------------------------

def test_a_key_added_after_the_act_cannot_anchor_it():
    """The finding's sharpest edge. The confirmation is unchanged and its key
    is the CURRENT one — only `added_at` says the device did not exist yet."""
    members = _members()
    _confirming_device(_target(members))["added_at"] = "2026-05-01T00:00:00Z"   # after ACT
    issues = _run(members)
    assert _bnd(issues, "LINT-BND-34"), "a post-dated key anchored an earlier act"
    assert "cannot anchor it" in _bnd(issues, "LINT-BND-34")[0]
    assert _bnd(issues, "LINT-BND-21"), \
        "the signature must also fail to resolve — not merely be flagged"


def test_a_device_added_before_the_act_is_fine():
    members = _members()
    _confirming_device(_target(members))["added_at"] = "2026-01-01T00:00:00Z"
    assert not _bnd(_run(members), "LINT-BND-34")


def test_a_device_removed_before_the_act_cannot_anchor_it():
    members = _members()
    _confirming_device(_target(members))["removed_at"] = "2026-03-01T00:00:00Z"
    issues = _run(members)
    assert _bnd(issues, "LINT-BND-34")
    assert "removed at" in _bnd(issues, "LINT-BND-34")[0]


# ---------------------------------------------------------------------------
# The other direction: evidence must not decay with the roster
# ---------------------------------------------------------------------------

def test_a_confirmation_valid_at_its_act_time_survives_the_members_retirement():
    """The member has since retired, so the CURRENT-status map excludes them.
    Resolved at the act time, the confirmation still verifies."""
    members = _members()
    target = _target(members)
    at_act = copy.deepcopy(target)                      # active, as it stood
    at_act["valid_from"] = "2026-01-01T00:00:00Z"
    at_act["valid_until"] = "2026-04-04T10:20:00Z"
    target["status"] = "retired"                        # ...and today
    target["valid_from"] = "2026-04-04T10:20:00Z"
    issues = _run(members, member_history={MID: [at_act, copy.deepcopy(target)]})
    assert not _bnd(issues, "LINT-BND-34"), _bnd(issues, "LINT-BND-34")
    assert not _bnd(issues, "LINT-BND-21"), \
        "a confirmation valid when it was made was rejected after retirement"


def test_the_acker_resolution_itself_does_not_decay_with_the_roster():
    """LINT-BND-12 was the other half: `_resolves_acker` read the
    current-status map, so a retired member made an old confirmation
    unresolvable. With a history it resolves at the act."""
    members = _members()
    target = _target(members)
    at_act = copy.deepcopy(target)
    at_act["valid_from"] = "2026-01-01T00:00:00Z"
    at_act["valid_until"] = "2026-04-04T10:20:00Z"
    target["status"] = "retired"
    target["valid_from"] = "2026-04-04T10:20:00Z"
    assert _bnd(_run(members), "LINT-BND-12"), \
        "without a history a retired member is unresolvable — unchanged behaviour"
    assert not _bnd(_run(members, member_history={MID: [at_act, copy.deepcopy(target)]}),
                    "LINT-BND-12"), \
        "with a history the acker must resolve as they stood at the act"


def test_a_member_retired_BEFORE_the_act_still_fails():
    """The as-of resolution must not become a way to launder a confirmation
    made after the member lost standing."""
    members = _members()
    target = _target(members)
    early = copy.deepcopy(target)
    early["status"] = "retired"
    early["valid_from"] = "2026-01-01T00:00:00Z"
    assert _bnd(_run(members, member_history={MID: [early]}), "LINT-BND-12")


# ---------------------------------------------------------------------------
# A history that cannot be resolved is rejected, never guessed
# ---------------------------------------------------------------------------

def test_two_overlapping_versions_for_one_mid_are_rejected():
    a = copy.deepcopy(_target(_members())); a["valid_from"] = "2026-01-01T00:00:00Z"
    b = copy.deepcopy(_target(_members())); b["valid_from"] = "2026-02-01T00:00:00Z"
    issues = _run(_members(), member_history={MID: [a, b]})
    assert _bnd(issues, "LINT-BND-34")
    assert "ambiguous history is rejected" in _bnd(issues, "LINT-BND-34")[0]


def test_a_history_that_does_not_cover_the_act_is_rejected():
    late = copy.deepcopy(_target(_members())); late["valid_from"] = "2026-06-01T00:00:00Z"
    issues = _run(_members(), member_history={MID: [late]})
    assert "does not cover the act" in _bnd(issues, "LINT-BND-34")[0]


def test_an_unparsable_history_bound_fails_closed():
    bad = copy.deepcopy(_target(_members())); bad["valid_from"] = "whenever"
    issues = _run(_members(), member_history={MID: [bad]})
    assert _bnd(issues, "LINT-BND-34")


def test_a_history_defect_is_reported_once_not_once_per_signature():
    """Signal, not noise: the same broken history is checked by several
    confirmation rules in one pass."""
    a = copy.deepcopy(_target(_members())); a["valid_from"] = "2026-01-01T00:00:00Z"
    b = copy.deepcopy(_target(_members())); b["valid_from"] = "2026-02-01T00:00:00Z"
    issues = _bnd(_run(_members(), member_history={MID: [a, b]}), "LINT-BND-34")
    assert len(issues) == 1, issues


# ---------------------------------------------------------------------------
# The signed roster is the tie-breaker
# ---------------------------------------------------------------------------

def test_a_selected_version_disagreeing_with_the_signed_roster_is_rejected():
    v = copy.deepcopy(_target(_members()))
    v["valid_from"] = "2026-01-01T00:00:00Z"
    roster = {"members": [{"mid": MID, "member_doc_digest": "f" * 64}]}
    issues = _run(_members(), member_history={MID: [v]}, roster=roster)
    assert _bnd(issues, "LINT-BND-34")
    assert "disagrees with the roster" in _bnd(issues, "LINT-BND-34")[0]


def test_a_roster_that_agrees_leaves_the_bundle_clean():
    import hashlib
    from lint_cli import dcbor
    v = copy.deepcopy(_target(_members()))
    v["valid_from"] = "2026-01-01T00:00:00Z"
    digest = hashlib.sha256(dcbor(
        {k: val for k, val in v.items()
         if k not in ("doc_cose_b64", "valid_from", "valid_until")})).hexdigest()
    roster = {"members": [{"mid": MID, "member_doc_digest": digest}]}
    assert not _bnd(_run(_members(), member_history={MID: [v]}, roster=roster),
                    "LINT-BND-34")


# ---------------------------------------------------------------------------
# The integration itself — the thing DR-11 actually found
# ---------------------------------------------------------------------------

def test_no_confirmation_key_is_resolved_from_the_current_status_map():
    """The structural regression guard. Every wallet-signature check must go
    through the act-time anchor; a `by_mid` lookup feeding a confirmation_key
    read is the pattern that made `as_of_resolve` dead code."""
    import re
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    body = src[src.index("def check_bundle("):]
    for m in re.finditer(r"confirmation_key", body):
        window = body[max(0, m.start() - 400):m.start()]
        if "_ck_owner" in window[-200:] or "def _device_at" in window:
            continue                     # the X-32 uniqueness sweep / the resolver
        assert "by_mid" not in window[-300:], \
            "a confirmation key is still resolved from the current-status map"


def test_as_of_resolution_is_reachable_from_the_linter_not_only_the_helper():
    assert "_anchor_at(" in (ROOT / "scripts" / "bundle_lint.py").read_text()
    assert "member_history" in bl.check_bundle.__doc__
