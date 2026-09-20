# SPDX-License-Identifier: MIT
"""R3-03 — attribution is resolved at the act, on every path.

Former defect (round-3 review, High), and the third appearance of one family:

* **Round 1 (DR-11 found it):** `as_of_resolve()` was correct and nothing
  called it.
* **Round 2 (my fix):** it was called — but the current-state gate was left
  standing beside it, and only the recipient-confirmation path was cleared.
* **Round 3:** four gates survived. At the grade-reveal site the two sat on
  consecutive lines, under a comment I wrote saying *"This comment made that
  claim before DR-11; the code did not."*

That is **additive fixing**: the correct path added beside the incorrect one,
which stays reachable. Hence the invariant this round adds — *when a fix
supersedes a check, DELETE the superseded check* — and hence
`test_the_current_status_map_is_gone`, which is the only test here that can
prevent a fourth appearance.

The four sites are `LINT-BND-28` (sender), `LINT-BND-29` (refusal),
`LINT-BND-26` (grade reveal) and — not in the review's list —
**`LINT-BND-18`**, which failed in the OPPOSITE direction: a retired member was
absent from the current map, so `am` was `None` and a *system* member's
acknowledgement in a `human_acceptance` scope was never checked at all. Three
rejected valid evidence; the fourth accepted invalid evidence.
"""
import copy
import importlib.util
import json
import pathlib
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bl = _load("bundle_lint", "bundle_lint.py")

MANIFEST = json.loads((ROOT / "samples" / "bundle.default.manifest.json").read_text())
SAMPLES = ROOT / "samples"


def _doc(name):
    return bl._load(str(SAMPLES / name))


ENTITY = MANIFEST["entity_uid"]
MED, ORG = _doc(MANIFEST["med"]), _doc(MANIFEST["org"])
MEMBERS = [_doc(m) for m in MANIFEST["members"]]
EVIDENCE = [_doc(e) for e in MANIFEST["evidence"]]
REVEALS = {r["message_id"]: r for r in json.loads(
    (SAMPLES / MANIFEST["grade_reveals"]).read_text())["reveals"]}

SE = next(e for e in EVIDENCE if e.get("type") == "SE-v1")
RETIRE_AT = "2026-05-01T00:00:00Z"          # after EVERY act, incl. the
                                            # 2026-04-09 grade-reveal read


def _retired_history(members, mid):
    """The member as it stood at the act, and as it stands today: retired."""
    target = next(m for m in members if m.get("mid") == mid)
    at_act = copy.deepcopy(target)
    at_act["valid_from"] = "2026-01-01T00:00:00Z"
    at_act["valid_until"] = RETIRE_AT
    target["status"] = "retired"
    target["valid_from"] = RETIRE_AT
    return {mid: [at_act, copy.deepcopy(target)]}


def _run(members, evidence=None, **kw):
    return bl.check_bundle(ENTITY, MED, ORG, members,
                           copy.deepcopy(evidence if evidence is not None else EVIDENCE),
                           reveals=REVEALS, **kw)


def _rule(issues, rule):
    return [m for r, m in issues if r == rule]


# ---------------------------------------------------------------------------
# The invariant, enforced structurally — the only test that stops a fourth round
# ---------------------------------------------------------------------------

def test_the_current_status_map_is_gone():
    """Not "is unused" — GONE. An unused wrong path is one refactor away from
    being used again, which is exactly how this survived two rounds."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    body = src[src.index("def check_bundle("):]
    # Strip comments AND whole docstring blocks — the first version matched a
    # line INSIDE a docstring that explains what was removed, which is prose,
    # not a reachable path.
    code, in_doc = [], False
    for ln in body.splitlines():
        if ln.count('"""') == 1:
            in_doc = not in_doc
            continue
        if in_doc or ln.strip().startswith("#") or ln.count('"""') == 2:
            continue
        code.append(ln)
    hits = [ln.strip() for ln in code
            if re.search(r"\bby_mid\b", ln) and "all_by_mid" not in ln
            and "se_by_mid" not in ln and "nde_by_mid" not in ln]
    assert not hits, f"the current-status map is reachable again: {hits}"


def test_the_surviving_current_state_use_is_documented_as_intentional():
    """`active` stays, for SATISFIABILITY — can the organisation's own policy
    still be met by the people it has today? That is legitimately a question
    about the present. Attribution is not."""
    src = (ROOT / "scripts" / "bundle_lint.py").read_text()
    i = src.index('active = [m for m in members if m.get("status") == "active"]')
    note = src[max(0, i - 700):i]
    assert "SATISFIABILITY" in note
    assert "no attribution rule may read this list" in note


# ---------------------------------------------------------------------------
# The three that rejected valid evidence
# ---------------------------------------------------------------------------

def test_a_sender_confirmation_survives_the_senders_later_retirement():
    """LINT-BND-28 runs where `sender_uid == entity`, i.e. over the SENDER's
    own bundle — the default manifest is the recipient's. Building the sender
    side explicitly rather than skipping: a skipped test leaves the path
    untested, which is how these gates survived two rounds."""
    sender_uid = SE["sender_uid"]
    smid = SE["sender_confirmation"]["mid"]
    members = [_doc("sample-BW-MEMBER.json")]          # the DE-side member
    assert members[0]["mid"] == smid and members[0]["uid"] == sender_uid
    hist = _retired_history(members, smid)
    issues = bl.check_bundle(sender_uid, _doc("sample-BW-MED.json"),
                             _doc("sample-BW-ORG-de.json"), members,
                             [copy.deepcopy(SE)], member_history=hist)
    assert not _rule(issues, "LINT-BND-28"), _rule(issues, "LINT-BND-28")


def test_a_grade_reveal_survives_the_disputing_members_later_retirement():
    """LINT-BND-26 — the site where the correct call and the wrong gate sat on
    consecutive lines."""
    gcm = _doc("sample-GCM.json")
    conf = gcm.get("reveal_confirmation")
    if not conf:
        pytest.skip("the shipped GCM carries no reveal_confirmation")
    members = copy.deepcopy(MEMBERS)
    hist = _retired_history(members, conf["mid"])
    issues = _run(members, evidence=EVIDENCE + [gcm], member_history=hist)
    assert not [m for m in _rule(issues, "LINT-BND-26")
                if "did not resolve" in m]


def test_a_member_refusal_survives_the_refusers_later_retirement():
    """LINT-BND-29."""
    re_ = _doc("sample-RE.json")
    assert re_["refusal_kind"] == "member", "the shipped RE is the member arm"
    members = copy.deepcopy(MEMBERS)
    hist = _retired_history(members, re_["mid"])
    issues = _run(members, evidence=EVIDENCE + [re_], member_history=hist)
    assert not [m for m in _rule(issues, "LINT-BND-29") if "did not resolve" in m]


# ---------------------------------------------------------------------------
# The fourth site — it failed OPEN
# ---------------------------------------------------------------------------

def test_a_retired_system_members_acknowledgement_is_still_rejected():
    """LINT-BND-18, the site the review does not list and the only one that
    failed in the permissive direction: a member absent from the current map
    made `am` None, so a SYSTEM member's acknowledgement in a human_acceptance
    scope was never checked."""
    org = copy.deepcopy(ORG)
    scoped = _doc("sample-BW-ORG-scoped.json")
    scope = copy.deepcopy(next(s for s in scoped["scope_map"]["scopes"]))
    scope["human_acceptance"] = True
    org["scope_map"] = {"scopes": [scope], "fallback": "default"}
    org["acceptance_policy"].setdefault(scope["acceptance_policy_ref"], "any-one")

    de = copy.deepcopy(next(e for e in EVIDENCE
                            if e.get("type") == "DE-v1" and e.get("s3_attestation")))
    de["scope_ref"] = {"scope_id": scope["scope_id"], "version": scope["version"]}
    amid = de["s3_attestation"]["mid"]

    members = copy.deepcopy(MEMBERS)
    target = next(m for m in members if m.get("mid") == amid)
    target["member_type"] = "system"                 # an agent acknowledged
    hist = _retired_history(members, amid)           # ...and has since retired

    issues = bl.check_bundle(ENTITY, MED, org, members, [SE, de],
                             reveals=REVEALS, member_history=hist)
    assert _rule(issues, "LINT-BND-18"), \
        "a retired system member's acknowledgement escaped the human_acceptance gate"


# ---------------------------------------------------------------------------
# As-of resolution must not launder a late act
# ---------------------------------------------------------------------------

def test_a_member_not_active_at_the_act_still_fails():
    """As-of resolution must not become a way to launder an act made without
    standing: the member was ALREADY retired when the submission happened.
    Run over the sender's own bundle, like the positive case above."""
    sender_uid = SE["sender_uid"]
    smid = SE["sender_confirmation"]["mid"]
    members = [_doc("sample-BW-MEMBER.json")]
    early = copy.deepcopy(members[0])
    early["status"] = "retired"
    early["valid_from"] = "2026-01-01T00:00:00Z"
    issues = bl.check_bundle(sender_uid, _doc("sample-BW-MED.json"),
                             _doc("sample-BW-ORG-de.json"), members,
                             [copy.deepcopy(SE)], member_history={smid: [early]})
    assert _rule(issues, "LINT-BND-28"), \
        "as-of resolution laundered an act made without standing"


def test_the_shipped_bundle_stays_clean():
    for rule in ("LINT-BND-18", "LINT-BND-26", "LINT-BND-28", "LINT-BND-29"):
        assert not _rule(_run(copy.deepcopy(MEMBERS)), rule), rule
