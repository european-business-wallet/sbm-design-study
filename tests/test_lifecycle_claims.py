# SPDX-License-Identifier: MIT
"""G3 — the lifecycle table's claims, checked rather than asserted in prose.

`docs/lifecycle-and-custody.md` §1 is the specification of what each change does
to traffic, to messages in flight and to evidence already issued. Nothing checked
it. Two columns in particular make load-bearing promises — "items already queued
for the old device stay queued", "a message keeps the version it pinned",
"unaffected", "remains verifiable through as-of reads" — and an unchecked promise
in a specification is the same class of defect as the mandate over-claim R27-PUB-05
corrected: a reader acts on it, and nothing tells the author when it stops being
true.

Every row of that table must appear in `CLAIMS` below, asserted by
`test_every_row_of_the_table_has_a_probe`, so a change added to the prose cannot
arrive without one.

**What these probes found.** Every claim holds — and the reason they hold is one
structural property worth naming: verification reads the DOCUMENTS a verifier was
handed, never live state and never an endpoint. Rewriting every endpoint in the
entity's discovery document to a different provider leaves a bundle verifying
exactly as before. That is why the table can say "unaffected" so often, and it is
also precisely why the one real gap is custody: `docs/retrievability.md` records
which published reads must keep answering, and which of them have no named server
once a provider exits.

**One distinction these probes exist to pin.** Satisfiability and attribution ask
different questions of the roster, deliberately (`bundle_lint` line ~540): "can
this organisation's policy still be met by the people it has TODAY" is legitimately
about the present, while "who made this confirmation, and were they entitled to"
is about the act. Retiring the last ack-capable member therefore SHOULD make
LINT-BND-08/09 fire and MUST NOT disturb attribution. Read carelessly, the first
looks like evidence decaying with the roster — the defect LINT-BND-34 closed — and
the first draft of this file mistook it for exactly that. So the distinction is
asserted in both directions.
"""
import copy
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import regen_samples as R  # noqa: E402
import test_fan_out as fan  # noqa: E402
import test_historical_resolution as hist  # noqa: E402

DOC = ROOT / "docs" / "lifecycle-and-custody.md"


# ---------------------------------------------------------------------------
# The table itself
# ---------------------------------------------------------------------------

def table_rows():
    """The first column of §1's table — the changes the document specifies."""
    body = DOC.read_text(encoding="utf-8").split("## 1. The changes", 1)[1]
    body = body.split("## 2.", 1)[0]
    rows = [line for line in body.splitlines()
            if line.startswith("|") and not set(line) <= set("|-: ")]
    return [row.split("|")[1].strip() for row in rows[1:]]


# ---------------------------------------------------------------------------
# Helpers over the retained-bundle verifier
# ---------------------------------------------------------------------------

def _fatal(issues):
    """The verdict, minus the DECLARED incomplete-verification residuals: those
    say material is absent, which is a different statement from evidence failing."""
    return sorted({rule for rule, _ in issues if "-I" not in rule})


def _verify(**over):
    kwargs = dict(members=hist._members(), evidence=copy.deepcopy(hist.EVIDENCE),
                  reveals=hist.REVEALS)
    kwargs.update(over)
    return _fatal(hist.bl.check_bundle(
        hist.ENTITY, kwargs.pop("med", hist.MED), kwargs.pop("org", hist.ORG),
        kwargs.pop("members"), kwargs.pop("evidence"), **kwargs))


def _member_versions(mutate, *, from_when="2026-06-01T00:00:00Z"):
    """The confirming member's binding in force at the act, plus a successor that
    takes effect AFTER it and carries `mutate`. Returns (members, history)."""
    at_act = copy.deepcopy(hist._target(hist._members()))
    mid = at_act["mid"]
    at_act.update(valid_from="2026-01-01T00:00:00Z", valid_until=from_when)
    after = copy.deepcopy(at_act)
    after.update(valid_from=from_when)
    after.pop("valid_until", None)
    mutate(after)
    members = [m for m in hist._members() if m.get("mid") != mid] + [after]
    return members, {mid: [at_act, after]}


def _org_chain():
    return [hist._doc("sample-BW-ORG-prev.json"), copy.deepcopy(hist.ORG)]


def _org_successor(version, valid_from):
    org = copy.deepcopy(hist.ORG)
    successor = copy.deepcopy(org)
    successor.update(
        policy_version=version, valid_from=valid_from,
        supersedes={"policy_version": org["policy_version"],
                    "doc_digest": {"alg": "SHA-256", "hash_mode": "raw-sha256",
                                   "hex": R.ORG_DIGESTS[org["policy_version"]]}})
    return successor


# ---------------------------------------------------------------------------
# One probe per row
# ---------------------------------------------------------------------------

def claim_a_member_joins():
    """"the member is addressable, and countable for acceptance where ack-capable".
    Countability is a question about the PRESENT roster, so adding an ack-capable
    member can only widen the eligible set — never narrow it."""
    assert _verify() == [], "the shipped bundle is the control"
    joined = hist._members()
    newcomer = copy.deepcopy(hist._target(joined))
    newcomer["mid"] = "N3WM3MB3R"
    # X-32: ONE confirmation key per (mid, device_id). A joining member that
    # reused another's key would fail LINT-BND-32 — correctly — and would test
    # that rule instead of this claim.
    for device in newcomer.get("devices") or []:
        device["device_id"] = f"new-{device['device_id']}"
        if isinstance(device.get("confirmation_key"), dict):
            device["confirmation_key"]["public_key_b64"] = hist.mock.demo_public_key_b64(
                f"wallet:{newcomer['mid']}:{device['device_id']}")
    assert _verify(members=joined + [newcomer]) == []


def claim_a_device_is_replaced():
    """"items already queued for the old device stay queued" — and a replacement
    is a NEW ENROLMENT, so it inherits nothing. Nothing published carries the
    replacement to the Delivery Service (§2), which is what makes both true."""
    m = fan.tc._load("mock_rdp", "mock_rdp.py")
    fan._group(m, fan.TWO_MEMBERS)
    fan._accept(m)
    queued = sorted(fan._items(m))
    assert "DEV-1" in queued, queued
    # The replacement device, never invited, has no claim on the old queue.
    assert fan._collect(m, "DEV-1b", mid="F1N2C3D4P") == []
    # And the old device's item is still there to collect.
    assert [i["message_id"] for i in fan._collect(m, "DEV-1")] == [fan.MSG]


def claim_a_role_changes():
    """"acceptance is evaluated over the roster **as of the act**" — so a
    capability withdrawn afterwards does not unmake the acknowledgement.

    Attribution is the claim. Satisfiability legitimately changes: an entity whose
    last ack-capable device lost the capability cannot meet its own policy TODAY,
    and LINT-BND-08/09 are right to say so.
    """
    def drop_ack(member):
        for device in member.get("devices") or []:
            device["capabilities"] = [c for c in (device.get("capabilities") or [])
                                      if c != "ack"]
    members, history = _member_versions(drop_ack)
    issues = _verify(members=members, member_history=history)
    assert "LINT-BND-12" not in issues, \
        "a capability withdrawn after the act unmade the acknowledgement"
    assert "LINT-BND-21" not in issues, \
        "a capability withdrawn after the act broke the published-key anchor"
    assert {"LINT-BND-08", "LINT-BND-09"} & set(issues), \
        "withdrawing the last ack capability left satisfiability unaffected"


def claim_a_member_is_suspended_retired_or_compromised():
    """"Evidence already issued: stays valid" — an ATTRIBUTION claim, and the one
    that must survive. Satisfiability is a separate question about today, and
    conflating the two is the misreading this file's docstring records."""
    for status in ("suspended", "retired"):
        members, history = _member_versions(lambda m, s=status: m.update(status=s))
        issues = _verify(members=members, member_history=history)
        assert "LINT-BND-12" not in issues, \
            f"a member {status} AFTER the act unmade its own acknowledgement"
        assert "LINT-BND-21" not in issues, \
            f"a member {status} AFTER the act broke its published-key anchor"
        # The present-tense question DOES change, and should: the entity can no
        # longer satisfy its own policy with the people it has now.
        assert {"LINT-BND-08", "LINT-BND-09"} & set(issues), \
            "retiring the last ack-capable member left satisfiability unaffected"

    # The dangerous direction: already retired AT the act, and attribution fails.
    at_act = copy.deepcopy(hist._target(hist._members()))
    mid = at_act["mid"]
    at_act.update(status="retired", valid_from="2026-01-01T00:00:00Z")
    members = [m for m in hist._members() if m.get("mid") != mid] + [at_act]
    assert "LINT-BND-12" in _verify(members=members, member_history={mid: [at_act]}), \
        "a member retired BEFORE the act still satisfied attribution"


def claim_the_acceptance_policy_changes():
    """"a message keeps the version it pinned" — a successor published after the
    act must not disturb a settled message; one in force before it must be
    reported, or the message pinned a superseded version."""
    assert _verify(policy_history=_org_chain()) == [], "the real chain is the control"
    after = _org_chain() + [_org_successor("2099-01-01.1", "2099-01-01T00:00:00Z")]
    assert _verify(policy_history=after) == [], \
        "a successor published after the act disturbed the pinned version"
    before = _org_chain() + [_org_successor("2026-03-02.1", "2026-03-02T00:00:00Z")]
    assert "LINT-BND-35" in _verify(policy_history=before), \
        "a successor already in force at the act was not reported"


def claim_a_group_falls_idle():
    """"evidence binds digests and session state, not a live group" — structural:
    no input to the retained-evidence verifier is a handle on a live group, so
    there is nothing for idleness to invalidate."""
    import inspect
    params = set(inspect.signature(hist.bl.check_bundle).parameters)
    assert not {"group", "mls_group", "session", "connection"} & params, params
    # `group_contexts` is RETAINED state — bytes, not a live group (LINT-BND-I4).
    assert "group_contexts" in params


def claim_the_entity_changes_provider():
    """"the **UID is stable** … unaffected". The strongest form of the claim:
    rewrite EVERY endpoint in the discovery document to a different provider and
    the bundle verifies unchanged, because verification reads documents and never
    dereferences a URL. Which is also why custody is the open question
    (docs/retrievability.md)."""
    moved = copy.deepcopy(hist.MED)
    rewritten = 0
    for value in moved.values():
        if not isinstance(value, dict):
            continue
        for key, inner in list(value.items()):
            if isinstance(inner, str) and inner.startswith("http"):
                value[key] = "https://successor-provider.example.eu/moved"
                rewritten += 1
    assert rewritten, "the fixture rewrote no endpoint, so it proves nothing"
    assert moved["uid"] == hist.MED["uid"], "the UID must be stable"
    assert _verify(med=moved) == []


def claim_the_entitys_own_status_changes():
    """"remains verifiable through as-of reads". A `uid-merged` entity redirects
    NEW traffic and reroutes nothing — the sender resubmits — and the outcome
    that says so is a published, sealed object carrying the surviving UID."""
    import json
    nde = json.loads((ROOT / "samples" / "sample-NDE-intake-merged.json")
                     .read_text())["projection"]
    assert nde["reason"] == "uid-merged"
    assert nde["redirect_uid"] != nde["recipient_uid"], \
        "a merger must point somewhere other than the retired UID"
    # Nothing reroutes: the outcome is a REJECTION at intake, not a delivery.
    assert nde["event"] == "A.2-SubmissionRejection"
    assert "payload_hash" not in nde, \
        "nothing was accepted, so there is no accepted-payload commitment"


CLAIMS = {
    "**A member joins**": claim_a_member_joins,
    "**A device is replaced**": claim_a_device_is_replaced,
    "**A role changes**": claim_a_role_changes,
    "**A member is suspended, retired or compromised**":
        claim_a_member_is_suspended_retired_or_compromised,
    "**The acceptance policy changes**": claim_the_acceptance_policy_changes,
    "**A group falls idle**": claim_a_group_falls_idle,
    "**The entity changes provider**": claim_the_entity_changes_provider,
    "**The entity's own status changes**": claim_the_entitys_own_status_changes,
}


def test_every_row_of_the_table_has_a_probe():
    """The drift guard. A change described in the prose without a probe here is a
    promise nothing keeps."""
    rows, probed = set(table_rows()), set(CLAIMS)
    assert rows == probed, {"unprobed rows": sorted(rows - probed),
                            "probes for no row": sorted(probed - rows)}


@pytest.mark.parametrize("row", sorted(CLAIMS))
def test_the_table_tells_the_truth(row):
    CLAIMS[row]()
