# SPDX-License-Identifier: MIT
"""Round 12 / B4 — R12-07, R12-08, D12-04: what a deposit is, and how long
its outcome lives.

R12-07. The reservation proved a package was committed, and nothing bound its
consumption to a deposit: ONE committed reservation authorised two different
invitations into two groups, both queued and both routed.

R12-08. `invitation_id` is the creator's own handle and nothing makes it
global, yet the ledger was keyed on the bare value: a second creator, with its
own reservation, choosing `invitation-1` got `invitation-conflict`.

D12-04. The contract said expiry makes outcome collection 404 as well, while
its outcome queue kept recorded outcomes until acknowledged.
"""
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_wire as w  # noqa: E402
import test_current_claims as tc  # noqa: E402
import test_principals as pr  # noqa: E402

GROUP2 = "Aaw1S4pWq9T5n7xYbXc2dQ"
TARGET = {"mid": "F1N2C3D4P", "device_id": "DEV-1"}


def _reserve(m, creator, key, uid=pr.FR):
    res = m.reserve_keypackages(uid, credential=creator, cipher_suite=tc.SUITE,
                                targets=[TARGET], idempotency_key=key)
    m.commit_reservation(res["reservation_id"], credential=creator)
    return res["reservation_id"], res["keypackages"][0]["keypackage_ref"]


def _deposit(m, creator, res_id, ref, inv="invitation-1", group=pr.GROUP, **over):
    return m.deposit_welcome(tc._record(
        invitation_id=inv, recipient_device="DEV-1", mls_group_id=group,
        reservation_id=res_id, keypackage_ref=ref,
        group_info_commitment=w.group_info_commitment(b"a demo GroupInfo",
                                                      cipher_suite=tc.SUITE), **over),
        credential=creator)


# ---------------------------------------------------------------------------
# R12-07 — one committed package, one invitation
# ---------------------------------------------------------------------------

def test_the_exact_retry_converges():
    m = pr._m(); res, ref = _reserve(m, pr.CREATOR, "r12b4-retry-00000001")
    assert _deposit(m, pr.CREATOR, res, ref) == _deposit(m, pr.CREATOR, res, ref)


@pytest.mark.parametrize("change", ["another invitation", "another group", "other content"])
def test_reusing_a_consumed_package_is_refused_before_anything_is_added(change):
    m = pr._m(); res, ref = _reserve(m, pr.CREATOR, "r12b4-reuse-00000001")
    _deposit(m, pr.CREATOR, res, ref)
    queued = sum(len(q) for q in m._WELCOME_QUEUE.values())
    kw = {"another invitation": dict(inv="invitation-2"),
          "another group": dict(inv="invitation-2", group=GROUP2),
          "other content": dict(inv="invitation-2", welcome_b64="b3RoZXIgd2VsY29tZQ==")}[change]
    with pytest.raises(m.InvitationError) as exc:
        _deposit(m, pr.CREATOR, res, ref, **kw)
    assert exc.value.reason == "keypackage-already-deposited"
    assert sum(len(q) for q in m._WELCOME_QUEUE.values()) == queued
    assert m.group_roster(GROUP2) == [], "a routing claim was added"


def test_burn_and_re_reserve_still_works():
    """R10-X2's recovery: a new reservation for the device deposits freely."""
    m = pr._m(); res, ref = _reserve(m, pr.CREATOR, "r12b4-burn-000000001")
    _deposit(m, pr.CREATOR, res, ref)
    res2, ref2 = _reserve(m, pr.CREATOR, "r12b4-burn-000000002")
    assert _deposit(m, pr.CREATOR, res2, ref2, inv="invitation-2", group=GROUP2)


# ---------------------------------------------------------------------------
# R12-08 — the handle is the creator's
# ---------------------------------------------------------------------------

def test_independent_creators_may_use_the_same_handle():
    m = pr._m()
    other = {"kind": "member", "uid": pr.DE, "mid": "F1N2C3D4P"}
    a = _deposit(m, pr.CREATOR, *_reserve(m, pr.CREATOR, "r12b4-handle-0000001"))
    b = _deposit(m, other, *_reserve(m, other, "r12b4-handle-0000002"), group=GROUP2)
    assert a["welcome_id"] != b["welcome_id"]
    assert _deposit(m, pr.CREATOR, *_reserve(m, pr.CREATOR, "r12b4-handle-0000001")) == a


def test_within_one_creator_a_reused_handle_is_still_a_conflict():
    m = pr._m()
    _deposit(m, pr.CREATOR, *_reserve(m, pr.CREATOR, "r12b4-handle-0000003"))
    res2, ref2 = _reserve(m, pr.CREATOR, "r12b4-handle-0000004")
    with pytest.raises(m.InvitationError) as exc:
        _deposit(m, pr.CREATOR, res2, ref2, group=GROUP2)       # same handle, new content
    assert exc.value.reason == "invitation-conflict"


# ---------------------------------------------------------------------------
# D12-04 — an outcome recorded before expiry outlives it
# ---------------------------------------------------------------------------

def test_a_recorded_outcome_outlives_the_invitation_and_a_late_refusal_does_not():
    m = pr._m()
    res, ref = _reserve(m, pr.CREATOR, "r12b4-expiry-0000001")
    _deposit(m, pr.CREATOR, res, ref)
    dev = {"kind": "device", "uid": pr.FR, "mid": "F1N2C3D4P", "device_id": "DEV-1",
           "keypackage_ref": ref}
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    m.refuse_welcome(wid, credential=dev, reason="group-info-mismatch",
                     offered_suite=tc.SUITE, refused_at="2026-04-04T10:05:00Z")
    # the invitation expires (2026-04-05T09:00Z); the creator returns later
    assert len(m.collect_outcomes(credential=pr.CREATOR)) == 1
    # a NEW refusal after expiry, of another invitation, is refused
    res2, ref2 = _reserve(m, pr.CREATOR, "r12b4-expiry-0000002")
    _deposit(m, pr.CREATOR, res2, ref2, inv="invitation-2", group=GROUP2)
    wid2 = next(x["welcome_id"] for x in m.collect_welcomes(credential=dict(dev, keypackage_ref=ref2))["welcomes"]
                if x["welcome_id"] != wid)
    with pytest.raises(m.InvitationError):
        m.refuse_welcome(wid2, credential=dict(dev, keypackage_ref=ref2),
                         reason="group-info-mismatch", offered_suite=tc.SUITE,
                         refused_at="2026-04-06T00:00:00Z")
    assert len(m.collect_outcomes(credential=pr.CREATOR)) == 1
