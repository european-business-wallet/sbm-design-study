# SPDX-License-Identifier: MIT
"""Round 11 / B4 — R11-06 and R11-07: every invitation ends, and only its own.

R11-06. The contract promised that a refusal dequeues and that an expired
Welcome is not served; burn-and-re-reserve (R10-X2) relies on abandoned
Welcomes expiring. Reproduced: after a successful refusal the same Welcome was
still served — and acknowledgeable, as if fresh — and collection read no clock
at all, so a Welcome that expired in April 2026 was still served in 2099.

R11-07. Routing state was one element per (group, device): every deposit added
it, any refusal discarded it. Two invitations for one device into one group —
which burn-and-re-reserve produces as a matter of course — then went wrong:
acknowledge the newer, refuse the older, and the device received nothing again.

The review's acceptance: refused/expired items are absent from collection,
never resurrect on retry and cannot be acknowledged as fresh; a refusal retry
returns its original outcome to the right principal; ordering permutations,
retries and expiry exercised; refusing an older invitation cannot remove a
later accepted one.
"""
import base64
import itertools
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import test_current_claims as tc  # noqa: E402
import test_invitation_lifecycle as il  # noqa: E402

GROUP = tc._record()["mls_group_id"]
RDP = "urn:sbm:rdp:demo-out"
DEV = ("EU-FR-PSBID-ZYWVTSRQPNM8M4", "F1N2C3D4P", "DEV-1")
IN_WINDOW, AFTER = "2026-04-04T10:05:00Z", "2099-01-01T00:00:00Z"
EXPIRES = tc._record()["expires_at"]                     # 2026-04-05T09:00:00Z


def _refuse(m, wid, cred):
    return m.refuse_welcome(wid, credential=cred, reason="group-info-mismatch",
                            offered_suite=tc.SUITE)


def _items_for(m, msg, accepted_at="2026-04-04T10:15:01Z"):
    m.ds_accept_message(msg, GROUP, base64.b64encode(msg.encode()).decode(),
                        accepted_at, principal=RDP)
    return [k for k in m._DELIVERY_ITEMS if k[1] == msg and k[2:] == DEV]


# ---------------------------------------------------------------------------
# R11-06 — refused and expired items end
# ---------------------------------------------------------------------------

def test_a_refused_welcome_leaves_the_queue_and_cannot_be_acknowledged():
    m = il._m(); dev = il._invite(m)
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    out = _refuse(m, wid, dev)
    assert m.collect_welcomes(credential=dev)["welcomes"] == []
    assert _refuse(m, wid, dev) == out, "the retry must return the original outcome"
    assert m.collect_welcomes(credential=dev)["welcomes"] == [], "the retry resurrected it"
    with pytest.raises(m.WelcomeAccessDenied):
        m.ack_welcome(wid, credential=dev)


def test_the_refusal_retry_answers_only_its_own_principal():
    m = il._m(); dev = il._invite(m)
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    _refuse(m, wid, dev)
    other = dict(dev, mid="F2X3Y4Z55")
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, wid, other)
    assert exc.value.reason == "invitation-unknown"


def test_an_expired_welcome_is_not_served_or_acknowledgeable():
    m = il._m(); dev = il._invite(m)
    assert m.collect_welcomes(credential=dev, at=AFTER)["welcomes"] == []
    assert len(m.collect_welcomes(credential=dev, at=EXPIRES)["welcomes"]) == 1, \
        "the window is closed at both ends: at expires_at the item is still served"
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    with pytest.raises(m.WelcomeAccessDenied):
        m.ack_welcome(wid, credential=dev, at=AFTER)
    assert m.collect_welcomes(credential=dev)["welcomes"], \
        "a refused late acknowledgement must not have consumed the item"


def test_an_unacknowledged_invitation_stops_routing_when_it_expires():
    m = il._m(); il._invite(m)
    assert _items_for(m, "01HZR11B4ROUTEINWINDOW001", accepted_at=IN_WINDOW)
    assert _items_for(m, "01HZR11B4ROUTEEXPIRED0001", accepted_at=AFTER) == []


def test_a_joined_invitation_keeps_routing_after_its_window_and_cannot_be_refused():
    m = il._m(); dev = il._invite(m)
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    m.ack_welcome(wid, credential=dev)
    with pytest.raises(m.InvitationError) as exc:
        _refuse(m, wid, dev)
    assert exc.value.reason == "invitation-unknown"
    assert _items_for(m, "01HZR11B4JOINEDLATE000001", accepted_at=AFTER), \
        "joining is not undone by the invitation window closing"


# ---------------------------------------------------------------------------
# R11-07 — two invitations, every order
# ---------------------------------------------------------------------------

def _scenarios():
    """Every ordering of every consistent choice: each invitation is either
    acknowledged or refused (or left open), never both."""
    for fate_old in ("ack", "refuse", None):
        for fate_new in ("ack", "refuse", None):
            ops = [(f, w) for f, w in ((fate_old, "old"), (fate_new, "new")) if f]
            for order in itertools.permutations(ops):
                yield list(order)


@pytest.mark.parametrize("ops", list(_scenarios()),
                         ids=lambda ops: "+".join(f"{f}-{w}" for f, w in ops) or "none")
def test_the_device_is_routed_while_any_invitation_is_live(ops):
    m = il._m()
    cred = {"old": il._invite(m, n=0), "new": il._invite(m, n=1)}
    wids = [w["welcome_id"] for w in m.collect_welcomes(credential=cred["old"])["welcomes"]]
    wid = dict(zip(("old", "new"), wids))
    for fate, which in ops:
        if fate == "ack":
            m.ack_welcome(wid[which], credential=cred[which])
        else:
            _refuse(m, wid[which], cred[which])
            assert _refuse(m, wid[which], cred[which])     # a retry changes nothing
    refused = {w for f, w in ops if f == "refuse"}
    expected = len(refused) < 2                       # an acked or open one remains
    assert bool(_items_for(m, "01HZR11B4PERMUTATION00001")) == expected, ops
    assert m.group_roster(GROUP, at=IN_WINDOW) == ([DEV] if expected else [])
