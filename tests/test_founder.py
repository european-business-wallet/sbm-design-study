# SPDX-License-Identifier: MIT
"""Round 12 / B3 — R12-04: the device that created the group is routed.

MLS begins a group with its creator (RFC 9420 §11) and adds everyone else;
nothing adds the creator through a Welcome. Routing was derived from Welcomes
alone and "consults nothing else", so the creator's device was never in it:
reproduced, a DE creator invites a FR device, the FR device acknowledges and
replies, and the creator collects nothing. The round-11 closure fixture never
saw it — it deposited an invitation for every device, the creator's included.

R12-X3: the creating device registers itself as the group's founding member,
device-authenticated, once per group. The review's acceptance: a normal
creator with no self-Welcome invites the peer, messages flow in both
directions, delivery is device-scoped; creator-device authentication, retries
and later membership transitions are covered.
"""
import base64
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import test_principals as pr  # noqa: E402

CREATOR_DEV = (pr.CREATOR["uid"], pr.CREATOR["mid"], "dev-07")       # the creating device
OTHER_OF_CREATOR = (pr.CREATOR["uid"], pr.CREATOR["mid"], "dev-08")  # its member's other device
RDP = "urn:sbm:rdp:demo-out"
b64 = lambda b: base64.b64encode(b).decode()  # noqa: E731


def _formed(m):
    """The creator invites ONE device of another member — and no one else."""
    pr._form(m, [pr.FR_DEV])
    for w in m.collect_welcomes(credential=pr._dev(pr.FR_DEV))["welcomes"]:
        m.ack_welcome(w["welcome_id"], credential=pr._dev(pr.FR_DEV))


def _send(m, msg, octets, at="2026-04-04T10:15:01Z"):
    return m.ds_accept_message(msg, pr.GROUP, b64(octets), at, principal=RDP)


def test_without_registration_the_creator_receives_nothing():
    """The review's reproduction, kept as the control."""
    m = pr._m(); _formed(m)
    _send(m, "01HZR12REPLY0000000000001", b"the FR member replies")
    assert pr._collect(m, CREATOR_DEV) == [] and len(pr._collect(m, pr.FR_DEV)) == 1


def test_messages_flow_both_ways_once_the_creator_is_registered():
    m = pr._m(); _formed(m)
    assert m.register_founder(pr.GROUP, credential=pr._dev(CREATOR_DEV)) is None
    assert m.group_roster(pr.GROUP) == sorted([CREATOR_DEV, pr.FR_DEV])
    _send(m, "01HZR12OPENING00000000001", b"the creator opens")
    _send(m, "01HZR12REPLY0000000000001", b"the FR member replies")
    for dev in (CREATOR_DEV, pr.FR_DEV):
        got = sorted(i["message_id"] for i in pr._collect(m, dev))
        assert got == ["01HZR12OPENING00000000001", "01HZR12REPLY0000000000001"], dev
    # device-scoped: the creator's OTHER device was never in the group
    assert pr._collect(m, OTHER_OF_CREATOR) == []


def test_registration_converges_and_a_group_has_one_founder():
    m = pr._m(); _formed(m)
    assert m.register_founder(pr.GROUP, credential=pr._dev(CREATOR_DEV)) is None
    assert m.register_founder(pr.GROUP, credential=pr._dev(CREATOR_DEV)) is None
    with pytest.raises(m.InvitationError) as exc:
        m.register_founder(pr.GROUP, credential=pr._dev(OTHER_OF_CREATOR))
    assert exc.value.reason == "founder-conflict"


@pytest.mark.parametrize("who", ["the invited counterparty", "a stranger", "before any deposit"])
def test_only_the_creator_that_formed_the_group_can_claim_it(who):
    m = pr._m()
    if who != "before any deposit":
        _formed(m)
    dev = {"the invited counterparty": pr.FR_DEV,
           "a stranger": (pr.FR, "Q9Q9Q9Q9Q", "dev-01"),
           "before any deposit": CREATOR_DEV}[who]
    with pytest.raises(m.InvitationError) as exc:
        m.register_founder(pr.GROUP, credential=pr._dev(dev))
    assert exc.value.reason == "group-unknown"
    assert m._FOUNDERS == {}


def test_registration_is_device_authenticated():
    m = pr._m(); _formed(m)
    with pytest.raises(m.WelcomeAccessDenied):
        m.register_founder(pr.GROUP, credential=pr.CREATOR)          # a member token


def test_the_founder_stays_routed_after_the_invitation_windows_close():
    """A later transition: every invitation's window has closed (the invited
    device joined, so it stays routed too); the founder is not an invitation
    and does not expire."""
    m = pr._m(); _formed(m)
    m.register_founder(pr.GROUP, credential=pr._dev(CREATOR_DEV))
    _send(m, "01HZR12MUCHLATER000000001", b"months later", at="2099-01-01T00:00:00Z")
    assert len(pr._collect(m, CREATOR_DEV)) == 1 and len(pr._collect(m, pr.FR_DEV)) == 1
