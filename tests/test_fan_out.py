# SPDX-License-Identifier: MIT
"""Round 10 / B3 — fan-out over the group the DS observed (R10-04, R10-09.1).

R10-X3: an accepted message creates one delivery item per device the DS
observed joining the bilateral group — BOTH entities — each item bound to its
OWN member. Sender-side copies are transport items only: the RDP issuing a DE
binds the receipt to the SE's addressee, so another entity's receipt never
becomes delivery evidence.

The review's lesson for how these are written: "tests with two devices of one
MID miss the actual topology". Everything here goes through the public
operations — reserve, commit, deposit the Welcomes, accept, collect,
acknowledge — with more than one member and more than one entity, because the
defect lived precisely in the composition of individually tested steps.
"""
import base64
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import test_current_claims as tc  # noqa: E402  — the published-lifecycle fixtures

FR = "EU-FR-PSBID-ZYWVTSRQPNM8M4"     # the addressee entity
DE = "EU-DE-EOID-7K3D9W0Q2M5FW0"      # the sending entity
GROUP = "Zzw1S4pWq9T5n7xYbXc2dQ"
RDP = "urn:sbm:rdp:demo-out"
MSG = "01HZR10B3FANOUT0000000001"
OCTETS = b"the one accepted ciphertext"


def _group(m, targets, *, key_prefix="b3"):
    """Form the group through the PUBLIC lifecycle: per entity, reserve its
    targets, commit, and deposit one Welcome per device into ONE group."""
    by_uid = {}
    for uid, mid, dev in targets:
        by_uid.setdefault(uid, []).append({"mid": mid, "device_id": dev})
    n = 0
    for i, (uid, tg) in enumerate(sorted(by_uid.items())):
        res = m.reserve_keypackages(uid, credential=tc.MEMBER_CRED,
                                    cipher_suite=tc.SUITE, targets=tg,
                                    idempotency_key=f"{key_prefix}-idempotency-{i:02}")
        m.commit_reservation(res["reservation_id"], credential=tc.MEMBER_CRED)
        for pkg in res["keypackages"]:
            m.deposit_welcome(tc._record(
                invitation_id=f"inv-{key_prefix}-{n}", recipient_device=pkg["device_id"],
                reservation_id=res["reservation_id"],
                keypackage_ref=pkg["keypackage_ref"], mls_group_id=GROUP),
                credential=tc.MEMBER_CRED)
            n += 1


def _accept(m):
    return m.ds_accept_message(MSG, GROUP, base64.b64encode(OCTETS).decode(),
                               principal=RDP)


def _session(dev):
    return {"kind": "token-digest", "digest": (dev[-1] * 64)}


def _principal(dev, mid=None):
    """R11-01: a device is (entity, member, label). A label alone may name
    devices of several members — this file's own topologies give `DEV-2` to
    two different members — so a caller whose device is not the one in
    BOTH_ENTITIES names its member."""
    if mid is not None:
        return (FR, mid, dev)
    return next(p for p in BOTH_ENTITIES if p[2] == dev)


def _collect(m, dev, mid=None):
    uid, mid, _ = _principal(dev, mid)
    sb = _session(dev)
    return m.collect_messages(credential={"kind": "device", "uid": uid, "mid": mid,
                                          "device_id": dev, "session": sb["digest"]},
                              session_binding=sb)["items"]


def _ack(m, uid, mid, dev, token):
    """The entity and member are the authenticated credential's (R11-01)."""
    sb = _session(dev)
    return m.receipt_ack(message_id=MSG, issuing_rdp_id=RDP, device_id=dev,
                         credential={"kind": "device", "uid": uid, "mid": mid,
                                     "device_id": dev, "session": sb["digest"]},
                         session_binding=sb, octets=OCTETS,
                         server_clock="2026-04-04T10:20:00Z",
                         collection_token=token)


def _items(m):
    return {k[4]: v for k, v in m._DELIVERY_ITEMS.items() if k[:2] == (RDP, MSG)}


TWO_MEMBERS = [(FR, "F1N2C3D4P", "DEV-1"), (FR, "G7H8J9K0Q", "DEV-2")]
BOTH_ENTITIES = TWO_MEMBERS + [(DE, "H2J3K4M5N", "DEV-3")]


# ---------------------------------------------------------------------------
# R10-04 — the ordinary topology is delivered, whole, on the first attempt
# ---------------------------------------------------------------------------

def test_two_members_of_one_entity_are_both_delivered_first_time():
    """The review's probe. Before B3: `delivery-recipient-conflict` on the
    first submission, `accepted` on the identical retry, and one member's
    device with nothing — which one decided by the lexical order of MIDs."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, TWO_MEMBERS)
    _accept(m)                                   # no conflict, first time
    items = _items(m)
    assert set(items) == {"DEV-1", "DEV-2"}
    assert {d: (i["recipient_uid"], i["mid"]) for d, i in items.items()} == \
        {"DEV-1": (FR, "F1N2C3D4P"), "DEV-2": (FR, "G7H8J9K0Q")}
    assert len(_collect(m, "DEV-1")) == 1 and len(_collect(m, "DEV-2")) == 1


def test_both_entities_each_device_bound_to_its_own_member():
    """R10-X3: the bilateral group holds the SENDER entity's devices too, and
    each item carries its own entity and member."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, BOTH_ENTITIES)
    _accept(m)
    items = _items(m)
    assert {d: (i["recipient_uid"], i["mid"]) for d, i in items.items()} == \
        {dev: (uid, mid) for uid, mid, dev in BOTH_ENTITIES}


def test_a_failure_halfway_through_fan_out_is_completed_by_the_retry(monkeypatch):
    """The review's acceptance: inject a failure mid-fan-out; the retry reaches
    every intended recipient EXACTLY ONCE, and the accepted bytes are
    preserved. Before B3 the retry returned the stored record and did nothing
    — `accepted`, with deliveries missing for ever."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, BOTH_ENTITIES)
    real, calls = m.queue_delivery, {"n": 0}

    def flaky(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("the DS went away halfway through fan-out")
        return real(*a, **kw)
    monkeypatch.setattr(m, "queue_delivery", flaky)
    with pytest.raises(RuntimeError):
        _accept(m)
    assert len(_items(m)) == 1, "the injected failure did not land mid-fan-out"
    record = _accept(m)                          # the identical retry
    items = _items(m)
    assert set(items) == {dev for _, _, dev in BOTH_ENTITIES}
    assert all(i["message_digest"] == record["envelope_hash"] for i in items.values())
    _accept(m)                                   # and again: nothing doubles
    assert len(_items(m)) == len(BOTH_ENTITIES)


def test_the_recipient_set_is_the_one_observed_at_acceptance():
    """R9-X3 holds across a resumed fan-out: a device that joins between the
    failed attempt and the retry does not retroactively receive the message.
    The retry resumes the SNAPSHOT, not a roster that has moved since."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, TWO_MEMBERS)
    _accept(m)
    _group(m, [(FR, "J4K5M6N7P", "DEV-9")], key_prefix="late")
    _accept(m)                                   # a retry after the join
    assert "DEV-9" not in _items(m)


def test_a_retry_naming_another_group_is_a_different_submission():
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, TWO_MEMBERS)
    _accept(m)
    with pytest.raises(m.TransportRejected) as exc:
        m.ds_accept_message(MSG, "AnotherGroupId0000000A", base64.b64encode(OCTETS).decode(),
                            principal=RDP)
    assert exc.value.reason == "duplicate-message-id"


# ---------------------------------------------------------------------------
# R10-09.1 — every device's own item terminates
# ---------------------------------------------------------------------------

def test_every_acknowledging_device_reaches_a_terminal_state():
    """Two devices of one member each collect and acknowledge. The first
    acknowledgement is the one recipient-level legal event and both get it
    back; but EACH device's own transport item must terminate. Before B3 the
    second stayed `transferred` and collectable for ever."""
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, [(FR, "F1N2C3D4P", "DEV-1"), (FR, "F1N2C3D4P", "DEV-2")])
    _accept(m)
    tok = {d: _collect(m, d, "F1N2C3D4P")[0]["collection_token"]
           for d in ("DEV-1", "DEV-2")}
    first = _ack(m, FR, "F1N2C3D4P", "DEV-1", tok["DEV-1"])
    second = _ack(m, FR, "F1N2C3D4P", "DEV-2", tok["DEV-2"])
    assert second == first, "the first legal event did not stand"
    assert {d: i["state"] for d, i in _items(m).items()} == \
        {"DEV-1": "acknowledged", "DEV-2": "acknowledged"}
    assert _collect(m, "DEV-1", "F1N2C3D4P") == [] and \
        _collect(m, "DEV-2", "F1N2C3D4P") == []


# ---------------------------------------------------------------------------
# R10-X3 — a sender-side copy is transport, never delivery evidence
# ---------------------------------------------------------------------------

def test_a_sender_side_receipt_cannot_become_a_de():
    """The DS cannot tell a sender copy from a recipient copy and does not
    try. The component that knows the addressee does: the RDP issuing the DE
    states the delivery context it is processing, and a receipt for another
    entity's device is refused there."""
    from lint_cli import DeliveryContext
    import json
    m = tc._load("mock_rdp", "mock_rdp.py")
    _group(m, BOTH_ENTITIES)
    rec = _accept(m)
    tok = _collect(m, "DEV-3")[0]["collection_token"]
    receipt = _ack(m, DE, "H2J3K4M5N", "DEV-3", tok)      # the SENDER's device
    # SBM-ADR-0015: the receipt key is the issuing RDP's.
    provider = json.loads(
        (ROOT / "samples" / "sample-BW-PROVIDER.json").read_text())["projection"]
    addressee = DeliveryContext(message_id=MSG, issuing_rdp_id=RDP, recipient_uid=FR,
                                observed_by=m.DS_PROVIDER_ID,
                                mid="H2J3K4M5N", device_id="DEV-3",
                                session_binding=_session("DEV-3"),
                                message_digest=rec["envelope_hash"])
    with pytest.raises(m.AckRejected):
        m.delivered_at_from_receipt(receipt, rec["envelope_hash"], provider=provider,
                                    expect=addressee)
