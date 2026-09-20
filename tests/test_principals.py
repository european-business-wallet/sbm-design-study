# SPDX-License-Identifier: MIT
"""Round 11 / B1 — R11-01: a principal is a tuple, never a label.

A MID is unique only within its entity and a device label only within its
member (umbrella §3). The published schemes bound a credential to a bare
`mid` or `device_id`, and the Delivery Service keyed and authorised on them.
Reproduced before this batch, through the public operations:

  * a FR device labelled `DEV-1` collected a DE device's message, and the DS
    SIGNED a receipt attributing that delivery to DE;
  * the same label in two entities made every acceptance of a message fail
    `delivery-recipient-conflict`, the retry included;
  * a DE member sharing a FR creator's MID collected and acknowledged the FR
    creator's outcome, committed its reservation, and got it back by reusing
    its `Idempotency-Key`;
  * two members of ONE entity with a `dev-01` each — the shipped samples'
    own topology — could not even be invited.

The review's acceptance, verbatim: "Two entities reuse the same MID and device
label on one DS: both receive exactly their own items; neither can collect,
acknowledge, refuse or delete the other's; receipts name the principal
actually authenticated; retry converges for both legitimate targets."
"""
import base64
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_wire as w  # noqa: E402
import test_current_claims as tc  # noqa: E402

FR = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
DE = "EU-DE-EOID-7K3D9W0Q2M5FW0"
MID, LABEL = "F1N2C3D4P", "DEV-1"          # the SAME local identifiers in both
GROUP = "Zzw1S4pWq9T5n7xYbXc2dQ"
RDP = "urn:sbm:rdp:demo-out"
MSG = "01HZR11B1PRINCIPAL0000001"
OCTETS = b"one ciphertext, two devices sharing a label"
FR_DEV, DE_DEV = (FR, MID, LABEL), (DE, MID, LABEL)
CREATOR = {"kind": "member", "uid": FR, "mid": "G7H8J9K0Q"}


def _m():
    return tc._load("mock_rdp", "mock_rdp.py")


def _session(p):
    return {"kind": "token-digest", "digest": ("a" if p[0] == FR else "d") * 64}


def _dev(p, **extra):
    return {"kind": "device", "uid": p[0], "mid": p[1], "device_id": p[2],
            "session": _session(p)["digest"], **extra}


def _form(m, devices):
    """Reserve per entity, commit, deposit one Welcome per device — the public
    lifecycle. Returns {principal: keypackage_ref}."""
    by_uid, refs, n = {}, {}, 0
    for p in devices:
        by_uid.setdefault(p[0], []).append({"mid": p[1], "device_id": p[2]})
    for i, (uid, targets) in enumerate(sorted(by_uid.items())):
        res = m.reserve_keypackages(uid, credential=CREATOR, cipher_suite=tc.SUITE,
                                    targets=targets,
                                    idempotency_key=f"r11-b1-idempotency-{i:02}")
        m.commit_reservation(res["reservation_id"], credential=CREATOR)
        for pkg in res["keypackages"]:
            p = (uid, pkg["mid"], pkg["device_id"])
            refs[p] = pkg["keypackage_ref"]
            m.deposit_welcome(tc._record(
                invitation_id=f"inv-r11-{n}", recipient_device=pkg["device_id"],
                reservation_id=res["reservation_id"],
                keypackage_ref=pkg["keypackage_ref"], mls_group_id=GROUP,
                group_info_commitment=w.group_info_commitment(
                    b"a demo GroupInfo", cipher_suite=tc.SUITE)),
                credential=CREATOR)
            n += 1
    return refs


def _accept(m):
    return m.ds_accept_message(MSG, GROUP, base64.b64encode(OCTETS).decode(),
                               principal=RDP)


def _collect(m, p):
    return m.collect_messages(credential=_dev(p), session_binding=_session(p))["items"]


def _ack(m, p, token, *, as_=None):
    who = as_ or p
    return m.receipt_ack(message_id=MSG, issuing_rdp_id=RDP, device_id=who[2],
                         credential=_dev(who), session_binding=_session(who),
                         octets=OCTETS, server_clock="2026-04-04T10:20:00Z",
                         collection_token=token)


# ---------------------------------------------------------------------------
# The review's acceptance — two entities, one MID, one label
# ---------------------------------------------------------------------------

def test_both_devices_are_delivered_first_time_and_the_retry_converges():
    m = _m()
    _form(m, [FR_DEV, DE_DEV])
    assert m.group_roster(GROUP) == sorted([FR_DEV, DE_DEV])
    first = _accept(m)                       # before: delivery-recipient-conflict
    assert _accept(m) == first               # the retry converges
    assert sorted(k[2:] for k in m._DELIVERY_ITEMS if k[:2] == (RDP, MSG)) == \
        sorted([FR_DEV, DE_DEV]), "one item per PRINCIPAL, exactly once each"
    assert len(_collect(m, FR_DEV)) == 1 and len(_collect(m, DE_DEV)) == 1


def test_each_receipt_names_the_principal_that_was_authenticated():
    m = _m()
    _form(m, [FR_DEV, DE_DEV])
    _accept(m)
    tok = {p: _collect(m, p)[0]["collection_token"] for p in (FR_DEV, DE_DEV)}
    fr, de = _ack(m, FR_DEV, tok[FR_DEV]), _ack(m, DE_DEV, tok[DE_DEV])
    assert (fr["recipient_uid"], fr["mid"], fr["device_id"]) == FR_DEV
    assert (de["recipient_uid"], de["mid"], de["device_id"]) == DE_DEV


def test_one_entitys_device_cannot_acknowledge_the_others_transfer():
    """The signed misattribution: the item is DE's; the credential is FR's
    device with the same label, in FR's own session."""
    m = _m()
    _form(m, [DE_DEV])                       # only DE's device is in the group
    _accept(m)
    assert _collect(m, FR_DEV) == [], "another entity's device received DE's bytes"
    de_token = _collect(m, DE_DEV)[0]["collection_token"]
    with pytest.raises(m.AckRejected):
        _ack(m, DE_DEV, de_token, as_=FR_DEV)
    assert m._ACK_LEDGER == {}, "a receipt was signed for the wrong principal"


def test_neither_can_collect_acknowledge_or_refuse_the_others_welcome():
    m = _m()
    refs = _form(m, [FR_DEV, DE_DEV])
    fr_q = m.collect_welcomes(credential=_dev(FR_DEV))["welcomes"]
    de_q = m.collect_welcomes(credential=_dev(DE_DEV))["welcomes"]
    assert len(fr_q) == 1 and len(de_q) == 1 and fr_q != de_q
    de_wid = de_q[0]["welcome_id"]
    with pytest.raises(m.WelcomeAccessDenied):
        m.ack_welcome(de_wid, credential=_dev(FR_DEV))
    with pytest.raises(m.InvitationError) as exc:
        m.refuse_welcome(de_wid, credential=_dev(FR_DEV, keypackage_ref=refs[DE_DEV]),
                         reason="group-info-mismatch", offered_suite=tc.SUITE)
    assert exc.value.reason == "invitation-unknown"
    assert m.ack_welcome(de_wid, credential=_dev(DE_DEV)) is None   # the owner can
    assert m.ack_welcome(de_wid, credential=_dev(DE_DEV)) is None   # and converges


def test_the_two_devices_hold_different_packages():
    """The demo KeyPackage bytes omitted the entity, so the same (MID, label)
    under two entities had ONE package reference for two devices."""
    refs = _form(_m(), [FR_DEV, DE_DEV])
    assert refs[FR_DEV] != refs[DE_DEV]


# ---------------------------------------------------------------------------
# Within ONE entity — the shipped samples' own topology
# ---------------------------------------------------------------------------

def test_two_members_each_with_dev_01_can_be_invited_and_delivered():
    """sample-BW-MEMBER-fr and -fr2 each publish a `dev-01`. The deposit found
    its package by the label and met the other member's, so this topology
    was refused `keypackage-not-consumed` before any message was sent."""
    m = _m()
    a, b = (FR, "F1N2C3D4P", "dev-01"), (FR, "F2X3Y4Z55", "dev-01")
    _form(m, [a, b])
    _accept(m)
    assert len(_collect(m, a)) == 1 and len(_collect(m, b)) == 1


def test_the_floor_is_the_refusing_members_own():
    """The floor was resolved by label across every member supplied, so of
    two members each publishing a `dev-01` the first one's answered."""
    m = _m()
    a, b = (FR, "F1N2C3D4P", "dev-01"), (FR, "F2X3Y4Z55", "dev-01")
    hw = "MLS_128_DHKEMP256_AES128GCM_SHA256_P256"
    members = [{"uid": FR, "mid": a[1], "devices": [{"device_id": "dev-01",
                                                     "min_cipher_suite": hw}]},
               {"uid": FR, "mid": b[1], "devices": [{"device_id": "dev-01"}]}]
    assert m.published_device_floor(members, a) == hw
    assert m.published_device_floor(members, b) == tc.SUITE, \
        "member b's device was given member a's floor"


# ---------------------------------------------------------------------------
# Creators sharing a MID across entities
# ---------------------------------------------------------------------------

def test_a_creator_in_another_entity_with_the_same_mid_owns_nothing_of_this_one():
    m = _m()
    fr_creator = {"kind": "member", "uid": FR, "mid": MID}
    de_creator = {"kind": "member", "uid": DE, "mid": MID}
    key = "r11-b1-shared-key-0001"
    target = [{"mid": "H2J3K4M5N", "device_id": "DEV-9"}]
    fr_res = m.reserve_keypackages(DE, credential=fr_creator, cipher_suite=tc.SUITE,
                                   targets=target, idempotency_key=key)
    # The same Idempotency-Key under another principal is another request —
    # never a replay that hands back the first creator's reservation.
    de_res = m.reserve_keypackages(DE, credential=de_creator, cipher_suite=tc.SUITE,
                                   targets=target, idempotency_key=key)
    assert de_res["reservation_id"] != fr_res["reservation_id"]
    for op in (m.commit_reservation, m.release_reservation):
        with pytest.raises(m.ReservationError) as exc:
            op(fr_res["reservation_id"], credential=de_creator)
        assert exc.value.reason == "reservation-unknown"


def test_outcomes_belong_to_the_creator_principal_and_name_the_refusing_member():
    m = _m()
    fr_creator = {"kind": "member", "uid": FR, "mid": MID}
    de_twin = {"kind": "member", "uid": DE, "mid": MID}
    res = m.reserve_keypackages(FR, credential=fr_creator, cipher_suite=tc.SUITE,
                                targets=[{"mid": "F2X3Y4Z55", "device_id": "dev-01"}],
                                idempotency_key="r11-b1-outcome-key-01")
    m.commit_reservation(res["reservation_id"], credential=fr_creator)
    pkg = res["keypackages"][0]
    m.deposit_welcome(tc._record(invitation_id="inv-r11-out", recipient_device="dev-01",
                                 reservation_id=res["reservation_id"],
                                 keypackage_ref=pkg["keypackage_ref"]),
                      credential=fr_creator)
    target = (FR, "F2X3Y4Z55", "dev-01")
    wid = m.collect_welcomes(credential=_dev(target))["welcomes"][0]["welcome_id"]
    m.refuse_welcome(wid, credential=_dev(target, keypackage_ref=pkg["keypackage_ref"]),
                     reason="group-info-mismatch", offered_suite=tc.SUITE)
    assert m.collect_outcomes(credential=de_twin) == [], \
        "a member of another entity sharing the MID saw the creator's outcome"
    [out] = m.collect_outcomes(credential=fr_creator)
    assert (out["recipient_uid"], out["mid"], out["device_id"]) == target
    with pytest.raises(m.InvitationError):
        m.ack_outcome(out["outcome_id"], credential=de_twin)
    assert m.ack_outcome(out["outcome_id"], credential=fr_creator) is None


# ---------------------------------------------------------------------------
# A label is not a principal
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("missing", ["uid", "mid"])
def test_a_credential_naming_only_part_of_the_principal_is_refused(missing):
    m = _m()
    _form(m, [FR_DEV])
    _accept(m)
    partial = {k: v for k, v in _dev(FR_DEV).items() if k != missing}
    with pytest.raises(m.DeliveryStateError) as exc:
        m.collect_messages(credential=partial, session_binding=_session(FR_DEV))
    assert exc.value.reason == "device-auth-required"
    with pytest.raises(m.WelcomeAccessDenied):
        m.collect_welcomes(credential=partial)
    member = {"kind": "member", "uid": FR, "mid": MID}
    with pytest.raises(m.WelcomeAccessDenied):
        m.collect_outcomes(credential={k: v for k, v in member.items() if k != missing})


def test_the_published_outcome_names_the_whole_principal():
    """A creator can only act on "which device refused" if the published
    object can say it: a label names a device of every member using it."""
    from lint_cli import validate_contract_object
    out = {"outcome_id": "out-1", "welcome_id": "wel-1", "mls_group_id": GROUP,
           "device_id": "dev-01", "reason": "group-info-mismatch",
           "offered_suite": tc.SUITE, "refused_at": "2026-04-04T10:05:00Z"}
    assert validate_contract_object("delivery-service-openapi.yaml",
                                    "GroupEstablishmentOutcome", out), \
        "an outcome without the refusing member's entity and MID validates"
    assert validate_contract_object("delivery-service-openapi.yaml",
                                    "GroupEstablishmentOutcome",
                                    dict(out, recipient_uid=FR, mid="F2X3Y4Z55")) == []
