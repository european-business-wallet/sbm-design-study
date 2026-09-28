# SPDX-License-Identifier: MIT
"""Round 10 / B4 — the invitation lifecycle, through the public operations.

R10-05  the invited device can READ the commitment it is told to check, and a
        substituted GroupInfo has a request, a reason and an outcome of its own.
R10-06  R10-X2 — burn and re-reserve: every stage of a failed group creation
        has one documented status and a safe package fate; an expired release
        is the promised 204; an idempotency key names its entity too.
R10-09  a repeated Welcome acknowledgement converges for its owner; one
        creator's backlog cannot hide another creator's outcome.

"No test may obtain the comparison value from a private invitation
dictionary" — so the device side here reads only what `collect_welcomes`
returns, and every outcome is produced by a real refusal, never seeded.
"""
import base64
import json
import pathlib
import sys

import prejoin
import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import mls_wire as w  # noqa: E402
import test_current_claims as tc  # noqa: E402
from lint_cli import request_schema, validate_contract_object  # noqa: E402

FR = "EU-FR-PSBID-ZYWVTSRQPNM8M4"
GROUP_INFO = b"a demo GroupInfo"            # what the creator's GroupInfo is
SUBSTITUTED = b"a GroupInfo somebody swapped in"


def _m():
    return tc._load("mock_rdp", "mock_rdp.py")


def _invite(m, *, mid="F1N2C3D4P", device="DEV-1", creator=None, n=0):
    """Reserve -> commit -> deposit, as `creator`, for one device. Returns the
    device credential that HOLDS the consumed package — the one a refusal
    must be authenticated by (R8-04)."""
    creator = creator or tc.MEMBER_CRED
    res = m.reserve_keypackages(FR, credential=creator, cipher_suite=tc.SUITE,
                                targets=[{"mid": mid, "device_id": device}],
                                idempotency_key=f"b4-idempotency-{creator['mid']}-{n:03}")
    m.commit_reservation(res["reservation_id"], credential=creator)
    pkg = res["keypackages"][0]
    m.deposit_welcome(tc._record(
        invitation_id=f"inv-b4-{creator['mid']}-{n}", recipient_device=device,
        reservation_id=res["reservation_id"], keypackage_ref=pkg["keypackage_ref"],
        group_info_commitment=w.group_info_commitment(GROUP_INFO, cipher_suite=tc.SUITE)),
        credential=creator)
    return {"kind": "device", "uid": FR, "device_id": device, "mid": mid,
            "keypackage_ref": pkg["keypackage_ref"]}


# ---------------------------------------------------------------------------
# R10-05 — the check the device is told to perform is one it can perform
# ---------------------------------------------------------------------------

def test_the_device_reads_the_commitment_from_its_own_queue():
    m = _m()
    dev = _invite(m)
    item = m.collect_welcomes(credential=dev)["welcomes"][0]
    assert validate_contract_object("delivery-service-openapi.yaml", "WelcomeQueue",
                                    m.collect_welcomes(credential=dev)) == []
    # Recomputed from the GroupInfo the decrypted Welcome carries, under the
    # suite the item names — nothing read from anywhere but the response.
    assert item["group_info_commitment"] == w.group_info_commitment(
        GROUP_INFO, cipher_suite=item["offered_suite"])


def test_a_substituted_group_info_is_detected_refused_and_reported():
    """The review's acceptance, end to end. The device detects the
    substitution using only its public queue item; the refusal is a VALID
    request under the published Schema; the creator collects an outcome that
    says what happened — and does not pretend it was a cipher-suite refusal."""
    m = _m()
    dev = _invite(m)
    item = m.collect_welcomes(credential=dev)["welcomes"][0]
    observed = w.group_info_commitment(SUBSTITUTED, cipher_suite=item["offered_suite"])
    assert observed != item["group_info_commitment"], "the probe detects nothing"

    request = {"reason": "group-info-mismatch", "offered_suite": item["offered_suite"]}
    _, validator = request_schema("delivery-service-openapi.yaml",
                                  "WelcomeRefusalRequest")
    # G1: the pre-join proof travels in the request, so a body without one is
    # no longer a valid `WelcomeRefusalRequest`.
    assert list(validator.iter_errors(request)), "the proof is required"
    proof = m.welcome_refusal_proof(item["welcome_id"], credential=dev,
                                    reason=request["reason"],
                                    offered_suite=request["offered_suite"],
                                    nonce=item["refusal_nonce"])
    assert list(validator.iter_errors(dict(request, refusal_proof=proof))) == []
    assert list(validator.iter_errors(dict(request, refusal_proof=proof,
                                           required_floor=tc.SUITE))), \
        "a GroupInfo mismatch may not carry a floor"

    m.refuse_welcome(item["welcome_id"], credential=dev, refused_at=tc.IN_WINDOW,
                     refusal_proof=proof, **request)
    outcomes = m.collect_outcomes(credential=tc.MEMBER_CRED)
    assert [o["reason"] for o in outcomes] == ["group-info-mismatch"]
    assert "required_floor" not in outcomes[0]
    assert validate_contract_object("delivery-service-openapi.yaml",
                                    "GroupEstablishmentOutcome", outcomes[0]) == []


def test_a_mismatch_refusal_cannot_claim_a_floor():
    m = _m()
    dev = _invite(m)
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    with pytest.raises(m.InvitationError) as exc:
        prejoin.refuse(m, wid, credential=dev, reason="group-info-mismatch",
                         offered_suite=tc.SUITE, required_floor=tc.SUITE,
                         refused_at=tc.IN_WINDOW)
    # Refused by the EXECUTED published request, which owns the rule.
    assert exc.value.reason == "refusal-request-invalid"


# ---------------------------------------------------------------------------
# R10-06 / R10-X2 — every stage of a failed group creation, one fate each
# ---------------------------------------------------------------------------

def _reserve(m, key="b4-burn-idempotency-01", uid=FR, targets=None):
    return m.reserve_keypackages(uid, credential=tc.MEMBER_CRED, cipher_suite=tc.SUITE,
                                 targets=targets or [{"mid": "F1N2C3D4P", "device_id": "DEV-1"},
                                                     {"mid": "G7H8J9K0Q", "device_id": "DEV-2"}],
                                 idempotency_key=key)


def test_before_commit_a_release_returns_every_package():
    m = _m(); res = _reserve(m)
    assert m.release_reservation(res["reservation_id"], credential=tc.MEMBER_CRED) is None
    assert m._RESERVATIONS[res["reservation_id"]]["state"] == "released"


@pytest.mark.parametrize("deposited", [0, 1, 2], ids=["no-welcome", "one-welcome", "all-welcomes"])
def test_after_commit_nothing_is_released_and_the_group_is_re_reserved(deposited):
    """Commit CONSUMES. Whether no Welcome, one, or all of them left before the
    group was abandoned, release refuses — returning a package whose Welcome
    may have reached a device would make a single-use package usable twice —
    and the creator reserves afresh, which works."""
    m = _m(); res = _reserve(m)
    m.commit_reservation(res["reservation_id"], credential=tc.MEMBER_CRED)
    for pkg in res["keypackages"][:deposited]:
        m.deposit_welcome(tc._record(
            invitation_id=f"inv-burn-{pkg['device_id']}", recipient_device=pkg["device_id"],
            reservation_id=res["reservation_id"], keypackage_ref=pkg["keypackage_ref"]),
            credential=tc.MEMBER_CRED)
    with pytest.raises(m.ReservationError) as exc:
        m.release_reservation(res["reservation_id"], credential=tc.MEMBER_CRED)
    assert exc.value.reason == "reservation-committed"
    assert m._RESERVATIONS[res["reservation_id"]]["state"] == "committed"
    fresh = _reserve(m, key="b4-burn-idempotency-02")
    assert fresh["reservation_id"] != res["reservation_id"]


def test_a_lost_commit_or_release_response_converges():
    m = _m(); res = _reserve(m)
    m.commit_reservation(res["reservation_id"], credential=tc.MEMBER_CRED)
    m.commit_reservation(res["reservation_id"], credential=tc.MEMBER_CRED)      # retry
    m2 = _m(); r2 = _reserve(m2)
    m2.release_reservation(r2["reservation_id"], credential=tc.MEMBER_CRED)
    assert m2.release_reservation(r2["reservation_id"], credential=tc.MEMBER_CRED) is None


def test_releasing_an_expired_reservation_is_the_promised_204():
    """R10-06: this raised `reservation-expired`, against a contract that
    says releasing an expired reservation is a 204."""
    m = _m(); res = _reserve(m)
    assert m.release_reservation(res["reservation_id"], credential=tc.MEMBER_CRED,
                                 now="2099-01-01T00:00:00Z") is None


def test_an_idempotency_key_names_its_entity_too():
    """R10-06: the same key, targets and suite under ANOTHER entity returned the
    first entity's reservation — its id and its packages. A cross-entity leak,
    not an idempotency slip."""
    m = _m()
    first = _reserve(m, key="b4-shared-idempotency", targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}])
    with pytest.raises(m.ReservationError) as exc:
        _reserve(m, key="b4-shared-idempotency", uid="EU-DE-EOID-7K3D9W0Q2M5FW0",
                 targets=[{"mid": "F1N2C3D4P", "device_id": "DEV-1"}])
    assert exc.value.reason == "reservation-conflict"
    assert m._RESERVATIONS[first["reservation_id"]]["uid"] == FR


# ---------------------------------------------------------------------------
# R10-09 — retries converge; one creator cannot starve another
# ---------------------------------------------------------------------------

def test_a_repeated_welcome_ack_converges_for_its_owner_only():
    m = _m(); dev = _invite(m)
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    assert m.ack_welcome(wid, credential=dev) is None
    assert m.ack_welcome(wid, credential=dev) is None                 # the lost 204
    other = {"kind": "device", "uid": FR, "device_id": "DEV-2", "mid": "F1N2C3D4P"}
    with pytest.raises(m.WelcomeAccessDenied):
        m.ack_welcome(wid, credential=other)          # still no existence oracle


def test_one_creators_backlog_cannot_hide_anothers_outcome():
    """R10-09, driven through PUBLIC refusals — Phase 1 reproduced this by
    seeding the queue, and recorded that the remediation test must not. Twenty
    outcomes for creator A, then one for creator B: B collects its one."""
    m = _m()
    a, b = tc.MEMBER_CRED, {"kind": "member", "uid": FR, "mid": "Z9Y8X7W6V"}
    for n in range(20):
        dev = _invite(m, device=f"DA-{n:02}", creator=a, n=n)
        wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
        prejoin.refuse(m, wid, credential=dev, reason="group-info-mismatch",
                         offered_suite=tc.SUITE, refused_at=tc.IN_WINDOW)
    dev = _invite(m, device="DB-00", creator=b, n=0)
    wid = m.collect_welcomes(credential=dev)["welcomes"][0]["welcome_id"]
    prejoin.refuse(m, wid, credential=dev, reason="group-info-mismatch",
                     offered_suite=tc.SUITE, refused_at=tc.IN_WINDOW)
    assert len(m.collect_outcomes(credential=a)) == 20
    got = m.collect_outcomes(credential=b)
    assert [o["device_id"] for o in got] == ["DB-00"], got
