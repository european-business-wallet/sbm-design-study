# SPDX-License-Identifier: MIT
"""Round 12 / B1 — R12-01 and R12-02: every confirmation kind is bound to the
message it claims to be about, and each kind obeys its own rules.

R12-01. Intake authorised the confirming member and counted the act without
asking what it was about: two members' authentic S3 statements about ANOTHER
content digest, octet commitment, group state, group or epoch satisfied a
`quorum:2` that the retained verifier (LINT-DE-02/04/16) then refused.

R12-02. The round-11 time check and INTF-3 ran for every kind, so the shipped,
genuinely signed refusal and reveal — whose Schemas forbid `verified_at` and
the policy reference — were refused. R12-X1: a verified refusal is terminal and
issues the member's RE; a reveal is dispute material and changes nothing.

The review's acceptance, in order: each changed field rejected without ledger
changes in both proof modes; matching confirmations still complete quorum; a
rejected attempt does not poison a later valid one; valid examples of all four
kinds reach their specified result; wrong fields and signatures fail before
state changes; retries and post-terminal acts for each kind.
"""
import base64
import copy
import importlib.util
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

import cbor2  # noqa: E402
import test_confirmation_acts as ca  # noqa: E402

_ld = lambda f: json.loads((ROOT / "samples" / f).read_text())["projection"]  # noqa: E731
REFUSAL = _ld("sample-RE.json")["refusal_confirmation"]
REVEAL = _ld("sample-GCM.json")["reveal_confirmation"]
A, B, C, FR = ca.A, ca.B, ca.C, ca.FR


def _three():
    """A third procurement member whose dev-01 publishes ITS OWN demo key."""
    import mock_rdp
    third = copy.deepcopy(ca.MEMBERS[1]); third["mid"] = C
    third["devices"][0]["confirmation_key"] = {
        "alg": "EdDSA", "public_key_b64": mock_rdp.demo_public_key_b64(f"wallet:{C}:dev-01")}
    return ca.MEMBERS + [third]
WRONG = {"payload_hash": dict(ca.SE["payload_hash"], hex="e" * 64),
         "envelope_hash": dict(ca.SE["envelope_hash"], hex="e" * 64),
         "mls_state": dict(ca.SE["mls_state"], hex="e" * 64),
         "mls_group_id": "OtherGroupOtherGroupOth", "mls_epoch": "99"}


def _ev():
    spec = importlib.util.spec_from_file_location("ev_r12b1", ROOT / "scripts" / "evidence_lint.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


def _dev(mid, **extra):
    return {"kind": "device", "uid": FR, "mid": mid, "device_id": "dev-01", **extra}


def _signed(m, conf):
    conf = {k: v for k, v in copy.deepcopy(conf).items()
            if k not in ("session_authenticated", "wallet_signature_b64")}
    conf["device_id"] = "dev-01"
    conf["wallet_signature_b64"] = m._wallet_sign(conf)
    return conf


def _s3(m, mid, mode, **change):
    s3 = dict(ca._s3(mid), **change)
    return (_signed(m, s3), _dev(mid)) if mode == "wallet" else (s3, ca._member(mid))


def _empty(m):
    return m._CONFIRMATION_ACTS == {} and m._CONFIRMATION_STATE == {}


# ===========================================================================
# R12-01 — an S3 about another context counts for nothing
# ===========================================================================

@pytest.mark.parametrize("mode", ["session", "wallet"])
@pytest.mark.parametrize("field", sorted(WRONG))
def test_an_s3_about_another_context_is_refused_before_anything_moves(field, mode):
    m = ca._m()
    conf, cred = _s3(m, A, mode, **{field: WRONG[field]})
    with pytest.raises(m.ConfirmationRejected) as exc:
        ca._deliver(m, "s3", conf, cred)
    assert exc.value.reason == "confirmation-rejected", exc.value
    assert _empty(m), "a refused act left a ledger entry"


@pytest.mark.parametrize("mode", ["session", "wallet"])
def test_matching_confirmations_still_complete_the_quorum(mode):
    m = ca._m()
    for mid in (A, B):
        ca._deliver(m, "s3", *_s3(m, mid, mode))
    assert ca._state(m)["state"] == "satisfied"


def test_a_refused_attempt_does_not_poison_a_later_valid_one():
    m = ca._m()
    with pytest.raises(m.ConfirmationRejected):
        ca._deliver(m, "s3", *_s3(m, A, "session", payload_hash=WRONG["payload_hash"]))
    ca._deliver(m, "s3", *_s3(m, A, "session"))       # not a conflict: nothing was stored
    ca._deliver(m, "s3", *_s3(m, B, "session"))
    assert ca._state(m)["state"] == "satisfied"


# ===========================================================================
# R12-02 — each kind its own rules
# ===========================================================================

AUTH = {"method": "wallet-eid-high", "loa": "high"}


def _refuse(m, conf=None, mid=A, at="2026-04-04T10:47:00Z", **kw):
    return ca._deliver(m, "refusal", conf or copy.deepcopy(REFUSAL), _dev(mid, **AUTH),
                       at=at, **kw)


def _reveal_se():
    """The SE the shipped reveal opens: its message, octets and commitment."""
    return dict(copy.deepcopy(ca.SE), **{k: REVEAL[k] for k in (
        "message_id", "envelope_hash", "grade_commitment", "recipient_uid")})


def _reveal(m, conf=None, **kw):
    se = _reveal_se()
    return m.deliver_confirmation(
        {"issuing_rdp_id": se["rdp_id"], "message_id": se["message_id"],
         "confirmation_kind": "reveal", "confirmation": conf or copy.deepcopy(REVEAL)},
        credential=_dev(A), se=se, rdp_id=ca.RDP_IN, observed_at="2026-04-09T10:00:00Z",
        members=ca.MEMBERS, org=ca.ORG, **kw), se


def test_a_valid_refusal_ends_the_message_with_the_members_re():
    m = ca._m()
    re_art = _refuse(m)
    re = re_art["projection"]
    assert (re["type"], re["refusal_kind"], re["reason"], re["mid"]) == \
        ("RE-v1", "member", "refused-by-user", A)
    assert re["refusal_confirmation"] == REFUSAL
    assert re["auth_context"] == {"identity": "member", "mid": A, **AUTH}, \
        "how RDP(in) authenticated the member — from the session, not the request"
    assert [r for r, _ in _ev().lint(re_art, verify_demo=True)] == []
    assert ca._state(m)["state"] == "refused"
    assert m.delivery_decision(ca.SE, "acceptance", state=ca._state(m))["outcome"] == "refused"
    assert _refuse(m) == re_art, "an exact retry converges on the same RE"


def test_a_valid_reveal_is_recorded_and_changes_nothing():
    m = ca._m()
    assert _reveal(m)[0] is None
    se = _reveal_se()
    assert m.confirmation_state(se["rdp_id"], se["message_id"])["state"] == "open"


@pytest.mark.parametrize("field,value", [
    ("payload_hash", {"alg": "SHA-256", "hex": "e" * 64, "hash_mode": "raw-sha256"}),
    ("message_id", "01HZ3OTHERMESSAGE00000001"),
])
def test_a_refusal_about_another_message_is_refused(field, value):
    m = ca._m()
    conf = _signed(m, dict(copy.deepcopy(REFUSAL), **{field: value}))
    with pytest.raises(m.ConfirmationRejected) as exc:
        _refuse(m, conf)
    assert exc.value.reason in ("confirmation-rejected", "confirmation-message-mismatch")
    assert _empty(m)


@pytest.mark.parametrize("field", ["grade_commitment", "envelope_hash"])
def test_a_reveal_of_another_commitment_is_refused(field):
    m = ca._m()
    other = "e" * 64 if field == "grade_commitment" else dict(REVEAL["envelope_hash"], hex="e" * 64)
    conf = _signed(m, dict(copy.deepcopy(REVEAL), **{field: other}))
    with pytest.raises(m.ConfirmationRejected) as exc:
        _reveal(m, conf)
    assert exc.value.reason == "confirmation-rejected"
    assert _empty(m)


@pytest.mark.parametrize("kind", ["refusal", "reveal"])
def test_a_broken_signature_is_refused_for_every_kind(kind):
    m = ca._m()
    conf = copy.deepcopy(REFUSAL if kind == "refusal" else REVEAL)
    arr = cbor2.loads(base64.b64decode(conf["wallet_signature_b64"]))
    items = list(arr.value if hasattr(arr, "value") else arr)
    sig = bytearray(items[3]); sig[0] ^= 1; items[3] = bytes(sig)
    conf["wallet_signature_b64"] = base64.b64encode(
        cbor2.dumps(cbor2.CBORTag(18, items) if hasattr(arr, "value") else items)).decode()
    with pytest.raises(m.ConfirmationRejected) as exc:
        _refuse(m, conf) if kind == "refusal" else _reveal(m, conf)
    assert exc.value.reason == "confirmation-signature-invalid"
    assert _empty(m)


def test_refusal_and_reveal_need_no_field_their_schemas_forbid():
    """The shipped objects are used verbatim: nothing is added to them."""
    assert "verified_at" not in REFUSAL and "acceptance_policy_ref" not in REFUSAL
    assert "verified_at" not in REVEAL and "acceptance_policy_ref" not in REVEAL
    m = ca._m()
    assert _refuse(m) is not None and _reveal(ca._m())[0] is None


# ---------------------------------------------------------------------------
# After the outcome — every kind
# ---------------------------------------------------------------------------

def test_acts_after_a_refusal_are_retained_and_change_nothing():
    m = ca._m()
    _refuse(m, mid=A)
    assert ca._deliver(m, "s3", *_s3(m, B, "session")) is None
    assert ca._deliver(m, "mismatch", dict(copy.deepcopy(ca.PROOF), mid=C),
                       ca._member(C), members=_three()) is None, "a second terminal act issued"
    st = ca._state(m)
    assert st["state"] == "refused" and st["counted"] == []
    assert {k[3] for k in m._CONFIRMATION_ACTS} == {A, B, C}


def test_a_refusal_after_s4_is_dispute_material_not_an_re():
    m = ca._m()
    for mid in (A, B):
        ca._deliver(m, "s3", *_s3(m, mid, "session"), members=_three())
    assert ca._deliver(m, "refusal", _signed(m, dict(copy.deepcopy(REFUSAL), mid=C)),
                       _dev(C, **AUTH), members=_three()) is None
    assert ca._state(m)["state"] == "satisfied"


def test_the_member_who_refused_may_still_reveal():
    """A reveal is not the member's delivery act. It shared that slot, so the
    member who had refused could not reveal: `confirmation-conflict`. The
    round-12 closure fixture found it; the test above used another member."""
    m = ca._m()
    se = _reveal_se()
    refusal = _signed(m, dict(copy.deepcopy(REFUSAL), message_id=se["message_id"],
                              payload_hash=se["payload_hash"]))
    m.deliver_confirmation(
        {"issuing_rdp_id": se["rdp_id"], "message_id": se["message_id"],
         "confirmation_kind": "refusal", "confirmation": refusal},
        credential=_dev(A, **AUTH), se=se, rdp_id=ca.RDP_IN,
        observed_at="2026-04-09T09:00:00Z", members=ca.MEMBERS, org=ca.ORG)
    assert _reveal(m)[0] is None
    assert _reveal(m)[0] is None, "an exact retry converges"
    assert m.confirmation_state(se["rdp_id"], se["message_id"])["state"] == "refused"
    other = _signed(m, dict(copy.deepcopy(REVEAL), read_at="2026-04-09T09:45:00Z"))
    with pytest.raises(m.ConfirmationRejected) as exc:
        _reveal(m, other)
    assert exc.value.reason == "confirmation-conflict", "one reveal per member and message"


def test_a_reveal_is_accepted_after_a_terminal_outcome():
    m = ca._m()
    se = _reveal_se()
    # end the reveal's message first — a refusal of THAT message by another member
    refusal = _signed(m, dict(copy.deepcopy(REFUSAL), mid=B, message_id=se["message_id"],
                              payload_hash=se["payload_hash"]))
    m.deliver_confirmation(
        {"issuing_rdp_id": se["rdp_id"], "message_id": se["message_id"],
         "confirmation_kind": "refusal", "confirmation": refusal},
        credential=_dev(B, **AUTH), se=se, rdp_id=ca.RDP_IN,
        observed_at="2026-04-09T09:00:00Z", members=ca.MEMBERS, org=ca.ORG)
    assert m.confirmation_state(se["rdp_id"], se["message_id"])["state"] == "refused"
    assert _reveal(m)[0] is None
    assert m.confirmation_state(se["rdp_id"], se["message_id"])["state"] == "refused"
