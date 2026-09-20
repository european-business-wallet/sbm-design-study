# SPDX-License-Identifier: MIT
"""Round 11 / B2 — R11-02 and R11-03: confirmations are per-member acts, and
issuance runs the rules its evidence will be held to.

R11-02. R10-07 keyed confirmations on the message: the second member's valid
`s3` was refused `confirmation-conflict`, so `quorum:2` and `all` could not be
completed through the published request, and a bare `message_id` put two
originating providers' messages in one slot. R11-X1: one act per member,
distinct members contribute, a verified mismatch is terminal.

R11-03. Issuance checked the request's shape and a MID string, then sealed.
Reproduced: a flipped wallet-signature byte produced a sealed NDE the evidence
linter then refused; a session confirmation from a MID nobody published
produced one too; and replaying an accepted request under another principal
returned the issued NDE, because the retry lookup ran before authorisation.

The review's acceptance (R11-03): "Invalid signature, wrong key, missing key,
unknown/wrong-entity/inactive member, ineligible device and wrong-principal
retry are rejected before any evidence or confirmation ledger entry exists. A
valid signature resolved from the named recipient device succeeds. Test at
issuance, not just afterwards."
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
import test_current_claims as tc  # noqa: E402

_ld = lambda f: json.loads((ROOT / "samples" / f).read_text())["projection"]  # noqa: E731
SE = _ld("sample-SE.json")                         # policy key `procurement` = quorum:2
ORG = _ld("sample-BW-ORG.json")
MEMBERS = [_ld("sample-BW-MEMBER-fr.json"), _ld("sample-BW-MEMBER-fr2.json")]
S3 = _ld("sample-DE.json")["s3_attestation"]      # session-authenticated, F1N2C3D4P
PROOF = _ld("sample-NDE-mismatch.json")["recipient_confirmation"]
FR, A, B, C = SE["recipient_uid"], "F1N2C3D4P", "F2X3Y4Z55", "G7H8J9K0Q"
# A third procurement member, so an act can arrive AFTER a terminal outcome.
THREE = MEMBERS + [dict(copy.deepcopy(MEMBERS[1]), mid=C)]
RDP_IN = "urn:sbm:rdp:mockeu-002"


def _m():
    return tc._load("mock_rdp", "mock_rdp.py")


def _member(mid, uid=FR):
    return {"kind": "member", "uid": uid, "mid": mid}


def _req(kind, conf, se=SE):
    return {"issuing_rdp_id": se["rdp_id"], "message_id": se["message_id"],
            "confirmation_kind": kind, "confirmation": conf}


def _deliver(m, kind, conf, cred, *, se=SE, at="2026-04-04T10:47:00Z",
             members=MEMBERS, org=ORG):
    return m.deliver_confirmation(_req(kind, conf, se), credential=cred, se=se,
                                  rdp_id=RDP_IN, observed_at=at,
                                  members=members, org=org)


def _s3(mid, se=SE):
    return dict(copy.deepcopy(S3), mid=mid, message_id=se["message_id"],
                acceptance_policy_ref=copy.deepcopy(se["acceptance_policy_ref"]))


def _state(m, se=SE):
    return m.confirmation_state(se["rdp_id"], se["message_id"])


def _ev():
    spec = importlib.util.spec_from_file_location("ev_b2", ROOT / "scripts" / "evidence_lint.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    return mod


# ===========================================================================
# R11-02 — acts per member
# ===========================================================================

def test_quorum_2_completes_through_the_public_request():
    """Before B2 the second member's `s3` was `confirmation-conflict`."""
    m = _m()
    _deliver(m, "s3", _s3(A), _member(A), at="2026-04-04T10:47:00Z")
    assert _state(m)["state"] == "open"
    _deliver(m, "s3", _s3(B), _member(B), at="2026-04-04T10:52:00Z")
    st = _state(m)
    assert st["state"] == "satisfied" and st["counted"] == [A, B]
    assert st["at"] == "2026-04-04T10:52:00Z", \
        "S4 is when RDP(in) observed the COMPLETING act (R11-X2)"


def test_all_completes_only_when_every_eligible_member_has_acted():
    """`all` over two eligible members: a BW-ORG version whose `procurement`
    policy is `all` (both samples hold the role), pinned by the SE."""
    m = _m()
    org = copy.deepcopy(ORG)
    org["acceptance_policy"]["procurement"] = "all"
    se = copy.deepcopy(SE)
    se["acceptance_policy_ref"] = dict(se["acceptance_policy_ref"],
                                       doc_digest=dict(se["acceptance_policy_ref"]["doc_digest"],
                                                       hex=m._org_body_digest(org)))
    _deliver(m, "s3", _s3(A, se), _member(A), se=se, org=org)
    assert _state(m, se)["state"] == "open"
    _deliver(m, "s3", _s3(B, se), _member(B), se=se, org=org)
    assert _state(m, se)["state"] == "satisfied"


def test_an_exact_retry_converges_and_does_not_double_count():
    m = _m()
    for _ in range(3):
        assert _deliver(m, "s3", _s3(A), _member(A)) is None
    assert _state(m)["counted"] == [A] and _state(m)["state"] == "open"


def test_the_same_member_making_a_different_claim_is_a_conflict():
    m = _m()
    _deliver(m, "s3", _s3(A), _member(A))
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, "mismatch", dict(PROOF, mid=A), _member(A))
    assert exc.value.reason == "confirmation-conflict"
    assert _state(m)["state"] == "open", "a refused claim changed the outcome"


def test_a_member_outside_the_selected_policy_is_recorded_and_not_counted():
    """`invoices` is any-one over its role holders — only F2X3Y4Z55."""
    m = _m()
    se = copy.deepcopy(SE)
    se["acceptance_policy_ref"] = dict(se["acceptance_policy_ref"], policy_key="invoices")
    _deliver(m, "s3", _s3(A, se), _member(A), se=se)
    assert _state(m, se)["state"] == "open" and _state(m, se)["counted"] == []
    _deliver(m, "s3", _s3(B, se), _member(B), se=se)
    assert _state(m, se)["state"] == "satisfied"


def test_equal_message_ids_from_two_originating_providers_do_not_collide():
    m = _m()
    other = dict(copy.deepcopy(SE), rdp_id="urn:sbm:rdp:mockeu-003")
    _deliver(m, "s3", _s3(A), _member(A))
    _deliver(m, "s3", _s3(A, other), _member(A), se=other)   # not a retry, not a conflict
    assert _state(m)["counted"] == [A] and _state(m, other)["counted"] == [A]


def test_a_verified_mismatch_is_terminal_and_later_acts_change_nothing():
    m = _m()
    _deliver(m, "s3", _s3(A), _member(A), members=THREE)
    nde = _deliver(m, "mismatch", dict(copy.deepcopy(PROOF), mid=B), _member(B),
                   members=THREE)
    assert nde["projection"]["reason"] == "payload-hash-mismatch"
    assert _deliver(m, "s3", _s3(C), _member(C), members=THREE) is None
    st = _state(m)
    assert st["state"] == "mismatch" and st["counted"] == [A], \
        "an act after the terminal outcome was counted"
    assert (SE["rdp_id"], SE["message_id"], FR, C) in m._CONFIRMATION_ACTS, \
        "the later act must be RETAINED, not dropped"


def test_a_mismatch_after_s4_is_dispute_material_not_an_nde():
    m = _m()
    _deliver(m, "s3", _s3(A), _member(A), members=THREE)
    _deliver(m, "s3", _s3(B), _member(B), members=THREE)
    assert _state(m)["state"] == "satisfied"
    late = _deliver(m, "mismatch", dict(copy.deepcopy(PROOF), mid=C), _member(C),
                    members=THREE)
    assert late is None, "a mismatch after S4 produced an NDE"
    assert _state(m)["state"] == "satisfied"
    assert (SE["rdp_id"], SE["message_id"], FR, C) in m._CONFIRMATION_ACTS


# ===========================================================================
# R11-03 — nothing is stored or sealed until the proof verifies
# ===========================================================================

def _signed(m, conf, *, seed=None, flip=False):
    """A wallet-signed confirmation by `dev-01` of its member. `seed` signs
    with another key; `flip` corrupts one signature byte and nothing else."""
    conf = {k: v for k, v in copy.deepcopy(conf).items() if k != "session_authenticated"}
    conf["device_id"] = "dev-01"
    if seed:
        payload = m._dcbor({k: v for k, v in conf.items() if k != "wallet_signature_b64"})
        conf["wallet_signature_b64"] = base64.b64encode(
            m.cose_sign(payload, kid="wallet", seed=seed)).decode()
    else:
        conf["wallet_signature_b64"] = m._wallet_sign(conf)
    if flip:
        arr = cbor2.loads(base64.b64decode(conf["wallet_signature_b64"]))
        items = list(arr.value if hasattr(arr, "value") else arr)
        sig = bytearray(items[3]); sig[0] ^= 1; items[3] = bytes(sig)
        conf["wallet_signature_b64"] = base64.b64encode(
            cbor2.dumps(cbor2.CBORTag(18, items) if hasattr(arr, "value") else items)).decode()
    return conf


def _dev(mid, uid=FR, device="dev-01"):
    return {"kind": "device", "uid": uid, "mid": mid, "device_id": device}


def _refused(m, kind, conf, cred, reason, **kw):
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, kind, conf, cred, **kw)
    assert exc.value.reason == reason, exc.value
    assert m._CONFIRMATION_ACTS == {} and m._CONFIRMATION_STATE == {}, \
        "a refused confirmation left a ledger entry"


def _without_key(members):
    ms = copy.deepcopy(members)
    for d in ms[0]["devices"]:
        d.pop("confirmation_key", None)
    return ms


def test_a_valid_signature_from_the_named_device_succeeds_and_lints_clean():
    m = _m()
    art = _deliver(m, "mismatch", _signed(m, PROOF), _dev(A))
    assert [r for r, _ in _ev().lint(art, verify_demo=True)] == []


@pytest.mark.parametrize("case,reason", [
    ("flipped signature byte", "confirmation-signature-invalid"),
    ("another device's key", "confirmation-signature-invalid"),
    ("no published key", "confirmation-signature-invalid"),
])
def test_a_proof_that_does_not_verify_is_refused_at_issuance(case, reason):
    m = _m()
    if case == "flipped signature byte":
        _refused(m, "mismatch", _signed(m, PROOF, flip=True), _dev(A), reason)
    elif case == "another device's key":
        _refused(m, "mismatch", _signed(m, PROOF, seed=f"wallet:{A}:dev-02-hsm"),
                 _dev(A), reason)
    else:
        _refused(m, "mismatch", _signed(m, PROOF), _dev(A), reason,
                 members=_without_key(MEMBERS))


def test_an_unknown_member_is_refused():
    m = _m()
    _refused(m, "mismatch", dict(copy.deepcopy(PROOF), mid="Q9Q9Q9Q9Q"),
             _member("Q9Q9Q9Q9Q"), "confirmation-member-ineligible")


def test_a_member_of_another_entity_is_refused():
    m = _m()
    _refused(m, "mismatch", copy.deepcopy(PROOF),
             _member(A, uid="EU-DE-EOID-7K3D9W0Q2M5FW0"), "confirmation-not-member-bound")


def test_an_inactive_member_is_refused():
    m = _m()
    ms = copy.deepcopy(MEMBERS); ms[0]["status"] = "suspended"
    _refused(m, "mismatch", copy.deepcopy(PROOF), _member(A),
             "confirmation-member-ineligible", members=ms)


def test_a_device_that_cannot_acknowledge_is_refused():
    m = _m()
    ms = copy.deepcopy(MEMBERS)
    ms[0]["devices"][0]["capabilities"] = ["receive"]      # dev-01 loses `ack`
    _refused(m, "mismatch", _signed(m, PROOF), _dev(A),
             "confirmation-member-ineligible", members=ms)


def test_a_wrong_principal_retry_is_refused_before_the_stored_answer():
    """Before B2 this returned the NDE issued to A — authentication bypassed
    on an idempotent read."""
    m = _m()
    first = _deliver(m, "mismatch", copy.deepcopy(PROOF), _member(A))
    with pytest.raises(m.ConfirmationRejected) as exc:
        _deliver(m, "mismatch", copy.deepcopy(PROOF), _member(B))
    assert exc.value.reason == "confirmation-not-member-bound"
    assert _deliver(m, "mismatch", copy.deepcopy(PROOF), _member(A)) == first


# ===========================================================================
# The reasons a client switches on are published
# ===========================================================================

def test_every_confirmation_reason_is_registered_and_none_is_a_phantom():
    import re
    raised = set(re.findall(r'ConfirmationRejected\(\s*"([a-z-]+)"',
                            (ROOT / "scripts" / "mock_rdp.py").read_text()))
    registered = {k for k in json.loads((ROOT / "registries" / "reason-codes.json")
                                        .read_text())["confirmation_rejection_reasons"]
                  if not k.startswith("$")}
    assert raised == registered, (sorted(raised - registered), sorted(registered - raised))
